//! macOS desktop backend — `CGEvent` for synthetic input and the built-in
//! `screencapture` binary for captures.
//!
//! `screencapture` is a system tool (`/usr/sbin/screencapture`) like `scrot`
//! on Linux — no crate needed, and it already returns a PNG. Input goes
//! through `core-graphics`' `CGEventPost`, the same API `xdotool` maps to on
//! X11.
//!
//! **Permissions are the gate.** macOS requires *Screen Recording* for the
//! capture to see the desktop and *Accessibility* for `CGEventPost` to reach
//! other apps. Both are granted in System Settings → Privacy & Security.
//! The probe checks the screen-recording one via `CGPreflightScreenCaptureAccess`;
//! the accessibility prompt fires lazily on the first `CGEventPost` (there's
//! no clean preflight without prompting the user, which we don't want at
//! detect time). Without them the calls fail loudly rather than pretend.
//!
//! Coordinate space is screenshot-space like every backend — see
//! [`traits::Capture`].

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use image::GenericImageView;

use crate::traits::{
    fit_dimensions, Capture, DesktopBackend, MouseButton, ScreenshotMeta, ScrollDir, MAX_EDGE,
};

const CMD_TIMEOUT: Duration = Duration::from_secs(15);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(20);

/// One macOS session's worth of state — the last capture's scale for the
/// image→display coordinate map.
pub struct MacBackend {
    last: Mutex<Option<Capture>>,
}

impl MacBackend {
    /// Screen-recording permission is preflightable via ScreenCaptureKit
    /// (`CGPreflightScreenCaptureAccess`). Accessibility (for CGEventPost) is
    /// not preflightable without prompting, so it's checked at first use.
    pub fn probe() -> Result<Self> {
        if let Err(e) = screen_capture_access() {
            bail!("{e} — grant Screen Recording in System Settings → Privacy & Security, then restart the app");
        }
        Ok(Self {
            last: Mutex::new(None),
        })
    }

    fn last_capture(&self) -> Option<Capture> {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn map(&self, c: [i32; 2]) -> [i32; 2] {
        match self.last_capture() {
            Some(cap) => cap.map_to_display(c),
            None => c,
        }
    }
}

#[async_trait::async_trait]
impl DesktopBackend for MacBackend {
    fn id(&self) -> &'static str {
        "macos"
    }

    async fn screenshot(&self, dest: &Path) -> Result<ScreenshotMeta> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let raw = tmp_sibling(dest);
        // `-x` silent, `-t png` format, `-o` writes to the path.
        run(
            "screencapture",
            &["-x", "-t", "png", &raw.to_string_lossy()],
            CAPTURE_TIMEOUT,
        )
        .await
        .context("screencapture")?;

        // Decode + downscale is CPU-bound and takes ~100–300 ms on a 4K grab.
        // The closure owns its copy of `raw`; the local one stays for cleanup.
        let dest_buf = dest.to_path_buf();
        let raw_for_task = raw.clone();
        let meta = tokio::task::spawn_blocking(move || downscale_png(&raw_for_task, &dest_buf))
            .await
            .context("screenshot task panicked")??;
        let _ = std::fs::remove_file(&raw);
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(meta.capture());
        Ok(meta)
    }

    async fn click(&self, button: MouseButton, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        cg_click(x, y, button, false)
    }

    async fn double_click(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        cg_click(x, y, MouseButton::Left, true)
    }

    async fn move_to(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        cg_move(x, y)
    }

    async fn drag(&self, from: [i32; 2], to: [i32; 2]) -> Result<()> {
        let [x1, y1] = self.map(from);
        let [x2, y2] = self.map(to);
        cg_move(x1, y1)?;
        cg_down(x1, y1, MouseButton::Left)?;
        for i in 1..=8 {
            let x = x1 + (x2 - x1) * i / 8;
            let y = y1 + (y2 - y1) * i / 8;
            cg_drag(x, y)?;
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        cg_up(x2, y2, MouseButton::Left)
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        // CGEventKeyboardSetUnicodeString takes the whole UTF-16 buffer in
        // one event — surrogate pairs stay together so supplementary-plane
        // chars actually compose (a per-unit event stream can't rebuild
        // them). Same path as SendInput's KEYEVENTF_UNICODE on Windows.
        let ev = CGEvent::new_keyboard_event(event_source()?, 0, true)
            .map_err(|_| anyhow!("CGEvent type-text"))?;
        ev.set_string(text);
        post(ev)
    }

    async fn key(&self, combo: &str, hold_ms: Option<u64>) -> Result<()> {
        let parts: Vec<&str> = combo
            .split('+')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.is_empty() {
            bail!("empty key combo");
        }
        match hold_ms {
            Some(ms) => {
                crate::keys::hold_chord(
                    &parts,
                    Duration::from_millis(ms),
                    |k| cg_key(k, true),
                    |k| {
                        let _ = cg_key(k, false);
                    },
                )
                .await
            }
            None => {
                for p in &parts {
                    cg_key(p, true)?;
                }
                for p in parts.iter().rev() {
                    cg_key(p, false)?;
                }
                Ok(())
            }
        }
    }

    async fn scroll(&self, dir: ScrollDir, amount: i32, at: Option<[i32; 2]>) -> Result<()> {
        if let Some(at) = at {
            self.move_to(at).await?;
        }
        let steps = amount.clamp(1, 500);
        let delta = match dir {
            ScrollDir::Up => steps,
            ScrollDir::Down => -steps,
            ScrollDir::Left => steps, // wheel1 is vertical; left/right map to wheel2
            ScrollDir::Right => -steps, // via the second axis below.
        };
        cg_scroll(dir, delta)
    }

    async fn cursor_position(&self) -> Result<[i32; 2]> {
        let pos = cg_cursor()?;
        Ok(match self.last_capture() {
            Some(cap) => cap.map_to_image(pos),
            None => pos,
        })
    }

    async fn launch_app(&self, command: &str) -> Result<()> {
        let spec = crate::traits::parse_launch(command)?;
        // A command-line tool on PATH (`code`, `kwrite`) is exec'd directly,
        // like on Linux. Anything else is an application name or bundle
        // (`Safari`, `/Applications/Foo.app`) — LaunchServices resolves those.
        if !spec.program.ends_with(".app") && crate::launch::program_exists(&spec.program) {
            return crate::launch::spawn_detached(&spec).await;
        }
        let mut args: Vec<&str> = vec!["-a", &spec.program];
        args.extend(spec.args.iter().map(String::as_str));
        run("open", &args, CMD_TIMEOUT).await?;
        Ok(())
    }
}

/* ============================ capture ============================ */

/// `CGPreflightScreenCaptureAccess` — true when the app already holds Screen
/// Recording permission. `None` on a link/build failure is treated as "ok"
/// so a marginal OS still probes (the actual screencapture call will fail
/// loudly anyway).
fn screen_capture_access() -> Result<()> {
    let ok = unsafe { CGPreflightScreenCaptureAccess() };
    if ok {
        Ok(())
    } else {
        Err(anyhow!("Screen Recording permission not granted"))
    }
}

/// Capture lands next to `dest` under a temp name, then is downscaled +
/// re-encoded into `dest` — identical to the X11 flow.
fn tmp_sibling(dest: &Path) -> PathBuf {
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "shot".into());
    dest.with_file_name(format!(".{stem}.tmp.png"))
}

fn downscale_png(raw: &Path, dest: &Path) -> Result<ScreenshotMeta> {
    let img = image::open(raw).with_context(|| format!("decode capture {}", raw.display()))?;
    let (dw, dh) = img.dimensions();
    let (tw, th) = fit_dimensions(dw, dh, MAX_EDGE);
    let out = if (tw, th) == (dw, dh) {
        img
    } else {
        img.resize_exact(tw, th, image::imageops::FilterType::Triangle)
    };
    out.save_with_format(dest, image::ImageFormat::Png)
        .with_context(|| format!("write screenshot {}", dest.display()))?;
    Ok(ScreenshotMeta {
        path: dest.to_path_buf(),
        display: [dw, dh],
        image: [tw, th],
    })
}

/// Run a system binary with a timeout, no sandboxing (macOS tools need the
/// real session). Mirrors the X11 `run` helper.
async fn run(cmd: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let mut c = tokio::process::Command::new(cmd);
    c.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    c.process_group(0);
    let child = c.spawn().with_context(|| format!("spawn `{cmd}`"))?;
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(r) => r.with_context(|| format!("wait for `{cmd}`"))?,
        Err(_) => bail!("`{cmd}` timed out after {}s", timeout.as_secs()),
    };
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("`{cmd}` failed ({}): {}", output.status, err.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/* ============================ input ============================ */

// `check-macos` builds this module off-target against a stub — the alias
// makes every `core_graphics::` path below resolve to it there and to the
// real crate on macOS.
#[cfg(not(target_os = "macos"))]
use crate::core_graphics_stub as core_graphics;

use core_graphics::event::{
    CGEvent, CGEventTapLocation, CGEventType, CGMouseButton, ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;

fn event_source() -> Result<CGEventSource> {
    CGEventSource::new(CGEventSourceStateID::HIDSystemState)
        .map_err(|_| anyhow!("CGEventSource unavailable"))
}

fn post(ev: CGEvent) -> Result<()> {
    ev.post(CGEventTapLocation::HID);
    Ok(())
}

fn point(x: i32, y: i32) -> CGPoint {
    CGPoint::new(x as f64, y as f64)
}

fn cg_button(b: MouseButton) -> CGMouseButton {
    match b {
        MouseButton::Left => CGMouseButton::Left,
        MouseButton::Middle => CGMouseButton::Center,
        MouseButton::Right => CGMouseButton::Right,
    }
}

fn cg_move(x: i32, y: i32) -> Result<()> {
    let ev = CGEvent::new_mouse_event(
        event_source()?,
        CGEventType::MouseMoved,
        point(x, y),
        CGMouseButton::Left,
    )
    .map_err(|_| anyhow!("CGEvent mousemove"))?;
    post(ev)
}

fn cg_down(x: i32, y: i32, b: MouseButton) -> Result<()> {
    let ty = match b {
        MouseButton::Left => CGEventType::LeftMouseDown,
        MouseButton::Right => CGEventType::RightMouseDown,
        MouseButton::Middle => CGEventType::OtherMouseDown,
    };
    let ev = CGEvent::new_mouse_event(event_source()?, ty, point(x, y), cg_button(b))
        .map_err(|_| anyhow!("CGEvent mousedown"))?;
    post(ev)
}

fn cg_up(x: i32, y: i32, b: MouseButton) -> Result<()> {
    let ty = match b {
        MouseButton::Left => CGEventType::LeftMouseUp,
        MouseButton::Right => CGEventType::RightMouseUp,
        MouseButton::Middle => CGEventType::OtherMouseUp,
    };
    let ev = CGEvent::new_mouse_event(event_source()?, ty, point(x, y), cg_button(b))
        .map_err(|_| anyhow!("CGEvent mouseup"))?;
    post(ev)
}

fn cg_drag(x: i32, y: i32) -> Result<()> {
    let ev = CGEvent::new_mouse_event(
        event_source()?,
        CGEventType::LeftMouseDragged,
        point(x, y),
        CGMouseButton::Left,
    )
    .map_err(|_| anyhow!("CGEvent drag"))?;
    post(ev)
}

fn cg_click(x: i32, y: i32, b: MouseButton, double: bool) -> Result<()> {
    cg_move(x, y)?;
    cg_down(x, y, b)?;
    cg_up(x, y, b)?;
    if double {
        cg_down(x, y, b)?;
        cg_up(x, y, b)?;
    }
    Ok(())
}

/// Map a name to a macOS keycode and press/release it.
fn cg_key(name: &str, down: bool) -> Result<()> {
    let code = keycode_from_name(name).ok_or_else(|| anyhow!("unknown key `{name}`"))?;
    let ev = CGEvent::new_keyboard_event(event_source()?, code, down)
        .map_err(|_| anyhow!("CGEvent key `{name}`"))?;
    post(ev)
}

fn cg_scroll(dir: ScrollDir, delta: i32) -> Result<()> {
    // CGEvent scroll takes wheel1 (vertical) / wheel2 (horizontal).
    let (w1, w2) = match dir {
        ScrollDir::Up | ScrollDir::Down => (delta, 0),
        ScrollDir::Left | ScrollDir::Right => (0, delta),
    };
    let ev = CGEvent::new_scroll_event(event_source()?, ScrollEventUnit::LINE, 1, w1, w2, 0)
        .map_err(|_| anyhow!("CGEvent scroll"))?;
    post(ev)
}

fn cg_cursor() -> Result<[i32; 2]> {
    // CGEventGetLocation returns the pointer's global coords.
    let p = unsafe { CGEventGetLocation(std::ptr::null()) };
    Ok([p.x as i32, p.y as i32])
}

/// Name → macOS virtual keycode (kVK_*). Covers the common set; unknown
/// single chars resolve through the ASCII keypad keys where sensible.
fn keycode_from_name(n: &str) -> Option<u16> {
    let code = match n.to_ascii_lowercase().as_str() {
        "ctrl" | "control" => 0x3B,                   // kVK_Control
        "shift" => 0x38,                              // kVK_Shift
        "alt" | "option" => 0x3A,                     // kVK_Option
        "meta" | "cmd" | "command" | "super" => 0x37, // kVK_Command
        "enter" | "return" => 0x24,                   // kVK_Return
        "esc" | "escape" => 0x35,                     // kVK_Escape
        "tab" => 0x30,                                // kVK_Tab
        "space" => 0x31,                              // kVK_Space
        "backspace" | "delete" => 0x33,               // kVK_Delete (backspace)
        "fwdel" => 0x75,                              // kVK_ForwardDelete
        "home" => 0x73,
        "end" => 0x77,
        "pageup" | "pgup" => 0x74,
        "pagedown" | "pgdn" => 0x79,
        "up" => 0x7E,
        "down" => 0x7D,
        "left" => 0x7B,
        "right" => 0x7C,
        "f1" => 0x7A,
        "f2" => 0x78,
        "f3" => 0x63,
        "f4" => 0x76,
        "f5" => 0x60,
        "f6" => 0x61,
        "f7" => 0x62,
        "f8" => 0x64,
        "f9" => 0x65,
        "f10" => 0x6D,
        "f11" => 0x67,
        "f12" => 0x6F,
        _ => {
            // Letters/digits — macOS keycodes follow the ANSI layout.
            return ansi_keycode(n);
        }
    };
    Some(code)
}

/// ANSI-layout keycodes for letters/digits (the US physical layout — what
/// CGEvent expects regardless of the user's input source).
fn ansi_keycode(n: &str) -> Option<u16> {
    let c = match n {
        "a" => 0x00,
        "s" => 0x01,
        "d" => 0x02,
        "f" => 0x03,
        "h" => 0x04,
        "g" => 0x05,
        "z" => 0x06,
        "x" => 0x07,
        "c" => 0x08,
        "v" => 0x09,
        "b" => 0x0B,
        "q" => 0x0C,
        "w" => 0x0D,
        "e" => 0x0E,
        "r" => 0x0F,
        "y" => 0x10,
        "t" => 0x11,
        "1" => 0x12,
        "2" => 0x13,
        "3" => 0x14,
        "4" => 0x15,
        "6" => 0x17,
        "5" => 0x16,
        "=" => 0x18,
        "9" => 0x19,
        "7" => 0x1A,
        "-" => 0x1B,
        "8" => 0x1C,
        "0" => 0x1D,
        "]" => 0x1E,
        "o" => 0x1F,
        "u" => 0x20,
        "[" => 0x21,
        "i" => 0x22,
        "p" => 0x23,
        "l" => 0x25,
        "j" => 0x26,
        "'" => 0x27,
        "k" => 0x28,
        ";" => 0x29,
        "\\" => 0x2A,
        "," => 0x2B,
        "/" => 0x2C,
        "n" => 0x2D,
        "m" => 0x2E,
        "." => 0x2F,
        "`" => 0x32,
        _ => return None,
    };
    Some(c)
}

/* FFI for CGPreflightScreenCaptureAccess / CGEventGetLocation — the
core-graphics crate doesn't re-export these yet. */
extern "C" {
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGEventGetLocation(event: *const core_graphics::sys::CGEvent) -> CGPoint;
}
