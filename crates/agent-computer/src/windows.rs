//! Windows desktop backend — `SendInput` for synthetic input and GDI
//! `BitBlt` for captures, both through the `windows` crate.
//!
//! No external tools, no helper binaries, no extra capture crate: unlike the
//! X11 backend (which shells out to `xdotool`/`scrot`), everything here is
//! in-process through Win32. DPI note — the process should mark itself
//! DPI-aware (`SetProcessDpiAwarenessContext`) or `SendInput` coordinates
//! and `BitBlt` pixels disagree on >100% scaling; both APIs speak physical
//! pixels once the process is aware, so they line up.
//!
//! Coordinate space is screenshot-space like every backend — see
//! [`traits::Capture`].

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::traits::{
    fit_dimensions, Capture, DesktopBackend, MouseButton, ScreenshotMeta, ScrollDir, MAX_EDGE,
};

/// One Windows session's worth of state — the last capture's scale, so input
/// coordinates map image→display exactly like the X11 backend.
pub struct WindowsBackend {
    last: Mutex<Option<Capture>>,
}

impl WindowsBackend {
    /// Probe is trivial on Windows — there's no `$DISPLAY`/tool to check for;
    /// if the process can call Win32 at all it can synthesize input. We still
    /// go through `probe()` so `detect` stays symmetric with Linux/macOS.
    pub fn probe() -> Result<Self> {
        // SendInput needs no `$DISPLAY`/external tool — a desktop session can
        // always synthesize input. The only real gate is "is there a screen to
        // look at", which GetSystemMetrics answers without a grab.
        if virtual_screen().is_some() {
            Ok(Self {
                last: Mutex::new(None),
            })
        } else {
            bail!("no display — headless or locked RDP session?")
        }
    }

    fn last_capture(&self) -> Option<Capture> {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Image coordinate → display coordinate.
    fn map(&self, c: [i32; 2]) -> [i32; 2] {
        match self.last_capture() {
            Some(cap) => cap.map_to_display(c),
            None => c,
        }
    }
}

#[async_trait::async_trait]
impl DesktopBackend for WindowsBackend {
    fn id(&self) -> &'static str {
        "windows"
    }

    async fn screenshot(&self, dest: &Path) -> Result<ScreenshotMeta> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let dest = dest.to_path_buf();
        let meta = tokio::task::spawn_blocking(move || capture_primary(&dest))
            .await
            .context("screenshot task panicked")??;
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(meta.capture());
        Ok(meta)
    }

    async fn click(&self, button: MouseButton, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        move_abs(x, y)?;
        send_click(button, false)
    }

    async fn double_click(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        move_abs(x, y)?;
        send_click(MouseButton::Left, false)?;
        send_click(MouseButton::Left, false)
    }

    async fn move_to(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        move_abs(x, y)
    }

    async fn drag(&self, from: [i32; 2], to: [i32; 2]) -> Result<()> {
        let [x1, y1] = self.map(from);
        let [x2, y2] = self.map(to);
        move_abs(x1, y1)?;
        mouse_button(true, MouseButton::Left)?;
        // A real drag needs intermediate moves so apps that poll see a path,
        // not a teleport — a couple of steps keeps cheap hover handlers happy.
        for i in 1..=8 {
            let x = x1 + (x2 - x1) * i / 8;
            let y = y1 + (y2 - y1) * i / 8;
            move_abs(x, y)?;
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        mouse_button(false, MouseButton::Left)
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        // SendInput with KEYEVENTF_UNICODE types any UTF-16 char, not just what
        // the layout maps — better than X11's keysym-only typing.
        type_unicode(text)
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
                    |k| key_vk(k, true),
                    |k| {
                        let _ = key_vk(k, false);
                    },
                )
                .await
            }
            None => {
                for p in &parts {
                    key_vk(p, true)?;
                }
                for p in parts.iter().rev() {
                    key_vk(p, false)?;
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
            _ => bail!("horizontal scroll not supported on Windows SendInput"),
        };
        wheel(delta)
    }

    async fn cursor_position(&self) -> Result<[i32; 2]> {
        let pos = get_cursor()?;
        Ok(match self.last_capture() {
            Some(cap) => cap.map_to_image(pos),
            None => pos,
        })
    }

    async fn launch_app(&self, command: &str) -> Result<()> {
        // Direct exec, no `cmd /c start` — see `launch::spawn_detached`.
        crate::launch::spawn_detached(&crate::traits::parse_launch(command)?).await
    }
}

/* ============================ capture ============================ */

use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateDCW, DeleteDC, DeleteObject,
    GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetSystemMetrics, SetCursorPos, SM_CXSCREEN, SM_CYSCREEN, WHEEL_DELTA,
};

/// The primary monitor's physical pixel size — `None` on a truly headless box.
fn virtual_screen() -> Option<(i32, i32)> {
    let w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    (w > 0 && h > 0).then(|| (w, h))
}

/// Grab the primary screen via GDI BitBlt, downscale to `MAX_EDGE`, write the
/// model-facing PNG to `dest`. Runs on `spawn_blocking` — BitBlt + the encode
/// are CPU work that must not sit on the async executor.
fn capture_primary(dest: &Path) -> Result<ScreenshotMeta> {
    let (dw, dh) = virtual_screen().ok_or_else(|| anyhow!("no display to capture"))?;
    let rgba = grab_primary(dw, dh).context("BitBlt capture")?;
    let (tw, th) = fit_dimensions(dw as u32, dh as u32, MAX_EDGE);
    let dyn_img = image::DynamicImage::ImageRgba8(
        image::RgbaImage::from_raw(dw as u32, dh as u32, rgba)
            .ok_or_else(|| anyhow!("bad capture buffer"))?,
    );
    let out = if (tw as u32, th as u32) == (dw as u32, dh as u32) {
        dyn_img
    } else {
        dyn_img.resize_exact(tw, th, image::imageops::FilterType::Triangle)
    };
    out.save_with_format(dest, image::ImageFormat::Png)
        .with_context(|| format!("write screenshot {}", dest.display()))?;
    Ok(ScreenshotMeta {
        path: dest.to_path_buf(),
        display: [dw as u32, dh as u32],
        image: [tw, th],
    })
}

/// `CreateDC` on the primary display → `BitBlt` the whole frame into a DIB,
/// return it as RGBA bytes (GDI emits BGRA — swap the channels here so the
/// shared `image` PNG path stays format-agnostic).
fn grab_primary(w: i32, h: i32) -> Result<Vec<u8>> {
    unsafe {
        let screen_dc = CreateDCW(
            windows::core::w!("DISPLAY"),
            windows::core::PCWSTR::null(),
            windows::core::PCWSTR::null(),
            None,
        );
        if screen_dc.is_invalid() {
            bail!("CreateDC(DISPLAY) failed");
        }
        let mem_dc = CreateCompatibleDC(Some(screen_dc));
        let bmp = CreateCompatibleBitmap(screen_dc, w, h);
        // HBITMAP → HGDIOBJ for SelectObject/DeleteObject.
        SelectObject(mem_dc, bmp.into());
        BitBlt(mem_dc, 0, 0, w, h, Some(screen_dc), 0, 0, SRCCOPY)
            .map_err(|e| anyhow!("BitBlt: {e}"))?;

        // Read the DIB back out as BGRA.
        let mut buf = vec![0u8; (w * h * 4) as usize];
        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        GetDIBits(
            mem_dc,
            bmp,
            0,
            h as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut info,
            DIB_RGB_COLORS,
        );

        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem_dc);
        let _ = DeleteDC(screen_dc);

        // BGRA → RGBA.
        for px in buf.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
        Ok(buf)
    }
}

/* ============================ input ============================ */

use windows::Win32::Foundation::POINT;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL,
    MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};

/// Absolute pixel move (the whole virtual desktop, so multi-monitor works).
fn move_abs(x: i32, y: i32) -> Result<()> {
    unsafe { SetCursorPos(x, y) }.map_err(|e| anyhow!("SetCursorPos: {e}"))
}

fn get_cursor() -> Result<[i32; 2]> {
    let mut p = POINT::default();
    unsafe { GetCursorPos(&mut p) }.map_err(|e| anyhow!("GetCursorPos: {e}"))?;
    Ok([p.x, p.y])
}

fn mouse_input(dx: i32, dy: i32, flags: MOUSE_EVENT_FLAGS, data: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key_input(vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS, unicode: u16) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: unicode,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> Result<()> {
    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if sent != inputs.len() as u32 {
        bail!("SendInput injected {sent}/{} events", inputs.len());
    }
    Ok(())
}

/// Press (`down` = true) or release a mouse button at the current position.
fn mouse_button(down: bool, b: MouseButton) -> Result<()> {
    let flag = match (b, down) {
        (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
        (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
        (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
        (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
        (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
        (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
    };
    send(&[mouse_input(0, 0, flag, 0)])
}

fn send_click(b: MouseButton, _double: bool) -> Result<()> {
    mouse_button(true, b)?;
    mouse_button(false, b)
}

fn wheel(delta_notches: i32) -> Result<()> {
    send(&[mouse_input(
        0,
        0,
        MOUSEEVENTF_WHEEL,
        (delta_notches * WHEEL_DELTA as i32) as u32,
    )])
}

/// Type a UTF-16 string char-by-char via KEYEVENTF_UNICODE.
fn type_unicode(text: &str) -> Result<()> {
    let mut inputs = Vec::with_capacity(text.encode_utf16().count() * 2);
    for unit in text.encode_utf16() {
        inputs.push(key_input(VIRTUAL_KEY(0), KEYEVENTF_UNICODE, unit));
        inputs.push(key_input(
            VIRTUAL_KEY(0),
            KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
            unit,
        ));
    }
    send(&inputs)
}

/// Map a key name to a virtual-key code and press/release it.
fn key_vk(name: &str, down: bool) -> Result<()> {
    let vk = vk_from_name(name).ok_or_else(|| anyhow!("unknown key `{name}`"))?;
    let flag = if down {
        KEYBD_EVENT_FLAGS(0)
    } else {
        KEYEVENTF_KEYUP
    };
    send(&[key_input(vk, flag, 0)])
}

/// Name → VK code. Covers the keys a model is likely to emit plus the common
/// alphanumeric range — anything else resolves through `VkKeyScan` semantics
/// we don't want to drag in for a name the user typed.
fn vk_from_name(n: &str) -> Option<VIRTUAL_KEY> {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    let key = match n.to_ascii_lowercase().as_str() {
        "ctrl" | "control" => VK_CONTROL,
        "shift" => VK_SHIFT,
        "alt" => VK_MENU,
        "meta" | "win" | "super" | "cmd" => VK_LWIN,
        "enter" | "return" => VK_RETURN,
        "esc" | "escape" => VK_ESCAPE,
        "tab" => VK_TAB,
        "space" => VK_SPACE,
        "backspace" => VK_BACK,
        "delete" | "del" => VK_DELETE,
        "insert" | "ins" => VK_INSERT,
        "home" => VK_HOME,
        "end" => VK_END,
        "pageup" | "pgup" => VK_PRIOR,
        "pagedown" | "pgdn" => VK_NEXT,
        "up" => VK_UP,
        "down" => VK_DOWN,
        "left" => VK_LEFT,
        "right" => VK_RIGHT,
        "f1" => VK_F1,
        "f2" => VK_F2,
        "f3" => VK_F3,
        "f4" => VK_F4,
        "f5" => VK_F5,
        "f6" => VK_F6,
        "f7" => VK_F7,
        "f8" => VK_F8,
        "f9" => VK_F9,
        "f10" => VK_F10,
        "f11" => VK_F11,
        "f12" => VK_F12,
        "printscreen" | "prtsc" => VK_SNAPSHOT,
        _ => {
            // Single char: letters/digits share their ASCII VK code.
            let ch = n.chars().next()?;
            if n.len() == 1 && ch.is_ascii_alphanumeric() {
                return Some(VIRTUAL_KEY(ch.to_ascii_uppercase() as u16));
            }
            return None;
        }
    };
    Some(key)
}
