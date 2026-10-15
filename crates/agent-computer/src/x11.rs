//! X11 backend — `xdotool` for input, `scrot` (or ImageMagick `import`) for
//! capture; scaling happens in-process via the pure-Rust `image` decoder.
//!
//! **Why this does not go through `ctx.sandbox`:** bwrap builds the namespace
//! with `--clearenv` and a fresh tmpfs on `/tmp`, so `$DISPLAY`,
//! `$XAUTHORITY` and `/tmp/.X11-unix` are all gone by construction — a
//! sandboxed desktop tool is a broken feature, not a hardened one. The
//! containment that matters for synthetic input is the permission gate
//! (`ToolClass::Process`), which is where the user's confirm/deny lands.
//!
//! The child environment is the *host's*, deliberately: xauth and the display
//! socket live in the invoking user's session.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use image::GenericImageView;

use crate::traits::{
    fit_dimensions, Capture, DesktopBackend, MouseButton, ScreenshotMeta, ScrollDir, MAX_EDGE,
};

/// Every one of these commands is short; a hung one is a hung session.
const CMD_TIMEOUT: Duration = Duration::from_secs(15);
/// Capture is the slow one — a 4K grab plus decode. Still bounded.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);

/// Which binary takes the actual screenshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureTool {
    /// `spectacle -b -n -o <file>` — KDE Plasma's native grabber, walks
    /// `zkde_screencast` so it sees the real compositor frame on **Wayland**.
    /// Preferred whenever a Wayland socket exists: X11 grabbers (`scrot`,
    /// `import`) read the X composite root, which on a Wayland session is a
    /// black surface — input through XWayland still works, only the eyes
    /// go dark.
    Spectacle,
    /// `scrot -o <file>` — the lightest X11 capture. Correct on a real X11
    /// session; reads a black frame on Wayland.
    Scrot,
    /// ImageMagick `import -window root <file>` — X11 fallback; same
    /// Wayland black-frame caveat as `scrot`.
    Import,
}

#[derive(Debug)]
pub struct X11Backend {
    capture_tool: CaptureTool,
    /// Scale installed by the last capture — the bridge from the model's grid
    /// to the display's. Shared across `ToolCtx` clones, so a screenshot in
    /// one tool call steers the click in the next. Deliberately NOT
    /// turn-scoped: `with_cancel`/`with_desktop` clone the same `Arc`, and a
    /// batched fan-out (`screenshot` + `computer` in one `batch_execute`)
    /// therefore maps every action against the newest frame — sequence the
    /// two instead of racing them.
    last: Mutex<Option<Capture>>,
}

impl X11Backend {
    /// Probe the host: `$DISPLAY`, `xdotool`, and a capture tool must all be
    /// present. The `Err` string is model-facing — it becomes the refusal
    /// text of the `none` backend.
    pub fn probe() -> Result<Self> {
        probe_inner(
            std::env::var_os("DISPLAY").is_some(),
            on_path("xdotool"),
            capture_tool_on_path(),
            std::env::var_os("WAYLAND_DISPLAY").is_some(),
        )
    }

    /// Map a screenshot-space coordinate onto the display. Without a capture
    /// the two spaces coincide (nothing has been scaled yet).
    fn map(&self, at: [i32; 2]) -> [i32; 2] {
        let last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match *last {
            Some(cap) => cap.map_to_display(at),
            None => at,
        }
    }

    /// The last capture's scale, for mapping display coordinates back.
    fn last_capture(&self) -> Option<Capture> {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One `xdotool` invocation.
    async fn x(&self, args: &[&str]) -> Result<String> {
        run("xdotool", args, CMD_TIMEOUT).await
    }
}

#[async_trait::async_trait]
impl DesktopBackend for X11Backend {
    fn id(&self) -> &'static str {
        "x11"
    }

    async fn screenshot(&self, dest: &Path) -> Result<ScreenshotMeta> {
        capture(self.capture_tool, &self.last, dest).await
    }

    async fn click(&self, button: MouseButton, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        let (xs, ys, bs) = (x.to_string(), y.to_string(), x_button(button).to_string());
        self.x(&["mousemove", "--sync", &xs, &ys, "click", &bs])
            .await?;
        Ok(())
    }

    async fn double_click(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        let (xs, ys) = (x.to_string(), y.to_string());
        self.x(&[
            "mousemove",
            "--sync",
            &xs,
            &ys,
            "click",
            "--repeat",
            "2",
            "--delay",
            "120",
            "1",
        ])
        .await?;
        Ok(())
    }

    async fn move_to(&self, at: [i32; 2]) -> Result<()> {
        let [x, y] = self.map(at);
        let (xs, ys) = (x.to_string(), y.to_string());
        self.x(&["mousemove", "--sync", &xs, &ys]).await?;
        Ok(())
    }

    async fn drag(&self, from: [i32; 2], to: [i32; 2]) -> Result<()> {
        let [x1, y1] = self.map(from);
        let [x2, y2] = self.map(to);
        let (x1s, y1s, x2s, y2s) = (
            x1.to_string(),
            y1.to_string(),
            x2.to_string(),
            y2.to_string(),
        );
        self.x(&[
            "mousemove",
            "--sync",
            &x1s,
            &y1s,
            "mousedown",
            "1",
            "mousemove",
            "--sync",
            &x2s,
            &y2s,
            "mouseup",
            "1",
        ])
        .await?;
        Ok(())
    }

    async fn type_text(&self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        // `--` so text that begins with `-` is typed, not parsed as flags.
        // XTEST types by keysym: non-ASCII that is not on the current layout
        // cannot be produced (the tool description says so).
        self.x(&["type", "--delay", "12", "--", text]).await?;
        Ok(())
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
            // A chord held down. `xdotool keydown`/`keyup` take one key each,
            // so each runs as its own process; `hold_chord` guarantees every
            // pressed key is released, on failure and on cancellation too.
            Some(ms) => {
                crate::keys::hold_chord(
                    &parts,
                    Duration::from_millis(ms),
                    |k| {
                        // Blocking is fine here: `xdotool keydown` returns at once.
                        run_blocking("xdotool", &["keydown", "--", k])
                    },
                    |k| {
                        let _ = run_blocking("xdotool", &["keyup", "--", k]);
                    },
                )
                .await?;
            }
            None => {
                self.x(&["key", "--", combo]).await?;
            }
        }
        Ok(())
    }

    async fn scroll(&self, dir: ScrollDir, amount: i32, at: Option<[i32; 2]>) -> Result<()> {
        if let Some(at) = at {
            self.move_to(at).await?;
        }
        let steps = amount.clamp(1, 500).to_string();
        let button = x_scroll_button(dir);
        // One process for N clicks — a wheel burst must not spawn 50 children.
        self.x(&["click", "--repeat", &steps, "--delay", "12", button])
            .await?;
        Ok(())
    }

    async fn cursor_position(&self) -> Result<[i32; 2]> {
        let out = self.x(&["getmouselocation", "--shell"]).await?;
        let mut xy = [0i32; 2];
        for line in out.lines() {
            if let Some(v) = line.strip_prefix("X=") {
                xy[0] = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Y=") {
                xy[1] = v.trim().parse().unwrap_or(0);
            }
        }
        Ok(match self.last_capture() {
            Some(cap) => cap.map_to_image(xy),
            None => xy,
        })
    }

    async fn launch_app(&self, command: &str) -> Result<()> {
        // Parsed and exec'd directly — no `sh -c`, so quoting, newlines and
        // `bash -c '…'` cannot smuggle a second command past the filter.
        crate::launch::spawn_detached(&crate::traits::parse_launch(command)?).await
    }
}

/// The probe, with its inputs injectable so the decision table is testable
/// without an X server (and without racing on the process environment).
fn probe_inner(
    has_display: bool,
    has_xdotool: bool,
    capture: Option<CaptureTool>,
    on_wayland: bool,
) -> Result<X11Backend> {
    if !has_display {
        bail!("$DISPLAY is not set — no X11 session to control (headless host?)");
    }
    if !has_xdotool {
        bail!("`xdotool` not found on PATH — install it to enable desktop control");
    }
    let capture_tool = capture.ok_or_else(|| {
        anyhow!(
            "neither `scrot` nor ImageMagick `import` found on PATH — install one to enable screenshots"
        )
    })?;
    // On Wayland only a compositor-aware grabber sees real pixels. `scrot`/
    // `import` read the XWayland root and return a black frame with no error,
    // so a model would "look" at nothing and click blind. Refuse up front.
    if on_wayland && capture_tool != CaptureTool::Spectacle {
        bail!(
            "this is a Wayland session and only X11 screen grabbers (`scrot`/`import`) are \
             installed — they capture a black frame. Install `spectacle` (KDE) to enable \
             screenshots, or log into an X11 session"
        );
    }
    Ok(X11Backend {
        capture_tool,
        last: Mutex::new(None),
    })
}

/// Which capture tool the host provides.
///
/// **Wayland session** (`WAYLAND_DISPLAY` is set): `spectacle` is the only
/// tool that sees the compositor's real frame — X11 grabbers read the X
/// composite root and come back black. `scrot`/`import` stay as fallbacks
/// when no KDE tool exists.
///
/// **X11 session**: `scrot` → `import` → `spectacle`. The last is still
/// listed in case a KDE app happens to be installed on a non-KDE X11
/// desktop (spectacle falls back to `xcb_image` then and works fine).
pub(crate) fn capture_tool_on_path() -> Option<CaptureTool> {
    let on_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    if on_wayland {
        if on_path("spectacle") {
            return Some(CaptureTool::Spectacle);
        }
    }
    if on_path("scrot") {
        Some(CaptureTool::Scrot)
    } else if on_path("import") {
        Some(CaptureTool::Import)
    } else if on_path("spectacle") {
        Some(CaptureTool::Spectacle)
    } else {
        None
    }
}

/// `PATH` lookup — no `which` subprocess, no shell.
fn on_path(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(bin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            candidate
                .metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            candidate.is_file()
        }
    })
}

/// X11 button numbers for the mouse buttons.
fn x_button(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
    }
}

/// X11 wheel buttons: 4/5 vertical, 6/7 horizontal.
fn x_scroll_button(dir: ScrollDir) -> &'static str {
    match dir {
        ScrollDir::Up => "4",
        ScrollDir::Down => "5",
        ScrollDir::Left => "6",
        ScrollDir::Right => "7",
    }
}

/// Grab the screen with `tool`, downscale it to the model's grid, and record
/// the scale in `last` so input coordinates can be mapped. Shared by every
/// backend that captures through an external tool (X11, Wayland via libei).
pub async fn capture(
    tool: CaptureTool,
    last: &Mutex<Option<Capture>>,
    dest: &Path,
) -> Result<ScreenshotMeta> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create {}", parent.display()))?;
    }
    // Capture to a sibling temp name: the capture tool picks its format
    // from the extension, and a half-written file must never be the one
    // the model is handed.
    let raw = tmp_sibling(dest);
    let raw_str = raw.to_string_lossy().into_owned();
    let grabbed = match tool {
        // `-b` background (no editor UI), `-n` no-notify (no KDE
        // notification popup blocking the next frame).
        CaptureTool::Spectacle => {
            run("spectacle", &["-b", "-n", "-o", &raw_str], CAPTURE_TIMEOUT).await
        }
        CaptureTool::Scrot => run("scrot", &["-o", &raw_str], CAPTURE_TIMEOUT).await,
        CaptureTool::Import => run("import", &["-window", "root", &raw_str], CAPTURE_TIMEOUT).await,
    };
    if let Err(e) = grabbed {
        let _ = std::fs::remove_file(&raw);
        return Err(e);
    }

    // Decode + downscale is CPU-bound and takes ~100–300 ms on a 4K grab.
    // The closure owns its copy of `raw`; the local one stays for cleanup.
    let dest = dest.to_path_buf();
    let raw_for_task = raw.clone();
    let meta = tokio::task::spawn_blocking(move || downscale_png(&raw_for_task, &dest))
        .await
        .context("screenshot task panicked")?;
    let _ = std::fs::remove_file(&raw);
    let meta = meta?;

    *last.lock().unwrap_or_else(|e| e.into_inner()) = Some(meta.capture());
    Ok(meta)
}

/// Capture lands next to its final name (same filesystem, same lifecycle) with
/// a `.tmp.png` extension so the capture tool still writes a real PNG and the
/// half-written file never wears the name the model was given.
fn tmp_sibling(dest: &Path) -> PathBuf {
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "shot".into());
    dest.with_file_name(format!(".{stem}.tmp.png"))
}

/// True when every sampled pixel is (near-)black. A real desktop — even a
/// dark-themed one — has a cursor, a panel or some text somewhere, so a frame
/// that is black everywhere is a failed grab, not a view. Samples a coarse
/// grid instead of walking all pixels of a 4K frame.
fn is_blank(img: &image::DynamicImage) -> bool {
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();
    if w == 0 || h == 0 {
        return true;
    }
    let (sx, sy) = ((w / 64).max(1), (h / 64).max(1));
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            let p = rgb.get_pixel(x, y).0;
            if p[0].max(p[1]).max(p[2]) > 8 {
                return false;
            }
            x += sx;
        }
        y += sy;
    }
    true
}

/// Decode the raw capture, downscale to [`MAX_EDGE`], write the PNG the model
/// sees. `display` is the *raw* size: synthetic input speaks the same space as
/// a full-screen grab, so the captured dimensions are the mapping's target,
/// not a separately queried screen size that could disagree with it.
fn downscale_png(raw: &Path, dest: &Path) -> Result<ScreenshotMeta> {
    let img = image::open(raw).with_context(|| format!("decode capture {}", raw.display()))?;
    let (dw, dh) = img.dimensions();
    if is_blank(&img) {
        bail!(
            "the capture is a uniform black frame — the screen is locked/asleep, or this \
             session does not let the grabber see it (Wayland, or a protected surface). \
             Nothing on screen can be read; do not click blind"
        );
    }
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

/// Run one desktop command with the host environment intact and a hard
/// timeout. Unlike the sandbox runner there is no env sanitization: the child
/// needs `$DISPLAY`/`$XAUTHORITY` (and `$HOME` for xauth) to reach the
/// session. `process_group(0)` + group-kill on timeout is the tree-kill half.
async fn run(cmd: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let mut c = tokio::process::Command::new(cmd);
    c.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    c.process_group(0);

    tracing::debug!(cmd, ?args, "desktop backend command");
    let child = c.spawn().with_context(|| format!("spawn `{cmd}`"))?;
    let pid = child.id();
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(r) => r.with_context(|| format!("wait for `{cmd}`"))?,
        Err(_) => {
            // The child is its own group leader — `kill -9 -pid` reaps the
            // whole tree, not just the direct child `kill_on_drop` would take.
            if let Some(pid) = pid {
                kill_group(pid);
            }
            bail!(
                "`{cmd}` timed out after {}s — process tree killed",
                timeout.as_secs()
            );
        }
    };
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("`{cmd}` failed ({}): {}", output.status, err.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Synchronous one-shot for key press/release: `hold_chord`'s `up` runs in a
/// `Drop`, where nothing can be awaited. Bounded so a wedged X server cannot
/// hang a cancel.
fn run_blocking(cmd: &str, args: &[&str]) -> Result<()> {
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawn `{cmd}`"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait()? {
            Some(st) if st.success() => return Ok(()),
            Some(st) => bail!("`{cmd}` failed ({st})"),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("`{cmd}` timed out");
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

#[cfg(target_family = "unix")]
fn kill_group(pgid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-9", &format!("-{pgid}")])
        .status();
}

#[cfg(not(target_family = "unix"))]
fn kill_group(_pgid: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe's refusal has to name the missing piece — this text is what
    /// the model reads when it tries to click on a headless host.
    #[test]
    fn probe_refusals_name_the_missing_piece() {
        let no_display = probe_inner(false, true, Some(CaptureTool::Scrot), false).unwrap_err();
        assert!(no_display.to_string().contains("$DISPLAY"), "{no_display}");

        let no_xdotool = probe_inner(true, false, Some(CaptureTool::Scrot), false).unwrap_err();
        assert!(no_xdotool.to_string().contains("xdotool"), "{no_xdotool}");

        let no_capture = probe_inner(true, true, None, false).unwrap_err();
        assert!(no_capture.to_string().contains("scrot"), "{no_capture}");

        // All three present → a live backend.
        let ok = probe_inner(true, true, Some(CaptureTool::Scrot), false).unwrap();
        assert_eq!(ok.id(), "x11");
    }

    /// Before any capture the two coordinate spaces coincide: a caller that
    /// skipped the screenshot means display coordinates.
    #[test]
    fn mapping_is_identity_until_a_capture_lands() {
        let b = probe_inner(true, true, Some(CaptureTool::Scrot), false).unwrap();
        assert_eq!(b.map([100, 200]), [100, 200]);
        assert!(b.last_capture().is_none());

        *b.last.lock().unwrap() = Some(Capture {
            display: [3840, 2160],
            image: [1568, 882],
        });
        assert_eq!(b.map([784, 441]), [1920, 1080]);
    }

    /// The temp capture name must keep a `.png` extension (the capture tool
    /// picks its format from it) and stay a sibling of the final file.
    #[test]
    fn temp_capture_name_is_a_png_sibling() {
        let dest = Path::new("/ws/.agent/attachments/shot-42.png");
        let tmp = tmp_sibling(dest);
        assert_eq!(tmp.parent(), dest.parent());
        assert_eq!(tmp.extension().and_then(|e| e.to_str()), Some("png"));
        assert_ne!(tmp, dest);
    }

    #[test]
    fn button_numbers_follow_x11() {
        assert_eq!(x_button(MouseButton::Left), 1);
        assert_eq!(x_button(MouseButton::Middle), 2);
        assert_eq!(x_button(MouseButton::Right), 3);
        assert_eq!(x_scroll_button(ScrollDir::Up), "4");
        assert_eq!(x_scroll_button(ScrollDir::Down), "5");
        assert_eq!(x_scroll_button(ScrollDir::Left), "6");
        assert_eq!(x_scroll_button(ScrollDir::Right), "7");
    }

    /// Exercise the real decode + downscale path with a generated PNG: the
    /// backend must write the scaled file AND record the raw size as the
    /// display space.
    #[test]
    fn downscale_writes_the_scaled_png_and_reports_both_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join(".shot.tmp.png");
        let dest = dir.path().join("shot.png");

        // 3000×600 source → long edge capped at 1568 (edge-bound, not area-bound).
        let src = image::RgbImage::from_fn(3000, 600, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 0])
        });
        image::DynamicImage::ImageRgb8(src)
            .save_with_format(&raw, image::ImageFormat::Png)
            .unwrap();

        let meta = downscale_png(&raw, &dest).unwrap();
        assert_eq!(meta.display, [3000, 600]);
        let (ew, eh) = fit_dimensions(3000, 600, MAX_EDGE);
        assert_eq!(meta.image, [ew, eh]);
        assert_eq!(meta.image[0], MAX_EDGE);
        assert!(dest.exists());
        assert_eq!(
            image::open(&dest).unwrap().dimensions(),
            (meta.image[0], meta.image[1])
        );
    }

    /// A capture whose long edge already fits is copied through unscaled —
    /// no resampling artifacts, no wasted work.
    #[test]
    fn small_capture_is_not_resized() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join(".small.tmp.png");
        let dest = dir.path().join("small.png");
        image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            640,
            480,
            image::Rgb([30, 60, 90]),
        ))
        .save_with_format(&raw, image::ImageFormat::Png)
        .unwrap();

        let meta = downscale_png(&raw, &dest).unwrap();
        assert_eq!(meta.display, [640, 480]);
        assert_eq!(meta.image, [640, 480]);
    }

    /// A missing/garbage capture is an error the model can read, not a panic.
    #[test]
    fn undecodable_capture_is_a_readable_error() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("junk.tmp.png");
        std::fs::write(&raw, b"not a png").unwrap();
        let err = downscale_png(&raw, &dir.path().join("out.png")).unwrap_err();
        assert!(err.to_string().contains("decode capture"), "{err}");
    }
    /// Wayland + only an X11 grabber = a black screenshot the model cannot
    /// tell from a real one. The probe must refuse, naming the fix.
    #[test]
    fn wayland_with_only_x11_grabbers_is_refused() {
        for tool in [CaptureTool::Scrot, CaptureTool::Import] {
            let e = probe_inner(true, true, Some(tool), true)
                .unwrap_err()
                .to_string();
            assert!(e.contains("Wayland") && e.contains("spectacle"), "{e}");
        }
        assert!(probe_inner(true, true, Some(CaptureTool::Spectacle), true).is_ok());
        // The same grabbers are fine on a real X11 session.
        assert!(probe_inner(true, true, Some(CaptureTool::Scrot), false).is_ok());
    }

    /// A frame that is black everywhere is a failed grab, reported as one.
    #[test]
    fn an_all_black_capture_is_an_error_not_a_screenshot() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join(".black.tmp.png");
        image::DynamicImage::ImageRgb8(image::RgbImage::new(2560, 1440))
            .save_with_format(&raw, image::ImageFormat::Png)
            .unwrap();
        let dest = dir.path().join("black.png");
        let e = downscale_png(&raw, &dest).unwrap_err().to_string();
        assert!(e.contains("black frame") && e.contains("blind"), "{e}");
        assert!(!dest.exists(), "no file may be handed to the model");
    }

    /// A dark theme is not a failed grab: one lit element is enough.
    #[test]
    fn a_dark_desktop_with_a_lit_pixel_is_still_a_screenshot() {
        let mut img = image::RgbImage::new(1920, 1080);
        for y in 0..1080 {
            for x in 0..40 {
                img.put_pixel(x, y, image::Rgb([40, 40, 48])); // a side panel
            }
        }
        assert!(!is_blank(&image::DynamicImage::ImageRgb8(img)));
        assert!(is_blank(&image::DynamicImage::ImageRgb8(
            image::RgbImage::new(1920, 1080)
        )));
    }
}
