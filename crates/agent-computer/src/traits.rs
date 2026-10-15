//! The desktop-control seam — one trait, one job per method.
//!
//! Coordinates in this API are **screenshot-space**: the model looks at the
//! PNG [`DesktopBackend::screenshot`] wrote, so every input method takes
//! `[x, y]` in *that image's* pixel grid and the backend maps it onto the real
//! display through the capture it last took. A backend that has not captured
//! yet falls back to identity (the caller's coordinates are display
//! coordinates) — which is what a caller that skipped the screenshot means.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Long-edge cap for the PNG handed to the model.
pub const MAX_EDGE: u32 = 1568;

/// Total-pixel cap for the PNG handed to the model. Providers resize any
/// image above ~1.15 megapixels (Anthropic: 1568 px long edge *and* ≈1.15 MP;
/// newer tiers accept more). A frame past that is silently rescaled
/// server-side, so the grid the model reads coordinates from no longer matches
/// the `image` size we reported and every click lands off target. Staying
/// inside the tighter limit keeps the two identical for every model.
pub const MAX_PIXELS: u64 = 1_150_000;

/// Which mouse button an action presses. The wire numbers are the backend's
/// business (X11: 1/2/3) — this enum stays protocol-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

/// Scroll wheel direction. Backend maps it to X11 buttons 4/5/6/7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollDir {
    Up,
    Down,
    Left,
    Right,
}

/// The mapping between the model's pixel grid and the display's — recorded by
/// the last capture, applied to every input coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capture {
    /// Native capture size — the space synthetic input speaks.
    pub display: [u32; 2],
    /// Downscaled size of the PNG the model was shown.
    pub image: [u32; 2],
}

impl Capture {
    /// Display pixels per image pixel, x axis.
    fn sx(&self) -> f64 {
        self.display[0].max(1) as f64 / self.image[0].max(1) as f64
    }

    /// Display pixels per image pixel, y axis.
    fn sy(&self) -> f64 {
        self.display[1].max(1) as f64 / self.image[1].max(1) as f64
    }

    /// Image coordinate → display coordinate, clamped into the display.
    pub fn map_to_display(&self, c: [i32; 2]) -> [i32; 2] {
        [
            (f64::round(c[0] as f64 * self.sx()) as i64).clamp(0, self.display[0].max(1) as i64 - 1)
                as i32,
            (f64::round(c[1] as f64 * self.sy()) as i64).clamp(0, self.display[1].max(1) as i64 - 1)
                as i32,
        ]
    }

    /// Display coordinate → image coordinate (for `cursor_position`, so the
    /// model reads back the same grid it sees), clamped into the image.
    pub fn map_to_image(&self, c: [i32; 2]) -> [i32; 2] {
        [
            (f64::round(c[0] as f64 / self.sx()) as i64).clamp(0, self.image[0].max(1) as i64 - 1)
                as i32,
            (f64::round(c[1] as f64 / self.sy()) as i64).clamp(0, self.image[1].max(1) as i64 - 1)
                as i32,
        ]
    }
}

/// What a capture produced: where the PNG landed plus both resolutions.
#[derive(Debug, Clone)]
pub struct ScreenshotMeta {
    /// The downscaled PNG written for the model.
    pub path: PathBuf,
    /// Native screen resolution — the space input coordinates are mapped into.
    pub display: [u32; 2],
    /// Resolution of `path` — the grid the model reads coordinates off.
    pub image: [u32; 2],
}

impl ScreenshotMeta {
    /// The scale this capture installed on its backend.
    pub fn capture(&self) -> Capture {
        Capture {
            display: self.display,
            image: self.image,
        }
    }
}

/// Downscale `(w, h)` so its long edge is ≤ `max_edge` **and** its area is
/// ≤ [`MAX_PIXELS`], preserving aspect. Never upscales; a zero dimension
/// passes through untouched.
pub fn fit_dimensions(w: u32, h: u32, max_edge: u32) -> (u32, u32) {
    let long = w.max(h);
    if long == 0 || w == 0 || h == 0 {
        return (w, h);
    }
    let edge_scale = max_edge as f64 / long as f64;
    let pixel_scale = (MAX_PIXELS as f64 / (w as f64 * h as f64)).sqrt();
    let scale = edge_scale.min(pixel_scale);
    if scale >= 1.0 {
        return (w, h);
    }
    // Floor (with a hair of slack for float undershoot) so the area bound
    // can never be exceeded by rounding up.
    let dim = |v: u32| (((v as f64) * scale + 1e-6).floor() as u32).max(1);
    (dim(w), dim(h))
}

/// A parsed `launch` request: one program plus its arguments, ready to be
/// exec'd **directly** — never through a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub program: String,
    pub args: Vec<String>,
}

/// Programs that are shells, not applications. `launch` exists to put a GUI
/// on screen; a shell here is `bash -c '<anything>'` outside the sandbox.
/// This is a guard against the obvious misuse, not a boundary — `launch` can
/// still start any other program, which is why it is approved on its own
/// terms (see `permissions.rs`).
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "powershell",
    "pwsh",
];

/// Split a `launch` command into program + args **without a shell**.
///
/// Grammar: tokens are separated by spaces/tabs; `'…'` is literal; `"…"`
/// allows `"` for a quote; a leading `~`/`~/` expands to the home directory
/// (nothing else does — `$VAR`, globs and operators are plain characters).
/// Control characters (newline, NUL, …) are refused outright: they are how a
/// second command rides along in a string a shell would parse.
pub fn parse_launch(command: &str) -> Result<LaunchSpec> {
    if command.trim().is_empty() {
        bail!("empty launch command");
    }
    if let Some(c) = command.chars().find(|c| c.is_control() && *c != '\t') {
        bail!("launch takes one line — control character {c:?} is not allowed");
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    // `started` distinguishes an empty quoted token (`''`) from no token.
    let mut started = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if started {
                    tokens.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => bail!("launch command has an unterminated quote"),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') if chars.peek() == Some(&'"') => {
                            cur.push('"');
                            chars.next();
                        }
                        Some(c) => cur.push(c),
                        None => bail!("launch command has an unterminated quote"),
                    }
                }
            }
            c => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        tokens.push(cur);
    }

    let mut it = tokens.into_iter();
    let program = it.next().unwrap_or_default();
    let args: Vec<String> = it.map(expand_home).collect();
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&program)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    if SHELLS.contains(&base) {
        bail!(
            "`{program}` is a shell — launch starts applications; run shell commands with `bash`"
        );
    }
    Ok(LaunchSpec { program, args })
}

/// `~` and `~/x` → the home directory; anything else untouched.
fn expand_home(arg: String) -> String {
    if arg != "~" && !arg.starts_with("~/") {
        return arg;
    }
    match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(h) => format!("{}{}", h.to_string_lossy(), &arg[1..]),
        None => arg,
    }
}

/// One desktop backend. Everything a computer-use loop needs, nothing more —
/// `screenshot` feeds the model's eyes, the rest are its hands.
#[async_trait::async_trait]
pub trait DesktopBackend: Send + Sync {
    /// Stable id for telemetry/UI (`"x11"`, `"wayland"`, `"none"`).
    fn id(&self) -> &'static str;

    /// Capture the screen, write a PNG (long edge ≤ [`MAX_EDGE`]) to `dest`,
    /// and remember the scale for the input methods below.
    async fn screenshot(&self, dest: &Path) -> Result<ScreenshotMeta>;

    /// Press `button` at `at`.
    async fn click(&self, button: MouseButton, at: [i32; 2]) -> Result<()>;

    /// Two left presses at `at`.
    async fn double_click(&self, at: [i32; 2]) -> Result<()>;

    /// Move the pointer to `at` without pressing.
    async fn move_to(&self, at: [i32; 2]) -> Result<()>;

    /// Press left at `from`, move to `to`, release.
    async fn drag(&self, from: [i32; 2], to: [i32; 2]) -> Result<()>;

    /// Type `text` into the focused window.
    async fn type_text(&self, text: &str) -> Result<()>;

    /// Press a key or chord (`"Return"`, `"ctrl+s"`); `hold_ms` keeps it down.
    async fn key(&self, combo: &str, hold_ms: Option<u64>) -> Result<()>;

    /// Scroll `amount` steps in `dir`, optionally after moving to `at`.
    async fn scroll(&self, dir: ScrollDir, amount: i32, at: Option<[i32; 2]>) -> Result<()>;

    /// Pointer position in screenshot coordinates.
    async fn cursor_position(&self) -> Result<[i32; 2]>;

    /// Launch a GUI application: a program plus args, parsed by
    /// [`parse_launch`] and exec'd directly — never through a shell. The
    /// process is detached from the agent — it outlives the tool call.
    /// Runs outside the sandbox on the real display session: launching is
    /// the "I want a GUI on screen" escape hatch the `bash` tool cannot be
    /// (its sandbox would hide `$DISPLAY`/`/tmp/.X11-unix` by construction).
    async fn launch_app(&self, command: &str) -> Result<()>;

    /// Acquire whatever the backend needs before the user is asked to approve
    /// a `computer` call — on Wayland, the compositor's input grant. Lets the
    /// system permission prompt come first, so an approval the user has
    /// already given in the app is not followed by a second, unexpected prompt.
    /// Errors here mean the action cannot run at all, so the approval card is
    /// never shown. Default: nothing to acquire.
    async fn prepare(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_dimensions_never_upscales() {
        assert_eq!(fit_dimensions(800, 600, MAX_EDGE), (800, 600));
        // Exactly on both limits (1568 long edge, 1568×733 ≈ 1.149 MP).
        assert_eq!(fit_dimensions(1568, 733, MAX_EDGE), (1568, 733));
        assert_eq!(fit_dimensions(0, 0, MAX_EDGE), (0, 0));
        assert_eq!(fit_dimensions(0, 500, MAX_EDGE), (0, 500));
    }

    #[test]
    fn fit_dimensions_caps_the_long_edge_keeping_aspect() {
        // Edge-bound: a wide strip is limited by its long edge.
        assert_eq!(fit_dimensions(3000, 300, MAX_EDGE), (1568, 156));
        // Odd aspect ratios still land inside both bounds.
        let (w, h) = fit_dimensions(3000, 1000, MAX_EDGE);
        assert_eq!(w, 1568);
        assert!(h <= MAX_EDGE && h > 0);
    }

    /// Pixel-bound: 16:9 frames hit the area cap before the edge cap, which
    /// is exactly what a server-side rescale would otherwise do for us.
    #[test]
    fn fit_dimensions_caps_total_pixels() {
        assert_eq!(fit_dimensions(3840, 2160, MAX_EDGE), (1429, 804));
        assert_eq!(fit_dimensions(2560, 1440, MAX_EDGE), (1429, 804));
        assert_eq!(fit_dimensions(1920, 1080, MAX_EDGE), (1429, 804));
        // Portrait caps by height instead.
        assert_eq!(fit_dimensions(1080, 1920, MAX_EDGE), (804, 1429));
        // A frame already inside both bounds is untouched.
        assert_eq!(fit_dimensions(1280, 720, MAX_EDGE), (1280, 720));
        for (w, h) in [
            (3840, 2160),
            (2560, 1600),
            (5120, 1440),
            (1081, 1921),
            (7680, 4320),
        ] {
            let (tw, th) = fit_dimensions(w, h, MAX_EDGE);
            assert!(tw as u64 * th as u64 <= MAX_PIXELS, "{w}x{h} -> {tw}x{th}");
            assert!(tw.max(th) <= MAX_EDGE, "{w}x{h} -> {tw}x{th}");
            // Aspect ratio is preserved to within a pixel.
            let drift = (tw as f64 / th as f64 - w as f64 / h as f64).abs();
            assert!(drift < 0.02, "{w}x{h} -> {tw}x{th}");
        }
    }

    #[test]
    fn capture_maps_image_coords_onto_the_display() {
        // 3840×2160 display shown as 1568×882: center of the image is the
        // center of the display, corners clamp into range.
        let cap = Capture {
            display: [3840, 2160],
            image: [1568, 882],
        };
        assert_eq!(cap.map_to_display([784, 441]), [1920, 1080]);
        assert_eq!(cap.map_to_display([0, 0]), [0, 0]);
        // The last image pixel maps to just inside the last display pixel
        // (1567/1568 × 3840 = 3837.55 → 3838) — never past the edge.
        assert_eq!(cap.map_to_display([1567, 881]), [3838, 2158]);
        // Out-of-range model output clamps instead of erroring the call.
        assert_eq!(cap.map_to_display([99_999, -5]), [3839, 0]);
    }

    #[test]
    fn capture_round_trips_and_survives_unscaled_capture() {
        let cap = Capture {
            display: [1920, 1080],
            image: [1920, 1080],
        };
        assert_eq!(cap.map_to_display([960, 540]), [960, 540]);
        assert_eq!(cap.map_to_image([960, 540]), [960, 540]);

        let scaled = Capture {
            display: [3840, 2160],
            image: [1568, 882],
        };
        assert_eq!(
            scaled.map_to_image(scaled.map_to_display([784, 441])),
            [784, 441]
        );
    }

    #[test]
    fn degenerate_display_does_not_panic() {
        let cap = Capture {
            display: [0, 0],
            image: [0, 0],
        };
        assert_eq!(cap.map_to_display([10, 10]), [0, 0]);
        assert_eq!(cap.map_to_image([10, 10]), [0, 0]);
    }
    #[test]
    fn launch_splits_program_and_args_without_a_shell() {
        let s = parse_launch("kwrite /tmp/a.txt").unwrap();
        assert_eq!(s.program, "kwrite");
        assert_eq!(s.args, ["/tmp/a.txt"]);

        let s = parse_launch("code 'my dir/x y' \"say \\\"hi\\\"\" ''").unwrap();
        assert_eq!(s.args, ["my dir/x y", "say \"hi\"", ""]);

        // Shell syntax is just characters here — nothing interprets it.
        let s = parse_launch("app $HOME a;b `c` d|e >f").unwrap();
        assert_eq!(s.args, ["$HOME", "a;b", "`c`", "d|e", ">f"]);
    }

    #[test]
    fn launch_refuses_a_second_command_riding_a_newline() {
        for cmd in [
            "kwrite\ntouch /tmp/x",
            "kwrite\rtouch /tmp/x",
            "kwrite\0x",
            "kwrite\x1b[0m",
        ] {
            let e = parse_launch(cmd).unwrap_err().to_string();
            assert!(e.contains("control character"), "{cmd:?}: {e}");
        }
    }

    #[test]
    fn launch_refuses_shells_by_name_path_and_exe_suffix() {
        for cmd in [
            "bash -c 'touch /tmp/x'",
            "/bin/sh -c id",
            "ZSH -c id",
            "C:\\Windows\\System32\\cmd.exe /c calc",
            "pwsh -Command x",
        ] {
            let e = parse_launch(cmd).unwrap_err().to_string();
            assert!(e.contains("is a shell"), "{cmd}: {e}");
        }
        // A program that merely *contains* a shell name is fine.
        assert!(parse_launch("bashful-gui").is_ok());
    }

    #[test]
    fn launch_rejects_empty_and_unterminated_quotes() {
        assert!(parse_launch("   ").is_err());
        assert!(parse_launch("app 'oops")
            .unwrap_err()
            .to_string()
            .contains("unterminated"));
        assert!(parse_launch("app \"oops")
            .unwrap_err()
            .to_string()
            .contains("unterminated"));
    }

    #[test]
    fn launch_expands_only_a_leading_tilde() {
        std::env::set_var("HOME", "/home/u");
        let s = parse_launch("code ~/proj ~ a~b ~x").unwrap();
        assert_eq!(s.args, ["/home/u/proj", "/home/u", "a~b", "~x"]);
    }
}
