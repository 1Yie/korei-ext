//! agent-computer — desktop control for computer-use tools.
//!
//! `detect_backend()` picks the best implemented backend (X11 today) and
//! otherwise returns a loud `none` that reports exactly why it cannot act.
//!
//! **This crate is deliberately not part of `agent-sandbox`.** The sandbox's
//! job is to hide the host from a process; a desktop backend's job is the
//! opposite — it must reach the live display server to be useful at all
//! (`--clearenv` + `--tmpfs /tmp` make the X socket unreachable by
//! construction). The defence line for desktop control is the permission
//! gate (`ToolClass::Process` → confirm / `dontAsk` deny), not filesystem
//! isolation: a process that can synthesize input for the whole session is
//! already outside what an fs sandbox can protect.
//!
//! Coordinates at this API surface are **screenshot-space** — see
//! [`traits::Capture`].

pub mod detect;
mod keys;
mod launch;
pub mod none;
pub mod traits;
pub mod x11;

// Wayland input over libei (portal-granted). Linux only.
#[cfg(target_os = "linux")]
pub mod libei;

// Per-OS backends — only compiled (and only link their OS APIs) on their
// own target, the same way `detect` only probes them there.
#[cfg(target_os = "windows")]
pub mod windows;

// Off-target typecheck: `check-macos` compiles the macOS backend on
// Linux/CI against a pure-Rust `core-graphics` stub so API drift breaks a
// normal `cargo check` instead of only surfacing on a macOS runner.
#[cfg(all(feature = "check-macos", not(target_os = "macos")))]
mod core_graphics_stub;
#[cfg(any(target_os = "macos", feature = "check-macos"))]
pub mod macos;

pub use detect::detect_backend;
pub use none::NoneBackend;
pub use traits::{
    fit_dimensions, parse_launch, Capture, DesktopBackend, LaunchSpec, MouseButton, ScreenshotMeta,
    ScrollDir, MAX_EDGE, MAX_PIXELS,
};
