//! The loud fallback — no desktop backend on this host.
//!
//! Every method reports the probe's reason verbatim: the message is
//! model-facing, so it must teach the fix (`$DISPLAY is not set`, `install
//! xdotool`) instead of failing silently or pretending to have clicked.

use std::path::Path;

use anyhow::{anyhow, Result};

use crate::traits::{DesktopBackend, MouseButton, ScreenshotMeta, ScrollDir};

pub struct NoneBackend {
    reason: String,
}

impl NoneBackend {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// The one error every method returns.
    fn unavailable(&self) -> anyhow::Error {
        anyhow!("desktop control unavailable: {}", self.reason)
    }
}

#[async_trait::async_trait]
impl DesktopBackend for NoneBackend {
    fn id(&self) -> &'static str {
        "none"
    }

    async fn screenshot(&self, _dest: &Path) -> Result<ScreenshotMeta> {
        Err(self.unavailable())
    }

    async fn click(&self, _button: MouseButton, _at: [i32; 2]) -> Result<()> {
        Err(self.unavailable())
    }

    async fn double_click(&self, _at: [i32; 2]) -> Result<()> {
        Err(self.unavailable())
    }

    async fn move_to(&self, _at: [i32; 2]) -> Result<()> {
        Err(self.unavailable())
    }

    async fn drag(&self, _from: [i32; 2], _to: [i32; 2]) -> Result<()> {
        Err(self.unavailable())
    }

    async fn type_text(&self, _text: &str) -> Result<()> {
        Err(self.unavailable())
    }

    async fn key(&self, _combo: &str, _hold_ms: Option<u64>) -> Result<()> {
        Err(self.unavailable())
    }

    async fn scroll(&self, _dir: ScrollDir, _amount: i32, _at: Option<[i32; 2]>) -> Result<()> {
        Err(self.unavailable())
    }

    async fn cursor_position(&self) -> Result<[i32; 2]> {
        Err(self.unavailable())
    }

    async fn launch_app(&self, _command: &str) -> Result<()> {
        Err(self.unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal must carry the probe's reason — a bare "unavailable" gives
    /// the model nothing to work with.
    #[tokio::test]
    async fn refusal_reports_the_probe_reason() {
        let b = NoneBackend::new("$DISPLAY is not set");
        let err = b.screenshot(Path::new("/tmp/x.png")).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("desktop control unavailable"), "{msg}");
        assert!(msg.contains("$DISPLAY is not set"), "{msg}");
        assert_eq!(b.id(), "none");
        assert!(b.cursor_position().await.is_err());
        assert!(b.key("Return", None).await.is_err());
    }
}
