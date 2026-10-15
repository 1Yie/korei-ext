use std::sync::Arc;

use agent_tool::{ToolContext, ToolError};

/// One shared desktop backend identity, independent of its implementation.
pub struct DesktopSlot(pub Arc<dyn agent_computer::DesktopBackend>);

pub trait DesktopCtx: ToolContext + Sized {
    /// Missing backends refuse without probing hardware.
    fn desktop(&self) -> Result<Arc<dyn agent_computer::DesktopBackend>, ToolError> {
        self.service::<DesktopSlot>()
            .map(|s| s.0.clone())
            .ok_or_else(|| {
                ToolError::Failed("desktop control is not available in this context".into())
            })
    }

    /// Captures and input calls share one backend and coordinate mapping.
    fn with_desktop(mut self, desktop: Arc<dyn agent_computer::DesktopBackend>) -> Self {
        self.extensions_mut()
            .insert_shared(Arc::new(DesktopSlot(desktop)));
        self
    }
}

impl<C: ToolContext> DesktopCtx for C {}
