//! Computer-use tools: drive the screen, and capture it.
//!
//! Generic over [`agent_capabilities::WorkspaceCtx`] and [`agent_capabilities::DesktopCtx`], so
//! this crate names no kernel type. The backend is a host-installed capability:
//! a headless host installs none and both tools refuse with a reason.

pub mod computer;
pub mod screenshot;

#[cfg(test)]
use agent_capabilities::WorkspaceCtx;

/// A context for this crate's own tests — the tools need a desktop and a root,
/// nothing else. The kernel's `ToolCtx` is the production implementation.
#[cfg(test)]
pub(crate) struct TestCtx {
    ext: agent_tool::Extensions,
    /// Set by the cancellation test, which needs a flag it can flip mid-call.
    pub cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

#[cfg(test)]
impl TestCtx {
    pub(crate) fn with_desktop(
        root: impl AsRef<std::path::Path>,
        desktop: std::sync::Arc<dyn agent_computer::DesktopBackend>,
    ) -> Self {
        let root = root.as_ref();
        let mut ext = agent_tool::Extensions::default();
        ext.insert_shared(std::sync::Arc::new(agent_capabilities::DesktopSlot(
            desktop,
        )));
        Self { ext, cancel: None }.with_workspace(root)
    }
}

#[cfg(test)]
impl agent_tool::ToolContext for TestCtx {
    fn extensions(&self) -> &agent_tool::Extensions {
        &self.ext
    }

    fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
        &mut self.ext
    }

    fn cancel_flag(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        self.cancel.clone()
    }
}
