//! Process tools: run a shell command, run a test suite, keep a service up.
//!
//! Generic over [`agent_capabilities::WorkspaceCtx`] and [`agent_capabilities::SandboxCtx`], so
//! this crate names no kernel type. `sandbox_cfg` is the shared
//! audit-verdict-to-`SandboxConfig` derivation both `bash` and `test_runner`
//! go through, so a test run is not a lesser command than a shell run.

pub mod bash;
pub mod risk;
pub mod sandbox_cfg;
pub mod services;
pub mod test_runner;
pub mod util;

#[cfg(test)]
use agent_capabilities::WorkspaceCtx;

/// A context for this crate's own tests.
///
/// The tools are generic over the two traits, so their tests need a context
/// and nothing else — no kernel, no registries. The kernel's `ToolCtx` is the
/// production implementation; this exists so the tests live where the tools do.
#[cfg(test)]
pub(crate) struct TestCtx {
    ext: agent_tool::Extensions,
}

#[cfg(test)]
impl TestCtx {
    pub(crate) fn with_sandbox(
        root: impl AsRef<std::path::Path>,
        sandbox: std::sync::Arc<dyn agent_sandbox::SandboxBackend>,
    ) -> Self {
        let root = root.as_ref();
        let mut ext = agent_tool::Extensions::default();
        ext.insert_shared(std::sync::Arc::new(agent_capabilities::SandboxSlot(
            sandbox,
        )));
        Self { ext }.with_workspace(root)
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
}
