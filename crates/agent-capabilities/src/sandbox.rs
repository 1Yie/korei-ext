use std::sync::Arc;

use agent_tool::{ToolContext, ToolError};

/// Shared backend selected by the host. Absence and an installed `none`
/// backend are distinct: absence refuses execution.
pub struct SandboxSlot(pub Arc<dyn agent_sandbox::SandboxBackend>);
pub struct SandboxLimitsSlot(pub agent_sandbox::SandboxLimits);

/// Live host policy source, inherited by child contexts. When installed it
/// takes precedence over the backward-compatible static `SandboxLimitsSlot`.
pub struct SandboxLimitsProviderSlot(
    pub Arc<dyn Fn() -> agent_sandbox::SandboxLimits + Send + Sync>,
);

pub trait SandboxCtx: ToolContext + Sized {
    fn sandbox(&self) -> Result<Arc<dyn agent_sandbox::SandboxBackend>, ToolError> {
        self.service::<SandboxSlot>()
            .map(|s| s.0.clone())
            .ok_or_else(|| {
                ToolError::Failed("shell execution is not available in this context".into())
            })
    }

    fn sandbox_limits(&self) -> agent_sandbox::SandboxLimits {
        if let Some(provider) = self.service::<SandboxLimitsProviderSlot>() {
            return (provider.0)();
        }
        self.service::<SandboxLimitsSlot>()
            .map(|s| s.0.clone())
            .unwrap_or_default()
    }

    fn install_sandbox(&mut self, sandbox: Arc<dyn agent_sandbox::SandboxBackend>) {
        self.extensions_mut()
            .insert_shared(Arc::new(SandboxSlot(sandbox)));
    }

    fn with_sandbox(mut self, sandbox: Arc<dyn agent_sandbox::SandboxBackend>) -> Self {
        self.install_sandbox(sandbox);
        self
    }

    fn with_sandbox_limits(mut self, limits: agent_sandbox::SandboxLimits) -> Self {
        self.extensions_mut()
            .insert_shared(Arc::new(SandboxLimitsSlot(limits)));
        self
    }

    fn install_sandbox_limits_provider(
        &mut self,
        provider: impl Fn() -> agent_sandbox::SandboxLimits + Send + Sync + 'static,
    ) {
        self.extensions_mut()
            .insert_shared(Arc::new(SandboxLimitsProviderSlot(Arc::new(provider))));
    }
}

impl<C: ToolContext> SandboxCtx for C {}
