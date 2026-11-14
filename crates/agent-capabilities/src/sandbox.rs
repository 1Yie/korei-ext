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
    /// Run a command using this context's workspace view and bounded capture.
    fn run_command<'a>(
        &'a self,
        cmd: &'a str,
        args: &'a [&'a str],
        cfg: &'a agent_sandbox::SandboxConfig,
    ) -> impl std::future::Future<Output = Result<agent_sandbox::CommandOutput, ToolError>> + Send + 'a
    where
        Self: crate::WorkspaceCtx,
    {
        async move {
            if self
                .extensions()
                .get_ref::<super::workspace_io::WorkspaceLease>()
                .is_none()
            {
                return self
                    .sandbox()?
                    .run_command(cmd, args, cfg)
                    .await
                    .map_err(|error| ToolError::Failed(error.to_string()));
            }
            let child = if args.is_empty() {
                #[cfg(windows)]
                {
                    self.spawn_process(cfg, "cmd.exe", &["/C", cmd])?
                }
                #[cfg(not(windows))]
                {
                    self.spawn_process(cfg, "/bin/sh", &["-c", cmd])?
                }
            } else {
                self.spawn_process(cfg, cmd, args)?
            };
            child
                .output(std::time::Duration::from_secs(cfg.timeout_secs))
                .await
                .map_err(ToolError::from)
        }
    }

    /// Start a piped process through the context's actual execution view.
    fn spawn_process(
        &self,
        cfg: &agent_sandbox::SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Result<agent_sandbox::process::ManagedChild, ToolError>
    where
        Self: crate::WorkspaceCtx,
    {
        let sandbox = self.sandbox()?;
        if let Some(view) = self
            .extensions()
            .get_ref::<super::workspace_io::WorkspaceLease>()
        {
            let lease = view.lease();
            let mut cfg = cfg.clone();
            for root in lease.roots() {
                let source = lease
                    .source_root(root)
                    .map_err(|error| ToolError::Failed(error.to_string()))?;
                if let crate::PathScope::Linked {
                    access: crate::RootAccess::Read,
                    ..
                } = view.scope(self, source)?
                {
                    if !cfg.deny_write.iter().any(|path| path == source) {
                        cfg.deny_write.push(source.to_path_buf());
                    }
                }
            }
            return sandbox
                .spawn_leased(lease, &cfg, cmd, args)
                .map(Into::into)
                .map_err(|error| ToolError::Failed(error.to_string()));
        }
        sandbox
            .validate_config(cfg)
            .map_err(|error| ToolError::Failed(error.to_string()))?;
        let mut command = sandbox.wrap_spawn(cfg, cmd, args).ok_or_else(|| {
            ToolError::Failed(format!(
                "sandbox backend `{}` cannot wrap this process",
                sandbox.id()
            ))
        })?;
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        command
            .spawn()
            .map(Into::into)
            .map_err(|error| ToolError::Failed(format!("process spawn: {error}")))
    }

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
