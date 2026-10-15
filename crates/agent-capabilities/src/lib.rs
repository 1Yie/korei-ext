//! Host capability adapters. The kernel does not depend on this crate.

pub mod workspace;
pub use workspace::{WorkspaceCtx, WorkspaceSlot};

#[cfg(feature = "sandbox")]
pub mod sandbox;
#[cfg(feature = "sandbox")]
pub use sandbox::{SandboxCtx, SandboxLimitsSlot, SandboxSlot};
#[cfg(feature = "desktop")]
pub mod desktop;
#[cfg(feature = "desktop")]
pub use desktop::{DesktopCtx, DesktopSlot};

use std::sync::Arc;

use agent_paths::AppPaths;
use agent_tool::ToolError;

/// Shared app directories installed by a host.
pub struct AppPathsSlot(pub AppPaths);

pub trait WorkspacePaths: WorkspaceCtx + Sized {
    fn paths(&self) -> Option<AppPaths> {
        self.service::<AppPathsSlot>().map(|s| s.0.clone())
    }

    fn install_paths(&mut self, paths: AppPaths) {
        self.extensions_mut()
            .insert_shared(Arc::new(AppPathsSlot(paths)));
    }

    /// Installed directories take precedence over the unbranded local default.
    fn app_paths(&self) -> Result<AppPaths, ToolError> {
        if let Some(paths) = self.paths() {
            return Ok(paths);
        }
        let root = self.root()?;
        Ok(AppPaths::new(
            root.join(".agent/config"),
            root.join(".agent/data"),
            ".agent",
        ))
    }

    fn workspace_state_dir(&self) -> Result<std::path::PathBuf, ToolError> {
        Ok(self.app_paths()?.workspace_dir(self.root()?))
    }
}

impl<C: WorkspaceCtx> WorkspacePaths for C {}
