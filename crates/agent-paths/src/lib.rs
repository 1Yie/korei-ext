//! Where the application keeps its files — passed in, never guessed.
//!
//! A library that writes settings, plugin state or session data must not decide
//! what the product is called. [`AppPaths`] carries the resolved directories
//! (and the workspace-local state directory name) so the product names itself
//! and every library below it stays name-agnostic.

use std::path::{Path, PathBuf};

/// The host's directories, resolved once by the product that owns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    /// `<config>/<app>` — user settings, plugin trust/state, user AGENTS.md.
    pub config_dir: PathBuf,
    /// `<data>/<app>` — sessions, memory, office documents.
    pub data_dir: PathBuf,
    /// The workspace-local state directory name, e.g. `.husk`. Holds
    /// attachments, subagent logs and repo-local plugins/agents.
    pub workspace_dir_name: String,
}

impl AppPaths {
    /// Assemble from already-resolved directories.
    pub fn new(
        config_dir: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
        workspace_dir_name: impl Into<String>,
    ) -> Self {
        Self {
            config_dir: config_dir.into(),
            data_dir: data_dir.into(),
            workspace_dir_name: workspace_dir_name.into(),
        }
    }

    /// Resolve `<dirs::config_dir>/<app>` and `<dirs::data_dir>/<app>` for an
    /// app name. `None` when the platform reports no home directory.
    ///
    /// Directory *migration* (a product renaming itself) is the product's job,
    /// not this crate's: run it before or after, or not at all.
    pub fn from_app_name(app: &str, workspace_dir_name: &str) -> Option<Self> {
        let config_dir = dirs::config_dir()?.join(app);
        let data_dir = dirs::data_dir()?.join(app);
        Some(Self::new(config_dir, data_dir, workspace_dir_name))
    }

    /// `<config>/<app>/<name>`.
    pub fn config_file(&self, name: &str) -> PathBuf {
        self.config_dir.join(name)
    }

    /// `<data>/<app>/<name>`.
    pub fn data_file(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }

    /// Throwaway paths under the system temp dir. Tests use this so they never
    /// touch the real user directories; the name is deliberately product-free.
    pub fn for_tests(label: &str) -> Self {
        let base =
            std::env::temp_dir().join(format!("agent-paths-test-{label}-{}", std::process::id()));
        Self::new(base.join("config"), base.join("data"), ".agent")
    }

    /// The product's own name, read from the config directory's last segment
    /// (`<config>/husk` → `husk`). Protocol identities (an MCP `clientInfo`,
    /// say) need a name but must not hardcode one.
    pub fn app_name(&self) -> &str {
        self.config_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("agent")
    }

    /// The workspace-local state directory under `root`.
    pub fn workspace_dir(&self, root: &Path) -> PathBuf {
        root.join(&self.workspace_dir_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_without_naming_the_product() {
        let p = AppPaths::new("/cfg/demo", "/data/demo", ".demo");
        assert_eq!(
            p.config_file("plugin-trust.json"),
            Path::new("/cfg/demo/plugin-trust.json")
        );
        assert_eq!(
            p.data_file("sessions.db"),
            Path::new("/data/demo/sessions.db")
        );
        assert_eq!(
            p.workspace_dir(Path::new("/repo")),
            Path::new("/repo/.demo")
        );
    }

    /// The crate names no product: a different app gets different dirs from the
    /// same code path.
    #[test]
    fn a_different_app_name_yields_different_dirs() {
        let a = AppPaths::new("/cfg/alpha", "/data/alpha", ".alpha");
        let b = AppPaths::new("/cfg/beta", "/data/beta", ".beta");
        assert_ne!(a.config_dir, b.config_dir);
        assert_ne!(
            a.workspace_dir(Path::new("/repo")),
            b.workspace_dir(Path::new("/repo"))
        );
    }
}
