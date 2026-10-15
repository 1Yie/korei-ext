use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_tool::{ToolContext, ToolError};

/// A local workspace selected by the host and shared with its children.
pub struct WorkspaceSlot(pub Arc<Path>);

pub trait WorkspaceCtx: ToolContext + Sized {
    fn with_workspace(mut self, root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let root = root.canonicalize().unwrap_or(root);
        self.extensions_mut()
            .insert_shared(Arc::new(WorkspaceSlot(Arc::from(root.as_path()))));
        self
    }

    fn root(&self) -> Result<&Path, ToolError> {
        self.extensions()
            .get_ref::<WorkspaceSlot>()
            .map(|s| s.0.as_ref())
            .ok_or_else(|| ToolError::Failed("workspace is not available in this context".into()))
    }

    /// Resolve a model-supplied path against the workspace root and prove it
    /// stays inside. Returns the canonical path or a sandbox-escape error.
    fn resolve(&self, path: &str) -> Result<PathBuf, ToolError> {
        let workspace_root = self.root()?;
        let p = Path::new(path);
        let joined = if p.is_absolute() {
            p.to_path_buf()
        } else {
            workspace_root.join(p)
        };
        // Canonicalize requires the path to exist; for writes to new files,
        // canonicalize the deepest existing ancestor and re-attach the
        // missing tail. Checking only the immediate parent made any
        // `<new-dir>/file` path report PathEscape.
        let canon = match joined.canonicalize() {
            Ok(c) => c,
            Err(_) => {
                let mut tail: Vec<std::ffi::OsString> = Vec::new();
                let mut cursor: &Path = joined.as_path();
                let base = loop {
                    if let Ok(c) = cursor.canonicalize() {
                        break c;
                    }
                    // `canonicalize` also fails for a *dangling* symlink
                    // (its target does not exist). Treating that as a
                    // plain missing path would return the in-workspace
                    // link path, and the later write follows the link to
                    // wherever it points — possibly outside the workspace.
                    if cursor
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        return Err(ToolError::PathEscape(path.to_string()));
                    }
                    let Some(name) = cursor.file_name() else {
                        return Err(ToolError::PathEscape(path.to_string()));
                    };
                    tail.push(name.to_os_string());
                    let Some(parent) = cursor.parent() else {
                        return Err(ToolError::PathEscape(path.to_string()));
                    };
                    cursor = parent;
                };
                let mut canon = base;
                for seg in tail.iter().rev() {
                    canon.push(seg);
                }
                canon
            }
        };
        if !canon.starts_with(workspace_root) {
            return Err(ToolError::PathEscape(path.to_string()));
        }
        Ok(canon)
    }
}

impl<C: ToolContext> WorkspaceCtx for C {}
