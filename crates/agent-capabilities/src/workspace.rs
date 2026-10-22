use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use agent_tool::{ToolContext, ToolError};

/// A local workspace selected by the host and shared with its children.
pub struct WorkspaceSlot(pub Arc<Path>);

/// What a linked root lets the file tools do there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootAccess {
    Read,
    ReadWrite,
}

impl RootAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "readwrite",
        }
    }

    /// Anything but `readwrite` reads as read-only — an unknown label must
    /// never widen access.
    pub fn from_str(s: &str) -> Self {
        match s {
            "readwrite" | "rw" => Self::ReadWrite,
            _ => Self::Read,
        }
    }
}

/// A directory outside the workspace the host granted, canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedRoot {
    pub path: PathBuf,
    pub access: RootAccess,
}

/// The host's live list of linked roots. Shared by `Arc`: the host keeps one
/// handle and replaces the list, every context holding the slot (children
/// included) sees the change on its next call.
#[derive(Debug, Default)]
pub struct LinkedRoots(RwLock<Arc<[LinkedRoot]>>);

impl LinkedRoots {
    pub fn set(&self, roots: Vec<LinkedRoot>) {
        if let Ok(mut w) = self.0.write() {
            *w = roots.into();
        }
    }

    pub fn snapshot(&self) -> Arc<[LinkedRoot]> {
        self.0
            .read()
            .map(|r| r.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }
}

/// Where a model-supplied path lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScope {
    /// Inside the workspace root.
    Workspace(PathBuf),
    /// Inside a linked root (`root`), with that root's access.
    Linked {
        path: PathBuf,
        root: PathBuf,
        access: RootAccess,
    },
    /// Outside every root — the canonical target, for the host to name.
    Outside(PathBuf),
}

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

    /// Install the host's linked-root list; children inherit the same handle.
    fn install_linked_roots(&mut self, roots: Arc<LinkedRoots>) {
        self.extensions_mut().insert_shared(roots);
    }

    /// The linked roots in force right now (empty when the host links none).
    fn linked_roots(&self) -> Arc<[LinkedRoot]> {
        self.extensions()
            .get_ref::<LinkedRoots>()
            .map(|r| r.snapshot())
            .unwrap_or_else(|| Arc::from(Vec::new()))
    }

    /// Resolve a path for a write: inside the workspace or a read-write
    /// linked root. A read-only linked root refuses with its reason; any
    /// other place is a sandbox escape.
    fn resolve(&self, path: &str) -> Result<PathBuf, ToolError> {
        match self.scope_of(path)? {
            PathScope::Workspace(p) => Ok(p),
            PathScope::Linked {
                path: p,
                access: RootAccess::ReadWrite,
                ..
            } => Ok(p),
            PathScope::Linked { root, .. } => Err(ToolError::Failed(format!(
                "`{path}` is in the linked workspace {} which is linked read-only — \
                 the user can grant read-write access to it",
                root.display()
            ))),
            PathScope::Outside(p) => Err(out_of_scope(path, &p)),
        }
    }

    /// Resolve a path for a read: inside the workspace or any linked root.
    fn resolve_read(&self, path: &str) -> Result<PathBuf, ToolError> {
        match self.scope_of(path)? {
            PathScope::Workspace(p) | PathScope::Linked { path: p, .. } => Ok(p),
            PathScope::Outside(p) => Err(out_of_scope(path, &p)),
        }
    }

    /// Classify a model-supplied path. Relative paths resolve against the
    /// workspace root, never against a linked root.
    fn scope_of(&self, path: &str) -> Result<PathScope, ToolError> {
        let canon = self.canonical(path)?;
        if canon.starts_with(self.root()?) {
            return Ok(PathScope::Workspace(canon));
        }
        // The most specific root wins when one linked root sits inside another.
        let linked = self.linked_roots();
        let hit = linked
            .iter()
            .filter(|r| canon.starts_with(&r.path))
            .max_by_key(|r| r.path.components().count());
        Ok(match hit {
            Some(r) => PathScope::Linked {
                path: canon,
                root: r.path.clone(),
                access: r.access,
            },
            None => PathScope::Outside(canon),
        })
    }

    /// Canonical form of a model-supplied path. Proves nothing about where it
    /// lands — [`scope_of`](Self::scope_of) does that.
    fn canonical(&self, path: &str) -> Result<PathBuf, ToolError> {
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
        Ok(canon)
    }
}

impl<C: ToolContext> WorkspaceCtx for C {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Ctx {
        ext: agent_tool::Extensions,
    }

    impl ToolContext for Ctx {
        fn extensions(&self) -> &agent_tool::Extensions {
            &self.ext
        }
        fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
            &mut self.ext
        }
    }

    struct Dirs {
        _tmp: tempfile::TempDir,
        ws: PathBuf,
        rw: PathBuf,
        ro: PathBuf,
        other: PathBuf,
    }

    fn dirs() -> Dirs {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let [ws, rw, ro, other] = ["ws", "rw", "ro", "other"].map(|n| base.join(n));
        for d in [&ws, &rw, &ro, &other] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f.txt"), "x").unwrap();
        }
        Dirs {
            _tmp: tmp,
            ws,
            rw,
            ro,
            other,
        }
    }

    fn ctx(d: &Dirs) -> (Ctx, Arc<LinkedRoots>) {
        let roots = Arc::new(LinkedRoots::default());
        roots.set(vec![
            LinkedRoot {
                path: d.rw.clone(),
                access: RootAccess::ReadWrite,
            },
            LinkedRoot {
                path: d.ro.clone(),
                access: RootAccess::Read,
            },
        ]);
        let mut c = Ctx::default().with_workspace(&d.ws);
        c.install_linked_roots(roots.clone());
        (c, roots)
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn a_read_write_root_takes_reads_and_writes() {
        let d = dirs();
        let (c, _) = ctx(&d);
        let f = d.rw.join("f.txt");
        assert_eq!(c.resolve(&s(&f)).unwrap(), f);
        assert_eq!(c.resolve_read(&s(&f)).unwrap(), f);
        // A new file in a missing directory still resolves.
        let new = d.rw.join("a/b/new.rs");
        assert_eq!(c.resolve(&s(&new)).unwrap(), new);
    }

    #[test]
    fn a_read_only_root_refuses_writes_with_the_reason() {
        let d = dirs();
        let (c, _) = ctx(&d);
        let f = d.ro.join("f.txt");
        assert_eq!(c.resolve_read(&s(&f)).unwrap(), f);
        match c.resolve(&s(&f)) {
            Err(ToolError::Failed(m)) => assert!(m.contains("read-only"), "{m}"),
            other => panic!("expected a read-only refusal, got {other:?}"),
        }
    }

    #[test]
    fn unlinked_paths_still_escape() {
        let d = dirs();
        let (c, _) = ctx(&d);
        let f = d.other.join("f.txt");
        // Outside every root: a grantable question, not a wall — the engine
        // turns this into an approval whose actions are the grants.
        assert!(matches!(
            c.resolve_read(&s(&f)),
            Err(ToolError::OutOfScope { .. })
        ));
        assert!(matches!(c.resolve(&s(&f)), Err(ToolError::OutOfScope { .. })));
        assert!(matches!(c.scope_of(&s(&f)).unwrap(), PathScope::Outside(p) if p == f));
    }

    #[test]
    fn relative_paths_never_resolve_against_a_linked_root() {
        let d = dirs();
        let (c, _) = ctx(&d);
        assert_eq!(c.resolve("f.txt").unwrap(), d.ws.join("f.txt"));
        // `../rw/f.txt` climbs out of the workspace into a linked root — that
        // is a real path into a granted root, so it resolves there.
        assert_eq!(c.resolve("../rw/f.txt").unwrap(), d.rw.join("f.txt"));
        assert!(matches!(c.resolve("../other/f.txt"), Err(ToolError::OutOfScope { .. })));
    }

    #[test]
    fn a_symlink_out_of_a_linked_root_escapes() {
        let d = dirs();
        let (c, _) = ctx(&d);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&d.other, d.rw.join("link")).unwrap();
            let via = d.rw.join("link/f.txt");
            assert!(matches!(c.resolve(&s(&via)), Err(ToolError::OutOfScope { .. })));
            std::os::unix::fs::symlink(d.other.join("missing"), d.rw.join("dangling")).unwrap();
            let dangling = d.rw.join("dangling");
            assert!(matches!(c.resolve(&s(&dangling)), Err(ToolError::PathEscape(_))));
        }
    }

    #[test]
    fn replacing_the_list_takes_effect_and_children_share_it() {
        let d = dirs();
        let (c, roots) = ctx(&d);
        let mut child = Ctx::default().with_workspace(&d.ws);
        child.ext = c.ext.inheritable();
        let f = d.rw.join("f.txt");
        assert!(child.resolve(&s(&f)).is_ok());
        roots.set(Vec::new());
        assert!(matches!(c.resolve(&s(&f)), Err(ToolError::OutOfScope { .. })));
        assert!(matches!(child.resolve(&s(&f)), Err(ToolError::OutOfScope { .. })));
    }

    #[test]
    fn the_innermost_linked_root_decides_access() {
        let d = dirs();
        let (c, roots) = ctx(&d);
        let inner = d.rw.join("vendor");
        std::fs::create_dir_all(&inner).unwrap();
        roots.set(vec![
            LinkedRoot {
                path: d.rw.clone(),
                access: RootAccess::ReadWrite,
            },
            LinkedRoot {
                path: inner.clone(),
                access: RootAccess::Read,
            },
        ]);
        assert!(c.resolve(&s(&inner.join("x"))).is_err());
        assert!(c.resolve(&s(&d.rw.join("x"))).is_ok());
    }
}

/// The refusal a path outside every granted root gets.
///
/// `OutOfScope` rather than `PathEscape`: the engine may offer the host the
/// chance to grant the directory, and `suggestion` names the project root worth
/// granting. A symlink that *climbs* out stays a `PathEscape` — that one is a
/// trap, not a missing permission.
fn out_of_scope(requested: &str, canon: &Path) -> ToolError {
    ToolError::OutOfScope {
        path: requested.to_string(),
        suggestion: suggest_root(canon).map(|p| p.to_string_lossy().into_owned()),
    }
}

/// The nearest directory above `path` that looks like a project root — what a
/// grant should name, rather than the one file that happened to be read.
pub fn suggest_root(path: &Path) -> Option<PathBuf> {
    const MARKERS: [&str; 4] = [".git", "Cargo.toml", "package.json", "pyproject.toml"];
    let mut cursor = if path.is_dir() {
        Some(path)
    } else {
        path.parent()
    };
    while let Some(dir) = cursor {
        if MARKERS.iter().any(|m| dir.join(m).exists()) {
            return Some(dir.to_path_buf());
        }
        cursor = dir.parent();
    }
    None
}
