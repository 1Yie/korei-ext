use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{PathScope, RootAccess, WorkspaceCtx};
#[cfg(feature = "sandbox")]
use agent_sandbox::snapshot::{RootId, SnapshotLease};
use agent_tool::ToolError;

fn failed(error: impl std::fmt::Display) -> ToolError {
    ToolError::Failed(error.to_string())
}

/// A concrete workspace view which checks live authorization at each operation.
pub struct WorkspaceIo<C> {
    ctx: Arc<C>,
    root: PathBuf,
    #[cfg(feature = "sandbox")]
    lease: Option<WorkspaceLease>,
}

impl<C> Clone for WorkspaceIo<C> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            root: self.root.clone(),
            #[cfg(feature = "sandbox")]
            lease: self.lease.clone(),
        }
    }
}

impl<C: WorkspaceCtx> WorkspaceIo<C> {
    pub(crate) fn new(ctx: Arc<C>) -> Result<Self, ToolError> {
        let root = ctx.root()?.to_path_buf();
        #[cfg(feature = "sandbox")]
        let lease = ctx.extensions().get_ref::<WorkspaceLease>().cloned();
        let view = Self {
            ctx,
            root,
            #[cfg(feature = "sandbox")]
            lease,
        };
        view.validate()?;
        Ok(view)
    }

    fn validate(&self) -> Result<(), ToolError> {
        if self.ctx.root()? != self.root {
            return Err(failed(
                "workspace root changed after file capability capture",
            ));
        }
        #[cfg(feature = "sandbox")]
        {
            let current = self.ctx.extensions().get_ref::<WorkspaceLease>();
            if current.map(|slot| Arc::as_ptr(&slot.lease))
                != self.lease.as_ref().map(|slot| Arc::as_ptr(&slot.lease))
            {
                return Err(failed("workspace lease binding changed"));
            }
            if let Some(lease) = &self.lease {
                lease.check(&*self.ctx)?;
            }
        }
        Ok(())
    }

    pub fn is_leased(&self) -> bool {
        #[cfg(feature = "sandbox")]
        return self.lease.is_some();
        #[cfg(not(feature = "sandbox"))]
        false
    }

    pub fn resolve(&self, path: &Path, write: bool) -> Result<PathBuf, ToolError> {
        self.validate()?;
        if let Some(text) = path.to_str() {
            return if write {
                self.ctx.resolve(text)
            } else {
                self.ctx.resolve_read(text)
            };
        }
        match self.ctx.scope_path(path)? {
            PathScope::Workspace(path) => Ok(path),
            PathScope::Linked { path, access, .. } if !write || access == RootAccess::ReadWrite => {
                Ok(path)
            }
            PathScope::Linked { root, .. } => Err(failed(format!(
                "{} is linked read-only — the user can grant read-write access to it",
                root.display()
            ))),
            PathScope::Outside(_) => Err(ToolError::PathEscape(path.display().to_string())),
        }
    }

    pub fn open(&self, path: &Path) -> Result<WorkspaceFile<C>, ToolError> {
        let path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            return Ok(WorkspaceFile {
                backend: FileBackend::Leased(
                    slot.lease.read_file(root, &relative).map_err(failed)?,
                ),
                view: self.clone(),
                path,
            });
        }
        Ok(WorkspaceFile {
            backend: FileBackend::Native(File::open(&path)?),
            view: self.clone(),
            path,
        })
    }

    pub fn read(&self, path: &Path) -> Result<Vec<u8>, ToolError> {
        let mut bytes = Vec::new();
        self.open(path)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub fn read_to_string(&self, path: &Path) -> Result<String, ToolError> {
        let mut text = String::new();
        self.open(path)?.read_to_string(&mut text)?;
        Ok(text)
    }

    pub fn read_optional(&self, path: &Path) -> Result<Option<Vec<u8>>, ToolError> {
        let path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            return match slot.lease.read_file(root, &relative) {
                Ok(mut file) => {
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes)?;
                    Ok(Some(bytes))
                }
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
                {
                    Ok(None)
                }
                Err(error) => Err(failed(error)),
            };
        }
        native_preimage(&path)
    }

    /// Read ignore configuration, routing prepared coordinates through the live lease.
    pub fn read_ignore_config(&self, path: &Path) -> Result<Option<Vec<u8>>, ToolError> {
        self.read_ignore_config_view(path, false)
    }

    /// Read the trusted origin of configuration that can select Host ignore files.
    pub fn read_ignore_config_baseline(&self, path: &Path) -> Result<Option<Vec<u8>>, ToolError> {
        self.read_ignore_config_view(path, true)
    }

    fn read_ignore_config_view(
        &self,
        path: &Path,
        _baseline: bool,
    ) -> Result<Option<Vec<u8>>, ToolError> {
        self.validate()?;
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let classify = |candidate: &Path| {
                self.validate()
                    .and_then(|()| slot.classify_ignore(&*self.ctx, candidate))
                    .map_err(|error| io::Error::other(error.to_string()))
            };
            return if _baseline {
                slot.lease.read_ignore_config_baseline(&path, classify)
            } else {
                slot.lease.read_ignore_config(&path, classify)
            }
            .map_err(failed);
        }
        native_preimage(&path)
    }

    /// The prepared root used for ignore ancestry and root-relative displays.
    pub fn io_root(&self, path: &Path) -> Result<PathBuf, ToolError> {
        let _path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, _) = slot.locate(&_path)?;
            return Ok(slot.lease.working_root(root).map_err(failed)?.to_path_buf());
        }
        Ok(self.root.clone())
    }

    /// A host-facing source path for display; file operations still use this view.
    pub fn source_path(&self, path: &Path) -> Result<PathBuf, ToolError> {
        let path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            return Ok(slot.lease.source_root(root).map_err(failed)?.join(relative));
        }
        Ok(path)
    }

    pub fn metadata(&self, path: &Path) -> Result<Metadata, ToolError> {
        let path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            return slot.lease.metadata(root, &relative).map_err(failed);
        }
        Ok(std::fs::metadata(path)?)
    }

    pub fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>, ToolError> {
        let path = self.resolve(path, false)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            return Ok(slot
                .lease
                .read_dir(root, &relative)
                .map_err(failed)?
                .into_iter()
                .map(|name| path.join(name))
                .collect());
        }
        std::fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()).map_err(ToolError::from))
            .collect()
    }

    /// Capture the destination before producing an approval preview.
    pub fn stage_write(&self, path: &Path) -> Result<WorkspaceWrite<C>, ToolError> {
        let path = self.resolve(path, true)?;
        #[cfg(feature = "sandbox")]
        if let Some(slot) = &self.lease {
            let (root, relative) = slot.locate(&path)?;
            let staged = slot.lease.stage_write(root, &relative).map_err(failed)?;
            return Ok(WorkspaceWrite {
                view: self.clone(),
                path,
                backend: WriteBackend::Leased(staged),
            });
        }
        let before = native_preimage(&path)?;
        Ok(WorkspaceWrite {
            view: self.clone(),
            path,
            backend: WriteBackend::Native(before),
        })
    }
}

fn native_preimage(path: &Path) -> Result<Option<Vec<u8>>, ToolError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

enum FileBackend {
    Native(File),
    #[cfg(feature = "sandbox")]
    Leased(agent_sandbox::snapshot::SnapshotFile),
}

/// A readable file whose backend and OS handle remain private.
pub struct WorkspaceFile<C> {
    backend: FileBackend,
    view: WorkspaceIo<C>,
    path: PathBuf,
}

impl<C: WorkspaceCtx> WorkspaceFile<C> {
    fn validate(&self) -> io::Result<()> {
        self.view
            .resolve(&self.path, false)
            .map(|_| ())
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        self.validate()?;
        Ok(Self {
            backend: match &self.backend {
                FileBackend::Native(file) => FileBackend::Native(file.try_clone()?),
                #[cfg(feature = "sandbox")]
                FileBackend::Leased(file) => FileBackend::Leased(file.try_clone()?),
            },
            view: self.view.clone(),
            path: self.path.clone(),
        })
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.validate()?;
        match &self.backend {
            FileBackend::Native(file) => file.metadata(),
            #[cfg(feature = "sandbox")]
            FileBackend::Leased(file) => file.metadata(),
        }
    }
}

impl<C: WorkspaceCtx> Read for WorkspaceFile<C> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.validate()?;
        match &mut self.backend {
            FileBackend::Native(file) => file.read(bytes),
            #[cfg(feature = "sandbox")]
            FileBackend::Leased(file) => file.read(bytes),
        }
    }
}

impl<C: WorkspaceCtx> Seek for WorkspaceFile<C> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.validate()?;
        match &mut self.backend {
            FileBackend::Native(file) => file.seek(position),
            #[cfg(feature = "sandbox")]
            FileBackend::Leased(file) => file.seek(position),
        }
    }
}

enum WriteBackend {
    Native(Option<Vec<u8>>),
    #[cfg(feature = "sandbox")]
    Leased(agent_sandbox::snapshot::SnapshotWrite),
}

/// A preimage-bound destination retaining its context and actual lease.
pub struct WorkspaceWrite<C> {
    view: WorkspaceIo<C>,
    path: PathBuf,
    backend: WriteBackend,
}

impl<C: WorkspaceCtx> WorkspaceWrite<C> {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn before(&self) -> Option<&[u8]> {
        match &self.backend {
            WriteBackend::Native(before) => before.as_deref(),
            #[cfg(feature = "sandbox")]
            WriteBackend::Leased(staged) => staged.before(),
        }
    }

    pub fn verify(&self) -> Result<(), ToolError> {
        if self.view.resolve(&self.path, true)? != self.path {
            return Err(failed("staged destination changed"));
        }
        match &self.backend {
            WriteBackend::Native(before) => {
                if &native_preimage(&self.path)? != before {
                    return Err(failed(format!(
                        "{} changed since preview — re-read and retry",
                        self.path.display()
                    )));
                }
                Ok(())
            }
            #[cfg(feature = "sandbox")]
            WriteBackend::Leased(staged) => staged.verify().map_err(failed),
        }
    }

    pub fn apply(&self, content: Option<&[u8]>, auto_mkdir: bool) -> Result<(), ToolError> {
        self.verify()?;
        match &self.backend {
            WriteBackend::Native(_) => {
                if let Some(bytes) = content {
                    if auto_mkdir {
                        if let Some(parent) = self.path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                    }
                    std::fs::write(&self.path, bytes)?;
                } else {
                    std::fs::remove_file(&self.path)?;
                }
                Ok(())
            }
            #[cfg(feature = "sandbox")]
            WriteBackend::Leased(staged) => staged.apply(content, auto_mkdir).map_err(failed),
        }
    }
}

#[cfg(feature = "sandbox")]
#[derive(Clone)]
pub(crate) struct WorkspaceLease {
    lease: Arc<SnapshotLease>,
    workspace: PathBuf,
    primary: RootId,
}

#[cfg(feature = "sandbox")]
impl WorkspaceLease {
    pub(crate) fn new(workspace: &Path, lease: SnapshotLease) -> Result<Self, ToolError> {
        let mut primary = None;
        for id in lease.roots() {
            if lease.source_root(id).map_err(failed)? == workspace
                || lease.working_root(id).map_err(failed)? == workspace
            {
                primary = Some(id);
                break;
            }
        }
        let primary =
            primary.ok_or_else(|| failed("workspace root is not in the prepared snapshot"))?;
        Ok(Self {
            lease: Arc::new(lease),
            workspace: workspace.to_path_buf(),
            primary,
        })
    }

    fn check<C: WorkspaceCtx>(&self, ctx: &C) -> Result<(), ToolError> {
        if ctx.root()? != self.workspace {
            return Err(failed("workspace root does not match the bound snapshot"));
        }
        self.lease.validate_root(self.primary).map_err(failed)?;
        Ok(())
    }

    fn locate(&self, path: &Path) -> Result<(RootId, PathBuf), ToolError> {
        if path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(ToolError::PathEscape(path.display().to_string()));
        }
        self.locate_optional(path)?.ok_or_else(|| {
            failed("root was not prepared for this execution; prepare a new execution snapshot")
        })
    }

    fn locate_optional(&self, path: &Path) -> Result<Option<(RootId, PathBuf)>, ToolError> {
        let mut hit = None;
        for id in self.lease.roots() {
            for root in [
                self.lease.source_root(id).map_err(failed)?,
                self.lease.working_root(id).map_err(failed)?,
            ] {
                if let Ok(relative) = path.strip_prefix(root) {
                    let length = root.components().count();
                    if hit
                        .as_ref()
                        .is_none_or(|(_, _, previous)| length > *previous)
                    {
                        let relative: PathBuf = relative
                            .components()
                            .filter(|part| !matches!(part, std::path::Component::CurDir))
                            .collect();
                        hit = Some((id, relative, length));
                    }
                }
            }
        }
        match hit {
            Some((id, relative, _)) => {
                if relative
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                {
                    return Err(ToolError::PathEscape(path.display().to_string()));
                }
                Ok(Some((id, relative)))
            }
            None => Ok(None),
        }
    }

    fn classify_ignore<C: WorkspaceCtx>(
        &self,
        ctx: &C,
        path: &Path,
    ) -> Result<Option<(RootId, PathBuf)>, ToolError> {
        if let Some((root, relative)) = self.locate_optional(path)? {
            let source = self.lease.source_root(root).map_err(failed)?.join(relative);
            let prepared = self.locate(&source)?;
            self.scope(ctx, &source)?;
            return Ok(Some(prepared));
        }
        if path.starts_with(ctx.root()?)
            || ctx
                .linked_roots()
                .iter()
                .any(|root| path.starts_with(&root.path))
        {
            return Err(failed(
                "root was not prepared for this execution; prepare a new execution snapshot",
            ));
        }
        Ok(None)
    }

    pub(crate) fn canonical<C: WorkspaceCtx>(
        &self,
        ctx: &C,
        path: &Path,
    ) -> Result<PathBuf, ToolError> {
        self.check(ctx)?;
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace.join(path)
        };
        let (id, relative) = self.locate(&path)?;
        Ok(self.lease.working_root(id).map_err(failed)?.join(relative))
    }

    pub(crate) fn scope<C: WorkspaceCtx>(
        &self,
        ctx: &C,
        path: &Path,
    ) -> Result<PathScope, ToolError> {
        let canonical = self.canonical(ctx, path)?;
        let (id, relative) = self.locate(&canonical)?;
        self.lease.validate_root(id).map_err(failed)?;
        if id == self.primary {
            return Ok(PathScope::Workspace(canonical));
        }
        let source = self.lease.source_root(id).map_err(failed)?;
        let source_path = source.join(relative);
        let linked = ctx.linked_roots();
        let authorization = linked
            .iter()
            .filter(|entry| {
                source_path.starts_with(&entry.path) || canonical.starts_with(&entry.path)
            })
            .max_by_key(|entry| entry.path.components().count());
        match authorization {
            Some(entry) => Ok(PathScope::Linked {
                path: canonical,
                root: entry.path.clone(),
                access: entry.access,
            }),
            None => Err(failed(format!(
                "prepared root {} has no live authorization",
                source.display()
            ))),
        }
    }
}

#[cfg(all(test, feature = "sandbox", unix))]
mod tests {
    use super::*;
    use crate::{LinkedRoot, LinkedRoots};
    use agent_sandbox::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[derive(Default)]
    struct Ctx(agent_tool::Extensions);
    impl agent_tool::ToolContext for Ctx {
        fn extensions(&self) -> &agent_tool::Extensions {
            &self.0
        }
        fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
            &mut self.0
        }
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        source: PathBuf,
        linked: PathBuf,
        extra: PathBuf,
        snapshot: WorkspaceSnapshot,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let linked = base.join("linked");
        let extra = base.join("extra");
        let storage = base.join("storage");
        for path in [&source, &linked, &extra, &storage] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
        for root in [&source, &linked, &extra] {
            std::fs::write(root.join("file"), b"before").unwrap();
        }
        let snapshot = WorkspaceSnapshot::prepare(
            &[source.clone(), linked.clone()],
            &storage,
            SnapshotBudget {
                max_bytes: 1024,
                max_entries: 32,
                max_depth: 8,
            },
            SnapshotPreference::PrivateCopy,
        )
        .unwrap();
        Fixture {
            _temp: temp,
            source,
            linked,
            extra,
            snapshot,
        }
    }

    fn context(f: &Fixture) -> (Ctx, Arc<LinkedRoots>) {
        let roots = Arc::new(LinkedRoots::default());
        roots.set(vec![LinkedRoot {
            path: f.linked.clone(),
            access: RootAccess::Read,
        }]);
        let mut ctx = Ctx::default().with_workspace(&f.source);
        ctx.install_linked_roots(roots.clone());
        ctx.install_workspace_lease(f.snapshot.lease().unwrap())
            .unwrap();
        (ctx, roots)
    }

    #[test]
    fn host_config_link_resolution_routes_private_bytes_and_live_grants() {
        let f = fixture();
        let (ctx, roots) = context(&f);
        let io = Arc::new(ctx).workspace_io().unwrap();
        let working = io.resolve(&f.source.join("file"), false).unwrap();
        std::fs::write(f.source.join("file"), b"ambient").unwrap();
        std::fs::write(f.linked.join("file"), b"ambient-linked").unwrap();
        let host = f._temp.path().join("host");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("config"), b"host").unwrap();
        symlink(&f.source, host.join("source")).unwrap();
        symlink(&working, host.join("private-file")).unwrap();
        symlink("../source/file", host.join("relative")).unwrap();
        symlink(&f.linked, host.join("linked")).unwrap();
        symlink(&f.extra, host.join("unprepared")).unwrap();
        for path in [
            f.source.join("file"),
            working.clone(),
            host.join("source/file"),
            host.join("private-file"),
            host.join("relative"),
            host.join("linked/file"),
        ] {
            assert_eq!(io.read_ignore_config(&path).unwrap().unwrap(), b"before");
        }
        assert_eq!(
            io.read_ignore_config(&host.join("config"))
                .unwrap()
                .unwrap(),
            b"host"
        );
        assert!(io
            .read_ignore_config(&host.join("missing"))
            .unwrap()
            .is_none());
        assert!(io
            .read_ignore_config(&f.source.join("missing"))
            .unwrap()
            .is_none());
        roots.set(vec![LinkedRoot {
            path: f.extra.clone(),
            access: RootAccess::Read,
        }]);
        for path in [
            f.linked.join("file"),
            host.join("linked/file"),
            f.extra.join("file"),
            host.join("unprepared/file"),
        ] {
            assert!(io.read_ignore_config(&path).is_err(), "{}", path.display());
            assert!(
                io.read_ignore_config_baseline(&path).is_err(),
                "{}",
                path.display()
            );
        }
        symlink(host.join("config"), working.with_file_name("link")).unwrap();
        assert!(io.read_ignore_config(&f.source.join("link")).is_err());
        assert!(io.read_ignore_config(&host.join("source/link")).is_err());
        assert!(io
            .read_ignore_config_baseline(&host.join("source/link"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn host_config_link_resolution_keeps_deleted_replaced_and_moved_source_ownership() {
        let f = fixture();
        let (ctx, _) = context(&f);
        let io = Arc::new(ctx).workspace_io().unwrap();
        io.stage_write(Path::new("file"))
            .unwrap()
            .apply(Some(b"private"), false)
            .unwrap();
        let moved = f._temp.path().join("moved-source");
        std::fs::rename(&f.source, &moved).unwrap();
        assert_eq!(
            io.read_ignore_config(&f.source.join("file"))
                .unwrap()
                .unwrap(),
            b"private"
        );
        std::fs::create_dir(&f.source).unwrap();
        std::fs::write(f.source.join("file"), b"replacement").unwrap();
        std::fs::write(moved.join("file"), b"moved-ambient").unwrap();
        for path in [f.source.join("file"), moved.join("file")] {
            assert_eq!(io.read_ignore_config(&path).unwrap().unwrap(), b"private");
            assert_eq!(
                io.read_ignore_config_baseline(&path).unwrap().unwrap(),
                b"before"
            );
        }
        let alias = f._temp.path().join("alias");
        symlink(&moved, &alias).unwrap();
        assert_eq!(
            io.read_ignore_config(&alias.join("file")).unwrap().unwrap(),
            b"private"
        );
        assert_eq!(
            io.read_ignore_config_baseline(&alias.join("file"))
                .unwrap()
                .unwrap(),
            b"before"
        );
    }

    #[test]
    fn host_config_link_resolution_preserves_prepared_primary_with_nested_read_grant_in_source_and_io(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let nested = source.join("nested");
        let storage = base.join("storage");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&storage).unwrap();
        std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(nested.join("config"), b"before").unwrap();
        let snapshot = WorkspaceSnapshot::prepare(
            &[source.clone()],
            &storage,
            SnapshotBudget {
                max_bytes: 1024,
                max_entries: 32,
                max_depth: 8,
            },
            SnapshotPreference::PrivateCopy,
        )
        .unwrap();
        let lease = snapshot.lease().unwrap();
        let outer = lease.roots().next().unwrap();
        let private = lease.working_root(outer).unwrap().join("nested/config");
        std::fs::write(nested.join("config"), b"ambient").unwrap();
        let roots = Arc::new(LinkedRoots::default());
        let mut ctx = Ctx::default().with_workspace(&source);
        ctx.install_linked_roots(roots.clone());
        ctx.install_workspace_lease(lease).unwrap();
        let ctx = Arc::new(ctx);
        let io = ctx.workspace_io().unwrap();
        for grants in [
            vec![],
            vec![LinkedRoot {
                path: nested.clone(),
                access: RootAccess::Read,
            }],
        ] {
            roots.set(grants);
            for path in [nested.join("config"), private.clone()] {
                assert_eq!(io.resolve(&path, false).unwrap(), private);
                assert_eq!(ctx.resolve_read(path.to_str().unwrap()).unwrap(), private);
                assert_eq!(io.read(&path).unwrap(), b"before");
                assert_eq!(io.read_ignore_config(&path).unwrap().unwrap(), b"before");
            }
        }
    }

    #[test]
    fn files_clones_views_and_staged_destinations_keep_the_real_lease() {
        let mut f = fixture();
        let (ctx, _) = context(&f);
        let ctx = Arc::new(ctx);
        let io = ctx.workspace_io().unwrap();
        std::fs::write(f.source.join("file"), b"ambient").unwrap();
        assert_eq!(io.read(Path::new("./file")).unwrap(), b"before");
        let working = io.resolve(Path::new("file"), false).unwrap();
        assert_eq!(io.read(&working).unwrap(), b"before");
        assert_eq!(io.read_dir(Path::new(".")).unwrap(), vec![working.clone()]);
        assert_eq!(io.metadata(Path::new(".")).unwrap().is_dir(), true);
        let file = io.open(Path::new("file")).unwrap();
        let clone = file.try_clone().unwrap();
        let write = io.stage_write(Path::new("file")).unwrap();
        drop(ctx);
        drop(io);
        assert!(f.snapshot.seal().is_err());
        drop(file);
        assert!(f.snapshot.seal().is_err());
        drop(clone);
        assert!(f.snapshot.seal().is_err());
        write.apply(Some(b"private"), false).unwrap();
        drop(write);
        assert_eq!(std::fs::read(f.source.join("file")).unwrap(), b"ambient");
        f.snapshot.seal().unwrap();
    }

    #[test]
    fn prepared_grants_recheck_on_handles_and_commit_and_unprepared_grants_refuse() {
        let f = fixture();
        let (ctx, roots) = context(&f);
        let io = Arc::new(ctx).workspace_io().unwrap();
        let path = f.linked.join("file");
        assert!(io.stage_write(&path).is_err());
        roots.set(vec![LinkedRoot {
            path: f.linked.clone(),
            access: RootAccess::ReadWrite,
        }]);
        let target = io.stage_write(&path).unwrap();
        let mut file = io.open(&path).unwrap();
        roots.set(vec![]);
        assert!(target.verify().is_err());
        assert!(file.read(&mut [0; 1]).is_err());
        assert!(io.metadata(&path).is_err());
        roots.set(vec![
            LinkedRoot {
                path: f.linked.clone(),
                access: RootAccess::ReadWrite,
            },
            LinkedRoot {
                path: f.extra.clone(),
                access: RootAccess::ReadWrite,
            },
        ]);
        let error = io.read(&f.extra.join("file")).unwrap_err().to_string();
        assert!(error.contains("new execution snapshot"), "{error}");
        assert!(io.stage_write(&f.extra.join("new")).is_err());
        target.apply(Some(b"private"), false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"before");
        assert_eq!(std::fs::read(f.extra.join("file")).unwrap(), b"before");
    }

    #[test]
    fn root_switch_aliases_and_same_content_replacement_refuse() {
        let f = fixture();
        let (ctx, _) = context(&f);
        let changed = ctx.with_workspace(&f.extra);
        assert!(changed.resolve_read("file").is_err());
        let (ctx, _) = context(&f);
        let io = Arc::new(ctx).workspace_io().unwrap();
        let target = io.stage_write(Path::new("file")).unwrap();
        let working = target.path().to_path_buf();
        std::fs::rename(&working, working.with_extension("old")).unwrap();
        std::fs::write(&working, b"before").unwrap();
        assert!(
            target.verify().is_err(),
            "same bytes cannot replace a staged inode"
        );
        std::fs::remove_file(&working).unwrap();
        symlink(f.extra.join("file"), &working).unwrap();
        assert!(io.read(Path::new("file")).is_err());
        assert!(io.metadata(Path::new("file")).is_err());
        assert!(target.apply(Some(b"escape"), false).is_err());
        std::fs::remove_file(&working).unwrap();
        std::fs::hard_link(working.with_extension("old"), &working).unwrap();
        assert!(io.open(Path::new("file")).is_err());
        assert!(io.stage_write(Path::new("file")).is_err());
        let parent = working.parent().unwrap().join("dir");
        symlink(&f.extra, &parent).unwrap();
        assert!(io.read(Path::new("dir/file")).is_err());
        assert!(io.read_dir(Path::new("dir")).is_err());
        assert!(io.stage_write(Path::new("dir/new")).is_err());
        assert_eq!(std::fs::read(f.extra.join("file")).unwrap(), b"before");
        let socket = f._temp.path().join("s");
        let _socket = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::rename(socket, working.parent().unwrap().join("socket")).unwrap();
        assert!(io.open(Path::new("socket")).is_err());
        assert!(io.metadata(Path::new("socket")).is_err());
        assert!(io.stage_write(Path::new("socket")).is_err());
        let root = working.parent().unwrap();
        let directory = root.join("staged-parent");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("file"), b"before").unwrap();
        let staged = io.stage_write(Path::new("staged-parent/file")).unwrap();
        std::fs::rename(&directory, root.join("saved-parent")).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("file"), b"before").unwrap();
        assert!(staged.verify().is_err());
        let saved_root = root.with_extension("saved");
        std::fs::rename(root, &saved_root).unwrap();
        std::fs::create_dir(root).unwrap();
        let error = io.metadata(Path::new(".")).unwrap_err().to_string();
        assert!(error.contains("root identity changed"), "{error}");
        std::fs::remove_dir(root).unwrap();
        symlink(&f.extra, root).unwrap();
        assert!(io.metadata(Path::new(".")).is_err());
        std::fs::remove_file(root).unwrap();
        std::fs::rename(saved_root, root).unwrap();
    }
}
