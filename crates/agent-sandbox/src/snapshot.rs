//! Private workspaces with stable, lease-scoped root grants.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context, Result};

use crate::snapshot_fs::{clone_into, regular, Dir};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotPreference {
    NativePreferred,
    PrivateCopy,
}

/// Preparation limits, measured as logical bytes across baseline and working
/// copies. These limits do not enforce disk usage after execution starts.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotBudget {
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_depth: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStats {
    pub native_cow_files: u64,
    pub private_copy_files: u64,
    pub prepared_bytes: u64,
    pub prepared_entries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RootId(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    Prepared,
    Sealed,
    Published,
    RecoveryRequired,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    CreateFile,
    ModifyFile,
    DeleteFile,
    CreateDirectory,
    ModifyDirectory,
    DeleteDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotChange {
    pub root: RootId,
    pub path: PathBuf,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone)]
pub struct PublishConflict {
    pub change: SnapshotChange,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RecoveryRecord {
    pub root: RootId,
    pub target: PathBuf,
    /// A private, same-volume directory containing displaced originals and
    /// staged replacements. Retain this path in the host's durable audit.
    pub directory: PathBuf,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct PublishReport {
    pub applied: Vec<SnapshotChange>,
    pub conflicts: Vec<PublishConflict>,
    pub recovery_required: Vec<RecoveryRecord>,
    pub recovery_material: Vec<PathBuf>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    directory: bool,
    identity: (u64, u64),
    mode: u32,
}

struct Root {
    source: Dir,
    identity: (u64, u64),
    root_mode: u32,
    baseline: Dir,
    working: Dir,
    original: BTreeMap<PathBuf, Entry>,
}

#[derive(Default)]
struct RootBatch {
    values: Vec<Root>,
    next: OnceLock<Box<RootBatch>>,
}

impl RootBatch {
    fn iter(&self) -> impl Iterator<Item = &Root> {
        std::iter::successors(Some(self), |batch| batch.next.get().map(Box::as_ref))
            .flat_map(|batch| batch.values.iter())
    }

    fn len(&self) -> usize {
        self.iter().count()
    }

    fn get(&self, index: usize) -> Option<&Root> {
        self.iter().nth(index)
    }

    fn clear(&mut self) {
        self.values.clear();
        let mut next = self.next.take();
        while let Some(mut batch) = next {
            batch.values.clear();
            next = batch.next.take();
        }
    }
}

impl Drop for RootBatch {
    fn drop(&mut self) {
        self.clear();
    }
}

impl std::ops::Index<usize> for RootBatch {
    type Output = Root;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("snapshot root index out of bounds")
    }
}

struct Private {
    container: Option<Dir>,
    roots: RootBatch,
    active: AtomicUsize,
}

impl Drop for Private {
    fn drop(&mut self) {
        // A displaced container is retained rather than following an attacker
        // controlled path during cleanup.
        self.roots.clear();
        if let Some(container) = self.container.take() {
            if Dir::open(&container.path).and_then(|d| d.identity()).ok()
                == container.identity().ok()
            {
                let _ = remove_contents(&container);
                let path = container.path.clone();
                drop(container);
                if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                    if let Ok(parent) = Dir::open(parent) {
                        let _ = parent.unlink(Path::new(name), true);
                    }
                }
            }
        }
    }
}

/// A host-minted capability. Keeping a lease alive prevents sealing.
pub struct SnapshotLease {
    private: Arc<Private>,
    root_count: usize,
}

/// A file capability that keeps its snapshot unsealable until closed.
pub struct SnapshotFile {
    file: File,
    lease: SnapshotLease,
}

/// A pinned preimage and destination in a private workspace.
pub struct SnapshotWrite {
    lease: SnapshotLease,
    root: RootId,
    relative: PathBuf,
    ancestor: PathBuf,
    identity: (u64, u64),
    file: Option<File>,
    before: Option<Vec<u8>>,
}

impl SnapshotWrite {
    pub fn before(&self) -> Option<&[u8]> {
        self.before.as_deref()
    }

    pub fn verify(&self) -> Result<()> {
        let root = self.lease.dir(self.root)?;
        let ancestor = if self.ancestor.as_os_str().is_empty() {
            root.identity()?
        } else {
            root.child(&self.ancestor)?.identity()?
        };
        if ancestor != self.identity {
            bail!("staged parent directory changed");
        }
        let current = match root.read(&self.relative) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        match (&self.file, current) {
            (None, None) => Ok(()),
            (Some(original), Some(mut current)) => {
                regular(original)?;
                if file_identity(original)? != file_identity(&current)? {
                    bail!("staged file identity changed");
                }
                let mut bytes = Vec::new();
                current.read_to_end(&mut bytes)?;
                if Some(bytes.as_slice()) != self.before() {
                    bail!("staged preimage changed");
                }
                Ok(())
            }
            _ => bail!("staged target changed"),
        }
    }

    /// Apply bytes, or delete with `None`, after checking the pinned preimage.
    pub fn apply(&self, content: Option<&[u8]>, auto_mkdir: bool) -> Result<()> {
        self.verify()?;
        let root = self.lease.dir(self.root)?;
        if auto_mkdir {
            if let Some(parent) = self.relative.parent() {
                let mut prefix = PathBuf::new();
                for component in parent.components() {
                    prefix.push(component);
                    match root.child(&prefix) {
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            root.mkdir(&prefix)?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        match content {
            None => {
                self.verify()?;
                root.unlink(&self.relative, false)?;
            }
            Some(bytes) => {
                let mut file = match &self.file {
                    Some(original) => {
                        let file = root.write(&self.relative)?;
                        if file_identity(&file)? != file_identity(original)? {
                            bail!("staged file identity changed");
                        }
                        self.verify()?;
                        file
                    }
                    None => root.create(&self.relative)?,
                };
                regular(&file)?;
                file.set_len(0)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
        }
        Ok(())
    }
}

impl SnapshotFile {
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            lease: self.lease.retain(),
        })
    }

    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    pub fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

impl Read for SnapshotFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for SnapshotFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for SnapshotFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

/// Empty private launch directory with no workspace read/write capability.
pub struct WorkerScope {
    private: Arc<Private>,
}

impl WorkerScope {
    pub fn prepare(storage_root: &Path) -> Result<Self> {
        let storage = Dir::open(storage_root)?;
        check_private(&storage)?;
        let container = storage.mkdir(Path::new(&unique("worker")))?;
        Ok(Self {
            private: Arc::new(Private {
                container: Some(container),
                roots: RootBatch::default(),
                active: AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn directory(&self) -> Result<&Path> {
        let dir = self
            .private
            .container
            .as_ref()
            .context("missing worker directory")?;
        if Dir::open(&dir.path)?.identity()? != dir.identity()? {
            bail!("private worker directory identity changed");
        }
        Ok(&dir.path)
    }
}

impl Drop for SnapshotLease {
    fn drop(&mut self) {
        self.private.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SnapshotLease {
    fn dir(&self, root: RootId) -> Result<&Dir> {
        let working = &self.root(root)?.working;
        let container = self
            .private
            .container
            .as_ref()
            .context("snapshot container is unavailable")?;
        let relative = working
            .path
            .strip_prefix(&container.path)
            .context("working root left its snapshot container")?;
        let current = container.child(relative)?;
        if current.identity()? != working.identity()? {
            bail!("private execution root identity changed");
        }
        Ok(working)
    }

    /// Check a prepared execution root through its retained container handle.
    pub fn validate_root(&self, root: RootId) -> Result<()> {
        self.dir(root)?;
        Ok(())
    }

    /// Metadata obtained through the prepared root's no-follow handles.
    pub fn metadata(&self, root: RootId, relative: &Path) -> Result<std::fs::Metadata> {
        let dir = self.dir(root)?;
        if relative.as_os_str().is_empty() {
            return Ok(dir.metadata()?);
        }
        if dir.is_dir(relative)? {
            Ok(dir.child(relative)?.metadata()?)
        } else {
            Ok(dir.read(relative)?.metadata()?)
        }
    }

    /// Enumerate one directory through its pinned root.
    pub fn read_dir(&self, root: RootId, relative: &Path) -> Result<Vec<std::ffi::OsString>> {
        let dir = self.dir(root)?;
        if relative.as_os_str().is_empty() {
            Ok(dir.names()?)
        } else {
            Ok(dir.child(relative)?.names()?)
        }
    }

    /// Capture a write destination without changing its contents.
    pub fn stage_write(&self, root: RootId, relative: &Path) -> Result<SnapshotWrite> {
        crate::snapshot_fs::relative(relative)?;
        let dir = self.dir(root)?;
        let mut ancestor = relative.parent().unwrap_or(Path::new("")).to_path_buf();
        let identity = loop {
            if ancestor.as_os_str().is_empty() {
                break dir.identity()?;
            }
            match dir.child(&ancestor) {
                Ok(parent) => break parent.identity()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    ancestor.pop();
                }
                Err(error) => return Err(error.into()),
            }
        };
        let (file, before) = match dir.read(relative) {
            Ok(mut file) => {
                let mut before = Vec::new();
                file.read_to_end(&mut before)?;
                (Some(file), Some(before))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(error.into()),
        };
        Ok(SnapshotWrite {
            lease: self.retain(),
            root,
            relative: relative.to_path_buf(),
            ancestor,
            identity,
            file,
            before,
        })
    }
    fn retain(&self) -> Self {
        self.private.active.fetch_add(1, Ordering::AcqRel);
        Self {
            private: Arc::clone(&self.private),
            root_count: self.root_count,
        }
    }

    pub fn roots(&self) -> impl Iterator<Item = RootId> + '_ {
        (0..self.root_count).map(RootId)
    }

    pub fn working_root(&self, root: RootId) -> Result<&Path> {
        Ok(&self.root(root)?.working.path)
    }

    pub fn source_root(&self, root: RootId) -> Result<&Path> {
        Ok(&self.root(root)?.source.path)
    }

    /// Maps a host absolute path to its linked private root and relative path.
    pub fn map_source(&self, path: &Path) -> Result<(RootId, PathBuf)> {
        for (id, root) in self.private.roots.iter().take(self.root_count).enumerate() {
            if let Ok(relative) = path.strip_prefix(&root.source.path) {
                if !relative.as_os_str().is_empty() {
                    crate::snapshot_fs::relative(relative)?;
                }
                return Ok((RootId(id), relative.to_owned()));
            }
        }
        bail!("path is outside the leased source roots")
    }

    pub fn read_file(&self, root: RootId, path: &Path) -> Result<SnapshotFile> {
        Ok(SnapshotFile {
            file: self.dir(root)?.read(path)?,
            lease: self.retain(),
        })
    }

    /// Read ignore configuration through current grants; missing paths and directories yield None.
    pub fn read_ignore_config<F>(&self, path: &Path, classify: F) -> Result<Option<Vec<u8>>>
    where
        F: FnMut(&Path) -> io::Result<Option<(RootId, PathBuf)>>,
    {
        self.read_ignore_config_view(path, classify, false)
    }

    /// Read prepared configuration from its immutable baseline.
    pub fn read_ignore_config_baseline<F>(
        &self,
        path: &Path,
        classify: F,
    ) -> Result<Option<Vec<u8>>>
    where
        F: FnMut(&Path) -> io::Result<Option<(RootId, PathBuf)>>,
    {
        self.read_ignore_config_view(path, classify, true)
    }

    fn read_ignore_config_view<F>(
        &self,
        path: &Path,
        mut classify: F,
        baseline: bool,
    ) -> Result<Option<Vec<u8>>>
    where
        F: FnMut(&Path) -> io::Result<Option<(RootId, PathBuf)>>,
    {
        if let Some(target) = classify(path)? {
            return self.read_prepared_ignore(path, target, &mut classify, baseline);
        }
        let (anchor, mut pending) = ignore_components(path)?;
        let mut directory = Dir::open(&anchor)?;
        let mut links = 0;
        loop {
            let remaining: PathBuf = pending.iter().collect();
            let coordinate = directory.path.join(&remaining);
            if let Some(target) = classify(&coordinate)? {
                return self.read_prepared_ignore(&coordinate, target, &mut classify, baseline);
            }
            if let Some(alias) = self.ignore_directory_alias(&directory)? {
                let path = alias.join(&remaining);
                let target =
                    classify(&path)?.context("prepared configuration alias lost its root")?;
                return self.read_prepared_ignore(&path, target, &mut classify, baseline);
            }
            let name = pending
                .pop_front()
                .context("configuration path is a directory")?;
            if name == ".." {
                directory = directory.config_parent()?;
                continue;
            }
            match directory.symlink_target(Path::new(&name)) {
                Ok(Some(target)) => {
                    links += 1;
                    if links > 40 {
                        bail!("too many configuration symlinks");
                    }
                    if target.has_root() {
                        let absolute = directory.path.join(&target);
                        let (anchor, mut components) = ignore_components(&absolute)?;
                        components.append(&mut pending);
                        pending = components;
                        directory = Dir::open(&anchor)?;
                    } else {
                        let mut components = ignore_relative_components(&target)?;
                        components.append(&mut pending);
                        pending = components;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            if !pending.is_empty() {
                directory = match directory.child(Path::new(&name)) {
                    Ok(directory) => directory,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error.into()),
                };
                continue;
            }
            if directory.is_dir(Path::new(&name))? {
                return Ok(None);
            }
            let mut file = match directory.read(Path::new(&name)) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if let Some(alias) = self.ignore_directory_alias(&directory)? {
                let path = alias.join(&name);
                let target =
                    classify(&path)?.context("prepared configuration alias lost its root")?;
                return self.read_prepared_ignore(&path, target, &mut classify, baseline);
            }
            let identity = file_identity(&file)?;
            for root in self.private.roots.iter() {
                if let Some((relative, _)) = root
                    .original
                    .iter()
                    .find(|(_, entry)| !entry.directory && entry.identity == identity)
                {
                    let path = root.source.path.join(relative);
                    let target =
                        classify(&path)?.context("prepared configuration alias lost its root")?;
                    return self.read_prepared_ignore(&path, target, &mut classify, baseline);
                }
            }
            if let Some(target) = classify(&coordinate)? {
                return self.read_prepared_ignore(&coordinate, target, &mut classify, baseline);
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if self.ignore_directory_alias(&directory)?.is_some() {
                bail!("Host configuration directory entered a prepared root");
            }
            if classify(&coordinate)?.is_some() {
                bail!("Host configuration authorization changed");
            }
            return Ok(Some(bytes));
        }
    }

    fn read_prepared_ignore<F>(
        &self,
        path: &Path,
        (root, relative): (RootId, PathBuf),
        classify: &mut F,
        baseline: bool,
    ) -> Result<Option<Vec<u8>>>
    where
        F: FnMut(&Path) -> io::Result<Option<(RootId, PathBuf)>>,
    {
        let directory = if baseline {
            &self.root(root)?.baseline
        } else {
            self.dir(root)?
        };
        let file = match directory.is_dir(&relative) {
            Ok(true) => return Ok(None),
            Ok(false) => directory.read(&relative),
            Err(error) => Err(error),
        };
        let bytes = match file {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Some(bytes)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if classify(path)? != Some((root, relative)) {
            bail!("prepared configuration authorization changed");
        }
        Ok(bytes)
    }

    fn ignore_directory_alias(&self, directory: &Dir) -> Result<Option<PathBuf>> {
        let identity = directory.identity()?;
        for root in self.private.roots.iter() {
            if identity == root.identity || identity == root.working.identity()? {
                return Ok(Some(root.source.path.clone()));
            }
            if let Some((relative, _)) = root
                .original
                .iter()
                .find(|(_, entry)| entry.directory && entry.identity == identity)
            {
                return Ok(Some(root.source.path.join(relative)));
            }
        }
        let lineage = directory.lineage()?;
        for root in self.private.roots.iter() {
            if lineage.contains(&root.identity) || lineage.contains(&root.working.identity()?) {
                bail!("Host configuration directory entered a prepared root");
            }
        }
        if let Some(container) = &self.private.container {
            if identity == container.identity()? || lineage.contains(&container.identity()?) {
                bail!("private snapshot storage is not Host configuration");
            }
        }
        Ok(None)
    }

    /// Creates a new regular file using O_EXCL/handle-relative traversal.
    pub fn create_file(&self, root: RootId, path: &Path) -> Result<SnapshotFile> {
        Ok(SnapshotFile {
            file: self.root(root)?.working.create(path)?,
            lease: self.retain(),
        })
    }

    /// Opens the inode before checking its type, then truncates that handle.
    pub fn write_file(&self, root: RootId, path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = self.root(root)?.working.write(path)?;
        file.set_len(0)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn create_directory(&self, root: RootId, path: &Path) -> Result<()> {
        self.root(root)?.working.mkdir(path)?;
        Ok(())
    }

    fn root(&self, root: RootId) -> Result<&Root> {
        if root.0 >= self.root_count {
            bail!("root was not granted to this lease");
        }
        self.private
            .roots
            .get(root.0)
            .context("unknown snapshot root")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for root in self.private.roots.iter().take(self.root_count) {
            if Dir::open(&root.working.path)?.identity()? != root.working.identity()? {
                bail!("private execution root identity changed");
            }
        }
        Ok(())
    }
}

fn ignore_components(path: &Path) -> Result<(PathBuf, VecDeque<OsString>)> {
    if !path.is_absolute() {
        bail!("configuration path must be absolute");
    }
    let mut anchor = PathBuf::new();
    let mut pending = VecDeque::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => anchor.push(part.as_os_str()),
            Component::Normal(_) | Component::ParentDir => {
                pending.push_back(part.as_os_str().to_owned())
            }
            Component::CurDir => {}
        }
    }
    Ok((anchor, pending))
}

fn ignore_relative_components(path: &Path) -> Result<VecDeque<OsString>> {
    let mut pending = VecDeque::new();
    for part in path.components() {
        match part {
            Component::Normal(_) | Component::ParentDir => {
                pending.push_back(part.as_os_str().to_owned())
            }
            Component::CurDir => {}
            _ => bail!("unsupported drive-relative configuration symlink"),
        }
    }
    Ok(pending)
}

pub struct WorkspaceSnapshot {
    private: Arc<Private>,
    storage: Dir,
    state: SnapshotState,
    stats: SnapshotStats,
    budget: SnapshotBudget,
    preference: SnapshotPreference,
    changes: Vec<SnapshotChange>,
}

fn prepare_batch(
    sources: Vec<Dir>,
    container: Dir,
    first_index: usize,
    budget: SnapshotBudget,
    preference: SnapshotPreference,
    stats: &mut SnapshotStats,
) -> Result<Private> {
    let mut private = Private {
        container: Some(container),
        roots: RootBatch::default(),
        active: AtomicUsize::new(0),
    };
    for (offset, source) in sources.into_iter().enumerate() {
        let index = first_index
            .checked_add(offset)
            .context("root index overflow")?;
        let container = private.container.as_ref().unwrap();
        let base = container.mkdir(Path::new(&format!("baseline-{index}")))?;
        let work = container.mkdir(Path::new(&format!("working-{index}")))?;
        let original = inventory(&source, budget)?;
        copy_tree(&source, &base, &original, budget, preference, stats)?;
        copy_tree(
            &base,
            &work,
            &inventory(&base, budget)?,
            budget,
            preference,
            stats,
        )?;
        if !tree_equal(&source, &base, &original, budget)? {
            bail!("source changed during snapshot preparation");
        }
        let identity = source.identity()?;
        let root_mode = mode(&source.metadata()?);
        private.roots.values.push(Root {
            source,
            identity,
            root_mode,
            baseline: base,
            working: work,
            original,
        });
    }
    private.container.as_ref().unwrap().sync()?;
    Ok(private)
}

impl WorkspaceSnapshot {
    pub fn prepare(
        source_roots: &[PathBuf],
        storage_root: &Path,
        budget: SnapshotBudget,
        preference: SnapshotPreference,
    ) -> Result<Self> {
        if source_roots.is_empty() || budget.max_entries == 0 || budget.max_depth == 0 {
            bail!("snapshot requires roots and explicit nonzero entry/depth budgets");
        }
        let storage = Dir::open(storage_root).context("open private snapshot storage")?;
        check_private(&storage)?;
        let mut sources = Vec::new();
        for path in source_roots {
            let source = Dir::open(path).context("open source root without links")?;
            for previous in &sources {
                let previous: &Dir = previous;
                if roots_overlap(&source, previous)? {
                    bail!("source roots overlap");
                }
            }
            if roots_overlap(&source, &storage)? {
                bail!("source and snapshot storage overlap");
            }
            sources.push(source);
        }
        let name = unique("execution");
        let container = storage.mkdir(Path::new(&name))?;
        let mut stats = SnapshotStats::default();
        let private = prepare_batch(sources, container, 0, budget, preference, &mut stats)?;
        Ok(Self {
            private: Arc::new(private),
            storage,
            state: SnapshotState::Prepared,
            stats,
            budget,
            preference,
            changes: Vec::new(),
        })
    }

    /// Append disjoint roots without widening existing leases. The Host must
    /// exclude overlap with every running owner's fixed OS read grants first.
    pub fn append_roots(&mut self, source_roots: &[PathBuf]) -> Result<Vec<RootId>> {
        if self.state != SnapshotState::Prepared || source_roots.is_empty() {
            bail!("appending roots requires a prepared snapshot and nonempty roots");
        }
        if Dir::open(&self.storage.path)?.identity()? != self.storage.identity()? {
            bail!("snapshot storage identity changed");
        }
        check_private(&self.storage)?;
        let container = self
            .private
            .container
            .as_ref()
            .context("missing snapshot container")?;
        if Dir::open(&container.path)?.identity()? != container.identity()? {
            bail!("snapshot container identity changed");
        }
        let mut sources = Vec::new();
        for path in source_roots {
            let source = Dir::open(path).context("open source root without links")?;
            for previous in self
                .private
                .roots
                .iter()
                .map(|root| &root.source)
                .chain(&sources)
            {
                if roots_overlap(&source, previous)? {
                    bail!("source roots overlap");
                }
            }
            if roots_overlap(&source, &self.storage)? {
                bail!("source and snapshot storage overlap");
            }
            sources.push(source);
        }
        let first = self.private.roots.len();
        let end = first
            .checked_add(sources.len())
            .context("root index overflow")?;
        let mut stats = self.stats;
        let mut prepared = prepare_batch(
            sources,
            container.mkdir(Path::new(&unique("roots")))?,
            first,
            self.budget,
            self.preference,
            &mut stats,
        )?;
        let mut tail = &self.private.roots;
        while let Some(next) = tail.next.get() {
            tail = next;
        }
        if let Err(batch) = tail.next.set(Box::new(std::mem::take(&mut prepared.roots))) {
            drop(batch);
            bail!("snapshot root admission changed");
        }
        drop(prepared.container.take());
        self.stats = stats;
        Ok((first..end).map(RootId).collect())
    }

    pub fn state(&self) -> SnapshotState {
        self.state
    }
    pub fn stats(&self) -> SnapshotStats {
        self.stats
    }

    pub fn lease(&self) -> Result<SnapshotLease> {
        if self.state != SnapshotState::Prepared {
            bail!("snapshot is not accepting new work");
        }
        self.private.active.fetch_add(1, Ordering::AcqRel);
        Ok(SnapshotLease {
            private: Arc::clone(&self.private),
            root_count: self.private.roots.len(),
        })
    }

    /// Return `None` while capability leases remain; validate and seal otherwise.
    /// The Host must stop admission before attempting publication.
    pub fn try_seal(&mut self) -> Result<Option<&[SnapshotChange]>> {
        if self.state != SnapshotState::Prepared {
            bail!("snapshot is not prepared");
        }
        if self.private.active.load(Ordering::Acquire) != 0 {
            return Ok(None);
        }
        self.seal().map(Some)
    }

    /// Host must first stop admission and quiesce all capability users. Active
    /// process guards and leases make an early seal fail closed.
    pub fn seal(&mut self) -> Result<&[SnapshotChange]> {
        if self.state != SnapshotState::Prepared {
            bail!("snapshot is not prepared");
        }
        if self.private.active.load(Ordering::Acquire) != 0 {
            bail!("snapshot still has active execution leases");
        }
        let mut changes = Vec::new();
        for (id, root) in self.private.roots.iter().enumerate() {
            if mode(&root.working.metadata()?) != mode(&root.baseline.metadata()?) {
                bail!("execution root permission changes are unsupported");
            }
            let working = inventory(&root.working, self.budget)?;
            let baseline = inventory(&root.baseline, self.budget)?;
            let paths: BTreeSet<_> = baseline.keys().chain(working.keys()).collect();
            for path in paths {
                let old = baseline.get(path);
                let new = working.get(path);
                if let (Some(old), Some(new)) = (old, new) {
                    if old.directory != new.directory {
                        bail!("file/directory type replacement requires separate executions");
                    }
                    if old.mode == new.mode
                        && (old.directory
                            || files_equal(&root.baseline.read(path)?, &root.working.read(path)?)?)
                    {
                        continue;
                    }
                }
                let kind = match (old, new) {
                    (None, Some(e)) if e.directory => ChangeKind::CreateDirectory,
                    (None, Some(_)) => ChangeKind::CreateFile,
                    (Some(e), None) if e.directory => ChangeKind::DeleteDirectory,
                    (Some(_), None) => ChangeKind::DeleteFile,
                    (Some(e), Some(_)) if e.directory => ChangeKind::ModifyDirectory,
                    (Some(_), Some(_)) => ChangeKind::ModifyFile,
                    _ => unreachable!(),
                };
                changes.push(SnapshotChange {
                    root: RootId(id),
                    path: path.clone(),
                    kind,
                });
            }
        }
        changes.sort_by_key(|c| {
            let depth = c.path.components().count();
            match c.kind {
                ChangeKind::CreateDirectory => (0, depth),
                ChangeKind::DeleteDirectory => (2, usize::MAX - depth),
                ChangeKind::ModifyDirectory => (3, usize::MAX - depth),
                _ => (1, depth),
            }
        });
        self.changes = changes;
        self.state = SnapshotState::Sealed;
        Ok(&self.changes)
    }

    pub fn diff(&self) -> Result<&[SnapshotChange]> {
        if self.state == SnapshotState::Prepared {
            bail!("seal before reading the diff");
        }
        Ok(&self.changes)
    }

    /// Cancellation is honored before the first host mutation. Once publishing
    /// starts the host receives every partial result and recovery location.
    pub fn publish(&mut self, cancelled: impl Fn() -> bool) -> Result<PublishReport> {
        if self.state != SnapshotState::Sealed {
            bail!("publish requires a sealed snapshot");
        }
        let mut report = PublishReport::default();
        if cancelled() {
            report.cancelled = true;
            return Ok(report);
        }
        for change in &self.changes {
            let root = &self.private.roots[change.root.0];
            if let Err(error) = preflight(root, change) {
                report.conflicts.push(PublishConflict {
                    change: change.clone(),
                    reason: error.to_string(),
                });
            }
        }
        // Preflight every path before making recovery directories or staging.
        if !report.conflicts.is_empty() {
            return Ok(report);
        }
        if cancelled() {
            report.cancelled = true;
            return Ok(report);
        }
        let mut created = BTreeMap::new();
        for change in &self.changes {
            if change.kind == ChangeKind::ModifyDirectory {
                continue;
            }
            let root = &self.private.roots[change.root.0];
            if let Err(error) = publish_one(root, change, &mut report, &created) {
                report.conflicts.push(PublishConflict {
                    change: change.clone(),
                    reason: error.to_string(),
                });
                break;
            }
            if change.kind == ChangeKind::CreateDirectory {
                match root.source.child(&change.path).and_then(|dir| {
                    Ok(Entry {
                        directory: true,
                        identity: dir.identity()?,
                        mode: mode(&dir.metadata()?),
                    })
                }) {
                    Ok(entry) => {
                        created.insert((change.root, change.path.clone()), entry);
                    }
                    Err(error) => {
                        report.conflicts.push(PublishConflict {
                            change: change.clone(),
                            reason: error.to_string(),
                        });
                        break;
                    }
                }
            }
            if !report.recovery_required.is_empty() {
                break;
            }
        }
        if report.conflicts.is_empty() && report.recovery_required.is_empty() {
            let mut directories: Vec<_> = self
                .changes
                .iter()
                .filter(|change| {
                    matches!(
                        change.kind,
                        ChangeKind::CreateDirectory | ChangeKind::ModifyDirectory
                    )
                })
                .collect();
            directories.sort_by_key(|change| std::cmp::Reverse(change.path.components().count()));
            for change in directories {
                let root = &self.private.roots[change.root.0];
                let result = if change.kind == ChangeKind::ModifyDirectory {
                    publish_one(root, change, &mut report, &created)
                } else {
                    (|| -> Result<()> {
                        let (parent, name) = checked_parent(root, change, &created)?;
                        let directory = parent.child(Path::new(&name))?;
                        let expected = &created[&(change.root, change.path.clone())];
                        if directory.identity()? != expected.identity
                            || mode(&directory.metadata()?) != expected.mode
                        {
                            bail!("created directory identity or permissions changed");
                        }
                        directory.set_permissions(
                            root.working.child(&change.path)?.metadata()?.permissions(),
                        )?;
                        directory.sync()?;
                        Ok(())
                    })()
                };
                if let Err(error) = result {
                    report.conflicts.push(PublishConflict {
                        change: change.clone(),
                        reason: error.to_string(),
                    });
                    break;
                }
            }
        }
        if !report.applied.is_empty()
            && !report.conflicts.is_empty()
            && report.recovery_required.is_empty()
        {
            let completed_files = report.applied.iter().filter(|change| {
                !matches!(
                    change.kind,
                    ChangeKind::CreateDirectory | ChangeKind::DeleteDirectory
                )
            });
            for (change, directory) in completed_files.zip(&report.recovery_material) {
                report.recovery_required.push(RecoveryRecord {
                    root: change.root,
                    target: self.private.roots[change.root.0]
                        .source
                        .path
                        .join(&change.path),
                    directory: directory.clone(),
                    reason: "partial publication requires host reconciliation of applied changes"
                        .into(),
                });
            }
            if report.recovery_required.is_empty() {
                let change = &report.applied[0];
                let source = &self.private.roots[change.root.0].source.path;
                report.recovery_required.push(RecoveryRecord {
                    root: change.root,
                    target: source.join(&change.path),
                    directory: source.clone(),
                    reason: "partial directory publication requires host reconciliation".into(),
                });
            }
        }
        self.state = if !report.recovery_required.is_empty() {
            SnapshotState::RecoveryRequired
        } else if report.conflicts.is_empty() {
            SnapshotState::Published
        } else {
            SnapshotState::Sealed
        };
        Ok(report)
    }

    /// Discards only the private execution state. Published host effects and
    /// same-volume recovery material remain owned by the host.
    pub fn rollback(mut self) -> Result<()> {
        if self.private.active.load(Ordering::Acquire) != 0 {
            bail!("cannot discard an active snapshot");
        }
        self.state = SnapshotState::RolledBack;
        Ok(())
    }
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn roots_overlap(a: &Dir, b: &Dir) -> Result<bool> {
    Ok(overlaps(&a.path, &b.path)
        || a.lineage()?.contains(&b.identity()?)
        || b.lineage()?.contains(&a.identity()?))
}
fn unique(prefix: &str) -> String {
    format!(
        ".korei-{prefix}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn inventory(root: &Dir, budget: SnapshotBudget) -> Result<BTreeMap<PathBuf, Entry>> {
    fn visit(
        dir: &Dir,
        prefix: &Path,
        map: &mut BTreeMap<PathBuf, Entry>,
        budget: SnapshotBudget,
        bytes: &mut u64,
    ) -> Result<()> {
        for name in dir.names()? {
            let path = prefix.join(&name);
            if path.components().count() > budget.max_depth
                || map.len() as u64 >= budget.max_entries
            {
                bail!("snapshot entry/depth budget exceeded");
            }
            let directory = dir.is_dir(Path::new(&name))?;
            let (identity, mode) = if directory {
                let child = dir.child(Path::new(&name))?;
                let identity = child.identity()?;
                let mode = mode(&child.metadata()?);
                map.insert(
                    path.clone(),
                    Entry {
                        directory,
                        identity,
                        mode,
                    },
                );
                visit(&child, &path, map, budget, bytes)?;
                continue;
            } else {
                let file = dir.read(Path::new(&name))?;
                let metadata = file.metadata()?;
                *bytes = bytes
                    .checked_add(metadata.len())
                    .context("snapshot byte count overflow")?;
                if *bytes > budget.max_bytes {
                    bail!("snapshot byte budget exceeded");
                }
                (file_identity(&file)?, mode(&metadata))
            };
            map.insert(
                path,
                Entry {
                    directory,
                    identity,
                    mode,
                },
            );
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, Path::new(""), &mut entries, budget, &mut 0)?;
    if entries
        .values()
        .any(|entry| entry.identity.0 != root.identity().map(|id| id.0).unwrap_or(u64::MAX))
    {
        bail!("cross-device source trees are forbidden");
    }
    Ok(entries)
}

fn copy_tree(
    source: &Dir,
    target: &Dir,
    entries: &BTreeMap<PathBuf, Entry>,
    budget: SnapshotBudget,
    preference: SnapshotPreference,
    stats: &mut SnapshotStats,
) -> Result<()> {
    for (path, entry) in entries {
        stats.prepared_entries = stats
            .prepared_entries
            .checked_add(1)
            .context("entry overflow")?;
        if stats.prepared_entries > budget.max_entries {
            bail!("snapshot preparation entry budget exceeded");
        }
        if entry.directory {
            target.mkdir(path)?;
            continue;
        }
        let input = source.read(path)?;
        let before = input.metadata()?;
        if file_identity(&input)? != entry.identity {
            bail!("source file identity changed");
        }
        stats.prepared_bytes = stats
            .prepared_bytes
            .checked_add(before.len())
            .context("byte overflow")?;
        if stats.prepared_bytes > budget.max_bytes {
            bail!("snapshot preparation byte budget exceeded");
        }
        let (output, native) = clone_into(
            &input,
            target,
            path,
            preference == SnapshotPreference::NativePreferred,
        )?;
        set_mode(&output, entry.mode)?;
        output.sync_all()?;
        if !files_equal(&input, &output)? || before.len() != input.metadata()?.len() {
            bail!("source changed during copy");
        }
        if native {
            stats.native_cow_files += 1;
        } else {
            stats.private_copy_files += 1;
        }
    }
    for (path, entry) in entries.iter().rev() {
        if entry.directory {
            target
                .child(path)?
                .set_permissions(source.child(path)?.metadata()?.permissions())?;
        }
    }
    target.sync()?;
    Ok(())
}

fn tree_equal(
    source: &Dir,
    baseline: &Dir,
    original: &BTreeMap<PathBuf, Entry>,
    budget: SnapshotBudget,
) -> Result<bool> {
    let current = inventory(source, budget)?;
    if &current != original {
        return Ok(false);
    }
    for (path, entry) in original {
        if !entry.directory && !files_equal(&source.read(path)?, &baseline.read(path)?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn files_equal(a: &File, b: &File) -> Result<bool> {
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let mut a = a.try_clone()?;
    let mut b = b.try_clone()?;
    a.seek(SeekFrom::Start(0))?;
    b.seek(SeekFrom::Start(0))?;
    let mut x = [0; 65536];
    let mut y = [0; 65536];
    loop {
        let nx = a.read(&mut x)?;
        let ny = b.read(&mut y)?;
        if nx != ny || x[..nx] != y[..ny] {
            return Ok(false);
        }
        if nx == 0 {
            return Ok(true);
        }
    }
}

fn preflight(root: &Root, change: &SnapshotChange) -> Result<()> {
    let current_root = Dir::open(&root.source.path)?;
    if current_root.identity()? != root.identity
        || mode(&current_root.metadata()?) != root.root_mode
    {
        bail!("source root identity or permissions changed");
    }
    let mut parent = change.path.parent();
    while let Some(path) = parent.filter(|p| !p.as_os_str().is_empty()) {
        if let Some(entry) = root.original.get(path) {
            let current = root.source.child(path)?;
            if current.identity()? != entry.identity || mode(&current.metadata()?) != entry.mode {
                bail!("source parent identity or permissions changed");
            }
        }
        parent = path.parent();
    }
    match root.original.get(&change.path) {
        Some(entry) => {
            if root.source.is_dir(&change.path)? != entry.directory {
                bail!("target type changed");
            }
            if entry.directory {
                let directory = root.source.child(&change.path)?;
                if directory.identity()? != entry.identity
                    || mode(&directory.metadata()?) != entry.mode
                {
                    bail!("target directory identity or permissions changed");
                }
            } else {
                let file = root.source.read(&change.path)?;
                if file_identity(&file)? != entry.identity
                    || mode(&file.metadata()?) != entry.mode
                    || !files_equal(&file, &root.baseline.read(&change.path)?)?
                {
                    bail!("target content, permissions or identity changed");
                }
            }
        }
        None => match root.source.is_dir(&change.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => bail!("new target already exists or is unsafe"),
        },
    }
    Ok(())
}

fn publish_one(
    root: &Root,
    change: &SnapshotChange,
    report: &mut PublishReport,
    created: &BTreeMap<(RootId, PathBuf), Entry>,
) -> Result<()> {
    preflight(root, change)?;
    let (parent, name) = checked_parent(root, change, created)?;
    if change.kind == ChangeKind::CreateDirectory {
        parent.mkdir(Path::new(&name))?;
        report.applied.push(change.clone());
        parent.sync()?;
        return Ok(());
    }
    if change.kind == ChangeKind::DeleteDirectory {
        // rmdir refuses to discard concurrent additions.
        parent.unlink(Path::new(&name), true)?;
        report.applied.push(change.clone());
        return Ok(());
    }
    let recovery = parent.mkdir(Path::new(&unique("publish")))?;
    report.recovery_material.push(recovery.path.clone());
    if change.kind == ChangeKind::ModifyDirectory {
        let original = recovery.mkdir(Path::new("original"))?;
        original.set_permissions(root.baseline.child(&change.path)?.metadata()?.permissions())?;
        original.sync()?;
        recovery.sync()?;
        parent.sync()?;
        preflight(root, change)?;
        let directory = parent.child(Path::new(&name))?;
        directory.set_permissions(root.working.child(&change.path)?.metadata()?.permissions())?;
        report.applied.push(change.clone());
        directory.sync()?;
        return Ok(());
    }
    let stage = Path::new("replacement");
    if change.kind != ChangeKind::DeleteFile {
        let input = root.working.read(&change.path)?;
        let (output, _) = clone_into(&input, &recovery, stage, true)?;
        set_mode(&output, mode(&input.metadata()?))?;
        output.sync_all()?;
        recovery.sync()?;
    }
    if change.kind != ChangeKind::CreateFile {
        // NOREPLACE prevents overwriting an existing recovery object.
        // Moving the original is the first destructive publish operation.
        preflight(root, change)?;
        report.recovery_required.push(RecoveryRecord {
            root: change.root,
            target: root.source.path.join(&change.path),
            directory: recovery.path.clone(),
            reason: "publish interrupted after preparing recovery material".into(),
        });
        parent.rename_new(Path::new(&name), &recovery, Path::new("original"))?;
        recovery.sync()?;
        parent.sync()?;
        let displaced = recovery.read(Path::new("original"))?;
        let original = &root.original[&change.path];
        if file_identity(&displaced)? != original.identity
            || mode(&displaced.metadata()?) != original.mode
            || !files_equal(&displaced, &root.baseline.read(&change.path)?)?
        {
            let reason = "target changed during publish; displaced data retained";
            if recovery
                .rename_new(Path::new("original"), &parent, Path::new(&name))
                .is_ok()
            {
                recovery.sync()?;
                parent.sync()?;
                report.recovery_required.pop();
            }
            bail!("{reason}");
        }
    }
    if change.kind == ChangeKind::CreateFile {
        report.recovery_required.push(RecoveryRecord {
            root: change.root,
            target: root.source.path.join(&change.path),
            directory: recovery.path.clone(),
            reason: "publish interrupted while installing a new file".into(),
        });
    }
    if change.kind != ChangeKind::DeleteFile {
        if let Err(error) = recovery.rename_new(stage, &parent, Path::new(&name)) {
            // Restore only into a vacant name; never overwrite a user change.
            if change.kind == ChangeKind::ModifyFile
                && recovery
                    .rename_new(Path::new("original"), &parent, Path::new(&name))
                    .is_ok()
            {
                recovery.sync()?;
                parent.sync()?;
                report.recovery_required.pop();
            }
            return Err(error.into());
        }
    }
    recovery.sync()?;
    parent.sync()?;
    report.recovery_required.pop();
    report.applied.push(change.clone());
    Ok(())
}

fn checked_parent(
    root: &Root,
    change: &SnapshotChange,
    created: &BTreeMap<(RootId, PathBuf), Entry>,
) -> Result<(Dir, std::ffi::OsString)> {
    let mut dir = Dir::open(&root.source.path)?;
    if dir.identity()? != root.identity || mode(&dir.metadata()?) != root.root_mode {
        bail!("source root identity or permissions changed");
    }
    let mut prefix = PathBuf::new();
    let mut components = change.path.components().peekable();
    while let Some(component) = components.next() {
        let name = component.as_os_str();
        if components.peek().is_none() {
            return Ok((dir, name.to_owned()));
        }
        prefix.push(name);
        dir = dir.child(Path::new(name))?;
        let expected = root
            .original
            .get(&prefix)
            .or_else(|| created.get(&(change.root, prefix.clone())))
            .context("unrecognized publish parent")?;
        if dir.identity()? != expected.identity || mode(&dir.metadata()?) != expected.mode {
            bail!("publish parent identity or permissions changed");
        }
    }
    bail!("empty publish path")
}

fn remove_contents(dir: &Dir) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    for name in dir.names()? {
        let path = Path::new(&name);
        if let Ok(child) = dir.child(path) {
            remove_contents(&child)?;
            drop(child);
            dir.unlink(path, true)?;
        } else {
            dir.unlink(path, false)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod ignore_config_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn host_config_link_resolution_uses_physical_parent_components() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        let storage = base.join("storage");
        let host = base.join("host");
        let actual = base.join("actual");
        for path in [&source, &storage, &host, &actual] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(actual.join("child")).unwrap();
        std::fs::write(actual.join("config"), b"physical-parent").unwrap();
        std::fs::write(host.join("config"), b"lexical-parent").unwrap();
        symlink(actual.join("child"), host.join("dir")).unwrap();
        symlink("dir/../config", host.join("link")).unwrap();
        let snapshot = WorkspaceSnapshot::prepare(
            &[source],
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
        assert_eq!(
            lease
                .read_ignore_config(&host.join("link"), |_| Ok(None))
                .unwrap()
                .unwrap(),
            b"physical-parent"
        );
        symlink("cycle", host.join("cycle")).unwrap();
        assert!(lease
            .read_ignore_config(&host.join("cycle"), |_| Ok(None))
            .is_err());
        assert!(lease
            .read_ignore_config(&host.join("missing/config"), |_| Ok(None))
            .unwrap()
            .is_none());
    }

    #[test]
    fn host_config_link_resolution_rejects_replacement_after_probe() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        std::fs::write(base.join("config"), b"first").unwrap();
        std::fs::write(base.join("outside"), b"second").unwrap();
        let directory = Dir::open(&base).unwrap();
        assert!(directory
            .symlink_target(Path::new("config"))
            .unwrap()
            .is_none());
        std::fs::rename(base.join("config"), base.join("saved")).unwrap();
        symlink("outside", base.join("config")).unwrap();
        assert!(directory.read(Path::new("config")).is_err());
        std::fs::create_dir(base.join("child")).unwrap();
        assert!(directory
            .symlink_target(Path::new("child"))
            .unwrap()
            .is_none());
        std::fs::rename(base.join("child"), base.join("saved-child")).unwrap();
        symlink(&base, base.join("child")).unwrap();
        assert!(directory.child(Path::new("child")).is_err());
    }
}

#[cfg(unix)]
fn file_identity(f: &File) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = f.metadata()?;
    Ok((m.dev(), m.ino()))
}
#[cfg(unix)]
fn mode(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}
#[cfg(unix)]
fn set_mode(f: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(unix)]
fn check_private(dir: &Dir) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = dir.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        bail!("snapshot storage must be owned by this user with mode 0700");
    }
    Ok(())
}

#[cfg(windows)]
fn file_identity(f: &File) -> Result<(u64, u64)> {
    Ok(crate::snapshot_fs::file_identity(f)?)
}
#[cfg(windows)]
fn mode(m: &std::fs::Metadata) -> u32 {
    if m.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}
#[cfg(windows)]
fn set_mode(f: &File, mode: u32) -> Result<()> {
    let mut permissions = f.metadata()?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    f.set_permissions(permissions)?;
    Ok(())
}
#[cfg(windows)]
fn check_private(dir: &Dir) -> Result<()> {
    crate::snapshot_fs::check_private(dir).map_err(Into::into)
}
