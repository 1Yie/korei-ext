//! Fixed OS access facts retained by an execution owner.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};

use crate::snapshot_fs::Dir;

#[derive(Debug)]
struct PinnedPath {
    alias: PathBuf,
    path: PathBuf,
    directory: Dir,
    file: Option<File>,
    lineage: Vec<(u64, u64)>,
    special: bool,
}

impl PinnedPath {
    fn open(path: &Path) -> Result<Self> {
        let canonical = path.canonicalize().context("resolve OS grant identity")?;
        let (directory, file) = if canonical.is_dir() {
            (Dir::open(&canonical)?, None)
        } else {
            let directory = Dir::open(canonical.parent().context("grant has no parent")?)?;
            let file = directory.read(Path::new(
                canonical.file_name().context("grant has no filename")?,
            ))?;
            crate::snapshot_fs::regular(&file)?;
            (directory, Some(file))
        };
        let lineage = directory.lineage()?;
        Ok(Self {
            alias: path.to_owned(),
            path: canonical,
            directory,
            file,
            lineage,
            special: false,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.alias.canonicalize()? != self.path
            || self.directory.lineage()? != self.lineage
            || Dir::open(&self.directory.path)?.identity()? != self.directory.identity()?
        {
            bail!("OS grant path identity or lineage changed");
        }
        if let Some(file) = &self.file {
            let current = if self.special {
                File::open(&self.path)?
            } else {
                self.directory.read(Path::new(
                    self.path.file_name().context("grant has no filename")?,
                ))?
            };
            if crate::snapshot::file_identity(&current)? != crate::snapshot::file_identity(file)? {
                bail!("OS grant file identity changed");
            }
        }
        Ok(())
    }

    fn overlaps(&self, candidate: &Dir, recursive: bool) -> Result<bool> {
        self.validate()?;
        Ok(self.lineage.contains(&candidate.identity()?)
            || (recursive
                && self.file.is_none()
                && candidate.lineage()?.contains(&self.directory.identity()?)))
    }
}

#[derive(Debug)]
struct Access {
    source: PinnedPath,
    destination: Option<PathBuf>,
    operation: &'static str,
    recursive: bool,
}

#[derive(Debug, Default)]
struct Facts {
    ready: bool,
    access: Vec<Access>,
    denied: Vec<(PathBuf, &'static str)>,
    #[cfg(windows)]
    copies: Vec<(PathBuf, PathBuf)>,
    #[cfg(target_os = "macos")]
    metadata_read: bool,
    unknown: Option<String>,
}

/// Opaque facts about one actual OS-isolated owner, independent of its endpoint.
/// Only the owner's completed capability release marks this object quiescent.
#[derive(Debug, Default)]
pub struct EffectiveOsGrants {
    quiescent: AtomicBool,
    facts: Mutex<Facts>,
}

impl EffectiveOsGrants {
    pub fn is_quiescent(&self) -> bool {
        self.quiescent.load(Ordering::Acquire)
    }

    /// Conservatively check a fixed candidate pair against this owner's access.
    /// Unknown access or changed identities require owner cleanup before admission.
    pub fn check_root_addition(&self, source: &Path, working: &Path) -> Result<()> {
        if self.is_quiescent() {
            return Ok(());
        }
        let facts = self.facts.lock().unwrap_or_else(|e| e.into_inner());
        if !facts.ready {
            bail!("isolated owner is starting; effective OS grants are not yet known");
        }
        if let Some(reason) = &facts.unknown {
            bail!(
                "isolated owner OS access is unknown: {reason}; stop the owner before adding roots"
            );
        }
        for path in [source, working] {
            let candidate = Dir::open(path).context("pin candidate root without aliases")?;
            for access in &facts.access {
                if access
                    .source
                    .overlaps(&candidate, access.recursive)
                    .with_context(|| format!("cannot verify {} grant identity", access.operation))?
                    || access.destination.as_ref().is_some_and(|destination| {
                        destination.starts_with(path) || path.starts_with(destination)
                    })
                {
                    bail!(
                        "root {} conflicts with active {} grant {}{}; stop the owner before adding this root",
                        path.display(),
                        access.operation,
                        access.source.alias.display(),
                        access.destination.as_ref().map(|p| format!(" -> {}", p.display())).unwrap_or_default(),
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn allow(
        &self,
        source: &Path,
        destination: Option<&Path>,
        operation: &'static str,
    ) -> Result<()> {
        let source = PinnedPath::open(source)?;
        let recursive = source.file.is_none();
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .access
            .push(Access {
                source,
                destination: destination.map(Path::to_owned),
                operation,
                recursive,
            });
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn seatbelt_implicit(&self) -> Result<()> {
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .metadata_read = true;
        for path in ["/", "/dev/urandom", "/dev/random", "/dev/null"] {
            let path = Path::new(path);
            let source = if path.is_dir() {
                PinnedPath::open(path)?
            } else {
                let canonical = path.canonicalize()?;
                let directory = Dir::open(canonical.parent().context("device has no parent")?)?;
                let lineage = directory.lineage()?;
                let file = Some(File::open(&canonical)?);
                PinnedPath {
                    alias: path.to_owned(),
                    path: canonical,
                    directory,
                    file,
                    lineage,
                    special: true,
                }
            };
            // Device literals are fixed system objects, not runtime directory grants.
            source.validate()?;
            self.facts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .access
                .push(Access {
                    source,
                    destination: None,
                    operation: "Seatbelt implicit literal access",
                    recursive: false,
                });
        }
        Ok(())
    }

    pub(crate) fn deny(&self, path: &Path, operation: &'static str) {
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .denied
            .push((path.to_owned(), operation));
    }

    #[cfg(windows)]
    pub(crate) fn copied(&self, source: &Path, destination: &Path) {
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .copies
            .push((source.to_owned(), destination.to_owned()));
    }

    #[cfg(windows)]
    pub(crate) fn unknown(&self, reason: &str) {
        self.facts.lock().unwrap_or_else(|e| e.into_inner()).unknown = Some(reason.into());
    }

    pub(crate) fn ready(&self) {
        self.facts.lock().unwrap_or_else(|e| e.into_inner()).ready = true;
    }

    pub(crate) fn released(&self) {
        self.quiescent.store(true, Ordering::Release);
    }
}
