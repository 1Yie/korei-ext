//! File-write commits — the side effect a patch tool stages and the engine
//! applies only after the permission decision.
//!
//! The kernel knows nothing about files: a staged tool returns an
//! [`agent_tool::Commit`], and this module is where "write these bytes to this
//! path, refuse if the file moved since the preview, tell the host what
//! changed" lives. The host learns about each applied change through
//! [`WriteObserver`], installed on the context's extension slots — that is how
//! undo tracking hears about writes without the engine carrying a tracker.

use std::path::PathBuf;
use std::sync::Arc;

use agent_tool::Commit;

/// What to do with `path` when the commit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOp {
    /// Create or overwrite `path` with the staged content.
    Write,
    /// Remove `path` (`*** Delete File`).
    Delete,
}

/// One staged file effect.
#[derive(Debug, Clone)]
pub struct FileWrite {
    /// Canonical workspace path.
    pub path: PathBuf,
    /// The full new content (ignored for `Delete`).
    pub content: Vec<u8>,
    pub op: WriteOp,
    /// Create parent directories first (`*** Add File` to a nested path).
    pub auto_mkdir: bool,
}

impl FileWrite {
    /// The common overwrite case.
    pub fn write(path: PathBuf, content: Vec<u8>) -> Self {
        Self {
            path,
            content,
            op: WriteOp::Write,
            auto_mkdir: false,
        }
    }
}

/// Install point: a host stores `Arc<dyn WriteObserver>` wrapped in this on
/// the context's extension slots; the file tools read it back.
pub struct WriteObserverSlot(pub Arc<dyn WriteObserver>);

/// Told about every file change a commit actually applied. A host that tracks
/// writes for undo implements this and installs it on the tool context;
/// without one, writes still land, just unobserved.
pub trait WriteObserver: Send + Sync {
    /// `old` is the file's bytes before the write (`None` = it did not exist);
    /// `new` is empty for a delete.
    fn on_write(&self, path: PathBuf, old: Option<Vec<u8>>, new: Vec<u8>);
}

/// Build the [`Commit`] for a set of staged writes.
///
/// All-or-nothing on the pre-image: the preview was computed against each file
/// as it was *then*, so `verify` re-reads every path and abandons the whole
/// commit if any moved while the approval card was open — a multi-file patch
/// is never left half-applied.
pub fn commit_writes(
    writes: Vec<FileWrite>,
    observer: Option<Arc<dyn WriteObserver>>,
) -> Option<Commit> {
    if writes.is_empty() {
        return None;
    }
    let pre: Vec<Option<Vec<u8>>> = writes.iter().map(|w| std::fs::read(&w.path).ok()).collect();
    let paths: Vec<PathBuf> = writes.iter().map(|w| w.path.clone()).collect();
    let verify = move || {
        for (path, expected) in paths.iter().zip(pre.iter()) {
            if *expected != std::fs::read(path).ok() {
                return Err(format!(
                    "{} changed after the preview was generated; \
                     nothing was written — re-read the file and retry",
                    path.display()
                ));
            }
        }
        Ok(())
    };
    let apply = async move {
        for w in writes {
            let old = std::fs::read(&w.path).ok();
            match w.op {
                WriteOp::Delete => {
                    tokio::fs::remove_file(&w.path)
                        .await
                        .map_err(|e| format!("delete failed for {}: {e}", w.path.display()))?;
                    if let Some(o) = &observer {
                        o.on_write(w.path, old, Vec::new());
                    }
                }
                WriteOp::Write => {
                    if w.auto_mkdir {
                        if let Some(parent) = w.path.parent() {
                            let _ = tokio::fs::create_dir_all(parent).await;
                        }
                    }
                    tokio::fs::write(&w.path, &w.content)
                        .await
                        .map_err(|e| format!("write failed for {}: {e}", w.path.display()))?;
                    if let Some(o) = &observer {
                        o.on_write(w.path, old, w.content);
                    }
                }
            }
        }
        Ok(())
    };
    Some(Commit::new(apply).verified(verify))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Seen(Mutex<Vec<(PathBuf, Option<Vec<u8>>, Vec<u8>)>>);
    impl WriteObserver for Seen {
        fn on_write(&self, path: PathBuf, old: Option<Vec<u8>>, new: Vec<u8>) {
            self.0.lock().unwrap().push((path, old, new));
        }
    }

    /// Applying writes the files and tells the observer each pre-image / new
    /// content — that is the whole undo contract.
    #[tokio::test]
    async fn apply_writes_and_reports_each_change() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("sub/b.txt");
        std::fs::write(&a, "old").unwrap();
        let seen = Arc::new(Seen::default());
        let obs: Arc<dyn WriteObserver> = seen.clone();
        let commit = commit_writes(
            vec![
                FileWrite::write(a.clone(), b"new".to_vec()),
                FileWrite {
                    path: b.clone(),
                    content: b"fresh".to_vec(),
                    op: WriteOp::Write,
                    auto_mkdir: true,
                },
            ],
            Some(obs),
        )
        .unwrap();
        (commit.verify)().unwrap();
        commit.apply.await.unwrap();
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "fresh");
        let got = seen.0.lock().unwrap();
        assert_eq!(got[0], (a, Some(b"old".to_vec()), b"new".to_vec()));
        assert_eq!(got[1], (b, None, b"fresh".to_vec()));
    }

    /// K1: the preview was computed against the files as they were. If one moved
    /// while the approval card was open, the WHOLE commit is refused and nothing
    /// is written — a multi-file patch is never left half-applied.
    #[tokio::test]
    async fn verify_refuses_when_a_file_moved_after_the_preview() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "a0").unwrap();
        std::fs::write(&b, "b0").unwrap();
        let commit = commit_writes(
            vec![
                FileWrite::write(a.clone(), b"a1".to_vec()),
                FileWrite::write(b.clone(), b"b1".to_vec()),
            ],
            None,
        )
        .unwrap();
        // The user edits b while the card is open.
        std::fs::write(&b, "user edit").unwrap();
        let err = (commit.verify)().unwrap_err();
        assert!(
            err.contains("b.txt") && err.contains("nothing was written"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&a).unwrap(),
            "a0",
            "a must stay untouched"
        );
    }

    #[tokio::test]
    async fn delete_removes_the_file_and_reports_an_empty_new() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, "gone").unwrap();
        let seen = Arc::new(Seen::default());
        let obs: Arc<dyn WriteObserver> = seen.clone();
        let commit = commit_writes(
            vec![FileWrite {
                path: a.clone(),
                content: Vec::new(),
                op: WriteOp::Delete,
                auto_mkdir: false,
            }],
            Some(obs),
        )
        .unwrap();
        commit.apply.await.unwrap();
        assert!(!a.exists());
        assert_eq!(
            seen.0.lock().unwrap()[0],
            (a, Some(b"gone".to_vec()), Vec::new())
        );
    }

    #[test]
    fn no_writes_means_no_commit() {
        assert!(commit_writes(Vec::new(), None).is_none());
    }
}
