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

use agent_capabilities::{WorkspaceCtx, WorkspaceWrite};
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
pub struct FileWrite<C> {
    pub target: WorkspaceWrite<C>,
    /// The full new content (ignored for `Delete`).
    pub content: Vec<u8>,
    pub op: WriteOp,
    /// Create parent directories first (`*** Add File` to a nested path).
    pub auto_mkdir: bool,
}

impl<C: WorkspaceCtx> FileWrite<C> {
    /// The common overwrite case.
    pub fn write(target: WorkspaceWrite<C>, content: Vec<u8>) -> Self {
        Self {
            target,
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
pub fn commit_writes<C: WorkspaceCtx>(
    writes: Vec<FileWrite<C>>,
    observer: Option<Arc<dyn WriteObserver>>,
) -> Option<Commit> {
    if writes.is_empty() {
        return None;
    }
    let writes = Arc::new(writes);
    let checking = writes.clone();
    let verify = move || verify_writes(&checking);
    let apply = async move {
        tokio::task::spawn_blocking(move || {
            verify_writes(&writes)?;
            for w in writes.iter() {
                let content = match w.op {
                    WriteOp::Write => Some(w.content.as_slice()),
                    WriteOp::Delete => None,
                };
                w.target
                    .apply(content, w.auto_mkdir)
                    .map_err(|e| format!("write failed for {}: {e}", w.target.path().display()))?;
                if let Some(observer) = &observer {
                    observer.on_write(
                        w.target.path().to_path_buf(),
                        w.target.before().map(<[u8]>::to_vec),
                        content.map_or_else(Vec::new, <[u8]>::to_vec),
                    );
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| format!("file commit task: {e}"))?
    };
    Some(Commit::new(apply).verified(verify))
}

fn verify_writes<C: WorkspaceCtx>(writes: &[FileWrite<C>]) -> Result<(), String> {
    for write in writes {
        write.target.verify().map_err(|e| format!(
            "{} changed after the preview was generated; nothing was written — re-read the file and retry: {e}",
            write.target.path().display()
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
    fn target(path: &std::path::Path) -> WorkspaceWrite<Ctx> {
        let mut root = path.parent().unwrap();
        while !root.exists() {
            root = root.parent().unwrap();
        }
        Arc::new(Ctx::default().with_workspace(root))
            .workspace_io()
            .unwrap()
            .stage_write(path)
            .unwrap()
    }

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
        let root = dir.path().canonicalize().unwrap();
        let a = root.join("a.txt");
        let b = root.join("sub/b.txt");
        std::fs::write(&a, "old").unwrap();
        let seen = Arc::new(Seen::default());
        let obs: Arc<dyn WriteObserver> = seen.clone();
        let commit = commit_writes(
            vec![
                FileWrite::write(target(&a), b"new".to_vec()),
                FileWrite {
                    target: target(&b),
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
        let root = dir.path().canonicalize().unwrap();
        let a = root.join("a.txt");
        let b = root.join("b.txt");
        std::fs::write(&a, "a0").unwrap();
        std::fs::write(&b, "b0").unwrap();
        let commit = commit_writes(
            vec![
                FileWrite::write(target(&a), b"a1".to_vec()),
                FileWrite::write(target(&b), b"b1".to_vec()),
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
        let a = dir.path().canonicalize().unwrap().join("a.txt");
        std::fs::write(&a, "gone").unwrap();
        let seen = Arc::new(Seen::default());
        let obs: Arc<dyn WriteObserver> = seen.clone();
        let commit = commit_writes(
            vec![FileWrite {
                target: target(&a),
                content: b"ignored for delete".to_vec(),
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
        assert!(commit_writes::<Ctx>(Vec::new(), None).is_none());
    }
}
