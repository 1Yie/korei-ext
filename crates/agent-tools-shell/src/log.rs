//! Shared tail reader and writer for background process logs.
//!
//! Both `service` and `bg_run` append stdout+stderr to a file; the tail read
//! is the same operation, and a non-UTF-8 byte must not turn a log read into
//! a tool error.
//!
//! Writes are guarded: job output routinely carries tokens, URLs and source
//! code, so the directory is private to this process (0700, a name no other
//! local user can guess) and every log file is created 0600 without following
//! a symlink planted at its path.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use agent_tool::ToolError;

/// Cap on one tail read — a job can write unbounded output.
pub(crate) const MAX_LOG_BYTES: u64 = 256 * 1024;
pub(crate) const DEFAULT_TAIL_LINES: usize = 80;

/// One private directory per process per log kind, created on first use.
static DIRS: LazyLock<Mutex<BTreeMap<String, PathBuf>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Per-process directory for one kind of log (`agent-svc`, `agent-bg`).
///
/// The name mixes the pid with the clock so a different local user cannot
/// predict it and plant a file or a symlink inside — the pid alone is public.
pub(crate) fn log_dir(prefix: &str) -> Result<PathBuf, ToolError> {
    let mut dirs = DIRS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(dir) = dirs.get(prefix) {
        return Ok(dir.clone());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos:032x}",
        std::process::id()
    ));
    make_private_dir(&dir)?;
    dirs.insert(prefix.to_string(), dir.clone());
    Ok(dir)
}

#[cfg(unix)]
fn make_private_dir(dir: &Path) -> Result<(), ToolError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| ToolError::Failed(format!("log dir {}: {e}", dir.display())))?;
    // A pre-existing directory keeps its own mode; force ours.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| ToolError::Failed(format!("log dir {}: {e}", dir.display())))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_private_dir(dir: &Path) -> Result<(), ToolError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ToolError::Failed(format!("log dir {}: {e}", dir.display())))
}

/// Create `dir/<name>.log` private to this user, refusing a symlink.
pub(crate) fn create_log(dir: &Path, name: &str) -> Result<(std::fs::File, PathBuf), ToolError> {
    let path = dir.join(format!("{name}.log"));
    let file = open_private(&path)
        .map_err(|e| ToolError::Failed(format!("log file {}: {e}", path.display())))?;
    Ok((file, path))
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW: a symlink at the path is an attack, not a log.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Last `lines` of `path`, reading at most [`MAX_LOG_BYTES`] from the tail.
pub(crate) fn read_tail(path: &Path, lines: usize) -> Result<String, ToolError> {
    let mut f = std::fs::File::open(path)
        .map_err(|e| ToolError::Failed(format!("log {}: {e}", path.display())))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let off = len.saturating_sub(MAX_LOG_BYTES);
    f.seek(SeekFrom::Start(off)).ok();
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| ToolError::Failed(format!("log {}: {e}", path.display())))?;
    let mut buf = String::from_utf8_lossy(&bytes).into_owned();
    // If we cut mid-line, drop the partial first line.
    if off > 0 {
        if let Some(nl) = buf.find('\n') {
            buf.drain(..=nl);
        }
    }
    let tail: Vec<&str> = buf.lines().collect();
    let start = tail.len().saturating_sub(lines);
    Ok(tail[start..].join("\n"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_log_dir_is_private_and_unpredictable() {
        let dir = log_dir("agent-test-private").unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
        assert!(
            !dir.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(&std::process::id().to_string()),
            "the pid alone must not be the name: {}",
            dir.display()
        );
        // Cached: a second call is the same directory.
        assert_eq!(dir, log_dir("agent-test-private").unwrap());
    }

    #[test]
    fn a_log_file_is_private_and_never_follows_a_symlink() {
        let dir = log_dir("agent-test-open").unwrap();
        let (_f, path) = create_log(&dir, "a").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", path.display());

        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = dir.join("b.log");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(
            create_log(&dir, "b").is_err(),
            "opening through a symlink must fail"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }
}
