//! Detached application launch, shared by every backend.
//!
//! The program is exec'd **directly** from a [`LaunchSpec`] — there is no
//! shell to parse metacharacters, newlines or quoting (see
//! [`crate::traits::parse_launch`]). The host environment is left intact: a
//! GUI needs `$DISPLAY`/`$XAUTHORITY` and friends to reach the session.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::traits::LaunchSpec;

/// How long to watch a fresh process for an immediate failure (bad flag,
/// missing library) before treating it as running and detaching.
const EARLY_EXIT_WINDOW: Duration = Duration::from_millis(600);

/// `PATH` lookup — no `which` subprocess, no shell. A program containing a
/// path separator is checked as given. Only macOS needs it (to tell a CLI
/// tool from an application name), hence the `dead_code` allowance elsewhere.
#[cfg_attr(
    not(any(target_os = "macos", feature = "check-macos", test)),
    allow(dead_code)
)]
pub(crate) fn program_exists(program: &str) -> bool {
    let is_file = |p: &std::path::Path| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    };
    if program.contains(['/', '\\']) {
        return is_file(std::path::Path::new(program));
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_file(&dir.join(program)))
}

/// Start `spec` detached from the agent: it outlives the tool call and gets
/// no stdio. A process that dies inside [`EARLY_EXIT_WINDOW`] with a failure
/// status is reported; one still running is left alone and reaped in the
/// background so it never lingers as a zombie.
pub(crate) async fn spawn_detached(spec: &LaunchSpec) -> Result<()> {
    let mut c = tokio::process::Command::new(&spec.program);
    c.args(&spec.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // The child outlives the tool call — dropping the handle must not kill it.
        .kill_on_drop(false);
    // Own process group: a SIGHUP/SIGINT aimed at the agent's group does not
    // take the application with it.
    #[cfg(unix)]
    c.process_group(0);
    // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    #[cfg(windows)]
    c.creation_flags(0x0000_0008 | 0x0000_0200);

    let mut child = c
        .spawn()
        .with_context(|| format!("launch `{}`", spec.program))?;
    match tokio::time::timeout(EARLY_EXIT_WINDOW, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => bail!("`{}` exited immediately with {status}", spec.program),
        Ok(Err(e)) => Err(e).with_context(|| format!("wait for `{}`", spec.program)),
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::traits::parse_launch;

    #[tokio::test]
    async fn runs_the_program_directly_with_literal_args() {
        let dir = tempfile::tempdir().unwrap();
        // `touch` receives the path verbatim — spaces and `;` are data, not syntax.
        let name = format!("{}/a b;c.txt", dir.path().display());
        let spec = parse_launch(&format!("touch '{name}'")).unwrap();
        spawn_detached(&spec).await.unwrap();
        assert!(std::path::Path::new(&name).exists());
    }

    #[tokio::test]
    async fn a_missing_program_is_a_readable_error() {
        let spec = parse_launch("definitely-not-installed-xyz --flag").unwrap();
        let e = spawn_detached(&spec).await.unwrap_err().to_string();
        assert!(e.contains("definitely-not-installed-xyz"), "{e}");
    }

    #[tokio::test]
    async fn an_immediate_failure_is_reported() {
        let spec = parse_launch("false").unwrap();
        let e = spawn_detached(&spec).await.unwrap_err().to_string();
        assert!(e.contains("exited immediately"), "{e}");
    }

    #[tokio::test]
    async fn a_long_running_program_is_left_running() {
        let spec = parse_launch("sleep 5").unwrap();
        let t = std::time::Instant::now();
        spawn_detached(&spec).await.unwrap();
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn program_exists_checks_path_and_explicit_paths() {
        assert!(program_exists("sh"));
        assert!(program_exists("/bin/sh"));
        assert!(!program_exists("definitely-not-installed-xyz"));
        assert!(!program_exists("/nonexistent/dir/prog"));
    }
}
