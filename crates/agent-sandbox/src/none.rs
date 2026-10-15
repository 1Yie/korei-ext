//! `none.rs` — the loud fallback when no sandbox backend is available.
//!
//! Contract (sandbox-model.md §Fallback chain): running on `none` is allowed
//! but loud — `id() == "none"` drives the persistent `UNSANDBOXED` UI chip,
//! and every `bash` call must confirm regardless of permission mode (the
//! kernel enforces that in `permissions.rs`; this backend just runs the
//! command on the raw host with env sanitization + timeout + tree-kill).

use std::time::Instant;

use anyhow::{Context, Result};

use crate::env_sanitize::sanitize_env;
use crate::traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};

pub struct NoneBackend;

#[async_trait::async_trait]
impl SandboxBackend for NoneBackend {
    fn id(&self) -> &'static str {
        "none"
    }

    fn tier(&self) -> SandboxTier {
        SandboxTier::L2
    }

    async fn run_command(
        &self,
        cmd: &str,
        _args: &[&str],
        cfg: &SandboxConfig,
    ) -> Result<CommandOutput> {
        let started = Instant::now();
        let timeout = std::time::Duration::from_secs(cfg.timeout_secs.min(600));

        // Even on `none`, env sanitization applies — containment may fail but
        // leakage never gets a pass. PATH pruning keeps every absolute entry
        // except ones under the workspace: an agent can plant binaries there,
        // and on this backend they'd execute unsandboxed.
        let mut envs = sanitize_env(&cfg.env_vars);
        let denied = vec![cfg.workspace_dir.clone()];
        crate::env_sanitize::apply_environment_policy(&mut envs, &cfg.environment, None, &denied);

        // Windows has no `sh` and no process groups — `cmd /C` plus
        // `kill_on_drop` (real tree-kill needs a job object; that lands with
        // the dedicated Windows backend). Unix keeps sh + group-kill.
        #[cfg(unix)]
        let (shell, shell_flag) = ("sh", "-c");
        #[cfg(windows)]
        let (shell, shell_flag) = ("cmd", "/C");

        let mut command = tokio::process::Command::new(shell);
        command
            .arg(shell_flag)
            .arg(cmd)
            .current_dir(&cfg.workspace_dir)
            .env_clear()
            .envs(envs)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0); // own process group → group-kill on timeout

        // Linux: PR_SET_PDEATHSIG — the child gets SIGKILL the instant the
        // parent dies, so a GUI crash can't orphan a `sleep 600`.
        #[cfg(target_os = "linux")]
        unsafe {
            command.pre_exec(|| {
                // prctl(PR_SET_PDEATHSIG, SIGKILL) — raw syscall via libc,
                // zero deps (libc is already in the graph via tokio).
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = command.spawn().context("spawn sh")?;
        let child_id = child.id();
        // `wait_with_output` collects piped stdout/stderr atomically.
        let status = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let elapsed = started.elapsed().as_millis() as u64;

        let (out, err, code, is_timeout) = match status {
            Ok(Ok(o)) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.code().unwrap_or(-1),
                false,
            ),
            Ok(Err(e)) => (String::new(), e.to_string(), -1, false),
            Err(_) => {
                // Timeout — kill the whole process group (the child is its
                // own group leader via process_group(0)).
                if let Some(id) = child_id {
                    libc_kill_group(id);
                }
                (
                    String::new(),
                    "[timeout — process tree killed]".to_string(),
                    -1,
                    true,
                )
            }
        };

        Ok(CommandOutput {
            status: code,
            stdout: out,
            stderr: err,
            is_timeout,
            sandbox_denials: Vec::new(),
            peak_memory_mb: None,
            elapsed_ms: elapsed,
        })
    }

    /// Persistent spawn — same loud-unsandboxed contract as `run_command`
    /// but caller-owned: no `kill_on_drop`. PDEATHSIG still applies so the
    /// service dies with the agent process.
    fn wrap_spawn(
        &self,
        cfg: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Option<tokio::process::Command> {
        let mut envs = sanitize_env(&cfg.env_vars);
        let denied = vec![cfg.workspace_dir.clone()];
        crate::env_sanitize::apply_environment_policy(&mut envs, &cfg.environment, None, &denied);
        let mut command = tokio::process::Command::new(cmd);
        command
            .args(args)
            .current_dir(&cfg.workspace_dir)
            .env_clear()
            .envs(envs);
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(target_os = "linux")]
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Some(command)
    }
}

/// `kill(-pgid, SIGKILL)` via `/proc` — no libc dep. Fails silently on
/// non-Linux (the backend is best-effort there).
#[cfg(target_family = "unix")]
fn libc_kill_group(pgid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-9", &format!("-{pgid}")])
        .status();
}

#[cfg(not(target_family = "unix"))]
fn libc_kill_group(_pgid: u32) {}

/// `kill(-pgid, SIGKILL)` — `process_group(0)` made the child a group leader,
/// so the negative pid reaps the whole tree on timeout.
#[cfg(target_family = "unix")]
fn _assert_process_group_is_used() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{SandboxBackend, SandboxConfig};

    fn cfg(dir: &std::path::Path, secs: u64) -> SandboxConfig {
        SandboxConfig {
            workspace_dir: dir.to_path_buf(),
            timeout_secs: secs,
            ..Default::default()
        }
    }

    /// The timeout must kill the whole PROCESS GROUP, not just drop the
    /// future: `smart_test_runner`/`bash` rely on this to avoid leaving an
    /// orphaned `cargo test` behind. The child here backgrounds a grandchild
    /// so a shallow kill would leave it running.
    #[tokio::test]
    async fn timeout_kills_the_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("grandchild-alive");
        // Background grandchild writes its marker only if it gets to run; the
        // foreground sleep keeps the group alive past the timeout.
        let cmd = format!("sh -c 'sleep 2; touch {}' & sleep 300", marker.display());
        let out = NoneBackend
            .run_command(&cmd, &[], &cfg(dir.path(), 1))
            .await
            .unwrap();
        assert!(out.is_timeout, "expected the wall timeout to fire");
        assert_eq!(out.status, -1);

        // Well past the grandchild's own 2 s sleep: if the group survived the
        // timeout it would have created the marker by now.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert!(
            !marker.exists(),
            "grandchild survived the timeout — the group was not killed"
        );
    }

    /// A command that finishes inside the budget reports success, not a
    /// timeout — the kill path must not fire early.
    #[tokio::test]
    async fn fast_command_is_not_a_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let out = NoneBackend
            .run_command("echo ready", &[], &cfg(dir.path(), 30))
            .await
            .unwrap();
        assert!(!out.is_timeout);
        assert_eq!(out.status, 0);
        assert!(out.stdout.contains("ready"));
    }
}
