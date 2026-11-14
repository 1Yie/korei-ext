//! `mac_sandbox_exec.rs` — macOS Seatbelt backend via `sandbox-exec`.
//!
//! The srt-derived model, expressed in SBPL (Seatbelt's last match wins,
//! so order IS the semantics):
//! 1. `(deny default)` — nothing allowed unless a rule says so.
//! 2. Read the whole host — `(allow file-read* (subpath "/"))` — every
//!    toolchain/SDK/dotfile is visible, same flip as bwrap's `--ro-bind / /`.
//! 3. Writable: workspace + scratch tmp + writable cache dirs + cfg's
//!    extra_rw_mounts — package installs land in their real caches.
//! 4. `deny_write` paths — appended after the allows: `.git/hooks`,
//!    rc files, agent config stay read-only inside writable roots.
//! 5. `deny_read` — built-in `SENSITIVE_NAMES` + cfg additions mask
//!    secrets that sit inside the read-everything plane.
//! 6. `allow_read` — carve-outs AFTER the denies re-open a subtree.
//! 7. Network — three modes like Linux:
//!    `allow_network` → open network;
//!    `allowed_domains` empty → no network rules (deny default kills it);
//!    `allowed_domains` set → `(remote tcp "127.0.0.1:PORT")` restricted
//!    to the host proxy's loopback port. macOS has no netns and no
//!    unix-socket bridging needed — the child dials the proxy's TCP mux
//!    directly, domain enforcement happens host-side.
//!
//! Honest gaps vs Linux bwrap:
//!  - no mount pins: `mv .git aside` isn't blocked (deny file-write*
//!    covers the *contents*; the rename is a write on the parent). The
//!    mandatory deny set still protects hooks/config/modules.
//!  - no pid namespace — timeout kills the process GROUP instead
//!    (process_group(0) + `kill -9 -<pgid>`).
//!  - no GIT_SSH_COMMAND: BSD nc can't carry HTTP-CONNECT proxy auth;
//!    git-over-ssh is unsupported in proxied mode (HTTPS git works).
//!  - DNS inside the sandbox is denied — name resolution happens at the
//!    proxy, host-side.
//!
//! `spawn_leased` does not use that profile. Prepared execution goes through
//! `spawn_isolated`: one process, fork denied, no network or extra read
//! exceptions, and monitored RSS. Unprepared `run_command` and `wrap_spawn`
//! keep the profile above.
//!
//! UNTESTED-on-CI note: this file compiles only on macOS.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

use crate::env_sanitize::sanitize_env;
use crate::shared::{
    cache_mounts, format_denials, net_mode, register_egress, sensitive_masks, NetMode, ProxiedRun,
};
use crate::traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};

pub struct MacSandboxExec;

/// Escape a path for embedding in an SBPL string literal.
fn sb(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// What this run's network looks like.
enum MacNet {
    /// Full shared network (`allow_network: true`).
    Allow,
    /// No network rules — `deny default` makes everything fail.
    Deny,
    /// Loopback-only egress through the host proxy's TCP mux port.
    Proxied(ProxiedRun),
}

fn mac_net_plan(cfg: &SandboxConfig) -> MacNet {
    match net_mode(cfg) {
        NetMode::Open => return MacNet::Allow,
        NetMode::Closed => return MacNet::Deny,
        NetMode::Proxied => {}
    }
    match register_egress(cfg) {
        Some(run) => MacNet::Proxied(run),
        None => {
            tracing::warn!("sandbox: egress proxy unavailable — degrading to full network deny");
            MacNet::Deny
        }
    }
}

/// SBPL profile for this run — workspace, writable roots and the deny
/// overlays baked in as `(subpath)` literals.
fn sbpl(cfg: &SandboxConfig, ws: &Path, net: &MacNet) -> String {
    let mut p = String::from("(version 1)(deny default)");
    // Process machinery — exec/fork/signal within the sandboxed family.
    p.push_str("(allow process-exec process-fork)(allow signal (target same-sandbox))");
    // Mach + sysctl: runtimes (dyld, CF, node/python) look up services and
    // sysctls during startup — denying these breaks almost everything.
    p.push_str("(allow mach-lookup sysctl-read sysctl-write (regex \"^hw\\.\") iokit-open)");

    // --- filesystem: read everything, write only where granted ---
    p.push_str("(allow file-read* file-map-executable (subpath \"/\"))");
    // Pseudo-devices (needed for writes too).
    p.push_str(
        "(allow file-read* file-write* (literal \"/dev/null\") (literal \"/dev/zero\") \
         (literal \"/dev/urandom\") (literal \"/dev/random\") (literal \"/dev/tty\") \
         (regex \"^/dev/ptmx\") (regex \"^/dev/ttys\"))",
    );
    // Writable roots — scratch, workspace, caller mounts, toolchain caches.
    let mut writable: Vec<PathBuf> = vec![
        "/tmp".into(),
        "/private/tmp".into(),
        "/private/var/folders".into(),
        "/var/tmp".into(),
    ];
    writable.push(ws.to_path_buf());
    writable.extend(cfg.extra_rw_mounts.iter().cloned());
    writable.extend(cache_mounts());
    for d in &writable {
        p.push_str(&format!(
            "(allow file-read* file-write* file-map-executable (subpath \"{}\"))",
            sb(d)
        ));
    }

    // --- overlays (each later rule wins over earlier allows) ---
    // deny_write first so secrets/etc. can't be modified inside writable
    // roots — the .git internals set comes from the audit plan.
    for d in cfg.deny_write.iter().filter(|d| d.exists()) {
        p.push_str(&format!("(deny file-write* (subpath \"{}\"))", sb(d)));
    }
    // deny_read — built-in sensitive set + cfg additions.
    for d in sensitive_masks()
        .into_iter()
        .chain(cfg.deny_read.iter().cloned())
    {
        p.push_str(&format!(
            "(deny file-read* file-write* file-map-executable (subpath \"{}\"))",
            sb(&d)
        ));
    }
    // allow_read carve-outs LAST — re-open what a deny shadowed.
    for d in &cfg.allow_read {
        p.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))",
            sb(d)
        ));
    }

    // --- network ---
    match net {
        MacNet::Allow => p.push_str("(allow network* system-socket)"),
        MacNet::Deny => p.push_str("(deny network*)"),
        MacNet::Proxied(run) => {
            // Only outbound to the proxy's loopback port — DNS included.
            // `system-socket` stays: mach lookup tables live behind it.
            p.push_str(&format!(
                "(allow network-outbound (remote tcp \"127.0.0.1:{}\"))\
                 (allow system-socket)",
                run.proxy.tcp_port()
            ));
        }
    }
    p
}

/// Env for a proxied run — same vars as Linux but pointing at the
/// loopback TCP port directly (no in-sandbox socat listeners).
fn proxied_env(run: &ProxiedRun) -> Vec<(String, String)> {
    let endpoint = format!("127.0.0.1:{}", run.proxy.tcp_port());
    crate::shared::proxy_env_vars(&run.user, &run.pass, &endpoint, None)
}

#[async_trait::async_trait]
impl SandboxBackend for MacSandboxExec {
    fn id(&self) -> &'static str {
        "sandbox-exec"
    }

    fn tier(&self) -> SandboxTier {
        SandboxTier::L2
    }
    fn capabilities(&self) -> crate::SandboxCapabilities {
        crate::SandboxCapabilities {
            filesystem: true,
            network: true,
            snapshots: false,
        }
    }

    async fn run_command(
        &self,
        cmd: &str,
        _args: &[&str],
        cfg: &SandboxConfig,
    ) -> Result<CommandOutput> {
        self.validate_config(cfg)?;
        let started = Instant::now();
        let timeout = std::time::Duration::from_secs(cfg.timeout_secs.min(600));
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let net = mac_net_plan(cfg);
        let run_key = match &net {
            MacNet::Proxied(r) => Some(r.key.clone()),
            _ => None,
        };
        let mut envs = sanitize_env(&cfg.env_vars);
        for (k, v) in &cfg.trusted_env {
            envs.push((k.clone(), v.clone()));
        }
        if let MacNet::Proxied(run) = &net {
            envs.extend(proxied_env(run));
        }
        let profile = sbpl(cfg, &ws, &net);

        let mut command = tokio::process::Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(&profile)
            .arg("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .current_dir(&ws)
            .env_clear()
            .envs(envs)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            // Own process group so the timeout path kills the whole tree,
            // not just the direct child (the old `kill -9 <pid>` orphaned
            // grandchildren).
            .process_group(0);
        let child = command.spawn().context("spawn sandbox-exec")?;
        let child_id = child.id();
        // Held across the wait: if this future is dropped (a cancelled turn),
        // the guard kills the whole group, not just `sh`.
        let mut group = crate::group_kill::GroupGuard::new(child_id);
        let status = tokio::time::timeout(timeout, child.wait_with_output()).await;
        group.disarm();
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
                if let Some(id) = child_id {
                    // Negative pid = the whole process group.
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &format!("-{id}")])
                        .status();
                }
                (
                    String::new(),
                    "[timeout — process group killed]".into(),
                    -1,
                    true,
                )
            }
        };

        // Drain this run's egress denials + drop its policy — parity with
        // the Linux path's escalation channel.
        let denials = if let (Some(k), MacNet::Proxied(run)) = (run_key.as_deref(), &net) {
            let d = format_denials(&run.proxy.denials_for(k));
            run.proxy.unregister(k);
            d
        } else {
            Vec::new()
        };
        Ok(CommandOutput {
            status: code,
            stdout: out,
            stderr: err,
            is_timeout,
            sandbox_denials: denials,
            peak_memory_mb: None,
            elapsed_ms: elapsed,
        })
    }

    fn wrap_spawn(
        &self,
        cfg: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Option<tokio::process::Command> {
        self.validate_config(cfg).ok()?;
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let net = mac_net_plan(cfg);
        let profile = sbpl(cfg, &ws, &net);
        let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(&profile).arg(cmd).args(args);
        let mut envs = sanitize_env(&cfg.env_vars);
        for (k, v) in &cfg.trusted_env {
            envs.push((k.clone(), v.clone()));
        }
        // A registered run keeps its policy forever — the service may live
        // for hours; the proxy drops it at process exit (same semantics as
        // the Linux wrap_spawn path).
        if let MacNet::Proxied(run) = &net {
            envs.extend(proxied_env(run));
        }
        c.env_clear().envs(envs);
        // Own process group: pause/resume and kill address the whole tree,
        // and a negative-pid signal can never reach the agent's own group.
        #[cfg(unix)]
        c.process_group(0);
        Some(c)
    }

    fn spawn_leased(
        &self,
        lease: std::sync::Arc<crate::snapshot::SnapshotLease>,
        cfg: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Result<crate::spawn::SandboxedChild> {
        if cfg.allow_network || !cfg.allowed_domains.is_empty() || !cfg.allow_read.is_empty() {
            anyhow::bail!(
                "prepared macOS execution does not grant network or extra read exceptions"
            );
        }
        if cfg.max_processes > 1 {
            anyhow::bail!("prepared macOS execution supports exactly one process");
        }
        let executable = std::fs::canonicalize(cmd)
            .with_context(|| format!("canonicalize prepared executable {cmd}"))?;
        let request = crate::spawn::IsolatedSpawn {
            executable,
            linux_launcher: None,
            linux_cgroup_parent: None,
            args: args.iter().map(std::ffi::OsString::from).collect(),
            root: Some(lease.map_source(&cfg.workspace_dir)?.0),
            kind: crate::spawn::ExecutionKind::Tool,
            read_only: vec!["/usr/lib".into(), "/System/Library".into()],
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            env: Vec::new(),
            // A zero host cap cannot be expressed as an absent monitor limit.
            max_memory_bytes: if cfg.max_memory_mb == 0 {
                u64::MAX
            } else {
                cfg.max_memory_mb.saturating_mul(1024 * 1024)
            },
            max_processes: 1,
            memory_enforcement: crate::spawn::MemoryEnforcement::MonitoredRss,
            tool_policy: Some(cfg.clone()),
        };
        crate::spawn::spawn_isolated(lease, &request)
    }
}

/// `sandbox-exec` shipped with macOS — absent ⇒ fall through to `none`.
pub fn sandbox_exec_on_path() -> bool {
    std::process::Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use super::MacSandboxExec;
    use crate::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
    use crate::spawn::SandboxedChild;
    use crate::traits::{SandboxBackend, SandboxConfig};

    fn prepared() -> (tempfile::TempDir, WorkspaceSnapshot, SandboxConfig) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("source");
        let storage = root.join("storage");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&storage).unwrap();
        std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(source.join("original"), "unchanged").unwrap();
        let snapshot = WorkspaceSnapshot::prepare(
            &[source.clone()],
            &storage,
            SnapshotBudget {
                max_bytes: 1024 * 1024,
                max_entries: 64,
                max_depth: 8,
            },
            SnapshotPreference::PrivateCopy,
        )
        .unwrap();
        let cfg = SandboxConfig {
            workspace_dir: source,
            allow_network: false,
            ..SandboxConfig::default()
        };
        (temp, snapshot, cfg)
    }

    async fn finish(mut child: SandboxedChild) -> std::process::ExitStatus {
        child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (status, _, _) = tokio::join!(
            child.wait(),
            async {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).await.unwrap();
                bytes
            },
            async {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).await.unwrap();
                bytes
            },
        );
        status.unwrap()
    }

    #[tokio::test]
    async fn prepared_launch_writes_the_private_view_and_releases_the_lease() {
        let (_temp, mut snapshot, cfg) = prepared();
        let source = cfg.workspace_dir.clone();
        let lease = Arc::new(snapshot.lease().unwrap());
        let (id, relative) = lease.map_source(&source.join("original")).unwrap();
        let private_file = lease.working_root(id).unwrap().join(relative);
        let mut child = MacSandboxExec
            .spawn_leased(
                lease.clone(),
                &cfg,
                "/bin/sh",
                &["-c", "printf leased > original; sleep 30"],
            )
            .unwrap();
        assert!(
            snapshot.seal().is_err(),
            "a live prepared process must occupy the lease"
        );
        child.kill().await.unwrap();
        drop(lease);
        assert_eq!(std::fs::read_to_string(&private_file).unwrap(), "leased");
        assert_eq!(
            std::fs::read_to_string(source.join("original")).unwrap(),
            "unchanged"
        );
        assert_eq!(snapshot.seal().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prepared_launch_rejects_network_process_trees_and_forks() {
        let (_temp, mut snapshot, mut cfg) = prepared();
        let source = cfg.workspace_dir.clone();
        let lease = Arc::new(snapshot.lease().unwrap());
        cfg.allow_network = true;
        let Err(error) = MacSandboxExec.spawn_leased(
            lease.clone(),
            &cfg,
            "/bin/sh",
            &["-c", "printf no > original"],
        ) else {
            panic!("network must be rejected before launch");
        };
        assert!(error.to_string().contains("network"), "{error}");
        cfg.allow_network = false;
        cfg.max_processes = 2;
        let Err(error) = MacSandboxExec.spawn_leased(
            lease.clone(),
            &cfg,
            "/bin/sh",
            &["-c", "printf no > original"],
        ) else {
            panic!("a process tree must be rejected before launch");
        };
        assert!(error.to_string().contains("one process"), "{error}");
        cfg.max_processes = 1;
        let child = MacSandboxExec
            .spawn_leased(
                lease.clone(),
                &cfg,
                "/bin/sh",
                &["-c", "(/bin/sh -c 'printf child > child-marker')"],
            )
            .unwrap();
        let status = finish(child).await;
        assert!(!status.success(), "fork must be denied, status {status}");
        drop(lease);
        let changes = snapshot.seal().unwrap();
        assert!(
            changes
                .iter()
                .all(|change| change.path != std::path::Path::new("child-marker")),
            "forked child must not write {changes:?}"
        );
        assert_eq!(
            std::fs::read_to_string(source.join("original")).unwrap(),
            "unchanged"
        );
    }
}
