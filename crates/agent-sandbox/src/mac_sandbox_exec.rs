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

    async fn run_command(
        &self,
        cmd: &str,
        _args: &[&str],
        cfg: &SandboxConfig,
    ) -> Result<CommandOutput> {
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
        Some(c)
    }
}

/// `sandbox-exec` shipped with macOS — absent ⇒ fall through to `none`.
pub fn sandbox_exec_on_path() -> bool {
    std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-h")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
