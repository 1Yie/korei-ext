//! `linux_bwrap.rs` — bubblewrap backend (primary on Linux), ported to the
//! `@anthropic-ai/sandbox-runtime` architecture.
//!
//! 1. `--ro-bind / /` — the whole host mounts read-only. Read access is the
//!    default; *write* is the privilege, granted only to the workspace, the
//!    per-run dir, tmpfs `/tmp`/`/var/tmp`, and a small toolchain-cache
//!    list (package caches must be writable for installs to work).
//! 2. `deny_write` — config a sandboxed command could edit to widen its own
//!    access (`.git/hooks`, shell rc files, agent config dirs, `.mcp.json`,
//!    `.vscode`/`.idea`) re-binds read-only after the rw binds, so it wins
//!    the overlap. Ancestor dirs get writable *self-binds*: a mountpoint
//!    can't be renamed or removed, which closes the `mv .git aside` escape
//!    — while keeping `git add`/`npm install` working inside `.git`
//!    (srt pins ancestors read-only; we keep them writable deliberately).
//! 3. `deny_read` — credential dirs (`~/.ssh`, `~/.aws`, …) mask with a
//!    tmpfs (dir) or `/dev/null` re-bind (file), applied *after* the rw
//!    binds so they can mask paths inside writable roots too. `allow_read`
//!    entries re-bind on top as carve-outs.
//! 4. Network — three modes, srt-shaped:
//!    `allow_network` → host network shared, no proxy;
//!    `allowed_domains` empty → `--unshare-net`, full deny;
//!    `allowed_domains` set → `--unshare-net` + the host-side
//!    [`crate::proxy::SandboxProxy`] unix socket bind-mounted in, plus
//!    in-sandbox `socat` loopback listeners (3128 HTTP, 1080 SOCKS5)
//!    and `*_PROXY` env vars. Egress narrows to the domain allowlist,
//!    with DNS, resolved-address and per-run attribution enforced by
//!    the host proxy.
//! 5. socat missing → degrade to full deny + a warn log (loud, never
//!    silently open).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::env_sanitize::sanitize_env;
use crate::traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};

pub struct LinuxBwrap;

use crate::shared::{
    cache_mounts, format_denials, net_mode, register_egress, run_dir, sensitive_masks, NetMode,
};

/// `socat` presence — required in-sandbox for the proxied mode's
/// loopback listeners. Cached.
fn have_socat() -> bool {
    static HAVE: OnceLock<bool> = OnceLock::new();
    *HAVE.get_or_init(|| {
        std::process::Command::new("socat")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// What this run's network should look like.
enum NetPlan {
    /// `--unshare-net`, no proxy env.
    Deny,
    /// Shared host network (`allow_network: true`).
    Allow,
    /// Proxied egress — unix socket + in-sandbox socat + `*_PROXY` env.
    Proxied {
        run_key: String,
        sock: PathBuf,
        user: String,
        pass: String,
    },
}

fn net_plan(cfg: &SandboxConfig, _run_dir: &Path) -> NetPlan {
    match net_mode(cfg) {
        NetMode::Open => return NetPlan::Allow,
        // No allowlist => deny-all; denied_domains alone can only subtract.
        NetMode::Closed => return NetPlan::Deny,
        NetMode::Proxied => {}
    }
    if !have_socat() {
        tracing::warn!(
            "sandbox: egress policy configured but `socat` is missing — \
             degrading to full network deny for this run"
        );
        return NetPlan::Deny;
    }
    let Some(run) = register_egress(cfg) else {
        tracing::warn!("sandbox: egress proxy unavailable — degrading to full network deny");
        return NetPlan::Deny;
    };
    NetPlan::Proxied {
        run_key: run.key,
        sock: run.proxy.unix_path().to_path_buf(),
        user: run.user,
        pass: run.pass,
    }
}

/// Proxy env vars for a proxied run — injected after sanitization so the
/// denylist can't strip them. Port of srt's `generateProxyEnvVars`.
/// Proxy env vars for a proxied run — injected after sanitization so the
/// denylist can't strip them. Ports 3128/1080 are the in-sandbox socat
/// listeners bridging to the proxy's unix socket.
fn proxy_env_vars(net: &NetPlan) -> Vec<(String, String)> {
    let NetPlan::Proxied { user, pass, .. } = net else {
        return Vec::new();
    };
    // git-over-ssh rides the HTTP CONNECT listener via socat PROXY
    // (portable across socat versions; SOCKS5-CONNECT needs ≥1.8).
    let ssh = format!(
        "ssh -o ControlMaster=no -o ControlPath=none \
         -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=3128,proxyauth={user}:{pass}'"
    );
    let mut v = crate::shared::proxy_env_vars(user, pass, "localhost:3128", Some(&ssh));
    v.push(("RSYNC_PROXY".into(), "localhost:1080".into()));
    v
}

/// `p` lies at or under `root` by path segments.
fn at_or_under(p: &Path, root: &Path) -> bool {
    p == root || p.starts_with(root)
}

/// Writable self-bind pins for every directory between a deny-write seed
/// and the writable root covering it — a mountpoint can't be renamed or
/// removed, so `mv .git aside; mkdir .git` can't unwrap the deny. Writable
/// (not ro like srt): `.git` must stay writable for `git add`/`git commit`.
fn ancestor_pins(seeds: &[PathBuf], writable_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut pins = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for seed in seeds {
        let mut dir = seed.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d.as_os_str() == "/" {
                break;
            }
            if !writable_roots.iter().any(|r| at_or_under(&d, r)) {
                break; // above the writable root — nothing to pin
            }
            if writable_roots.contains(&d) {
                break; // the root itself is already a live rw mountpoint
            }
            if seen.insert(d.clone()) && d.is_dir() {
                pins.push(d.clone());
            }
            dir = d.parent().map(Path::to_path_buf);
        }
    }
    pins.sort();
    pins
}

/// How deep below `$HOME` host Unix sockets are searched for, and the work
/// caps that keep a huge home directory from slowing every command down.
const SOCKET_SCAN_DEPTH: usize = 4;
const SOCKET_SCAN_BUDGET: usize = 200_000;
const SOCKET_MASK_CAP: usize = 512;

/// Host pathname Unix sockets under `root` that the sandbox must not reach.
///
/// `--ro-bind / /` keeps them connectable: `connect()` on a path never goes
/// through the network namespace, and a read-only mount does not stop it
/// either. `skip` roots (the workspace, writable mounts) are the sandbox's
/// own territory — masking a pre-existing socket there would make a server
/// that unlinks and rebinds it fail with EBUSY.
///
/// Bounded by depth, entries visited and result count; symlinks are never
/// followed. Anything beyond the bounds stays reachable, which is logged.
fn host_socket_masks(root: &Path, skip: &[PathBuf]) -> Vec<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            visited += 1;
            if visited > SOCKET_SCAN_BUDGET || found.len() >= SOCKET_MASK_CAP {
                tracing::warn!(
                    root = %root.display(),
                    "sandbox: host socket scan hit its bound — some sockets stay reachable"
                );
                return found;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if ft.is_socket() {
                found.push(path);
            } else if ft.is_dir() && depth + 1 < SOCKET_SCAN_DEPTH {
                let name = entry.file_name();
                if name == ".git" || name == "node_modules" {
                    continue;
                }
                if skip.iter().any(|s| at_or_under(&path, s)) {
                    continue;
                }
                stack.push((path, depth + 1));
            }
        }
    }
    found.sort();
    found
}

/// Assemble the `bwrap` argv up to the `--` separator — shared by
/// `run_command` (appends `sh -c …`) and `wrap_spawn`.
fn sandbox_argv(cfg: &SandboxConfig, run_dir: &Path, ws: &Path, net: &NetPlan) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(160);

    // The flip: everything readable, nothing writable.
    argv.push("--ro-bind".into());
    argv.push("/".into());
    argv.push("/".into());
    argv.push("--dev".into());
    argv.push("/dev".into());
    argv.push("--proc".into());
    argv.push("/proc".into());
    argv.push("--tmpfs".into());
    argv.push("/tmp".into());
    // /run holds the host's service sockets — docker, system and session
    // dbus, ssh-agent, snapd, libvirt. Reachable through a read-only bind
    // whatever the network mode, so replace it with an empty tmpfs. It goes
    // in before every later bind: the run dir and the proxy socket live
    // under it and are re-mounted on top.
    if Path::new("/run").is_dir() {
        argv.push("--tmpfs".into());
        argv.push("/run".into());
        // /etc/resolv.conf usually points into /run (systemd-resolved).
        // Bring back just that file, never its neighbours.
        if let Ok(resolv) = Path::new("/etc/resolv.conf").canonicalize() {
            if resolv.starts_with("/run") && resolv.is_file() {
                argv.push("--ro-bind".into());
                argv.push(resolv.to_string_lossy().into_owned());
                argv.push(resolv.to_string_lossy().into_owned());
            }
        }
    }
    // /var/tmp: tmpfs'd by srt; a bound dir works and keeps it on disk.
    if Path::new("/var/tmp").exists() {
        argv.push("--bind".into());
        argv.push(run_dir.to_string_lossy().into_owned());
        argv.push("/var/tmp".into());
    }

    // Writable roots.
    argv.push("--bind".into());
    argv.push(run_dir.to_string_lossy().into_owned());
    argv.push(run_dir.to_string_lossy().into_owned());
    for extra_rw in &cfg.extra_rw_mounts {
        if extra_rw.exists() {
            argv.push("--bind".into());
            argv.push(extra_rw.to_string_lossy().into_owned());
            argv.push(extra_rw.to_string_lossy().into_owned());
        }
    }
    for cache in cache_mounts() {
        argv.push("--bind".into());
        argv.push(cache.to_string_lossy().into_owned());
        argv.push(cache.to_string_lossy().into_owned());
    }
    for extra_ro in &cfg.extra_ro_mounts {
        if extra_ro.exists() {
            argv.push("--ro-bind".into());
            argv.push(extra_ro.to_string_lossy().into_owned());
            argv.push(extra_ro.to_string_lossy().into_owned());
        }
    }
    // Workspace bind last among the writable roots.
    argv.push("--bind".into());
    argv.push(ws.to_string_lossy().into_owned());
    argv.push(ws.to_string_lossy().into_owned());

    // denyWrite — mandatory protected set + caller's. Pins first so the
    // denies' ancestors can't be moved aside.
    let writable_roots: Vec<PathBuf> = {
        let mut v = cfg.extra_rw_mounts.clone();
        v.push(ws.to_path_buf());
        v
    };
    let deny_write: Vec<PathBuf> = cfg
        .deny_write
        .iter()
        .filter(|p| p.exists())
        .cloned()
        .collect();
    for pin in ancestor_pins(&deny_write, &writable_roots) {
        argv.push("--bind".into());
        argv.push(pin.to_string_lossy().into_owned());
        argv.push(pin.to_string_lossy().into_owned());
    }
    for p in &deny_write {
        argv.push("--ro-bind".into());
        argv.push(p.to_string_lossy().into_owned());
        argv.push(p.to_string_lossy().into_owned());
    }

    // denyRead — masks land after every rw bind so they cover paths inside
    // writable roots too. A dir gets a tmpfs (empty), a file gets
    // /dev/null re-bound over it.
    let mut deny_read: Vec<PathBuf> = sensitive_masks();
    deny_read.extend(cfg.deny_read.iter().cloned());
    for mask in &deny_read {
        if !mask.exists() {
            continue;
        }
        if mask.is_dir() {
            argv.push("--tmpfs".into());
            argv.push(mask.to_string_lossy().into_owned());
        } else {
            argv.push("--ro-bind".into());
            argv.push("/dev/null".into());
            argv.push(mask.to_string_lossy().into_owned());
        }
    }
    // Host Unix sockets under $HOME (terminal multiplexers, editor and IPC
    // daemons). /run is already empty; these are the ones outside it.
    if let Some(home) = crate::shared::dirs_home() {
        let mut own: Vec<PathBuf> = writable_roots.clone();
        own.push(run_dir.to_path_buf());
        for sock in host_socket_masks(&home, &own) {
            // A socket can vanish between the scan and this mount (a temp
            // dir removed mid-run). bwrap then cannot create the mount point
            // and refuses to start, so only mask what still exists.
            if at_or_under(&sock, ws) || !sock.exists() {
                continue;
            }
            argv.push("--ro-bind".into());
            argv.push("/dev/null".into());
            argv.push(sock.to_string_lossy().into_owned());
        }
    }
    // allowRead carve-outs re-bind over the masks.
    for p in &cfg.allow_read {
        if p.exists() {
            argv.push("--ro-bind".into());
            argv.push(p.to_string_lossy().into_owned());
            argv.push(p.to_string_lossy().into_owned());
        }
    }

    // Network.
    match net {
        NetPlan::Allow => {}
        NetPlan::Deny => {
            argv.push("--unshare-net".into());
        }
        NetPlan::Proxied { sock, .. } => {
            argv.push("--unshare-net".into());
            // The egress proxy's unix socket — the sandbox's only way out.
            argv.push("--bind".into());
            argv.push(sock.to_string_lossy().into_owned());
            argv.push(sock.to_string_lossy().into_owned());
        }
    }

    argv.push("--unshare-pid".into());
    argv.push("--new-session".into());
    argv.push("--die-with-parent".into());

    // Environment.
    argv.push("--clearenv".into());
    let mut extra = cfg.env_vars.clone();
    let defaults: Vec<(String, String)> = [
        ("TMPDIR", "/tmp"),
        ("TEMP", "/tmp"),
        ("TMP", "/tmp"),
        ("BUN_INSTALL_CACHE_DIR", "/tmp/bun-cache"),
        ("npm_config_cache", "/tmp/npm-cache"),
        ("YARN_CACHE_FOLDER", "/tmp/yarn-cache"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .chain([
        (
            "XDG_RUNTIME_DIR".to_string(),
            run_dir.to_string_lossy().into_owned(),
        ),
        (
            "CARGO_TARGET_DIR".to_string(),
            ws.join("target").to_string_lossy().into_owned(),
        ),
    ])
    .collect();
    for (k, v) in defaults {
        if !extra.iter().any(|(ek, _)| *ek == k) {
            extra.push((k, v));
        }
    }
    let mut envs = sanitize_env(&extra);
    // PATH coherence under the new mount model: `/` is bound, so every
    // entry resolves — the only pruning left is agent-writable roots
    // (workspace/tmp/run-dir binaries stay off PATH).
    crate::env_sanitize::apply_environment_policy(
        &mut envs,
        &cfg.environment,
        Some(&[PathBuf::from("/")]),
        &[
            ws.to_path_buf(),
            PathBuf::from("/tmp"),
            run_dir.to_path_buf(),
        ],
    );
    for (k, v) in envs {
        argv.push("--setenv".into());
        argv.push(k);
        argv.push(v);
    }
    // Proxy vars after sanitization — they must survive the denylist.
    for (k, v) in proxy_env_vars(net) {
        argv.push("--setenv".into());
        argv.push(k);
        argv.push(v);
    }
    for (k, v) in &cfg.trusted_env {
        argv.push("--setenv".into());
        argv.push(k.clone());
        argv.push(v.clone());
    }

    argv.push("--chdir".into());
    argv.push(ws.to_string_lossy().into_owned());
    argv.push("--".into());
    argv
}

/// POSIX single-quote a string for `sh -c` embedding.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The in-sandbox preamble for proxied runs: two socat loopback listeners
/// (3128 HTTP/CONNECT — also the mux's SOCKS endpoint via sniffing; 1080
/// advertised SOCKS) forwarding to the bound unix socket, then a trap that
/// kills them when the user command exits (srt's shape).
fn sandbox_preamble(net: &NetPlan) -> String {
    let NetPlan::Proxied { sock, .. } = net else {
        return String::new();
    };
    let sock = sock.to_string_lossy();
    format!(
        "socat TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:{sock} \
         >/dev/null 2>&1 &\n\
         socat TCP-LISTEN:1080,fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:{sock} \
         >/dev/null 2>&1 &\n\
         trap 'rc=$?; kill %1 %2 2>/dev/null; exit $rc' EXIT\n\
         n=0; while [ $n -lt 100 ]; do \
         socat -u /dev/null TCP:127.0.0.1:3128 >/dev/null 2>&1 && break; \
         n=$((n+1)); sleep 0.02; done\n"
    )
}

/// bwrap died while creating a mount point for a mask whose host file had
/// just been removed — nothing of the user command ran.
fn is_mask_setup_race(o: &std::process::Output) -> bool {
    !o.status.success()
        && o.stdout.is_empty()
        && String::from_utf8_lossy(&o.stderr).starts_with("bwrap: Can't mkdir parents for")
}

/// Format proxy denials into the human-facing list on `CommandOutput`.
#[async_trait::async_trait]
impl SandboxBackend for LinuxBwrap {
    fn id(&self) -> &'static str {
        "bwrap"
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
        let run_dir = run_dir();
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let net = net_plan(cfg, &run_dir);
        let run_key = match &net {
            NetPlan::Proxied { run_key, .. } => Some(run_key.clone()),
            _ => None,
        };

        let mut inner = String::new();
        if cfg.max_memory_mb > 0 {
            inner.push_str(&format!("ulimit -v {}; ", cfg.max_memory_mb * 1024));
        }
        if cfg.max_processes > 0 {
            inner.push_str(&format!("ulimit -u {}; ", cfg.max_processes));
        }
        inner.push_str(&sandbox_preamble(&net));
        inner.push_str(cmd);

        let timeout = std::time::Duration::from_secs(cfg.timeout_secs.min(600));
        // A host socket can vanish between the $HOME scan and bwrap creating
        // its mask mount point; bwrap then refuses to start (before any user
        // code ran). The argv is rebuilt — the rescan no longer sees the
        // socket — and the run is retried, bounded.
        let mut attempt = 0u32;
        let status = loop {
            let mut argv = sandbox_argv(cfg, &run_dir, &ws, &net);
            argv.push("/bin/sh".into());
            argv.push("-c".into());
            argv.push(inner.clone());
            let child = tokio::process::Command::new("bwrap")
                .args(&argv)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .context("spawn bwrap")?;
            let status = tokio::time::timeout(timeout, child.wait_with_output()).await;
            if let Ok(Ok(o)) = &status {
                if attempt < 3 && is_mask_setup_race(o) {
                    attempt += 1;
                    continue;
                }
            }
            break status;
        };
        let elapsed = started.elapsed().as_millis() as u64;

        let (out, err, code, is_timeout) = match status {
            Ok(Ok(o)) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.code().unwrap_or(-1),
                false,
            ),
            Ok(Err(e)) => (String::new(), e.to_string(), -1, false),
            Err(_) => (
                String::new(),
                "[timeout — process tree killed]".to_string(),
                -1,
                true,
            ),
        };

        // Drain this run's egress denials + drop its policy. The run dir
        // is intentionally left in place — the process-global proxy's
        // unix socket lives there, and other commands may be in flight.
        let denials = if let Some(k) = run_key.as_deref() {
            crate::shared::global_proxy(&run_dir)
                .map(|p| {
                    let d = format_denials(&p.denials_for(k));
                    p.unregister(k);
                    d
                })
                .unwrap_or_default()
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
        let run_dir = run_dir();
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let net = net_plan(cfg, &run_dir);
        let mut argv = sandbox_argv(cfg, &run_dir, &ws, &net);
        let preamble = sandbox_preamble(&net);
        if preamble.is_empty() {
            argv.push(cmd.into());
            argv.extend(args.iter().map(|a| (*a).into()));
        } else {
            // Long-lived child still needs the in-sandbox listeners —
            // wrap in sh -c, exec the command so signals reach it.
            let mut quoted = String::from(preamble.as_str());
            quoted.push_str("exec ");
            quoted.push_str(&shell_quote(cmd));
            for a in args {
                quoted.push(' ');
                quoted.push_str(&shell_quote(a));
            }
            argv.push("/bin/sh".into());
            argv.push("-c".into());
            argv.push(quoted);
        }
        let mut c = tokio::process::Command::new("bwrap");
        c.args(&argv);
        Some(c)
    }
}

#[cfg(test)]
mod socket_mask_tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn finds_sockets_within_depth_and_skips_owned_roots() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".config/app")).unwrap();
        std::fs::create_dir_all(h.join("ws")).unwrap();
        std::fs::create_dir_all(h.join("a/b/c/d")).unwrap();
        let _s1 = UnixListener::bind(h.join(".config/app/ipc.sock")).unwrap();
        let _s2 = UnixListener::bind(h.join("ws/own.sock")).unwrap();
        let _s3 = UnixListener::bind(h.join("a/b/c/d/too-deep.sock")).unwrap();
        std::fs::write(h.join("plain.txt"), "x").unwrap();

        let got = host_socket_masks(h, &[h.join("ws")]);
        assert_eq!(got, vec![h.join(".config/app/ipc.sock")]);
    }

    #[test]
    fn does_not_follow_symlinked_dirs() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let _s = UnixListener::bind(outside.path().join("x.sock")).unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("link")).unwrap();
        assert!(host_socket_masks(home.path(), &[]).is_empty());
    }
}
