//! S3: `--ro-bind / /` also exposes host pathname Unix sockets (`/run/docker.sock`,
//! the user's ssh-agent, dbus …). A network namespace does not cut those — a
//! `connect()` to a path never touches the netns — so the sandbox must hide
//! them itself, in every network mode.
//!
//! Offline. Needs bwrap + curl, and `$XDG_RUNTIME_DIR` under `/run` (the place
//! such sockets live; `/tmp` is already a private tmpfs in the sandbox).
#![cfg(target_os = "linux")]

use std::os::unix::net::UnixListener;

use agent_sandbox::traits::{SandboxBackend, SandboxConfig};
use agent_sandbox::LinuxBwrap;

fn have(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn runtime_dir() -> Option<std::path::PathBuf> {
    let d = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    (d.starts_with("/run") && d.is_dir()).then_some(d)
}

fn cfg(ws: &std::path::Path, allow_network: bool, allowed: &[&str]) -> SandboxConfig {
    SandboxConfig {
        workspace_dir: ws.to_path_buf(),
        allow_network,
        allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
        timeout_secs: 20,
        ..Default::default()
    }
}

/// Does a process inside the sandbox manage to connect to a host Unix socket?
async fn reaches_host_socket(cfg: &SandboxConfig, rt: &std::path::Path) -> bool {
    let dir = tempfile::Builder::new()
        .prefix("s3-probe-")
        .tempdir_in(rt)
        .unwrap();
    let sock = dir.path().join("svc.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let cmd = format!(
        "curl -sS -m 3 --unix-socket {} http://x/ >/dev/null 2>&1; true",
        sock.display()
    );
    LinuxBwrap.run_command(&cmd, &[], cfg).await.unwrap();
    // A finished handshake waits in the backlog even if never accept()ed.
    listener.accept().is_ok()
}

#[tokio::test]
async fn host_unix_sockets_are_unreachable_in_every_network_mode() {
    let Some(rt) = runtime_dir() else {
        eprintln!("SKIP: XDG_RUNTIME_DIR is not under /run");
        return;
    };
    for bin in ["bwrap", "curl"] {
        if !have(bin) {
            eprintln!("SKIP: {bin} not installed");
            return;
        }
    }
    let ws = tempfile::tempdir().unwrap();
    for (label, c) in [
        ("deny", cfg(ws.path(), false, &[])),
        ("allow", cfg(ws.path(), true, &[])),
    ] {
        assert!(
            !reaches_host_socket(&c, &rt).await,
            "{label}: sandbox reached a host Unix socket under {}",
            rt.display()
        );
    }
}

/// The shield must not take the proxied mode's own socket away: the in-sandbox
/// socat bridge dials it, and it lives under the same runtime directory.
#[tokio::test]
async fn proxied_mode_still_reaches_its_proxy() {
    if runtime_dir().is_none() {
        eprintln!("SKIP: XDG_RUNTIME_DIR is not under /run");
        return;
    }
    for bin in ["bwrap", "curl", "socat"] {
        if !have(bin) {
            eprintln!("SKIP: {bin} not installed");
            return;
        }
    }
    let ws = tempfile::tempdir().unwrap();
    // Only `allowed.example` is listed, so `blocked.example` is refused by the
    // proxy itself (an HTTP answer, never a dial) — which needs the socket.
    let c = cfg(ws.path(), false, &["allowed.example"]);
    let out = LinuxBwrap
        .run_command(
            "curl -sS -m 5 -o /dev/null -w '%{http_code}' http://blocked.example/ 2>/dev/null; true",
            &[],
            &c,
        )
        .await
        .unwrap();
    let code = out.stdout.trim();
    assert!(
        code.len() == 3 && code != "000",
        "proxy was unreachable (http_code={code:?}, status={}, stdout={:?}, stderr={:?})",
        out.status,
        out.stdout,
        out.stderr
    );
}

/// Sockets outside `/run` — editors, terminal multiplexers and IPC daemons keep
/// theirs under `$HOME`. Uses a throwaway directory, never a real service.
#[tokio::test]
async fn home_sockets_are_masked_but_the_workspace_is_not() {
    for bin in ["bwrap", "curl"] {
        if !have(bin) {
            eprintln!("SKIP: {bin} not installed");
            return;
        }
    }
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("s3-home-")
        .tempdir_in(
            home.join(".config")
                .exists()
                .then(|| home.join(".config"))
                .unwrap_or(home.clone()),
        )
        .unwrap();
    let sock = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();

    let ws = tempfile::tempdir().unwrap();
    let c = cfg(ws.path(), false, &[]);
    let cmd = format!(
        "curl -sS -m 3 --unix-socket {} http://x/ >/dev/null 2>&1; true",
        sock.display()
    );
    LinuxBwrap.run_command(&cmd, &[], &c).await.unwrap();
    assert!(
        listener.accept().is_err(),
        "a socket under $HOME was reachable from the sandbox"
    );
}

/// Name resolution keeps working: `/etc/resolv.conf` is usually a symlink into
/// `/run`, which is now an empty tmpfs.
#[tokio::test]
async fn resolv_conf_is_still_readable() {
    if !have("bwrap") {
        eprintln!("SKIP: bwrap not installed");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let out = LinuxBwrap
        .run_command(
            "grep -c nameserver /etc/resolv.conf",
            &[],
            &cfg(ws.path(), true, &[]),
        )
        .await
        .unwrap();
    assert_eq!(out.status, 0, "resolv.conf unreadable: {:?}", out);
    assert_ne!(out.stdout.trim(), "0");
}

/// The proxy bridge is started in the background; the user command must not
/// begin before it is listening, or its first request fails at random.
#[tokio::test]
async fn proxy_listener_is_ready_when_the_command_starts() {
    for bin in ["bwrap", "socat"] {
        if !have(bin) {
            eprintln!("SKIP: {bin} not installed");
            return;
        }
    }
    let ws = tempfile::tempdir().unwrap();
    let c = cfg(ws.path(), false, &["allowed.example"]);
    let mut not_ready = 0;
    for _ in 0..40 {
        let out = LinuxBwrap
            .run_command(
                "socat -u /dev/null TCP:127.0.0.1:3128 2>/dev/null && echo up || echo down",
                &[],
                &c,
            )
            .await
            .unwrap();
        if out.stdout.trim() != "up" {
            not_ready += 1;
        }
    }
    assert_eq!(
        not_ready, 0,
        "listener was not ready in {not_ready}/40 runs"
    );
}
