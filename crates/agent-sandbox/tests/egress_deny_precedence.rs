//! S2: a configured denylist must hold even when `allow_network` is true.
//!
//! Offline: the "server" is a loopback listener on the host. A sandbox that
//! still shares the host network reaches it; one that was moved behind the
//! egress proxy (own netns, proxy as the only way out) cannot.
//! Needs bwrap + socat + curl; skips (loudly) when one is missing.
#![cfg(target_os = "linux")]

use std::net::TcpListener;

use agent_sandbox::traits::{SandboxBackend, SandboxConfig};
use agent_sandbox::LinuxBwrap;

fn have(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `curl` at a host loopback listener from inside the sandbox; return
/// whether the connection ever reached the host.
async fn reaches_host_loopback(cfg: &SandboxConfig) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let cmd = format!("curl -sS -m 3 http://127.0.0.1:{port}/ >/dev/null 2>&1; true");
    LinuxBwrap.run_command(&cmd, &[], cfg).await.unwrap();
    // A completed handshake waits in the backlog even if never accept()ed.
    listener.accept().is_ok()
}

fn cfg(ws: &std::path::Path, denied: &[&str]) -> SandboxConfig {
    SandboxConfig {
        workspace_dir: ws.to_path_buf(),
        allow_network: true,
        denied_domains: denied.iter().map(|s| s.to_string()).collect(),
        timeout_secs: 20,
        ..Default::default()
    }
}

#[tokio::test]
async fn denylist_is_enforced_when_network_is_allowed() {
    for bin in ["bwrap", "socat", "curl"] {
        if !have(bin) {
            eprintln!("SKIP: {bin} not installed");
            return;
        }
    }
    let ws = tempfile::tempdir().unwrap();

    // Control: plain allow shares the host network — loopback is reachable.
    assert!(
        reaches_host_loopback(&cfg(ws.path(), &[])).await,
        "control: allow_network=true without a denylist should share the host network"
    );

    // With any denylist the run must go through the policy-enforcing proxy.
    assert!(
        !reaches_host_loopback(&cfg(ws.path(), &["blocked.example"])).await,
        "allow_network=true + denied_domains must not hand out the raw host network"
    );
}
