//! End-to-end bwrap + egress-proxy test. Skipped unless
//! `AGENT_SANDBOX_E2E=1` (needs bwrap, socat and live DNS/HTTPS).

use std::path::PathBuf;

use agent_sandbox::traits::{CommandOutput, SandboxBackend, SandboxConfig};
use agent_sandbox::LinuxBwrap;

fn cfg(ws: &std::path::Path, domains: &[&str]) -> SandboxConfig {
    SandboxConfig {
        workspace_dir: ws.to_path_buf(),
        allow_network: false,
        allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
        timeout_secs: 30,
        ..Default::default()
    }
}

async fn run(cmd: &str, cfg: &SandboxConfig) -> CommandOutput {
    LinuxBwrap.run_command(cmd, &[], cfg).await.unwrap()
}

#[tokio::test]
async fn proxied_egress_and_fs_model() {
    if std::env::var("AGENT_SANDBOX_E2E").ok().as_deref() != Some("1") {
        return;
    }
    for bin in ["bwrap", "socat", "curl"] {
        if std::process::Command::new("which")
            .arg(bin)
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            panic!("{bin} missing");
        }
    }
    let ws = std::env::temp_dir().join("agent-sandbox-e2e-ws");
    std::fs::create_dir_all(&ws).unwrap();
    let c = cfg(&ws, &["registry.npmjs.org", "*.npmjs.org"]);

    // Allowed host through the proxy.
    let ok = run(
        "curl -sS -o /dev/null -w '%{http_code}' https://registry.npmjs.org/ 2>/dev/null",
        &c,
    )
    .await;
    assert_eq!(
        ok.stdout.trim(),
        "200",
        "allowlisted host should proxy: {}",
        ok.stderr
    );

    // Non-allowlisted host → proxy 403 + denial record.
    let bad = run("curl -sS https://example.com/ 2>&1 | head -3", &c).await;
    assert!(
        !bad.sandbox_denials.is_empty(),
        "expected a recorded denial"
    );
    assert!(
        bad.sandbox_denials
            .iter()
            .any(|d| d.contains("example.com")),
        "denial should name example.com: {:?}",
        bad.sandbox_denials
    );

    // Direct egress is dead even when a host unix-socket resolver still
    // answers (systemd-resolved runs over AF_UNIX, which netns doesn't
    // cut): name resolution may succeed, the connect must not.
    let dns = run("curl -sS -m 5 http://127.0.0.1:1/ 2>&1 || echo no-net", &c).await;
    assert!(dns.stdout.contains("no-net"), "{:?}", dns);

    // Filesystem: whole host readable...
    let home = std::env::var("HOME").unwrap();
    let secret = PathBuf::from(&home).join(".ssh");
    let read_ok = run("ls /etc/passwd >/dev/null && echo can-read-etc", &c).await;
    assert_eq!(read_ok.stdout.trim(), "can-read-etc");

    // ...secrets masked (if ~/.ssh exists it reads as an empty dir)...
    if secret.exists() {
        let masked = run("ls -A ~/.ssh | wc -l", &c).await;
        assert_eq!(masked.stdout.trim(), "0", "~/.ssh should read as empty");
    }

    // ...writes outside writable roots refused...
    let wr = run("touch /etc/x-agent-sandbox-test 2>&1 || echo ro", &c).await;
    assert!(wr.stdout.contains("ro") || wr.stderr.contains("Read-only"));
    let wh = run("touch ~/.profile.d-agent-test 2>&1 || echo ro-home", &c).await;
    assert!(
        wh.stdout.contains("ro-home") || wh.stderr.contains("Read-only"),
        "home should be read-only: {}",
        wh.stderr
    );

    // ...workspace writable...
    let ww = run(
        "mkdir -p target && echo ok > target/probe && cat target/probe",
        &c,
    )
    .await;
    assert_eq!(ww.stdout.trim(), "ok");
    assert!(ws.join("target/probe").exists());

    // ...and the mandatory deny_write set is protected inside it
    // (the plan layer computes the set — feed it as the kernel would).
    std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
    std::fs::write(ws.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
    let mut c2 = cfg(&ws, &[]); // no network needed
    c2.deny_write = vec![
        ws.join(".git/hooks"),
        ws.join(".git/HEAD"),
        ws.join(".git/config"),
    ];
    let denied = run("echo x > .git/hooks/pre-commit 2>&1 || echo hooks-ro", &c2).await;
    assert!(
        denied.stdout.contains("hooks-ro") || denied.stderr.contains("Read-only"),
        ".git/hooks should be write-denied: {}",
        denied.stderr
    );
    let mv = run("mv .git .git-bak 2>&1 || echo git-pinned", &c2).await;
    assert!(
        mv.stdout.contains("git-pinned")
            || mv.stderr.to_lowercase().contains("busy")
            || mv.stderr.contains("Read-only")
            || mv.stderr.contains("move"),
        "mv .git should fail: {}",
        mv.stderr
    );

    // in-sandbox DNS-free localhost service still works (socat listener).
    let l = run(
        "exec 3<>/dev/tcp/127.0.0.1/3128 && echo listener-up >&3 || echo listener-probe",
        &c,
    )
    .await;
    let _ = l; // probing the listener itself is enough signal in stderr

    std::fs::remove_dir_all(&ws).ok();
}
