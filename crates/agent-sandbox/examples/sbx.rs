use agent_sandbox::*;

#[tokio::main]
async fn main() {
    let (backend, _) = detect_backend();
    let dir = tempfile::tempdir().unwrap();
    let cfg = SandboxConfig {
        workspace_dir: dir.path().to_path_buf(),
        allow_network: true,
        timeout_secs: 10,
        ..Default::default()
    };

    println!("Backend: {}", backend.id());

    // 1. Sensitive dir check (~/.ssh)
    let out = backend.run_command("ls ~/.ssh 2>&1; echo ---; cat ~/.ssh/id_rsa 2>&1 | head -2; echo ---; env | grep -iE 'key|token|secret' || echo 'env clean'", &[], &cfg).await.unwrap();
    println!("--- Sensitive check ---\n{}", out.stdout);

    // 2. /tmp check: verify /tmp is writable and isolated
    let out = backend
        .run_command(
            "touch /tmp/sbx_test.txt && ls -ld /tmp /tmp/sbx_test.txt",
            &[],
            &cfg,
        )
        .await
        .unwrap();
    println!("--- /tmp check ---\n{}", out.stdout);

    // 3. Dev environment check: node, bun, cargo, python
    let out = backend
        .run_command("which node bun cargo python3 2>&1 || true", &[], &cfg)
        .await
        .unwrap();
    println!("--- Dev tools check ---\n{}", out.stdout);

    // 4. Runtime execution check: node and bun evaluation
    let out = backend.run_command("node -e 'console.log(\"Node: \" + process.version)' && bun -e 'console.log(\"Bun: \" + Bun.version)'", &[], &cfg).await.unwrap();
    println!("--- Runtime eval check ---\n{}", out.stdout);
    if !out.stderr.is_empty() {
        println!("stderr: {}", out.stderr);
    }
}
