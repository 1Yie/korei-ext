#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use agent_sandbox::snapshot::*;
use agent_sandbox::spawn::*;
use tokio::io::AsyncReadExt;

async fn collect_output(mut process: SandboxedChild) -> std::process::Output {
    let mut stdout = process.stdout.take().unwrap();
    let mut stderr = process.stderr.take().unwrap();
    process.stdin.take();
    let (status, stdout, stderr) = tokio::join!(
        process.wait(),
        async move {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await.unwrap();
            bytes
        },
        async move {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).await.unwrap();
            bytes
        },
    );
    std::process::Output {
        status: status.unwrap(),
        stdout,
        stderr,
    }
}

fn snapshot() -> (tempfile::TempDir, WorkspaceSnapshot, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("source");
    let storage = root.join("storage");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&storage).unwrap();
    fs::set_permissions(&storage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(source.join("secret"), b"host secret").unwrap();
    let snapshot = WorkspaceSnapshot::prepare(
        &[source.clone()],
        &storage,
        SnapshotBudget {
            max_bytes: 1024 * 1024,
            max_entries: 64,
            max_depth: 8,
        },
        SnapshotPreference::NativePreferred,
    )
    .unwrap();
    (temp, snapshot, source)
}

fn request(lease: &SnapshotLease, script: String, kind: ExecutionKind) -> IsolatedSpawn {
    IsolatedSpawn {
        executable: "/bin/sh".into(),
        linux_launcher: None,
        linux_cgroup_parent: std::env::var_os("KOREI_TEST_CGROUP_PARENT").map(PathBuf::from),
        args: vec![OsString::from("-c"), script.into()],
        root: Some(lease.roots().next().unwrap()),
        kind,
        read_only: if cfg!(target_os = "macos") {
            vec!["/usr/lib".into(), "/System/Library".into()]
        } else {
            ["/usr/lib", "/lib", "/lib64"]
                .into_iter()
                .map(PathBuf::from)
                .filter(|path| path.exists())
                .collect()
        },
        deny_read: vec![],
        deny_write: vec![],
        env: vec![],
        max_memory_bytes: 4 * 1024 * 1024 * 1024,
        max_processes: 1,
        memory_enforcement: if cfg!(target_os = "macos") {
            MemoryEnforcement::MonitoredRss
        } else {
            MemoryEnforcement::OsHard
        },
        tool_policy: None,
    }
}

#[test]
fn launcher_rejects_invalid_context_without_executing_target() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("executed");
    for allowance in ["1", "0", "+1", "4294967295"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-sandbox-launcher"))
            .args([
                "--max-processes",
                allowance,
                "--",
                "/bin/sh",
                "-c",
                "printf effect > \"$1\"",
                "target",
            ])
            .arg(&marker)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(126));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("agent-sandbox-launcher:"));
        assert!(!marker.exists());
        #[cfg(not(target_os = "linux"))]
        if allowance == "1" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("only on Linux"));
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_launcher_resource_is_rejected_on_other_platforms() {
    let (_temp, snapshot, source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, "printf unexpected".into(), ExecutionKind::Worker);
    request.linux_launcher = Some(env!("CARGO_BIN_EXE_agent-sandbox-launcher").into());
    let error = spawn_isolated(lease, &request).err().unwrap();
    assert!(error.to_string().contains("Linux launcher is unsupported"));
    assert_eq!(fs::read(source.join("secret")).unwrap(), b"host secret");
}

#[cfg(target_os = "linux")]
fn install_launcher(directory: &std::path::Path) -> PathBuf {
    let path = directory.join("agent-sandbox-launcher");
    fs::copy(env!("CARGO_BIN_EXE_agent-sandbox-launcher"), &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    path
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_cgroup_parent_is_required_and_ordinary_directories_are_never_written() {
    let (temp, mut snapshot, _) = snapshot();
    let launcher = install_launcher(temp.path());
    let fake = temp.path().join("fake-cgroup");
    fs::create_dir(&fake).unwrap();
    for name in [
        "cgroup.procs",
        "cgroup.kill",
        "cgroup.events",
        "cgroup.type",
    ] {
        fs::write(fake.join(name), b"untouched").unwrap();
    }
    for parent in [None, Some(fake.clone())] {
        let lease = snapshot.lease().unwrap();
        let working = lease
            .working_root(lease.roots().next().unwrap())
            .unwrap()
            .to_owned();
        let mut request = request(&lease, "touch executed".into(), ExecutionKind::Worker);
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.linux_launcher = Some(launcher.clone());
        request.linux_cgroup_parent = parent;
        let error = spawn_isolated(lease, &request).err().unwrap();
        let error = format!("{error:#}");
        if unsafe { libc::geteuid() } != 0 {
            assert!(error.contains("cgroup"), "{error}");
        }
        assert!(!working.join("executed").exists());
    }
    for name in [
        "cgroup.procs",
        "cgroup.kill",
        "cgroup.events",
        "cgroup.type",
    ] {
        assert_eq!(fs::read(fake.join(name)).unwrap(), b"untouched");
    }
    assert_eq!(fs::read_dir(&fake).unwrap().count(), 4);
    snapshot.seal().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compile_task_probe(directory: &std::path::Path) -> PathBuf {
    let executable = directory.join("task-probe");
    let output = std::process::Command::new("cc")
        .args(["-pthread", "-o"])
        .arg(&executable)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/security_probe.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

#[cfg(target_os = "linux")]
#[test]
fn linux_missing_invalid_launcher_and_host_root_are_rejected() {
    let (temp, snapshot, _) = snapshot();
    let launcher = install_launcher(temp.path());
    if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } == 0 {
        let lease = snapshot.lease().unwrap();
        let mut request = request(&lease, "printf effect".into(), ExecutionKind::Worker);
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.linux_launcher = Some(launcher);
        assert!(spawn_isolated(lease, &request)
            .err()
            .unwrap()
            .to_string()
            .contains("non-root host UID"));
        return;
    }
    let invalid = temp.path().join("invalid-launcher");
    fs::write(&invalid, b"#!/bin/sh\nprintf effect\n").unwrap();
    fs::set_permissions(&invalid, fs::Permissions::from_mode(0o500)).unwrap();
    for helper in [
        None,
        Some(temp.path().join("missing")),
        Some(invalid),
        Some(PathBuf::from("relative")),
    ] {
        let lease = snapshot.lease().unwrap();
        let mut request = request(&lease, "printf effect".into(), ExecutionKind::Worker);
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.linux_launcher = helper;
        assert!(spawn_isolated(lease, &request).is_err());
    }
    for limit in [0, u32::MAX] {
        let lease = snapshot.lease().unwrap();
        let mut request = request(&lease, "printf effect".into(), ExecutionKind::Worker);
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.linux_launcher = Some(launcher.clone());
        request.max_processes = limit;
        assert!(spawn_isolated(lease, &request).is_err());
    }
    let lease = snapshot.lease().unwrap();
    let private = lease
        .working_root(lease.roots().next().unwrap())
        .unwrap()
        .to_path_buf();
    drop(lease);
    for writable in [temp.path().join("source"), private] {
        let local = install_launcher(&writable);
        let lease = snapshot.lease().unwrap();
        let mut request = request(&lease, "printf effect".into(), ExecutionKind::Worker);
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.linux_launcher = Some(local);
        assert!(spawn_isolated(lease, &request).is_err());
    }
    let alias = temp.path().join("source-alias");
    std::os::unix::fs::symlink(temp.path().join("source"), &alias).unwrap();
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, "printf effect".into(), ExecutionKind::Worker);
    request.executable = fs::canonicalize("/bin/sh").unwrap();
    request.linux_launcher = Some(launcher);
    request.read_only.push(alias);
    assert!(spawn_isolated(lease, &request).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_runtime_symlink_grant_works_and_alias_denies_fail_closed() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let (temp, snapshot, source) = snapshot();
    let runtime = temp.path().join("runtime");
    let real = runtime.join("usr/lib");
    let alias = runtime.join("lib");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("value"), b"granted\n").unwrap();
    std::os::unix::fs::symlink("usr/lib", &alias).unwrap();
    let launcher = install_launcher(temp.path());
    let lease = snapshot.lease().unwrap();
    let mut allowed = request(&lease, String::new(), ExecutionKind::Worker);
    allowed.executable = fs::canonicalize("/bin/sh").unwrap();
    allowed.linux_launcher = Some(launcher.clone());
    allowed.read_only.push(alias.clone());
    allowed.args = vec![
        "-c".into(),
        "IFS= read -r value < \"$1\"; printf '%s' \"$value\"".into(),
        "target".into(),
        alias.join("value").into_os_string(),
    ];
    let output = collect_output(spawn_isolated(lease, &allowed).unwrap()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"granted");
    for denied in [real.join("value"), alias.join("value"), real.clone()] {
        for write in [false, true] {
            let lease = snapshot.lease().unwrap();
            let mut protected = allowed.clone();
            protected.read_only.push(real.clone());
            if write {
                protected.deny_write.push(denied.clone());
            } else {
                protected.deny_read.push(denied.clone());
            }
            let error = spawn_isolated(lease, &protected).err().unwrap();
            assert!(
                error.to_string().contains("runtime alias conflicts"),
                "{error:#}"
            );
        }
    }
    let workspace_alias = runtime.join("workspace");
    std::os::unix::fs::symlink(&source, &workspace_alias).unwrap();
    let lease = snapshot.lease().unwrap();
    let private = lease
        .working_root(lease.roots().next().unwrap())
        .unwrap()
        .to_path_buf();
    drop(lease);
    for forbidden in [workspace_alias, private.clone()] {
        let lease = snapshot.lease().unwrap();
        let mut protected = allowed.clone();
        protected.read_only.push(forbidden);
        assert!(spawn_isolated(lease, &protected).is_err());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_task_allowance_rejects_extra_forks_and_threads() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let (temp, snapshot, _) = snapshot();
    let launcher = install_launcher(temp.path());
    let executable = compile_task_probe(temp.path());
    for count in [1, 4] {
        for mode in ["tasks-fork", "tasks-thread"] {
            let lease = snapshot.lease().unwrap();
            let mut request = request(&lease, String::new(), ExecutionKind::Worker);
            request.executable = executable.clone();
            request.linux_launcher = Some(launcher.clone());
            request.args = vec![mode.into(), count.to_string().into()];
            request.max_processes = count;
            let output = collect_output(spawn_isolated(lease, &request).unwrap()).await;
            assert!(
                output.status.success(),
                "{mode}/{count}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"limited\n");
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_native_target_path_and_arguments_survive_launcher_exec() {
    use std::os::unix::ffi::OsStringExt;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let (temp, snapshot, _) = snapshot();
    let executable = compile_task_probe(temp.path());
    let native = temp.path().join(OsString::from_vec(b"task-\xff".to_vec()));
    fs::rename(executable, &native).unwrap();
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, String::new(), ExecutionKind::Worker);
    request.linux_launcher = Some(install_launcher(temp.path()));
    request.executable = native;
    request.args = vec![
        "bytes".into(),
        OsString::from_vec(b"argument-\xfe".to_vec()),
    ];
    let output = collect_output(spawn_isolated(lease, &request).unwrap()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"argument-\xfe");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_launcher_refuses_capabilities_bad_topology_and_insufficient_inherited_limit() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let (temp, snapshot, _) = snapshot();
    let launcher = install_launcher(temp.path());
    let executable = compile_task_probe(temp.path());
    for mode in ["capabilities", "launcher-extra-task", "launcher-low-hard"] {
        let lease = snapshot.lease().unwrap();
        let runtime = request(&lease, String::new(), ExecutionKind::Worker);
        let mut command = tokio::process::Command::new("bwrap");
        command.args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]);
        for path in runtime.read_only {
            command
                .arg("--ro-bind")
                .arg(path.canonicalize().unwrap())
                .arg(path);
        }
        command
            .arg("--ro-bind")
            .arg(&launcher)
            .arg("/.korei-launcher");
        command.arg("--ro-bind").arg(&executable).arg(&executable);
        if mode == "capabilities" {
            command.args([
                "--cap-add",
                "CAP_SYS_RESOURCE",
                "--",
                "/.korei-launcher",
                "--max-processes",
                "1",
                "--",
            ]);
            command.arg(&executable).args(["bytes", "effect"]);
        } else {
            command
                .arg("--")
                .arg(&executable)
                .arg(mode)
                .arg(&executable);
        }
        let output = command.kill_on_drop(true).output().await.unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty(), "{mode}: target executed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let expected = match mode {
            "capabilities" => "capabilities are not cleared",
            "launcher-extra-task" => "unexpected PID namespace task topology",
            _ => "inherited task allowance is insufficient",
        };
        assert!(stderr.contains(expected), "{mode}: {stderr}");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_cancellation_reaps_the_monitor_and_terminates_the_target_tree() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let (temp, snapshot, _) = snapshot();
    let executable = compile_task_probe(temp.path());
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, String::new(), ExecutionKind::Worker);
    request.executable = executable;
    request.linux_launcher = Some(install_launcher(temp.path()));
    request.args = vec!["tasks-wait".into(), "4".into()];
    request.max_processes = 4;
    let mut process = spawn_isolated(lease, &request).unwrap();
    let pid = process.id().unwrap();
    let mut stdout = BufReader::new(process.stdout.take().unwrap());
    let mut stderr = process.stderr.take().unwrap();
    process.stdin.take();
    let mut line = String::new();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            line = stdout.read_line(&mut line) => line.map(|bytes| bytes != 0),
            status = process.wait() => status.map(|_| false),
        }
    })
    .await;
    let mut descendants = std::collections::BTreeSet::from([pid]);
    let mut pending = vec![pid];
    while let Some(parent) = pending.pop() {
        let children = fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
            .unwrap_or_default();
        for child in children
            .split_whitespace()
            .map(|pid| pid.parse::<u32>().unwrap())
        {
            if descendants.insert(child) {
                pending.push(child);
            }
        }
    }
    if process.id().is_some() {
        process.start_kill().unwrap();
    }
    let exited = tokio::time::timeout(std::time::Duration::from_secs(5), process.wait()).await;
    if !matches!(&exited, Ok(Ok(_))) {
        process.start_kill().unwrap();
        process.wait().await.unwrap();
    }
    let mut errors = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stderr.read_to_end(&mut errors),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        matches!(ready, Ok(Ok(true))) && line == "ready\n",
        "{}",
        String::from_utf8_lossy(&errors)
    );
    assert!(exited.unwrap().unwrap().code() != Some(0));
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let live = descendants.iter().any(|pid| {
            fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, state)| !state.starts_with('Z') && !state.starts_with('X'))
            })
        });
        if !live {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "target task survived cancellation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_launch_with_one_and_four_tasks_under_a_busy_host_uid() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run as an ordinary Linux user"
    );
    let mut host_tasks = Vec::new();
    for _ in 0..8 {
        match tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => host_tasks.push(child),
            Err(error) => {
                for task in &mut host_tasks {
                    let _ = task.start_kill();
                    let _ = task.wait().await;
                }
                panic!("create host UID load: {error}");
            }
        }
    }
    let mut outcomes = Vec::new();
    for max_processes in [1, 4] {
        let (temp, snapshot, _) = snapshot();
        let lease = snapshot.lease().unwrap();
        let mut request = request(&lease, "printf isolated".into(), ExecutionKind::Worker);
        request.linux_launcher = Some(install_launcher(temp.path()));
        request.executable = fs::canonicalize("/bin/sh").unwrap();
        request.max_processes = max_processes;
        match spawn_isolated(lease, &request) {
            Ok(process) => {
                let output = collect_output(process).await;
                outcomes.push((
                    max_processes,
                    output.status.success() && output.stdout == b"isolated",
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
            Err(error) => outcomes.push((max_processes, false, error.to_string())),
        }
    }
    for task in &mut host_tasks {
        let _ = task.start_kill();
        task.wait().await.unwrap();
    }
    for (limit, success, stderr) in outcomes {
        assert!(success, "max_processes={limit}: {stderr}");
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn worker_stdio_is_piped_and_host_environment_and_files_are_denied() {
    let (_temp, mut snapshot, source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap().to_owned();
    // read/printf are shell builtins: this check needs no subprocess grant.
    let script = format!(
        "if IFS= read -r x < '{}'; then exit 21; fi; if IFS= read -r x < '{}'; then exit 22; fi; if printf overwrite > '{}'; then exit 23; fi; if printf overwrite > '{}'; then exit 24; fi; test -z \"$HOME\" || exit 25; test -z \"$HUSK_SECURITY_SENTINEL\" || exit 26; printf isolated",
        source.join("secret").display(), working.join("secret").display(), source.join("secret").display(), working.join("secret").display(),
    );
    let request = request(&lease, script, ExecutionKind::Worker);
    let process = spawn_isolated(lease, &request).unwrap();
    assert!(process.stdin.is_some());
    assert!(snapshot.seal().is_err());
    let output = collect_output(process).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"isolated");
    assert_eq!(fs::read(source.join("secret")).unwrap(), b"host secret");
    snapshot.seal().unwrap();
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn tool_writes_only_private_roots_and_preserves_protection_denies() {
    let (_temp, mut snapshot, source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let working = lease.working_root(root).unwrap().to_owned();
    let script = format!("printf tool > new; if printf overwrite > '{}'; then exit 21; fi; if printf overwrite > secret; then exit 22; fi", source.join("secret").display());
    let mut request = request(&lease, script, ExecutionKind::Tool);
    request.deny_write.push(working.join("secret"));
    request.tool_policy = Some(agent_sandbox::SandboxConfig {
        workspace_dir: source.clone(),
        ..Default::default()
    });
    let process = spawn_isolated(lease, &request).unwrap();
    let output = collect_output(process).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(working.join("new")).unwrap(), b"tool");
    assert_eq!(fs::read(source.join("secret")).unwrap(), b"host secret");
    assert_eq!(snapshot.seal().unwrap().len(), 1);
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn native_tool_cannot_fork_out_of_its_scope() {
    let (temp, mut snapshot, source) = snapshot();
    let executable = compile_task_probe(temp.path()).canonicalize().unwrap();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let marker = lease.working_root(root).unwrap().join("fork-escape");
    let mut request = request(&lease, String::new(), ExecutionKind::Tool);
    request.executable = executable;
    request.args = vec!["fork-denied".into(), marker.clone().into_os_string()];
    request.tool_policy = Some(agent_sandbox::SandboxConfig {
        workspace_dir: source,
        ..Default::default()
    });
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        collect_output(spawn_isolated(lease, &request).unwrap()),
    )
    .await
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"fork-denied\n");
    assert!(!marker.exists());
    snapshot.seal().unwrap();
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn running_process_cannot_release_its_scope() {
    let (_temp, mut snapshot, source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, "while :; do :; done".into(), ExecutionKind::Tool);
    request.tool_policy = Some(agent_sandbox::SandboxConfig {
        workspace_dir: source,
        ..Default::default()
    });
    let mut process = spawn_isolated(lease, &request).unwrap();
    let premature_seal = snapshot.seal().is_ok();
    process.kill().await.unwrap();
    assert!(!premature_seal, "running tool released its scope");
    snapshot.seal().unwrap();
}

#[test]
#[cfg(target_os = "macos")]
fn dropped_wait_and_runtime_leave_the_owner_responsible_for_cleanup() {
    for abandon_endpoint in [false, true] {
        let (_temp, mut snapshot, _) = snapshot();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut process = runtime.block_on(async {
            let lease = snapshot.lease().unwrap();
            let request = request(&lease, "while :; do :; done".into(), ExecutionKind::Worker);
            let mut process = spawn_isolated(lease, &request).unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), process.wait(),)
                    .await
                    .is_err()
            );
            assert!(snapshot.seal().is_err());
            process
        });
        let pid = process.id().unwrap();
        drop(runtime);
        assert!(snapshot.seal().is_err());
        if abandon_endpoint {
            drop(process);
        } else {
            process.start_kill().unwrap();
            // The endpoint stays alive without any runtime driving its completion.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while process.id().is_some() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while snapshot.seal().is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "owner did not release lease"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn fork_is_denied_and_cancellation_kills_and_reaps() {
    let (_temp, mut snapshot, _source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let request = request(&lease, "while :; do :; done".into(), ExecutionKind::Worker);
    let mut process = spawn_isolated(lease, &request).unwrap();
    assert!(snapshot.seal().is_err());
    let status = process.kill().await.unwrap();
    assert!(!status.success());
    snapshot.seal().unwrap();
    snapshot.rollback().unwrap();
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn native_worker_cannot_connect_fork_or_read_host() {
    let (temp, snapshot, source) = snapshot();
    let executable = temp.path().canonicalize().unwrap().join("probe");
    let output = std::process::Command::new("/usr/bin/cc")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/security_probe.c"
        ))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    let mut request = request(&lease, String::new(), ExecutionKind::Worker);
    request.executable = executable;
    request.args = vec![
        source.join("secret").into_os_string(),
        lease
            .working_root(root)
            .unwrap()
            .join("secret")
            .into_os_string(),
        listener.local_addr().unwrap().port().to_string().into(),
    ];
    let process = spawn_isolated(lease, &request).unwrap();
    let output = collect_output(process).await;
    assert!(
        output.status.success(),
        "status {:?}, stderr {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"isolated\n");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
#[cfg(target_os = "macos")]
fn unsupported_limits_and_source_read_grants_refuse_before_start() {
    let (_temp, snapshot, source) = snapshot();
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, "exit 0".into(), ExecutionKind::Worker);
    request.max_processes = 2;
    assert!(spawn_isolated(lease, &request).is_err());
    let lease = snapshot.lease().unwrap();
    request.max_processes = 1;
    request.read_only.push(source);
    assert!(spawn_isolated(lease, &request).is_err());
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn empty_worker_scope_requires_no_workspace_and_refuses_tools_and_os_hard() {
    let temp = tempfile::tempdir().unwrap();
    let storage = temp.path().canonicalize().unwrap();
    fs::set_permissions(&storage, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = IsolatedSpawn {
        linux_launcher: None,
        linux_cgroup_parent: None,
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), "printf isolated".into()],
        root: None,
        kind: ExecutionKind::Worker,
        read_only: vec!["/usr/lib".into(), "/System/Library".into()],
        deny_read: vec![],
        deny_write: vec![],
        env: vec![],
        max_memory_bytes: 64 * 1024 * 1024,
        max_processes: 1,
        memory_enforcement: MemoryEnforcement::MonitoredRss,
        tool_policy: None,
    };
    let result =
        collect_output(spawn_isolated(WorkerScope::prepare(&storage).unwrap(), &request).unwrap())
            .await;
    assert!(result.status.success(), "{:?}", result.stderr);
    assert_eq!(result.stdout, b"isolated");
    assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
    request.kind = ExecutionKind::Tool;
    assert!(spawn_isolated(WorkerScope::prepare(&storage).unwrap(), &request).is_err());
    request.kind = ExecutionKind::Worker;
    request.memory_enforcement = MemoryEnforcement::OsHard;
    let error = spawn_isolated(WorkerScope::prepare(&storage).unwrap(), &request)
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
}

#[tokio::test]
#[cfg(target_os = "macos")]
async fn rss_monitor_survives_repeated_wait_cancellation_and_reaps() {
    let (temp, snapshot, _) = snapshot();
    let executable = temp.path().canonicalize().unwrap().join("rss-probe");
    let compile = std::process::Command::new("/usr/bin/cc")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/security_probe.c"
        ))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let lease = snapshot.lease().unwrap();
    let mut request = request(&lease, String::new(), ExecutionKind::Worker);
    request.executable = executable;
    request.args = vec!["rss".into()];
    request.max_memory_bytes = 32 * 1024 * 1024;
    let mut process = spawn_isolated(lease, &request).unwrap();
    let pid = process.id().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "RSS monitor was starved"
        );
        if let Ok(status) =
            tokio::time::timeout(std::time::Duration::from_millis(1), process.wait()).await
        {
            assert!(!status.unwrap().success());
            break;
        }
    }
    assert_eq!(process.wait().await.unwrap().code(), None);
    assert!(process.rss_limit_exceeded());
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);

    let lease = snapshot.lease().unwrap();
    let mut process = spawn_isolated(lease, &request).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while process.id().is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "RSS monitor requires a waiter"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!process.wait().await.unwrap().success());
    assert!(process.rss_limit_exceeded());
}
