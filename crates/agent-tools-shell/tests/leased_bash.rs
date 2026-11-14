#![cfg(target_os = "macos")]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_sandbox::{
    snapshot::{SnapshotBudget, SnapshotLease, SnapshotPreference, WorkspaceSnapshot},
    spawn::{spawn_isolated, ExecutionKind, IsolatedSpawn, MemoryEnforcement, SandboxedChild},
    CommandOutput, SandboxBackend, SandboxCapabilities, SandboxConfig, SandboxTier,
};
use agent_tool::ToolContext;

#[derive(Default)]
struct Ctx(agent_tool::Extensions);

impl agent_tool::ToolContext for Ctx {
    fn extensions(&self) -> &agent_tool::Extensions {
        &self.0
    }

    fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
        &mut self.0
    }
}

struct LeasedBackend;

#[async_trait::async_trait]
impl SandboxBackend for LeasedBackend {
    fn id(&self) -> &'static str {
        "leased-test"
    }

    fn tier(&self) -> SandboxTier {
        SandboxTier::L2
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            filesystem: true,
            network: true,
            snapshots: true,
        }
    }

    async fn run_command(
        &self,
        _: &str,
        _: &[&str],
        _: &SandboxConfig,
    ) -> anyhow::Result<CommandOutput> {
        anyhow::bail!("ordinary command execution must not be used")
    }

    fn wrap_spawn(
        &self,
        _: &SandboxConfig,
        _: &str,
        _: &[&str],
    ) -> Option<tokio::process::Command> {
        panic!("ordinary process wrapping must not be used")
    }

    fn spawn_leased(
        &self,
        lease: Arc<SnapshotLease>,
        cfg: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> anyhow::Result<SandboxedChild> {
        let request = IsolatedSpawn {
            executable: std::fs::canonicalize(cmd)?,
            linux_launcher: None,
            linux_cgroup_parent: None,
            args: args.iter().map(std::ffi::OsString::from).collect(),
            root: Some(lease.map_source(&cfg.workspace_dir)?.0),
            kind: ExecutionKind::Tool,
            read_only: vec!["/bin".into(), "/usr/lib".into(), "/System/Library".into()],
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            env: Vec::new(),
            max_memory_bytes: 64 * 1024 * 1024,
            max_processes: 1,
            memory_enforcement: MemoryEnforcement::MonitoredRss,
            tool_policy: Some(cfg.clone()),
        };
        spawn_isolated(lease, &request)
    }
}

fn fixture(backend: Arc<dyn SandboxBackend>) -> (tempfile::TempDir, WorkspaceSnapshot, Arc<Ctx>) {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("source");
    let storage = base.join("storage");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&storage).unwrap();
    std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(source.join("file"), "original").unwrap();
    let snapshot = WorkspaceSnapshot::prepare(
        &[source.clone()],
        &storage,
        SnapshotBudget {
            max_bytes: 1024 * 1024,
            max_entries: 128,
            max_depth: 16,
        },
        SnapshotPreference::PrivateCopy,
    )
    .unwrap();
    let mut ctx = Ctx::default().with_workspace(source);
    ctx.install_workspace_lease(snapshot.lease().unwrap())
        .unwrap();
    ctx.install_sandbox(backend);
    (temp, snapshot, Arc::new(ctx))
}

#[tokio::test]
async fn short_commands_share_private_writes_and_keep_their_output() {
    let (_temp, mut snapshot, ctx) = fixture(Arc::new(LeasedBackend));
    let source = ctx.root().unwrap().to_path_buf();
    let output = (agent_tools_shell::bash::spec::<Ctx>().exec)(
        serde_json::json!({"command": "printf changed > file; printf stdout; printf stderr >&2"}),
        ctx.clone(),
    )
    .await
    .unwrap();
    assert!(output.content.contains("stdout"));
    assert!(output.content.contains("stderr"));
    assert_eq!(
        ctx.workspace_io()
            .unwrap()
            .read_to_string(std::path::Path::new("file"))
            .unwrap(),
        "changed"
    );
    let tested = (agent_tools_shell::test_runner::spec::<Ctx>().exec)(
        serde_json::json!({"command": "printf tested > file; printf 'test result: failed\\n'"}),
        ctx.clone(),
    )
    .await
    .unwrap();
    assert!(tested.content.contains("test result: failed"));
    assert_eq!(
        ctx.workspace_io()
            .unwrap()
            .read_to_string(std::path::Path::new("file"))
            .unwrap(),
        "tested"
    );
    assert_eq!(
        std::fs::read_to_string(source.join("file")).unwrap(),
        "original"
    );
    assert!(snapshot.seal().is_err());
    drop(ctx);
    assert_eq!(snapshot.seal().unwrap().len(), 1);
    snapshot.rollback().unwrap();
}

#[tokio::test]
async fn a_prepared_bash_call_refuses_an_ordinary_backend() {
    let (_temp, mut snapshot, ctx) = fixture(Arc::new(agent_sandbox::NoneBackend));
    let source = ctx.root().unwrap().to_path_buf();
    let error = (agent_tools_shell::bash::spec::<Ctx>().exec)(
        serde_json::json!({"command": "printf changed > file"}),
        ctx.clone(),
    )
    .await
    .err()
    .expect("ordinary backend must be refused");
    assert!(error
        .to_string()
        .contains("no lease-bound process launcher"));
    assert_eq!(
        std::fs::read_to_string(source.join("file")).unwrap(),
        "original"
    );
    drop(ctx);
    assert!(snapshot.seal().unwrap().is_empty());
}

#[tokio::test]
async fn command_timeout_waits_for_the_real_owner_to_release_its_lease() {
    let (_temp, mut snapshot, ctx) = fixture(Arc::new(LeasedBackend));
    let cfg = SandboxConfig {
        workspace_dir: ctx.root().unwrap().to_path_buf(),
        timeout_secs: 0,
        ..Default::default()
    };
    let output = ctx
        .run_command("while :; do :; done", &[], &cfg)
        .await
        .unwrap();
    assert!(output.is_timeout);
    drop(ctx);
    assert!(snapshot.seal().unwrap().is_empty());
}

fn service_control(ctx: &Ctx) -> Arc<Ctx> {
    let mut control = Ctx::default().with_workspace(ctx.root().unwrap());
    control.extensions_mut().insert_shared(
        ctx.service::<agent_tools_shell::services::ServiceRegistrySlot>()
            .unwrap(),
    );
    Arc::new(control)
}

async fn service(ctx: &Arc<Ctx>, action: &str, id: &str) -> agent_tool::ToolResult {
    (agent_tools_shell::services::spec::<Ctx>().exec)(
        serde_json::json!({"action": action, "id": id}),
        ctx.clone(),
    )
    .await
    .unwrap()
}

async fn start_service(ctx: &Arc<Ctx>, command: &str) -> String {
    let started = (agent_tools_shell::bash::spec::<Ctx>().exec)(
        serde_json::json!({"command": command, "persistent": true}),
        ctx.clone(),
    )
    .await
    .unwrap();
    started
        .content
        .split_whitespace()
        .find_map(|part| part.strip_prefix("id="))
        .unwrap()
        .to_owned()
}

async fn wait_for_log(ctx: &Arc<Ctx>, id: &str, marker: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if service(ctx, "logs", id).await.content.contains(marker) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn persistent_service_survives_the_invocation_and_stops_before_publication() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    agent_tools_shell::services::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let control = service_control(&ctx);
    let slot = control
        .service::<agent_tools_shell::services::ServiceRegistrySlot>()
        .unwrap();
    assert!(slot.0.services().await.is_empty());
    let private = {
        let lease = snapshot.lease().unwrap();
        let root = lease.roots().next().unwrap();
        lease.working_root(root).unwrap().to_path_buf()
    };
    let source = ctx.root().unwrap().to_path_buf();
    let id = start_service(
        &ctx,
        "printf service > file; while :; do printf 'SERVICE_READY\\n'; done",
    )
    .await;
    drop(ctx);
    wait_for_log(&control, &id, "SERVICE_READY").await;
    assert!(service(&control, "list", &id)
        .await
        .content
        .contains("running"));
    assert!(snapshot.seal().is_err());
    let services = slot.0.services().await;
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].id, id);
    assert!(services[0].active);
    assert_eq!(
        services[0].workspace_view.as_deref(),
        Some(private.as_path())
    );
    assert_eq!(
        std::fs::read_to_string(source.join("file")).unwrap(),
        "original"
    );
    slot.0.stop(&id).await.unwrap();
    assert_eq!(snapshot.seal().unwrap().len(), 1);
    assert!(!service(&control, "list", &id).await.content.contains(&id));
    assert!(slot.0.services().await.is_empty());
    snapshot.rollback().unwrap();
}

#[tokio::test]
async fn natural_service_exit_includes_both_drained_log_streams() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    agent_tools_shell::services::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let control = service_control(&ctx);
    let id = start_service(&ctx, "printf 'STDOUT_END\\n'; printf 'STDERR_END\\n' >&2").await;
    drop(ctx);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if service(&control, "list", &id)
                .await
                .content
                .contains("exited(0)")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let output = service(&control, "logs", &id).await.content;
    assert!(output.contains("STDOUT_END"));
    assert!(output.contains("STDERR_END"));
    let slot = control
        .service::<agent_tools_shell::services::ServiceRegistrySlot>()
        .unwrap();
    let services = slot.0.services().await;
    assert_eq!(services.len(), 1);
    assert!(!services[0].active);
    assert_eq!(services[0].status, "exited(0)");
    assert!(snapshot.seal().unwrap().is_empty());
}

#[tokio::test]
async fn dropping_the_session_registry_cleans_services_without_a_reference_cycle() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    agent_tools_shell::services::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let control = service_control(&ctx);
    let id = start_service(&ctx, "printf 'DROP_READY\\n'; while :; do :; done").await;
    drop(ctx);
    wait_for_log(&control, &id, "DROP_READY").await;
    assert!(snapshot.seal().is_err());
    drop(control);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while snapshot.seal().is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn prepared_services_require_a_session_registry_before_launch() {
    let (_temp, mut snapshot, ctx) = fixture(Arc::new(LeasedBackend));
    let error = (agent_tools_shell::bash::spec::<Ctx>().exec)(
        serde_json::json!({"command": "printf escaped > file", "persistent": true}),
        ctx.clone(),
    )
    .await
    .err()
    .expect("prepared service must not use the process-wide default");
    assert!(error
        .to_string()
        .contains("require a session service registry"));
    let error = (agent_tools_shell::bg::spec::<Ctx>().exec)(
        serde_json::json!({"command": "printf escaped > file"}),
        ctx.clone(),
    )
    .await
    .err()
    .expect("prepared job must not use the process-wide default");
    assert!(error.to_string().contains("require a session job registry"));
    drop(ctx);
    assert!(snapshot.seal().unwrap().is_empty());
}

async fn bg(ctx: &Arc<Ctx>, args: serde_json::Value) -> agent_tool::ToolResult {
    (agent_tools_shell::bg::spec::<Ctx>().exec)(args, ctx.clone())
        .await
        .unwrap()
}

fn bg_id(output: &agent_tool::ToolResult) -> String {
    output
        .content
        .split_whitespace()
        .find_map(|part| part.strip_prefix("id="))
        .unwrap()
        .to_owned()
}

fn private_path(snapshot: &WorkspaceSnapshot, name: &str) -> std::path::PathBuf {
    let lease = snapshot.lease().unwrap();
    let root = lease.roots().next().unwrap();
    lease.working_root(root).unwrap().join(name)
}

async fn wait_for_growth(path: &std::path::Path, minimum: u64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) <= minimum {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn leased_bg_keeps_real_pause_resume_and_kill_across_calls() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    let registry = agent_tools_shell::bg::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let source = ctx.root().unwrap().to_path_buf();
    let mut control = Ctx::default().with_workspace(&source);
    control.extensions_mut().insert_shared(
        ctx.service::<agent_tools_shell::bg::BgRegistrySlot>()
            .unwrap(),
    );
    let control = Arc::new(control);
    let counter = private_path(&snapshot, "counter");
    let view = counter.parent().unwrap();
    assert!(registry.jobs_for_view(view).is_empty());
    let started = bg(
        &ctx,
        serde_json::json!({
            "command": "while :; do printf x >> counter; done",
            "notify": false
        }),
    )
    .await;
    let id = bg_id(&started);
    drop(ctx);
    wait_for_growth(&counter, 100).await;
    assert!(registry.jobs_for_view(&source).is_empty());
    let jobs = registry.jobs_for_view(view);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, id);
    assert!(matches!(
        jobs[0].state,
        agent_tools_shell::bg::BgJobState::Running
    ));
    bg(&control, serde_json::json!({"action": "pause", "id": id})).await;
    let frozen = std::fs::metadata(&counter).unwrap().len();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(std::fs::metadata(&counter).unwrap().len(), frozen);
    assert!(snapshot.seal().is_err());
    assert!(matches!(
        registry.jobs_for_view(view)[0].state,
        agent_tools_shell::bg::BgJobState::Paused
    ));
    registry.set_paused(&id, false).unwrap();
    wait_for_growth(&counter, frozen).await;
    bg(&control, serde_json::json!({"action": "kill", "id": id})).await;
    let jobs = registry.jobs();
    assert_eq!(registry.jobs_for_view(view), jobs);
    assert!(matches!(
        jobs[0].state,
        agent_tools_shell::bg::BgJobState::Done {
            reason: agent_tools_shell::bg::BgEndReason::Killed,
            ..
        }
    ));
    assert_eq!(snapshot.seal().unwrap().len(), 1);
    assert!(!source.join("counter").exists());
}

#[tokio::test]
async fn leased_bg_notifies_after_owner_and_log_cleanup() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    let registry = agent_tools_shell::bg::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let (tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    agent_tools_shell::bg::install_notifier(Arc::get_mut(&mut ctx).unwrap(), move |notice| {
        let _ = tx.send(notice);
    });
    let started = bg(
        &ctx,
        serde_json::json!({
            "command": "printf private > file; printf 'BG_STDOUT\\n'; printf 'BG_STDERR\\n' >&2"
        }),
    )
    .await;
    let id = bg_id(&started);
    drop(ctx);
    let notice = tokio::time::timeout(std::time::Duration::from_secs(5), notices.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(notice.contains(&id));
    assert!(notices.try_recv().is_err());
    let logs = registry.tail(&id, 80).unwrap();
    assert!(logs.contains("BG_STDOUT"));
    assert!(logs.contains("BG_STDERR"));
    assert!(matches!(
        registry.jobs()[0].state,
        agent_tools_shell::bg::BgJobState::Done {
            reason: agent_tools_shell::bg::BgEndReason::Exited,
            code: Some(0),
            ..
        }
    ));
    assert_eq!(snapshot.seal().unwrap().len(), 1);
}

#[tokio::test]
async fn dropping_the_bg_registry_keeps_cleanup_owned_until_quiescence() {
    let (_temp, mut snapshot, mut ctx) = fixture(Arc::new(LeasedBackend));
    let registry = agent_tools_shell::bg::install_registry(Arc::get_mut(&mut ctx).unwrap());
    let counter = private_path(&snapshot, "counter");
    bg(
        &ctx,
        serde_json::json!({
            "command": "while :; do printf x >> counter; done",
            "notify": false
        }),
    )
    .await;
    drop(ctx);
    wait_for_growth(&counter, 100).await;
    assert!(snapshot.seal().is_err());
    drop(registry);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while snapshot.seal().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_persistent_service_keeps_its_process_group_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let mut ctx = Ctx::default().with_workspace(temp.path());
    ctx.install_sandbox(Arc::new(agent_sandbox::NoneBackend));
    agent_tools_shell::services::install_registry(&mut ctx);
    let ctx = Arc::new(ctx);
    let id = start_service(&ctx, "printf 'NATIVE_READY\\n'; sleep 30").await;
    wait_for_log(&ctx, &id, "NATIVE_READY").await;
    let stopped = service(&ctx, "stop", &id).await;
    assert!(stopped.content.contains("stopped"));
    assert!(!service(&ctx, "list", &id).await.content.contains(&id));
}
