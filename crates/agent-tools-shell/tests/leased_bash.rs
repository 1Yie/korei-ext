#![cfg(target_os = "macos")]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_sandbox::{
    snapshot::{SnapshotBudget, SnapshotLease, SnapshotPreference, WorkspaceSnapshot},
    spawn::{spawn_isolated, ExecutionKind, IsolatedSpawn, MemoryEnforcement, SandboxedChild},
    CommandOutput, SandboxBackend, SandboxCapabilities, SandboxConfig, SandboxTier,
};

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
