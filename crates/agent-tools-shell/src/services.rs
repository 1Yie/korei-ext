//! `service` — manage long-lived background processes launched by
//! `bash(persistent: true)`.
//!
//! A session registry retains the actual process owner across calls. Process
//! cleanup and log draining both complete before a service reports its exit.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use futures::FutureExt;
use tokio::sync::Mutex;

use crate::log::{create_log, log_dir, pump, read_tail, DEFAULT_TAIL_LINES};
use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_sandbox::process::ManagedChild;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// The set of live background services one owner can see and stop. A host
/// installs one per session ([`ServiceRegistrySlot`]) so sessions never see
/// each other's services. Unprepared contexts can use the process default.
/// Dropping the registry kills whatever it still holds.
#[derive(Default)]
pub struct ServiceRegistry {
    map: Mutex<BTreeMap<String, Service>>,
}

/// Host-installed registry for this context (and its delegated children).
pub struct ServiceRegistrySlot(pub Arc<ServiceRegistry>);

/// Ids stay unique process-wide so log files never collide across registries.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn registry<C: SandboxCtx>(ctx: &C) -> Result<Arc<ServiceRegistry>, ToolError> {
    static DEFAULT: LazyLock<Arc<ServiceRegistry>> = LazyLock::new(Default::default);
    if let Some(slot) = ctx.service::<ServiceRegistrySlot>() {
        return Ok(slot.0.clone());
    }
    if ctx.workspace_lease().is_some() {
        return Err(ToolError::Failed(
            "prepared services require a session service registry".into(),
        ));
    }
    Ok(DEFAULT.clone())
}

/// Install a fresh per-owner registry on `ctx`, shared with delegated children.
pub fn install_registry<C: SandboxCtx>(ctx: &mut C) {
    ctx.extensions_mut()
        .insert_shared(Arc::new(ServiceRegistrySlot(Arc::default())));
}

struct Service {
    command: String,
    pid: Option<u32>,
    log_path: PathBuf,
    child: ManagedChild,
    readers: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
    log_error: Option<String>,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawn `command` through the context's native or leased process owner.
/// Called by `bash` when `persistent: true`. Returns the model-facing text.
pub async fn spawn_persistent<C: SandboxCtx>(
    ctx: &Arc<C>,
    cfg: &agent_sandbox::SandboxConfig,
    command: &str,
) -> Result<ToolResult, ToolError> {
    let registry = registry(&**ctx)?;
    let id = format!("svc-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    // Private dir + 0600 file, never through a symlink: service output can
    // carry tokens.
    let dir = log_dir("agent-svc")?;
    let (log, log_path) = create_log(&dir, &id)?;
    let log_err = log
        .try_clone()
        .map_err(|e| ToolError::Failed(e.to_string()))?;

    #[cfg(windows)]
    let mut child = ctx.spawn_process(cfg, "cmd.exe", &["/C", command])?;
    #[cfg(not(windows))]
    let mut child = ctx.spawn_process(cfg, "/bin/sh", &["-c", command])?;
    child.stdin.take();
    let pid = child.id();
    let mut readers = Vec::new();
    for (pipe, log) in [(child.stdout.take(), log), (child.stderr.take(), log_err)] {
        if let Some(pipe) = pipe {
            readers.push(pump(pipe, log, ctx.workspace_lease()));
        }
    }

    registry.map.lock().await.insert(
        id.clone(),
        Service {
            command: command.to_string(),
            pid,
            log_path: log_path.clone(),
            child,
            readers,
            log_error: None,
        },
    );

    Ok(ToolResult::text(format!(
        "service started: id={id} pid={:?} log={}\n\
         stdout+stderr append to the log. Manage it with the `service` tool: \
         list | logs | stop.",
        pid,
        log_path.display()
    )))
}

fn record_log_result(
    svc: &mut Service,
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
) {
    if let Err(error) = result
        .map_err(|error| error.to_string())
        .and_then(|result| result.map_err(|error| error.to_string()))
    {
        svc.log_error.get_or_insert(error);
        let _ = svc.child.start_kill();
    }
}

async fn status_of(svc: &mut Service) -> String {
    while let Some(index) = svc.readers.iter().position(|reader| reader.is_finished()) {
        let reader = svc.readers.swap_remove(index);
        record_log_result(svc, reader.await);
    }
    match svc.child.try_wait() {
        Ok(Some(status)) => {
            svc.pid = None;
            if !svc.readers.is_empty() {
                "draining".into()
            } else if let Some(error) = &svc.log_error {
                format!("failed(log: {error})")
            } else {
                format!("exited({})", status.code().unwrap_or(-1))
            }
        }
        Ok(None) if svc.log_error.is_some() => "stopping(log failure)".into(),
        Ok(None) => "running".into(),
        Err(error) => format!("unknown({error})"),
    }
}

async fn stop(svc: &mut Service) -> Result<std::process::ExitStatus, ToolError> {
    let status = svc
        .child
        .kill()
        .await
        .map_err(|error| ToolError::Failed(format!("service cleanup: {error}")))?;
    svc.pid = None;
    while let Some(reader) = svc.readers.last_mut() {
        let result = reader.await;
        svc.readers.pop();
        record_log_result(svc, result);
    }
    if let Some(error) = &svc.log_error {
        return Err(ToolError::Failed(format!("service log drain: {error}")));
    }
    Ok(status)
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
struct ServiceArgs {
    /// `list` — all services + liveness; `logs` — tail a service's log;
    /// `stop` — kill a service and report its exit status.
    action: String,
    /// Service id (`svc-N`), required for logs/stop.
    id: Option<String>,
    /// Lines of log tail for `logs` (default 80).
    tail_lines: Option<usize>,
}

pub fn spec<C: SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "service",
        schema: schema_for::<ServiceArgs>(
            "Manage background services started via bash(persistent: true). \
             action=list shows every service with pid/status/log path; \
             action=logs tails its output; action=stop kills it. Services \
             retain their sandbox and execution view across calls. Stop \
             waits for process cleanup and log draining.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        cancel_aware: false,
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

async fn exec<C: SandboxCtx>(args: Args, ctx: Arc<C>) -> Result<ToolResult, ToolError> {
    let parsed: ServiceArgs =
        serde_json::from_value(args).map_err(|e| ToolError::Args(format!("service args: {e}")))?;
    let reg = registry(&*ctx)?;
    match parsed.action.as_str() {
        "list" => {
            let mut map = reg.map.lock().await;
            if map.is_empty() {
                return Ok(ToolResult::text("no services running"));
            }
            let mut out = String::new();
            for (id, svc) in map.iter_mut() {
                let status = status_of(svc).await;
                out.push_str(&format!(
                    "{id}  pid={:?}  {status}  log={}\n    cmd: {}\n",
                    svc.pid,
                    svc.log_path.display(),
                    svc.command
                ));
            }
            Ok(ToolResult::text(out))
        }
        "logs" => {
            let id = parsed
                .id
                .ok_or_else(|| ToolError::Args("logs needs id".into()))?;
            let mut map = reg.map.lock().await;
            let svc = map
                .get_mut(&id)
                .ok_or_else(|| ToolError::Failed(format!("no service {id}")))?;
            let status = status_of(svc).await;
            let body = read_tail(
                &svc.log_path.clone(),
                parsed.tail_lines.unwrap_or(DEFAULT_TAIL_LINES),
            )?;
            Ok(ToolResult::text(format!(
                "── {id} ({status}) tail ──\n{body}"
            )))
        }
        "stop" => {
            let id = parsed
                .id
                .ok_or_else(|| ToolError::Args("stop needs id".into()))?;
            let mut map = reg.map.lock().await;
            let svc = map
                .get_mut(&id)
                .ok_or_else(|| ToolError::Failed(format!("no service {id}")))?;
            let status = tokio::time::timeout(std::time::Duration::from_secs(5), stop(svc))
                .await
                .map_err(|_| {
                    ToolError::Failed(
                        "service stop requested; cleanup is still pending, retry to observe it"
                            .into(),
                    )
                })??;
            map.remove(&id);
            Ok(ToolResult::text(format!("{id} stopped: {status}")))
        }
        other => Err(ToolError::Args(format!(
            "unknown action {other:?} — list | logs | stop"
        ))),
    }
}
