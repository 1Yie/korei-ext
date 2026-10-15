//! `service` — manage long-lived background processes launched by
//! `bash(persistent: true)`.
//!
//! Why a separate channel: `run_command` deliberately kills its whole
//! process tree when the call ends (pidns init + die-with-parent), so dev
//! servers / databases / watchers can't survive between bash calls.
//! `SandboxBackend::wrap_spawn` is the other spawn path — the kernel owns
//! the returned `Command`, so we park its `Child` in this process-wide
//! registry and hand the model a `service` tool to observe or stop it.
//!
//! Containment is unchanged: the service runs under the same sandbox argv
//! (read-only host fs + writable roots + domain-scoped egress proxy +
//! pidns + die-with-parent); it simply isn't reaped when the spawning
//! call returns. `--die-with-parent` still ends every service when the
//! agent process exits. On the `none` backend the child is unsandboxed
//! and loud, same contract as `run_command`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use futures::FutureExt;
use tokio::sync::Mutex;

use agent_capabilities::SandboxCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Cap on a `logs` read — services can write unbounded output.
const MAX_LOG_BYTES: u64 = 256 * 1024;
const DEFAULT_TAIL_LINES: usize = 80;

/// The set of live background services one owner can see and stop. A host
/// installs one per session ([`ServiceRegistrySlot`]) so sessions never see
/// each other's services; a context without a slot uses the process default.
/// Dropping the registry kills whatever it still holds.
#[derive(Default)]
pub struct ServiceRegistry {
    map: Mutex<BTreeMap<String, Service>>,
}

/// Host-installed registry for this context (and its delegated children).
pub struct ServiceRegistrySlot(pub Arc<ServiceRegistry>);

/// Ids stay unique process-wide so log files never collide across registries.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn registry<C: SandboxCtx>(ctx: &C) -> Arc<ServiceRegistry> {
    static DEFAULT: LazyLock<Arc<ServiceRegistry>> = LazyLock::new(Default::default);
    ctx.service::<ServiceRegistrySlot>()
        .map(|slot| slot.0.clone())
        .unwrap_or_else(|| DEFAULT.clone())
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
    /// `None` after a stop consumed it.
    child: Option<tokio::process::Child>,
}

impl Drop for Service {
    fn drop(&mut self) {
        // A removed entry never leaks its process — `start_kill` is the
        // sync variant Drop can call. (bwrap's die-with-parent also covers
        // process exit; this is for the `none` backend and early removal.)
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
        }
    }
}

fn log_dir() -> PathBuf {
    std::env::temp_dir().join(format!("agent-svc-{}", std::process::id()))
}

/// Spawn `command` as a registered background service via `wrap_spawn`.
/// Called by `bash` when `persistent: true`. Returns the model-facing text.
pub async fn spawn_persistent<C: SandboxCtx>(
    ctx: &Arc<C>,
    cfg: &agent_sandbox::SandboxConfig,
    command: &str,
) -> Result<ToolResult, ToolError> {
    let sandbox = ctx.sandbox()?;
    let mut cmd = sandbox
        .wrap_spawn(cfg, "/bin/sh", &["-c", command])
        .ok_or_else(|| {
            ToolError::Failed(format!(
                "sandbox backend {:?} can't spawn persistent services",
                sandbox.id()
            ))
        })?;

    let id = format!("svc-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let dir = log_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| ToolError::Failed(format!("service log dir: {e}")))?;
    let log_path = dir.join(format!("{id}.log"));
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| ToolError::Failed(format!("service log file: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| ToolError::Failed(e.to_string()))?;

    cmd.stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err))
        // Caller-owned lifetime — kill_on_drop would defeat the feature.
        .kill_on_drop(false);

    let child = cmd
        .spawn()
        .map_err(|e| ToolError::Failed(format!("spawn service: {e}")))?;
    let pid = child.id();

    registry(&**ctx).map.lock().await.insert(
        id.clone(),
        Service {
            command: command.to_string(),
            pid,
            log_path: log_path.clone(),
            child: Some(child),
        },
    );

    Ok(ToolResult::text(format!(
        "service started: id={id} pid={:?} log={}\n\
         stdout+stderr append to the log; it dies when the agent process \
         exits (die-with-parent). Manage it with the `service` tool: \
         list | logs | stop.",
        pid,
        log_path.display()
    )))
}

/// Last `lines` of the log, reading at most MAX_LOG_BYTES from the tail.
fn read_log_tail(path: &PathBuf, lines: usize) -> Result<String, ToolError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)
        .map_err(|e| ToolError::Failed(format!("log {}: {e}", path.display())))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let off = len.saturating_sub(MAX_LOG_BYTES);
    f.seek(SeekFrom::Start(off)).ok();
    let mut buf = String::new();
    f.read_to_string(&mut buf)
        .map_err(|e| ToolError::Failed(e.to_string()))?;
    // If we cut mid-line, drop the partial first line.
    if off > 0 {
        if let Some(nl) = buf.find('\n') {
            buf.drain(..=nl);
        }
    }
    let tail: Vec<&str> = buf.lines().collect();
    let start = tail.len().saturating_sub(lines);
    Ok(tail[start..].join("\n"))
}

fn status_of(svc: &mut Service) -> String {
    match svc.child.as_mut() {
        None => "stopped".into(),
        Some(c) => match c.try_wait() {
            Ok(Some(s)) => format!("exited({})", s.code().unwrap_or(-1)),
            Ok(None) => "running".into(),
            Err(e) => format!("unknown({e})"),
        },
    }
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
             share the sandbox (same fs/network policy) and die when the \
             agent process exits.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: None,
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

async fn exec<C: SandboxCtx>(args: Args, ctx: Arc<C>) -> Result<ToolResult, ToolError> {
    let parsed: ServiceArgs =
        serde_json::from_value(args).map_err(|e| ToolError::Args(format!("service args: {e}")))?;
    let reg = registry(&*ctx);
    match parsed.action.as_str() {
        "list" => {
            let mut map = reg.map.lock().await;
            if map.is_empty() {
                return Ok(ToolResult::text("no services running"));
            }
            let mut out = String::new();
            for (id, svc) in map.iter_mut() {
                let status = status_of(svc);
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
            let status = status_of(svc);
            let body = read_log_tail(
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
            // Take the child out under a short lock; await outside it.
            let child = {
                let mut map = reg.map.lock().await;
                let svc = map
                    .get_mut(&id)
                    .ok_or_else(|| ToolError::Failed(format!("no service {id}")))?;
                svc.child.take()
            };
            match child {
                None => Ok(ToolResult::text(format!("{id} already stopped"))),
                Some(mut c) => {
                    if c.try_wait().ok().flatten().is_none() {
                        c.kill().await.ok();
                    }
                    let status = tokio::time::timeout(std::time::Duration::from_secs(5), c.wait())
                        .await
                        .map(|r| r.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string()))
                        .unwrap_or_else(|_| "kill sent, wait timed out".into());
                    reg.map.lock().await.remove(&id);
                    Ok(ToolResult::text(format!("{id} stopped: {status}")))
                }
            }
        }
        other => Err(ToolError::Args(format!(
            "unknown action {other:?} — list | logs | stop"
        ))),
    }
}
