//! The MCP stdio bridge — one `serena start-mcp-server` child plus the
//! JSON-RPC request/response plumbing over its stdin/stdout.
//!
//! Everything here is about *one* server process: spawning it, correlating
//! responses by id, noticing when it dies, and keeping enough of its stderr
//! that a failure is diagnosable. Which workspace a bridge belongs to, and
//! when it is replaced, is [`super::manager`]'s job.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Mutex};

use agent_sandbox::process::{ManagedChild, ProcessInput};
use agent_sandbox::snapshot::SnapshotLease;
use agent_sandbox::spawn::SandboxedChild;
use agent_tool::ToolError;

/// `uvx` first-run can take a while (resolve + build + import); the
/// `initialize` handshake waits this long before giving up.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Per-request MCP timeout — Serena's symbol queries can be slow on the first
/// index, so allow more headroom than a file read.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(90);

/// How much of the child's stderr to keep for error messages. A ring buffer,
/// not a log: Serena is chatty on startup and we only ever want the tail.
const STDERR_TAIL_BYTES: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// One tool as the server describes it in `tools/list`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerenaToolInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Raw JSON Schema — surfaced on demand (`serena_list_tools` for one tool)
    /// rather than dumped for all ~40.
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<Value>,
}

/// A response slot: the reader resolves it with the server's reply, or with a
/// failure reason when the child dies (so a dead server fails its in-flight
/// requests *now* instead of parking them until the timeout).
type Pending = Arc<StdMutex<HashMap<u64, oneshot::Sender<Result<Value, ToolError>>>>>;
type Input = Arc<Mutex<Option<ProcessInput>>>;
type ChildOwner = Arc<Mutex<ManagedChild>>;
type Reader = tokio::task::JoinHandle<Result<(), String>>;

fn fail_pending(pending: &Pending, reason: &str) {
    for (_, tx) in pending.lock().unwrap_or_else(|e| e.into_inner()).drain() {
        let _ = tx.send(Err(ToolError::Failed(reason.to_owned())));
    }
}

async fn cleanup_child(child: &ChildOwner, stdin: &Input) -> Result<(), String> {
    let result = child
        .lock()
        .await
        .kill()
        .await
        .map(|_| ())
        .map_err(|e| format!("serena process cleanup: {e}"));
    stdin.lock().await.take();
    result
}

async fn read_frame(
    reader: &mut (impl AsyncBufRead + Unpin),
    frame: &mut Vec<u8>,
) -> std::io::Result<bool> {
    frame.clear();
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            return Ok(!frame.is_empty());
        }
        let end = bytes.iter().position(|&b| b == b'\n');
        let count = end.map_or(bytes.len(), |n| n + 1);
        if frame.len() + count > MAX_FRAME_BYTES {
            return Err(std::io::Error::other("serena incoming frame exceeds limit"));
        }
        frame.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(true);
        }
    }
}

struct PendingRequest<'a> {
    bridge: &'a SerenaBridge,
    id: u64,
    completed: bool,
}

impl Drop for PendingRequest<'_> {
    fn drop(&mut self) {
        self.bridge
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        if !self.completed {
            self.bridge.cancel("serena request cancelled");
        }
    }
}

/// What the meta-tool needs from a live server. A trait so the manager's
/// scoping and restart behaviour can be tested without `uvx`, without a
/// network, and without a Python environment.
#[async_trait::async_trait]
pub trait McpBridge: Send + Sync {
    /// `tools/call` — flattened text content.
    async fn call(&self, tool: &str, arguments: Value) -> Result<String, ToolError>;
    /// `tools/list`.
    async fn list_tools(&self) -> Result<Vec<SerenaToolInfo>, ToolError>;
    /// False once the child is gone; the manager must not hand this out again.
    fn is_healthy(&self) -> bool;
    /// Recent stderr for error context (empty when the child never wrote any).
    async fn diagnostics(&self) -> String;
}

/// Spawns one bridge for one workspace root.
#[async_trait::async_trait]
pub trait BridgeFactory: Send + Sync {
    async fn spawn(&self, root: &Path) -> Result<Arc<dyn McpBridge>, ToolError>;
}

/// How to launch Serena.
///
/// The installed CLI (`uv tool install -p 3.13 serena-agent` + `serena init`) is
/// preferred: `uvx` re-resolves the repo branch on every cold start. `uvx` stays
/// as the fallback; `AGENT_SERENA_CMD` / `AGENT_SERENA_SOURCE` let a deployment
/// pin a build, and tests point `argv_override` at a stub MCP server.
#[derive(Debug, Clone)]
pub struct SerenaLaunch {
    /// `None` = prefer an installed `serena` and fall back to `uvx`.
    pub program: Option<String>,
    pub source: String,
    /// Repeated `--mode` values. The default drops Serena's own memory and
    /// onboarding tools: nothing here uses them and they only lengthen the
    /// catalog. `AGENT_SERENA_MODES=` (empty) keeps them.
    pub modes: Vec<String>,
    /// Full argv override — the stub-server tests launch this way.
    pub argv_override: Option<Vec<String>>,
}

impl SerenaLaunch {
    pub fn from_env() -> Self {
        Self {
            program: std::env::var("AGENT_SERENA_CMD").ok(),
            source: std::env::var("AGENT_SERENA_SOURCE")
                .unwrap_or_else(|_| "git+https://github.com/oraios/serena".into()),
            modes: std::env::var("AGENT_SERENA_MODES")
                .map(|raw| {
                    raw.split([',', ' '])
                        .map(str::trim)
                        .filter(|m| !m.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|_| vec!["no-memories".into()]),
            argv_override: None,
        }
    }

    /// `start-mcp-server` plus the flags upstream documents for a workspace-scoped
    /// client: stdio, the project root, the `ide` context (basic file ops and
    /// shell belong to the host agent), and no dashboard window.
    fn server_args(&self, root: &Path) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "start-mcp-server".into(),
            "--transport".into(),
            "stdio".into(),
            "--project".into(),
            root.to_string_lossy().into_owned(),
            "--context".into(),
            "ide".into(),
            "--open-web-dashboard".into(),
            "false".into(),
        ];
        for mode in &self.modes {
            args.push("--mode".into());
            args.push(mode.clone());
        }
        args
    }

    /// `uvx` runs Serena straight from the repo — the documented fallback when
    /// nothing is installed. `-p 3.13` is not optional: Serena needs 3.13.
    fn uvx_args(&self, root: &Path) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "-p".into(),
            "3.13".into(),
            "--from".into(),
            self.source.clone(),
            "serena".into(),
        ];
        args.extend(self.server_args(root));
        args
    }

    fn argv_for(&self, program: &str, root: &Path) -> Vec<String> {
        if program.rsplit('/').next() == Some("uvx") {
            return self.uvx_args(root);
        }
        self.server_args(root)
    }

    /// Explicit override → installed `serena` → `uvx`.
    pub(crate) fn resolve(&self, root: &Path) -> (String, Vec<String>) {
        if let Some(argv) = &self.argv_override {
            let program = self.program.clone().unwrap_or_else(|| "serena".into());
            return (program, argv.clone());
        }
        if let Some(program) = &self.program {
            let args = self.argv_for(program, root);
            return (program.clone(), args);
        }
        match which("serena") {
            Some(installed) => (installed, self.server_args(root)),
            None => ("uvx".into(), self.uvx_args(root)),
        }
    }

    fn command(&self, program: &str, args: &[String], root: &Path) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Piped, never null: a startup failure with a nulled stderr is
            // undiagnosable (see `diagnostics`).
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        cmd
    }
}

/// First hit for `bin` on PATH — the difference between "the user installed
/// Serena" and "fall back to `uvx`".
fn which(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
        .map(|p| p.display().to_string())
}

pub struct SerenaBridge {
    /// Resolved launch command — what `resolve()` picked, for error messages.
    program: String,
    /// Root the server was scoped to — for diagnostics and error messages.
    root: std::path::PathBuf,
    stdin: Input,
    pending: Pending,
    req_id: AtomicU64,
    // Cleanup requests kill before yielding while this lock is held.
    child: ChildOwner,
    readers: Mutex<Vec<Reader>>,
    /// Closed request admission, shared with the stdout owner.
    dead: Arc<AtomicBool>,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
}

impl SerenaBridge {
    /// Spawn the server scoped to `root`, pump its streams, then run the
    /// `initialize` handshake.
    pub async fn spawn(root: &Path) -> Result<Arc<Self>, ToolError> {
        Self::spawn_with(root, SerenaLaunch::from_env()).await
    }

    pub async fn spawn_with(root: &Path, launch: SerenaLaunch) -> Result<Arc<Self>, ToolError> {
        let (program, args) = launch.resolve(root);
        let child = launch.command(&program, &args, root).spawn().map_err(|e| {
            ToolError::Failed(format!(
                "spawn serena via `{program}` failed: {e}\n(install it: `uv tool install \
                 -p 3.13 serena-agent`, then `serena init` — `uvx` is only the fallback)"
            ))
        })?;
        Self::connect(root, program, ManagedChild::from_process_group(child), None).await
    }

    /// Attach to an isolated server, retaining its lease until stdio cleanup completes.
    pub async fn from_isolated(
        root: &Path,
        program: String,
        child: SandboxedChild,
        lease: Arc<SnapshotLease>,
    ) -> Result<Arc<Self>, ToolError> {
        Self::from_managed(root, program, child.into(), Some(lease)).await
    }

    /// Attach to a managed child. A lease stays alive until owned stdio tasks finish.
    pub async fn from_managed(
        root: &Path,
        program: String,
        child: ManagedChild,
        lease: Option<Arc<SnapshotLease>>,
    ) -> Result<Arc<Self>, ToolError> {
        Self::connect(root, program, child, lease).await
    }

    async fn connect(
        root: &Path,
        program: String,
        mut child: ManagedChild,
        lease: Option<Arc<SnapshotLease>>,
    ) -> Result<Arc<Self>, ToolError> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ToolError::Failed("serena child has no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ToolError::Failed("serena child has no stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ToolError::Failed("serena child has no stderr".into()))?;

        let pending: Pending = Arc::new(StdMutex::new(HashMap::new()));
        let stderr_tail: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
        let bridge = Arc::new(Self {
            program,
            root: root.to_path_buf(),
            stdin: Arc::new(Mutex::new(Some(stdin))),
            pending: pending.clone(),
            req_id: AtomicU64::new(1),
            child: Arc::new(Mutex::new(child)),
            readers: Mutex::new(Vec::new()),
            dead: Arc::new(AtomicBool::new(false)),
            stderr_tail: stderr_tail.clone(),
        });

        // stderr → ring buffer. Chunked, not line-based: uv/pip progress and a
        // Python traceback both arrive without useful line structure.
        let stderr_ring = stderr_tail.clone();
        let stderr_lease = lease.clone();
        let stderr_task = tokio::spawn(async move {
            let _lease = stderr_lease;
            let mut reader = BufReader::new(stderr);
            let mut buf = [0u8; 4096];
            let tail = stderr_ring;
            loop {
                let n = reader
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("serena stderr: {e}"))?;
                if n == 0 {
                    break;
                }
                let mut ring = tail.lock().await;
                ring.extend(&buf[..n]);
                while ring.len() > STDERR_TAIL_BYTES {
                    ring.pop_front();
                }
            }
            Ok(())
        });

        let stdout_task = {
            let pending = pending.clone();
            let dead = bridge.dead.clone();
            let child = bridge.child.clone();
            let stdin = bridge.stdin.clone();
            tokio::spawn(async move {
                let _lease = lease;
                let mut reader = BufReader::new(stdout);
                let mut frame = Vec::new();
                let reason = loop {
                    match read_frame(&mut reader, &mut frame).await {
                        Ok(true) => {}
                        Ok(false) => break "serena server exited before answering".to_owned(),
                        Err(e) => break format!("serena stdout: {e}"),
                    }
                    let Ok(v) = serde_json::from_slice::<Value>(&frame) else {
                        continue;
                    };
                    if v.get("method").is_some()
                        || (v.get("result").is_none() && v.get("error").is_none())
                    {
                        continue;
                    }
                    if let Some(id) = v.get("id").and_then(|i| i.as_u64()) {
                        let tx = pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&id);
                        if let Some(tx) = tx {
                            let _ = tx.send(Ok(v));
                        }
                    }
                };
                dead.store(true, Ordering::Release);
                fail_pending(&pending, &reason);
                cleanup_child(&child, &stdin).await
            })
        };
        *bridge.readers.lock().await = vec![stderr_task, stdout_task];

        match bridge.initialize().await {
            Ok(()) => Ok(bridge),
            Err(e) => {
                let e = bridge.transport_failure(e).await;
                Err(ToolError::Failed(format!(
                    "serena did not come up ({}): {e}",
                    bridge.program,
                )))
            }
        }
    }

    async fn stderr_suffix(&self) -> String {
        let tail = self.diagnostics().await;
        if tail.trim().is_empty() {
            String::new()
        } else {
            format!("\nserena stderr (tail):\n{tail}")
        }
    }

    fn cancel(&self, reason: &str) {
        self.dead.store(true, Ordering::Release);
        fail_pending(&self.pending, reason);
        if let Ok(mut child) = self.child.try_lock() {
            let _ = child.start_kill();
        }
    }

    /// Confirm process termination and completion of every owned stdio task.
    pub async fn shutdown(&self) -> Result<(), ToolError> {
        self.cancel("serena bridge shut down");
        tokio::time::timeout(CLEANUP_TIMEOUT, async {
            cleanup_child(&self.child, &self.stdin)
                .await
                .map_err(ToolError::Failed)?;
            let mut readers = self.readers.lock().await;
            let mut failure = None;
            // Keep the handle in the bridge while waiting so cancellation cannot detach it.
            while let Some(reader) = readers.last_mut() {
                let result = reader
                    .await
                    .map_err(|e| format!("serena reader task: {e}"))
                    .and_then(|result| result);
                readers.pop();
                if let Err(error) = result {
                    failure.get_or_insert(error);
                }
            }
            failure.map_or(Ok(()), |error| Err(ToolError::Failed(error)))
        })
        .await
        .map_err(|_| ToolError::Failed("serena cleanup timed out; quiescence unconfirmed".into()))?
    }

    async fn transport_failure(&self, error: ToolError) -> ToolError {
        let error = match self.shutdown().await {
            Ok(()) => error,
            Err(cleanup) => ToolError::Failed(format!("{error}; {cleanup}")),
        };
        self.enrich(error).await
    }

    /// `initialize` + `notifications/initialized` handshake.
    async fn initialize(&self) -> Result<(), ToolError> {
        let init = json!({
            "jsonrpc":"2.0","id":0,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},
                      // The kernel is the client of this local MCP subprocess; the
                      // host's own name is not reachable here (the factory is a
                      // process-wide static), so it identifies itself neutrally.
                      "clientInfo":{"name":"agent-kernel","version": env!("CARGO_PKG_VERSION")}}
        });
        self.request(init, STARTUP_TIMEOUT).await?;
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        self.send(&note).await
    }

    /// Write one JSON-RPC line to the child's stdin.
    async fn send(&self, body: &Value) -> Result<(), ToolError> {
        if !self.is_healthy() {
            return Err(ToolError::Failed(format!(
                "serena server for {} is gone",
                self.root.display()
            )));
        }
        let mut line = serde_json::to_vec(body)
            .map_err(|e| ToolError::Failed(format!("serena encode: {e}")))?;
        line.push(b'\n');
        if line.len() > MAX_FRAME_BYTES {
            return Err(ToolError::Failed(
                "serena outgoing frame exceeds limit".into(),
            ));
        }
        let mut stdin = self.stdin.lock().await;
        let stdin = stdin
            .as_mut()
            .ok_or_else(|| ToolError::Failed("serena stdin is closed".into()))?;
        stdin
            .write_all(&line)
            .await
            .map_err(|e| ToolError::Failed(format!("serena stdin: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| ToolError::Failed(format!("serena flush: {e}")))
    }

    /// Send a request and wait for its reply.
    ///
    /// The pending slot is removed on **every** exit path — a send failure, a
    /// timeout, or a reply — because the map outlives the call: a leaked entry
    /// is a `Sender` nobody will ever resolve.
    async fn request(&self, body: Value, timeout: Duration) -> Result<Value, ToolError> {
        let id = body.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, tx);
        let mut guard = PendingRequest {
            bridge: self,
            id,
            completed: false,
        };
        let reply = tokio::time::timeout(timeout, async {
            self.send(&body).await?;
            rx.await
                .map_err(|_| ToolError::Failed("serena response channel closed".into()))?
        })
        .await
        .unwrap_or_else(|_| {
            Err(ToolError::Failed(format!(
                "serena request timed out after {}s",
                timeout.as_secs()
            )))
        });
        let v = match reply {
            Ok(v) => v,
            Err(e) => return Err(self.transport_failure(e).await),
        };
        guard.completed = true;
        if let Some(err) = v.get("error") {
            return Err(ToolError::Failed(format!("serena rpc: {err}")));
        }
        Ok(v.get("result").cloned().unwrap_or(v))
    }

    /// Append the stderr tail to a failure — the only window into what the
    /// server process actually said.
    async fn enrich(&self, e: ToolError) -> ToolError {
        ToolError::Failed(format!("{e}{}", self.stderr_suffix().await))
    }
}

impl Drop for SerenaBridge {
    fn drop(&mut self) {
        self.cancel("serena bridge dropped");
    }
}

#[async_trait::async_trait]
impl McpBridge for SerenaBridge {
    async fn call(&self, tool: &str, arguments: Value) -> Result<String, ToolError> {
        let id = self.req_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":tool,"arguments":arguments}
        });
        let result = self.request(body, CALL_TIMEOUT).await?;
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let text = content
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n");
            if !text.is_empty() {
                return Ok(text);
            }
        }
        Ok(result.to_string())
    }

    async fn list_tools(&self) -> Result<Vec<SerenaToolInfo>, ToolError> {
        let id = self.req_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}});
        let result = self.request(body, CALL_TIMEOUT).await?;
        Ok(result
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| serde_json::from_value::<SerenaToolInfo>(t.clone()).ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn is_healthy(&self) -> bool {
        !self.dead.load(Ordering::Acquire)
    }

    async fn diagnostics(&self) -> String {
        let ring = self.stderr_tail.lock().await;
        let bytes: Vec<u8> = ring.iter().copied().collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that steer the stub through the process env: the
    /// stub mode is per *process*, so two of them must not overlap.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        GUARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Full path libtest needs to run exactly this test in the child. Relative
    /// to this crate's test binary — `--exact` matches the module path inside
    /// it, which is `bridge::…` here, not the kernel's `tools::serena::bridge::…`.
    const STUB_TEST: &str = "bridge::tests::stub_mcp_server";
    const STUB_MODE: &str = "AGENT_SERENA_STUB";

    /// Launch the current test binary as a stub MCP server. The stub is the
    /// same executable re-entered with `--exact <stub test>` — no `uvx`, no
    /// network, no Python, and it exercises the *real* reader/writer plumbing
    /// (pending map, death detection, stderr capture).
    fn stub_launch() -> SerenaLaunch {
        SerenaLaunch {
            program: Some(
                std::env::current_exe()
                    .expect("test binary path")
                    .display()
                    .to_string(),
            ),
            source: String::new(),
            modes: Vec::new(),
            argv_override: Some(vec![
                "--exact".into(),
                STUB_TEST.into(),
                "--nocapture".into(),
                "--quiet".into(),
            ]),
        }
    }

    /// The stub server. Only active in the re-executed child; in the parent
    /// run it is a no-op test.
    ///
    /// Both conditions matter: the env var is process-global and libtest runs
    /// tests in parallel, so in the parent another test's `set_var` could be
    /// visible here — and then this test would read the *parent's* stdin and
    /// hang (or `exit` the parent's test binary mid-run). The `--exact` argv is
    /// only ever present in the child.
    #[test]
    fn stub_mcp_server() {
        let reexecuted = std::env::args().any(|a| a == "--exact");
        if std::env::var(STUB_MODE).is_err() || !reexecuted {
            return;
        }
        stub_main();
        std::process::exit(0);
    }

    fn stub_main() {
        use std::io::{BufRead, Write};
        let mode = std::env::var(STUB_MODE).unwrap_or_default();
        let mut held: Option<Value> = None;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { return };
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let id = v.get("id").cloned();
            let reply = |result: Value| {
                let mut out = std::io::stdout();
                let _ = writeln!(out, "{}", json!({"jsonrpc":"2.0","id":id,"result":result}));
                let _ = out.flush();
            };
            match method {
                "initialize" => reply(json!({"protocolVersion":"2024-11-05","capabilities":{}})),
                "tools/list" => reply(json!({"tools":[{
                    "name":"find_symbol",
                    "description":"Find symbols.\nMore detail.",
                    "inputSchema":{"type":"object","properties":{"name_path":{"type":"string"}},"required":["name_path"]}
                }]})),
                "tools/call" => match mode.as_str() {
                    // Exit without answering — the "serena died mid-call" case.
                    "die-on-call" => {
                        eprintln!("serena stub: fatal: index corrupt");
                        return;
                    }
                    // Never answer — drives the timeout path.
                    "silent" => {}
                    "oversized" => {
                        let _ = std::io::stdout().write_all(&vec![b'x'; MAX_FRAME_BYTES + 1]);
                        let _ = std::io::stdout().flush();
                    }
                    "reverse-order" => {
                        if let Some(first) = held.take() {
                            for request in [v, first] {
                                let response = json!({
                                    "jsonrpc":"2.0",
                                    "id":request["id"],
                                    "result":{"content":[{
                                        "type":"text",
                                        "text":request["params"]["arguments"]["name_path"],
                                    }]}
                                });
                                let _ = writeln!(std::io::stdout(), "{response}");
                            }
                            let _ = std::io::stdout().flush();
                        } else {
                            held = Some(v);
                        }
                    }
                    "rpc-error" => {
                        let error = json!({
                            "jsonrpc":"2.0",
                            "id":id,
                            "error":{"code":-32602,"message":"bad arguments"},
                        });
                        let _ = writeln!(std::io::stdout(), "{error}");
                        let _ = std::io::stdout().flush();
                    }
                    "write-on-call" => {
                        std::fs::write("private-effect", "isolated").unwrap();
                        if v["params"]["arguments"]["wait"] != true {
                            reply(json!({"content":[{"type":"text","text":"stub-ok"}]}));
                        }
                    }
                    _ => reply(json!({"content":[{"type":"text","text":"stub-ok"}]})),
                },
                _ => {}
            }
        }
    }

    async fn stub_session(
        mode: &str,
        root: &Path,
    ) -> (Arc<SerenaBridge>, std::sync::MutexGuard<'static, ()>) {
        let guard = env_guard();
        std::env::set_var(STUB_MODE, mode);
        // `.await`, never `block_on`: the bridge's reader tasks live on this
        // runtime, and blocking the current-thread runtime here would stall the
        // very task that answers `initialize`.
        let bridge = SerenaBridge::spawn_with(root, stub_launch())
            .await
            .expect("stub server should come up");
        (bridge, guard)
    }

    #[tokio::test]
    async fn initialize_call_and_list_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _guard) = stub_session("ok", dir.path()).await;
        assert!(bridge.is_healthy());
        assert_eq!(
            bridge
                .call("find_symbol", json!({"name_path":"x"}))
                .await
                .unwrap(),
            "stub-ok"
        );

        let tools = bridge.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "find_symbol");
        assert!(tools[0]
            .input_schema
            .as_ref()
            .unwrap()
            .get("properties")
            .is_some());
        bridge.shutdown().await.unwrap();
        assert!(bridge.readers.lock().await.is_empty());
        assert!(bridge.stdin.lock().await.is_none());
        assert!(bridge.child.lock().await.try_wait().unwrap().is_some());
    }

    /// A child that exits mid-request must promptly report its stderr diagnostics.
    #[tokio::test]
    async fn dying_child_fails_in_flight_calls_with_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _guard) = stub_session("die-on-call", dir.path()).await;

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            bridge.call("replace_symbol_body", json!({})),
        )
        .await
        .expect("a dead child must not park the caller until CALL_TIMEOUT")
        .expect_err("the call cannot succeed");
        let msg = format!("{err}");
        assert!(msg.contains("exited"), "{msg}");
        assert!(msg.contains("index corrupt"), "stderr tail missing: {msg}");
        assert!(!bridge.is_healthy(), "death must mark the bridge unhealthy");
        assert!(bridge.diagnostics().await.contains("index corrupt"));
    }

    /// Timeouts and send failures must not leave entries in `pending` — the
    /// map outlives the call, so a leaked slot is a sender nobody resolves.
    #[tokio::test]
    async fn failures_leave_no_pending_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _guard) = stub_session("silent", dir.path()).await;

        // Timeout path.
        let body = json!({"jsonrpc":"2.0","id":77,"method":"tools/call","params":{}});
        let err = bridge
            .request(body, Duration::from_millis(150))
            .await
            .expect_err("no reply must time out");
        assert!(format!("{err}").contains("timed out"), "{err}");
        assert!(
            bridge.pending.lock().unwrap().is_empty(),
            "timeout leaked a pending slot"
        );

        // A closed bridge rejects new sends without retaining pending entries.
        let body = json!({"jsonrpc":"2.0","id":78,"method":"tools/call","params":{}});
        bridge
            .request(body, Duration::from_millis(150))
            .await
            .expect_err("dead bridge");
        assert!(
            bridge.pending.lock().unwrap().is_empty(),
            "send failure leaked a pending slot"
        );
    }

    #[tokio::test]
    async fn cancelled_request_closes_the_transport_and_fails_other_waiters() {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _guard) = stub_session("silent", dir.path()).await;
        let other = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.call("find_symbol", json!({})).await })
        };
        assert!(tokio::time::timeout(
            Duration::from_millis(100),
            bridge.call("find_symbol", json!({})),
        )
        .await
        .is_err());
        tokio::time::timeout(Duration::from_secs(10), other)
            .await
            .unwrap()
            .unwrap()
            .expect_err("cancelling a request must fail other waiters");
        bridge.shutdown().await.unwrap();
        assert!(!bridge.is_healthy());
        assert!(bridge.pending.lock().unwrap().is_empty());
        assert!(bridge.child.lock().await.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn oversized_frame_fails_the_request_and_reaps_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _guard) = stub_session("oversized", dir.path()).await;
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            bridge.call("find_symbol", json!({})),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(
            error.to_string().contains("incoming frame exceeds limit"),
            "{error}"
        );
        assert!(!bridge.is_healthy());
        assert!(bridge.pending.lock().unwrap().is_empty());
        assert!(bridge.child.lock().await.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn concurrent_calls_match_out_of_order_replies_and_rpc_errors_keep_the_server() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (bridge, _guard) = stub_session("reverse-order", dir.path()).await;
            let (first, second) = tokio::join!(
                bridge.call("find_symbol", json!({"name_path":"first"})),
                bridge.call("find_symbol", json!({"name_path":"second"})),
            );
            assert_eq!(first.unwrap(), "first");
            assert_eq!(second.unwrap(), "second");
            bridge.shutdown().await.unwrap();
        }
        let (bridge, _guard) = stub_session("rpc-error", dir.path()).await;
        let error = bridge.call("find_symbol", json!({})).await.unwrap_err();
        assert!(error.to_string().contains("bad arguments"), "{error}");
        assert!(bridge.is_healthy());
        assert_eq!(bridge.list_tools().await.unwrap().len(), 1);
        bridge.shutdown().await.unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn isolated_transport_holds_the_real_lease_through_io_cleanup() {
        use std::os::unix::fs::PermissionsExt;

        use agent_sandbox::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
        use agent_sandbox::spawn::{
            spawn_isolated, ExecutionKind, IsolatedSpawn, MemoryEnforcement,
        };
        use agent_sandbox::traits::SandboxConfig;

        for termination in ["shutdown", "cancel", "drop"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let source = root.join("source");
            let storage = root.join("storage");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::create_dir_all(&storage).unwrap();
            std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(source.join("original"), "unchanged").unwrap();
            let mut snapshot = WorkspaceSnapshot::prepare(
                std::slice::from_ref(&source),
                &storage,
                SnapshotBudget {
                    max_bytes: 1024 * 1024,
                    max_entries: 64,
                    max_depth: 8,
                },
                SnapshotPreference::PrivateCopy,
            )
            .unwrap();
            let lease = Arc::new(snapshot.lease().unwrap());
            let program = std::env::current_exe().unwrap();
            let request = IsolatedSpawn {
                executable: program.clone(),
                args: vec![
                    "--exact".into(),
                    STUB_TEST.into(),
                    "--nocapture".into(),
                    "--quiet".into(),
                ],
                env: vec![
                    (STUB_MODE.into(), "write-on-call".into()),
                    ("RUST_TEST_THREADS".into(), "1".into()),
                ],
                root: lease.roots().next(),
                read_only: vec![program.clone(), "/usr/lib".into(), "/System/Library".into()],
                deny_read: Vec::new(),
                deny_write: Vec::new(),
                max_memory_bytes: 128 * 1024 * 1024,
                max_processes: 1,
                memory_enforcement: MemoryEnforcement::MonitoredRss,
                kind: ExecutionKind::Tool,
                tool_policy: Some(SandboxConfig {
                    workspace_dir: source.clone(),
                    ..Default::default()
                }),
                linux_launcher: None,
                linux_cgroup_parent: None,
            };
            let child = spawn_isolated(lease.clone(), &request).unwrap();
            let bridge = tokio::time::timeout(
                Duration::from_secs(10),
                SerenaBridge::from_isolated(&source, program.display().to_string(), child, lease),
            )
            .await
            .expect("isolated MCP handshake must complete")
            .unwrap();
            assert_eq!(
                bridge.call("find_symbol", json!({})).await.unwrap(),
                "stub-ok"
            );
            assert!(
                snapshot.seal().is_err(),
                "live transport must occupy the lease"
            );
            let retained = match termination {
                "shutdown" => {
                    bridge.shutdown().await.unwrap();
                    assert!(bridge.stdin.lock().await.is_none());
                    assert!(bridge.readers.lock().await.is_empty());
                    assert!(bridge.child.lock().await.try_wait().unwrap().is_some());
                    Some(bridge)
                }
                "cancel" => {
                    assert!(tokio::time::timeout(
                        Duration::from_millis(100),
                        bridge.call("find_symbol", json!({"wait":true})),
                    )
                    .await
                    .is_err());
                    assert!(!bridge.is_healthy());
                    Some(bridge)
                }
                "drop" => {
                    drop(bridge);
                    None
                }
                _ => unreachable!(),
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                while snapshot.seal().is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("transport termination must release the real lease");
            if let Some(bridge) = retained {
                assert!(bridge.stdin.lock().await.is_none());
                assert!(bridge
                    .readers
                    .lock()
                    .await
                    .iter()
                    .all(|task| task.is_finished()));
                assert!(bridge.child.lock().await.try_wait().unwrap().is_some());
            }
            let changes = snapshot.diff().unwrap();
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].path, Path::new("private-effect"));
            assert!(!source.join("private-effect").exists());
            assert_eq!(
                std::fs::read_to_string(source.join("original")).unwrap(),
                "unchanged"
            );
        }
    }

    #[tokio::test]
    async fn spawn_reports_a_missing_program_with_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let launch = SerenaLaunch {
            program: Some("/nonexistent/uvx-for-husk-test".into()),
            source: "git+https://example.invalid/serena".into(),
            modes: Vec::new(),
            argv_override: None,
        };
        let err = SerenaBridge::spawn_with(dir.path(), launch)
            .await
            .err()
            .expect("a missing uvx must surface, not panic");
        let msg = format!("{err}");
        assert!(msg.contains("spawn serena"), "{msg}");
        assert!(msg.contains("uvx-for-husk-test"), "{msg}");
    }

    /// The launch shape is a contract with Serena's CLI: stdio, the project, the
    /// `ide` context, no dashboard window, and `-p 3.13` on the `uvx` fallback.
    #[test]
    fn launch_args_follow_the_documented_serena_cli() {
        let launch = SerenaLaunch {
            program: None,
            source: "git+https://example.invalid/serena".into(),
            modes: vec!["no-memories".into()],
            argv_override: None,
        };
        let server = launch.server_args(Path::new("/ws"));
        assert_eq!(server[0], "start-mcp-server");
        let value = |flag: &str| {
            server
                .windows(2)
                .find(|w| w[0] == flag)
                .map(|w| w[1].clone())
        };
        assert_eq!(value("--transport").as_deref(), Some("stdio"));
        assert_eq!(value("--project").as_deref(), Some("/ws"));
        assert_eq!(value("--context").as_deref(), Some("ide"));
        assert_eq!(value("--mode").as_deref(), Some("no-memories"));
        assert_eq!(value("--open-web-dashboard").as_deref(), Some("false"));

        let uvx = launch.uvx_args(Path::new("/ws"));
        let head: Vec<&str> = uvx.iter().take(6).map(String::as_str).collect();
        assert_eq!(
            head,
            vec![
                "-p",
                "3.13",
                "--from",
                "git+https://example.invalid/serena",
                "serena",
                "start-mcp-server"
            ]
        );

        let bare = SerenaLaunch {
            modes: Vec::new(),
            ..launch
        };
        assert!(!bare
            .server_args(Path::new("/ws"))
            .iter()
            .any(|a| a == "--mode"));
    }
}
