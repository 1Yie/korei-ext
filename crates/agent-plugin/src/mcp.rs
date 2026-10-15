//! `mcp.rs` — MCP JSON-RPC 2.0 client over stdio or streamable HTTP.
//!
//! Transport comes from the manifest `entry`: `{command, args}` spawns a child
//! (newline-framed stdio), `{url}` POSTs to a streamable-HTTP endpoint (plain JSON or
//! SSE, `Mcp-Session-Id` carried across calls).
//!
//! Protocol `2024-11-05`, full lifecycle — anything less fails real servers:
//!
//! ```text
//! spawn → initialize → notifications/initialized → tools/list
//!   → (steady) tools/call + resources/prompts per caps
//!   → notifications/tools/list_changed → re-list → drain + kill
//! ```
//!
//! `id` resolves pending oneshots, `method` dispatches notifications. Per-call 30s
//! timeout; non-text `content[]` becomes a placeholder marker.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use crate::manifest::PluginManifest;

const PROTOCOL_VERSION: &str = "2024-11-05";
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Restarts allowed on transport failure (never mid-request).
#[allow(dead_code)]
const MAX_RESTARTS: u8 = 3;

/// Server capabilities declared at `initialize`.
#[derive(Debug, Default, Clone)]
pub struct ServerCaps {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
}

/// How the client reaches its server — picked by the manifest `entry`.
enum Transport {
    /// `{command, args}` — child process, newline-framed stdio.
    Stdio {
        stdin: Arc<Mutex<ChildStdin>>,
        /// Held for kill-on-drop; never touched directly.
        _child: Mutex<Child>,
    },
    /// `{url}` — streamable HTTP: each JSON-RPC message is one POST; the
    /// reply comes back in the POST response body (plain JSON or an SSE
    /// stream we scan for our request id).
    Http {
        url: String,
        client: reqwest::Client,
        session_id: Mutex<Option<String>>,
        headers: HashMap<String, String>,
    },
}

/// One live MCP server: spawned child + demux reader + tool schema cache.
pub struct McpClient {
    pub plugin_id: String,
    /// Name this host reports in the MCP `initialize` handshake. Supplied by
    /// the host, which owns its own name.
    client_name: String,
    transport: Transport,
    req_id: AtomicU64,
    pending: Arc<std::sync::Mutex<PendingMap>>,
    pub caps: std::sync::Mutex<ServerCaps>,
    /// Last successfully listed tool table (`tools/list`), for the SYNC read
    /// paths — `Plugin::export_tools`/`tool_names` run on the request path and
    /// used a `try_lock` on the async store, which reported "0 tools" to the
    /// model whenever a refresh happened to hold it. A failed refresh leaves
    /// the previous table in place; a successful one (even an empty list from
    /// a server that declares none) replaces it.
    tool_cache: std::sync::RwLock<Arc<Vec<Value>>>,
    /// `serverInfo` from the handshake — the server's own name/version. The
    /// manifest's `version` says nothing for a server added from the UI (it is
    /// written as "1.0.0"), so the live value is what the settings card shows.
    pub server_info: std::sync::Mutex<Value>,
    /// prompt name → description (from `prompts/list`, when declared).
    pub prompts: Mutex<Vec<Value>>,
    /// resource uri → metadata (from `resources/list`, when declared).
    pub resources: Mutex<Vec<Value>>,
    /// stderr ring buffer (surfaced on error cards) — stdio only.
    pub stderr_log: Arc<Mutex<Vec<String>>>,
}

/// JSON-RPC id → pending oneshot sender.
type PendingMap = HashMap<u64, oneshot::Sender<Result<Value, String>>>;

/// Clears a pending RPC slot on the way out of a call.
///
/// The slot is inserted before the request is written; the reader task only
/// removes it when a response actually arrives. A timeout — or a cancelled
/// caller — used to return without removing it, so a server that never answers
/// leaked one entry per call, forever. `std::sync::Mutex` (not the tokio one)
/// keeps this removal synchronous in `Drop`; the map is only ever touched in
/// short, await-free critical sections.
struct PendingSlot {
    map: Arc<std::sync::Mutex<PendingMap>>,
    id: u64,
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// Numeric id of a JSON-RPC response.
///
/// Our ids go out as numbers, but some servers echo them stringified; the old
/// `v["id"].as_u64()` returned `None` for those, which collapsed to key `0`
/// and never matched — the caller then waited out its full timeout.
fn response_id(v: &Value) -> Option<u64> {
    match v.get("id")? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

impl McpClient {
    /// Spawn + handshake + initial `tools/list` (+ resources/prompts when
    /// the server declares them). `deny_read` protects host-owned paths in
    /// sandboxed stdio children.
    pub async fn start(
        manifest: &PluginManifest,
        client_name: &str,
        deny_read: &[PathBuf],
    ) -> Result<Arc<Self>> {
        // No `entry` = a pure plugin (host-side capabilities only) — there is
        // nothing to connect and this constructor should never have run.
        let entry = manifest
            .entry
            .as_ref()
            .context("manifest has no `entry` — not a server-backed plugin")?;

        // HTTP transport — `entry.url` means streamable HTTP instead of a
        // spawned child. No env/stdin machinery applies.
        if let Some(url) = entry["url"].as_str() {
            // Declared `permissions.network` is the host allowlist for the
            // transport itself — a manifest that says `permissions: {}`
            // grants NO network, so its http entry would fail closed.
            // Loopback hosts always pass: a same-machine server is not
            // outbound network in any sandbox model.
            if let Some(perms) = &manifest.permissions {
                let host = reqwest::Url::parse(url)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_default();
                let ok = is_loopback_host(&host) || host_allowed(&host, &perms.network);
                if !ok {
                    return Err(anyhow::anyhow!(
                        "MCP `{}` url host `{host}` is not in its declared \
                         permissions.network allowlist ({} entries) — refusing \
                         to connect; add the host or drop the permissions block",
                        manifest.id,
                        perms.network.len(),
                    ));
                }
            }
            let headers: HashMap<String, String> = entry["headers"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| {
                            (
                                k.clone(),
                                resolve_indirect(v.as_str().unwrap_or(""), "header"),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let client = Arc::new(Self {
                plugin_id: manifest.id.clone(),
                client_name: client_name.to_string(),
                transport: Transport::Http {
                    url: url.to_string(),
                    client: reqwest::Client::builder()
                        .timeout(CALL_TIMEOUT)
                        .build()
                        .context("reqwest build")?,
                    session_id: Mutex::new(None),
                    headers,
                },
                req_id: AtomicU64::new(1),
                pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
                caps: std::sync::Mutex::new(ServerCaps::default()),
                tool_cache: std::sync::RwLock::new(Arc::new(Vec::new())),
                prompts: Mutex::new(Vec::new()),
                resources: Mutex::new(Vec::new()),
                stderr_log: Arc::new(Mutex::new(Vec::new())),
                server_info: std::sync::Mutex::new(Value::Null),
            });
            return client.handshake().await;
        }

        let command = entry["command"].as_str().context("mcp entry.command")?;
        let args: Vec<String> = entry["args"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // Child env = manifest env only — never inherit host env.
        // `env:VAR` indirection resolves from host env, but a manifest can
        // name ANY host variable — including `AWS_SECRET_ACCESS_KEY` — and
        // exfiltrate it into the plugin process. Gate that: secret-shaped
        // host vars are refused (empty value + warn) unless the variable
        // name is on a small allowlist of obviously-non-secret handles.
        let env: HashMap<String, String> = entry["env"]
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), resolve_indirect(v.as_str().unwrap_or(""), "env")))
                    .collect()
            })
            .unwrap_or_default();

        let stderr_log = Arc::new(Mutex::new(Vec::<String>::new()));
        // `sandboxed` or a declared `permissions` block → the child spawns
        // through the process sandbox instead of naked: filesystem grants
        // become mounts, `network` non-empty becomes allow_network (bwrap
        // can't host-filter — widened with a warn), `env` rides the
        // trusted-env channel so the manifest's own literals survive.
        let mut cmd = if manifest.wants_sandbox() {
            let perms = manifest.permissions.clone().unwrap_or_default();
            let (ro, rw) = perms.fs_mounts();
            if !perms.network.is_empty() {
                warn!(
                    plugin = %manifest.id,
                    "permissions.network has no host filtering in the process \
                     sandbox — widened to allow-all for this spawn"
                );
            }
            let ws = if manifest.dir.is_absolute() && manifest.dir.exists() {
                manifest.dir.clone()
            } else {
                std::env::temp_dir()
            };
            let cfg = agent_sandbox::SandboxConfig {
                workspace_dir: ws,
                deny_read: deny_read.to_vec(),
                allow_network: !perms.network.is_empty(),
                environment: agent_sandbox::plan::EnvironmentPolicy::Minimal,
                trusted_env: env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                extra_ro_mounts: ro,
                extra_rw_mounts: rw,
                ..Default::default()
            };
            let (backend, _loud) = agent_sandbox::detect_backend();
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            backend
                .wrap_spawn(&cfg, command, &arg_refs)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "MCP `{}` declared sandboxed spawn but this platform has \
                         no sandbox backend — refusing instead of spawning \
                         unsandboxed",
                        manifest.id
                    )
                })?
        } else {
            let mut c = tokio::process::Command::new(command);
            c.args(&args).env_clear().envs(&env);
            c
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        // Linux: PR_SET_PDEATHSIG — an MCP node server can't outlive the host.
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn MCP `{command} {}`", args.join(" ")))?;

        let stdin = child.stdin.take().context("child stdin")?;
        let stdout = child.stdout.take().context("child stdout")?;
        let mut stderr = child.stderr.take().context("child stderr")?;

        // stderr → ring buffer.
        let log = stderr_log.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(&mut stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let mut g = log.lock().await;
                g.push(l);
                if g.len() > 200 {
                    g.remove(0);
                }
            }
        });

        let client = Arc::new(Self {
            plugin_id: manifest.id.clone(),
            client_name: client_name.to_string(),
            transport: Transport::Stdio {
                stdin: Arc::new(Mutex::new(stdin)),
                _child: Mutex::new(child),
            },
            server_info: std::sync::Mutex::new(Value::Null),
            req_id: AtomicU64::new(1),
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
            caps: std::sync::Mutex::new(ServerCaps::default()),
            tool_cache: std::sync::RwLock::new(Arc::new(Vec::new())),
            prompts: Mutex::new(Vec::new()),
            resources: Mutex::new(Vec::new()),
            stderr_log,
        });

        // ---- demux reader task ----
        {
            let pending = client.pending.clone();
            let client_weak = Arc::downgrade(&client);
            tokio::spawn(async move {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if v.get("id").is_some()
                        && (v.get("result").is_some() || v.get("error").is_some())
                    {
                        // Response → resolve the pending oneshot. The lock is
                        // dropped before sending (the send is synchronous).
                        let tx = response_id(&v).and_then(|id| {
                            pending
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&id)
                        });
                        if let Some(tx) = tx {
                            let res = if let Some(err) = v.get("error") {
                                Err(err["message"].as_str().unwrap_or("rpc error").to_string())
                            } else {
                                Ok(v["result"].clone())
                            };
                            let _ = tx.send(res);
                        }
                    } else if v.get("method").is_some() {
                        // Notification → internal handler.
                        if let Some(c) = client_weak.upgrade() {
                            c.handle_notification(&v).await;
                        }
                    }
                }
            });
        }

        client.handshake().await
    }

    /// initialize → initialized → list — shared by both transports (the
    /// wire differs, the sequence doesn't).
    async fn handshake(self: &Arc<Self>) -> Result<Arc<Self>> {
        let init = self
            .call_rpc(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": self.client_name, "version": env!("CARGO_PKG_VERSION")},
                }),
            )
            .await
            .context("MCP initialize")?;

        *self.server_info.lock().unwrap() = init.get("serverInfo").cloned().unwrap_or(Value::Null);

        // Capture declared caps — gate every later call on them.
        let caps = init.get("capabilities").cloned().unwrap_or_default();
        *self.caps.lock().unwrap() = ServerCaps {
            tools: caps.get("tools").is_some(),
            resources: caps.get("resources").is_some(),
            prompts: caps.get("prompts").is_some(),
        };
        self.notify("notifications/initialized", json!({})).await?;
        self.refresh_lists().await?;

        info!(plugin = %self.plugin_id, "MCP ready");
        Ok(self.clone())
    }

    /// Re-pull `tools/list` + `resources/list` + `prompts/list` per caps.
    async fn refresh_lists(&self) -> Result<()> {
        let caps = self.caps.lock().unwrap().clone();
        if caps.tools {
            let r = self.call_rpc("tools/list", json!({})).await?;
            let tools = r["tools"].as_array().cloned().unwrap_or_default();
            // Publish the table the model-visible read paths consult. Written
            // only on success, so a failed refresh keeps the previous listing.
            *self.tool_cache.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(tools);
        }
        if caps.resources {
            let r = self.call_rpc("resources/list", json!({})).await?;
            *self.resources.lock().await = r["resources"].as_array().cloned().unwrap_or_default();
        }
        if caps.prompts {
            let r = self.call_rpc("prompts/list", json!({})).await?;
            *self.prompts.lock().await = r["prompts"].as_array().cloned().unwrap_or_default();
        }
        Ok(())
    }

    async fn handle_notification(&self, v: &Value) {
        match v["method"].as_str() {
            Some("notifications/tools/list_changed") => {
                // Hot-reload: re-list without restart.
                let _ = self.refresh_lists().await;
            }
            Some("notifications/cancelled") | Some("notifications/progress") => {
                // Forward to the step card.
            }
            _ => {}
        }
    }

    /// JSON-RPC call — allocate id → oneshot → write line → await ≤30 s
    /// (stdio) or POST and read the response body (HTTP).
    pub async fn call_rpc(&self, method: &str, params: Value) -> Result<Value> {
        match &self.transport {
            Transport::Stdio { stdin, .. } => {
                let id = self.req_id.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = oneshot::channel();
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id, tx);
                // Clear the slot on every exit — timeout, cancelled caller,
                // dropped receiver. The reader clears it only when a response
                // actually arrives, so without this a silent server leaks one
                // entry per call, forever.
                let _slot = PendingSlot {
                    map: self.pending.clone(),
                    id,
                };

                let line = serde_json::to_string(&json!({
                    "jsonrpc": "2.0", "id": id, "method": method, "params": params,
                }))?;
                {
                    let mut stdin = stdin.lock().await;
                    stdin.write_all(line.as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                    stdin.flush().await?;
                }

                tokio::time::timeout(CALL_TIMEOUT, rx)
                    .await
                    .context("MCP call timeout")??
                    .map_err(|e| anyhow::anyhow!(e))
            }
            Transport::Http {
                url,
                client,
                session_id,
                headers,
            } => {
                let id = self.req_id.fetch_add(1, Ordering::SeqCst);
                let body = json!({
                    "jsonrpc": "2.0", "id": id, "method": method, "params": params,
                });
                let msg = self
                    .http_roundtrip(client, url, session_id, headers, &body, Some(id))
                    .await?;
                // Same demux contract as stdio: result or error.message.
                if let Some(err) = msg.get("error") {
                    return Err(anyhow::anyhow!(err["message"]
                        .as_str()
                        .unwrap_or("rpc error")
                        .to_string()));
                }
                Ok(msg.get("result").cloned().unwrap_or(Value::Null))
            }
        }
    }

    /// One HTTP POST — shared by `call_rpc` (expects a response for `id`)
    /// and `notify` (fire-and-forget). Handles `Mcp-Session-Id` capture,
    /// static headers, and both reply shapes (plain JSON / SSE stream).
    async fn http_roundtrip(
        &self,
        client: &reqwest::Client,
        url: &str,
        session_id: &Mutex<Option<String>>,
        headers: &HashMap<String, String>,
        body: &Value,
        want_id: Option<u64>,
    ) -> Result<Value> {
        let mut req = client
            .post(url)
            .header("Accept", "application/json, text/event-stream")
            .json(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        if let Some(sid) = session_id.lock().await.clone() {
            req = req.header("Mcp-Session-Id", sid);
        }
        let resp = req.send().await.context("MCP http send")?;
        if let Some(sid) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            *session_id.lock().await = Some(sid.to_string());
        }
        let status = resp.status();
        // 202/204 = accepted, no response body (the notification path).
        if status.as_u16() == 202 || status.as_u16() == 204 {
            return Ok(Value::Null);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("MCP http {status}: {text}"));
        }
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = resp.text().await?;
        if ctype.contains("text/event-stream") {
            // SSE — scan `data:` lines for the JSON-RPC message with our id.
            for line in text.lines() {
                let Some(d) = line.strip_prefix("data:") else {
                    continue;
                };
                let Ok(v) = serde_json::from_str::<Value>(d.trim()) else {
                    continue;
                };
                if want_id.is_none() || response_id(&v) == want_id {
                    return Ok(v);
                }
            }
            return Err(anyhow::anyhow!("MCP SSE stream had no matching response"));
        }
        let v: Value = serde_json::from_str(text.trim()).context("MCP http response parse")?;
        Ok(v)
    }

    async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0", "method": method, "params": params,
        }))?;
        match &self.transport {
            Transport::Stdio { stdin, .. } => {
                let mut stdin = stdin.lock().await;
                stdin.write_all(line.as_bytes()).await?;
                stdin.write_all(b"\n").await?;
                stdin.flush().await?;
            }
            Transport::Http {
                url,
                client,
                session_id,
                headers,
            } => {
                let body: Value = serde_json::from_str(&line)?;
                // Notification — server replies 202/204 with no body.
                self.http_roundtrip(client, url, session_id, headers, &body, None)
                    .await?;
            }
        }
        Ok(())
    }

    /// `tools/call` — concatenate `type=="text"` content; mark non-text.
    /// `(name, version)` the server reported at `initialize`.
    pub fn server_info(&self) -> (String, String) {
        let v = self.server_info.lock().unwrap();
        let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        (get("name"), get("version"))
    }

    /// Tool names advertised by `tools/list`.
    pub async fn tool_names(&self) -> Vec<String> {
        self.tool_snapshot()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect()
    }

    /// Last successfully listed tool table — the sync read path. Never empty
    /// merely because a refresh is in flight.
    pub fn tool_snapshot(&self) -> Arc<Vec<Value>> {
        self.tool_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        let r = self
            .call_rpc("tools/call", json!({"name": name, "arguments": args}))
            .await?;
        let mut out = String::new();
        for item in r["content"].as_array().into_iter().flatten() {
            match item["type"].as_str() {
                Some("text") => out.push_str(item["text"].as_str().unwrap_or("")),
                Some(t) => out.push_str(&format!("[mcp: {t} content omitted]")),
                _ => {}
            }
            out.push('\n');
        }
        if r["isError"].as_bool().unwrap_or(false) {
            warn!(tool = name, "MCP tool error");
        }
        Ok(out)
    }

    /// `resources/read` — text resource content.
    pub async fn read_resource(&self, uri: &str) -> Result<String> {
        let r = self.call_rpc("resources/read", json!({"uri": uri})).await?;
        let mut out = String::new();
        for item in r["contents"].as_array().into_iter().flatten() {
            if let Some(t) = item["text"].as_str() {
                out.push_str(t);
            } else {
                out.push_str("[mcp: non-text resource omitted]");
            }
        }
        Ok(out)
    }

    /// `prompts/get` — render a prompt template.
    pub async fn get_prompt(&self, name: &str, args: Value) -> Result<String> {
        let r = self
            .call_rpc("prompts/get", json!({"name": name, "arguments": args}))
            .await?;
        let mut out = String::new();
        for m in r["messages"].as_array().into_iter().flatten() {
            if let Some(t) = m["content"]["text"].as_str() {
                out.push_str(t);
                out.push('\n');
            }
        }
        Ok(out)
    }
}

/// Whether a host env-var name looks like credential material — used to
/// gate the `env:VAR` indirection so a plugin manifest can't exfiltrate
/// host secrets into its child process. Mirrors the same denylist shape as
/// the sandbox env-sanitizer: suffix/prefix match, not substring (a var
/// literally *named* `API_KEY` or ending `_TOKEN` is refused; `NOTES_KEY`
/// would also match — erring toward refuse is the safe side).
/// `env:VAR` indirection → resolve from the host environment, refusing
/// secret-shaped names (same policy as manifest env vars). Plain values
/// pass through untouched. Shared with the hook runner (`hooks.rs`), which
/// gives a hook command the same env posture as an MCP child.
pub(crate) fn resolve_indirect(val: &str, kind: &str) -> String {
    match val.strip_prefix("env:") {
        Some(name) => {
            if host_env_is_secret(name) {
                tracing::warn!(
                    host_var = %name,
                    "MCP {kind} indirection to a secret-shaped host variable \
                     refused (would exfiltrate credentials into the plugin)"
                );
                String::new()
            } else {
                std::env::var(name).unwrap_or_default()
            }
        }
        None => val.to_string(),
    }
}

fn host_env_is_secret(name: &str) -> bool {
    let u = name.to_uppercase();
    const SECRET_SUFFIXES: &[&str] = &[
        "_KEY",
        "_SECRET",
        "_TOKEN",
        "_PASSWORD",
        "_PASSWD",
        "_CREDENTIAL",
        "_CREDENTIALS",
        "_AUTH",
        "_PRIVATE",
        "_CERT",
        "_PEM",
    ];
    const SECRET_EXACT: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "NPM_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "DOCKER_PASSWORD",
        "KUBECONFIG",
        "PRIVATE_KEY",
        "SECRET_KEY",
    ];
    SECRET_EXACT.contains(&u.as_str()) || SECRET_SUFFIXES.iter().any(|s| u.ends_with(s))
}

/// Loopback hosts bypass `permissions.network` — a same-machine MCP server
/// is a local process in every sandbox model, not outbound network.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
        || host == "0.0.0.0"
}

/// `host` ∈ allowlist — suffix match with a label boundary, so
/// `example.com` covers `api.example.com` but never `badexample.com`. An
/// entry may itself be `*.`-prefixed (same semantics either way).
fn host_allowed(host: &str, allow: &[String]) -> bool {
    allow.iter().any(|e| {
        let e = e.trim_start_matches("*.");
        !e.is_empty() && (host == e || host.ends_with(&format!(".{e}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Servers echo the id they were sent; our ids are numbers, but a
    /// stringified echo must still resolve (the old `as_u64()` missed it and
    /// the call waited out its full timeout).
    #[test]
    fn response_id_accepts_numbers_and_numeric_strings() {
        assert_eq!(response_id(&json!({"id": 7})), Some(7));
        assert_eq!(response_id(&json!({"id": "7"})), Some(7));
        assert_eq!(response_id(&json!({"id": " 42 "})), Some(42));
        // Non-numeric / absent ids stay unmatched rather than collapsing to 0.
        assert_eq!(response_id(&json!({"id": "req-1"})), None);
        assert_eq!(response_id(&json!({"id": null})), None);
        assert_eq!(response_id(&json!({"result": {}})), None);
    }

    /// A timed-out or cancelled call must not leave its sender parked in the
    /// pending map — the reader only removes a slot when a reply arrives.
    #[test]
    fn pending_slot_is_removed_on_drop() {
        let map: Arc<std::sync::Mutex<PendingMap>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (tx, _rx) = oneshot::channel();
        map.lock().unwrap().insert(1, tx);

        let slot = PendingSlot {
            map: map.clone(),
            id: 1,
        };
        assert!(map.lock().unwrap().contains_key(&1));
        drop(slot);
        assert!(!map.lock().unwrap().contains_key(&1));

        // Dropping an already-resolved slot is a no-op, not an error.
        drop(PendingSlot {
            map: map.clone(),
            id: 99,
        });
        assert!(map.lock().unwrap().is_empty());
    }
}
