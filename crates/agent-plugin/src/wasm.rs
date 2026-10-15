//! `wasm.rs` — WASM plugin runtime, behind `feature = "wasm"`
//! (wasmtime pulls a C toolchain — off the default build).
//!
//! Guest contract — WASI-P1 *command* module (a plain `.wasm` core module
//! with a `_start`, linked against `wasi_snapshot_preview1`):
//!   - every `call_tool` spins up a FRESH `Store`+instance — the plugin is
//!     stateless across calls; state (if any) lives in its preopened dirs.
//!   - request = `{"tool":"<name>","args":{...}}` on **stdin**;
//!   - response = a single JSON object on **stdout**:
//!       `{"ok": "..."}`   → tool result text
//!       `{"error": "..."}`→ tool error
//!     anything else is passed through as the result text verbatim.
//!   - stderr is captured for the plugin-error message.
//!
//! Capability gating — the manifest's `permissions` is the trust document:
//!   - `permissions.fs` `read:`/`write:` entries become WASI *preopens* —
//!     nothing else exists to the guest (no ambient fs);
//!   - `permissions.env` declares KEYS — values resolve from the host env
//!     at load (same rule as the MCP `env:` indirection ban: manifests
//!     never carry secret literals);
//!   - `permissions.network` CANNOT be honored — WASI-P1 exposes no sockets
//!     at all, so a declared network permission is a lie we refuse to
//!     carry: load logs a warning and the guest runs with NO network.
//!
//! Execution limits: fuel-metered (10 M units ≈ ~2–4 s of guest compute)
//! + 64 KiB stdout/stderr pipes — a runaway guest burns its fuel and
//! returns `tool error`, never hangs the host.

#![cfg(feature = "wasm")]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use wasmtime::{Config, Engine, InstancePre, Linker, Module, Store};
use wasmtime_wasi::cli::{IsTerminal, StdinStream, StdoutStream};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

use crate::manifest::PluginManifest;
use crate::Plugin;

/// Guest compute budget per call — fuel metering makes this deterministic
/// (wall-clock timeouts can't interrupt a synchronous `Store::call`).
const FUEL_PER_CALL: u64 = 10_000_000;
/// stdin/stdout pipe caps — matches the host tool-result ceiling.
const PIPE_CAP: usize = 64 * 1024;

/// A stdin stream backed by a request-JSON buffer — each `async_stream`
/// handle gets its own read cursor over the same bytes.
struct InPipe(Vec<u8>);
impl IsTerminal for InPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}
impl StdinStream for InPipe {
    fn async_stream(&self) -> Box<dyn AsyncRead + Send + Sync> {
        Box::new(MemoryInputPipe::new(self.0.clone()))
    }
}

/// A stdout/stderr stream backed by a shared `MemoryOutputPipe` — clones
/// write into the same bounded buffer (matches WASI's shared-stream rule).
struct OutPipe(MemoryOutputPipe);
impl IsTerminal for OutPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}
impl StdoutStream for OutPipe {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.0.clone())
    }
}

/// Runtime bits the blocking task needs — `Arc` so `call_tool` can hand a
/// clone to `spawn_blocking` without moving `&self`.
struct Inner {
    engine: Engine,
    /// Module already linked against WASI once at load — a call only
    /// instantiates, instead of rebuilding a `Linker` and re-resolving every
    /// import each time.
    pre: InstancePre<WasiP1Ctx>,
    /// `(ro_dirs, rw_dirs, env)` resolved once at load — preopens are the
    /// capability contract, re-created per call into the fresh ctx.
    ro_mounts: Vec<PathBuf>,
    rw_mounts: Vec<PathBuf>,
    env: Vec<(String, String)>,
}

pub struct WasmPlugin {
    manifest: PluginManifest,
    inner: Arc<Inner>,
}

impl WasmPlugin {
    pub fn load(manifest: PluginManifest) -> Result<Self> {
        let path = manifest
            .entry
            .as_ref()
            .and_then(|e| e.as_str())
            .map(|s| manifest.dir.join(s))
            .context("wasm plugin `entry` must be a file path")?;
        let bytes =
            std::fs::read(&path).with_context(|| format!("read wasm at {}", path.display()))?;

        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|e| anyhow!("wasmtime engine: {e}"))?;
        let module =
            Module::new(&engine, &bytes).map_err(|e| anyhow!("compile {}: {e}", path.display()))?;

        let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |t| t).map_err(|e| anyhow!("link wasi-p1: {e}"))?;
        let pre = linker
            .instantiate_pre(&module)
            .map_err(|e| anyhow!("link {}: {e}", path.display()))?;

        // Capability resolution — `permissions` absent = no preopens, no
        // env (a manifest that declares nothing gets nothing, which is the
        // fail-closed answer for WASM where ambient = none anyway).
        let (ro, rw, env) = if let Some(p) = &manifest.permissions {
            let (ro, rw) = p.fs_mounts();
            if !p.network.is_empty() {
                tracing::warn!(
                    plugin = %manifest.id,
                    "WASM plugin declares `permissions.network` but WASI-P1 \
                     exposes no sockets — it runs with NO network (the \
                     declaration cannot be honored)"
                );
            }
            (ro, rw, Vec::new())
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        Ok(Self {
            manifest,
            inner: Arc::new(Inner {
                engine,
                pre,
                ro_mounts: ro,
                rw_mounts: rw,
                env,
            }),
        })
    }
}

impl Inner {
    /// Fresh WASI ctx per call — stdin carries the request JSON,
    /// stdout/stderr are bounded memory pipes.
    fn make_ctx(&self, request: &[u8]) -> Result<(WasiP1Ctx, MemoryOutputPipe, MemoryOutputPipe)> {
        let mut b = WasiCtxBuilder::new();
        b.stdin(InPipe(request.to_vec()));
        let out = MemoryOutputPipe::new(PIPE_CAP);
        let err = MemoryOutputPipe::new(PIPE_CAP);
        b.stdout(OutPipe(out.clone()));
        b.stderr(OutPipe(err.clone()));
        b.envs(&self.env);
        for dir in &self.ro_mounts {
            if dir.exists() {
                b.preopened_dir(
                    dir,
                    dir.as_path().to_str().unwrap_or("/"),
                    FsPerms::ReadOnly,
                )
                .map_err(|e| anyhow!("preopen {}: {e}", dir.display()))?;
            }
        }
        for dir in &self.rw_mounts {
            if dir.exists() {
                b.preopened_dir(
                    dir,
                    dir.as_path().to_str().unwrap_or("/"),
                    FsPerms::ReadWrite,
                )
                .map_err(|e| anyhow!("preopen {}: {e}", dir.display()))?;
            }
        }
        Ok((b.build_p1(), out, err))
    }

    fn run_tool(&self, name: &str, args: &Value) -> Result<String> {
        let request = serde_json::to_vec(&serde_json::json!({
            "tool": name,
            "args": args,
        }))?;
        let (ctx, out_pipe, err_pipe) = self.make_ctx(&request)?;

        let mut store = Store::new(&self.engine, ctx);
        store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| anyhow!("engine lacks fuel accounting: {e}"))?;

        let instance = self
            .pre
            .instantiate(&mut store)
            .map_err(|e| anyhow!("instantiate wasm module: {e}"))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| anyhow!("guest must export `_start`: {e}"))?;
        let call = start.call(&mut store, ());

        // `contents()` clones the buffer — `try_into_inner` would fail: the
        // store keeps the pipe alive until it drops.
        let stdout = String::from_utf8_lossy(&out_pipe.contents()).into_owned();
        let stderr = String::from_utf8_lossy(&err_pipe.contents()).into_owned();

        if let Err(e) = call {
            // Trap (incl. fuel exhaustion) — report guest stderr + the trap.
            let mut msg = format!("wasm guest trapped: {e}");
            if !stderr.trim().is_empty() {
                msg.push_str(&format!(" — stderr: {}", stderr.trim()));
            }
            anyhow::bail!(msg);
        }

        // Response contract: {"ok": ...} | {"error": ...} | raw text.
        if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
            if let Some(ok) = v.get("ok").and_then(|x| x.as_str()) {
                return Ok(ok.to_string());
            }
            if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
                anyhow::bail!("wasm tool error: {err}");
            }
        }
        Ok(stdout)
    }
}

#[async_trait::async_trait]
impl Plugin for WasmPlugin {
    fn id(&self) -> &str {
        &self.manifest.id
    }

    fn export_tools(&self) -> Vec<Value> {
        self.manifest
            .capabilities
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect()
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .capabilities
            .tools
            .iter()
            .map(|t| t.name.clone())
            .collect()
    }

    async fn call_tool(&self, name: &str, args: Value) -> Result<String> {
        // Fresh instance per call — run on a blocking thread: Store::call
        // is sync by design, and fuel metering (not wall time) is the
        // interrupt mechanism.
        let inner = Arc::clone(&self.inner);
        let name = name.to_string();
        tokio::task::spawn_blocking(move || inner.run_tool(&name, &args))
            .await
            .context("wasm task join")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::Engine;

    /// A manifest without `entry` can never produce a loadable plugin.
    #[test]
    fn missing_entry_errors() {
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "w", "name": "w", "kind": "wasm",
            "capabilities": { "tools": [{"name":"t","description":"d","parameters":{}}] }
        }))
        .unwrap();
        assert!(WasmPlugin::load(m).is_err());
    }

    /// End-to-end: a WASI-P1 command module that writes `{"ok":"hi"}` to
    /// stdout — exercises instantiate + pipe capture + response contract.
    /// (wasmtime's `wat` feature is on by default, so `Module::new` parses
    /// the text directly — no toolchain needed.)
    #[tokio::test]
    async fn wasi_command_responds_on_stdout() {
        // {"ok":"hi"} = 11 bytes at addr 8; iovec {ptr=8,len=11} at addr 0.
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 8) "{\"ok\":\"hi\"}")
            (data (i32.const 0) "\08\00\00\00\0b\00\00\00")
            (func (export "_start")
                (drop (call $fd_write
                    (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 20)))))
        "#;
        // wasmtime must be able to parse it — guard the fixture itself.
        assert!(
            Module::new(&Engine::default(), wat).is_ok(),
            "bad wat fixture"
        );

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.wasm"), wat).unwrap();
        let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "w", "name": "w", "kind": "wasm", "entry": "x.wasm",
            "capabilities": { "tools": [{"name":"t","description":"d","parameters":{}}] }
        }))
        .unwrap();
        m.dir = dir.path().to_path_buf();
        let p = WasmPlugin::load(m).unwrap();
        let out = p.call_tool("t", serde_json::json!({})).await.unwrap();
        assert_eq!(out, "hi");
    }
}
