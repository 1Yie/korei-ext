//! Plugin manifest — self-describing `manifest.json` + `mcpServers` TOML
//! synthesis (plugin-system.md §Plugin contract + §Standard config format).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

/// Lifecycle events a hook can declare — the `AgentHook` trait's methods,
/// spelled for a manifest. Anything else is a manifest error.
pub const HOOK_EVENTS: [&str; 5] = [
    "on_user_input",
    "before_tool_execute",
    "after_tool_execute",
    "on_state_transition",
    "on_response",
];

/// Per-hook latency budget when the manifest does not set `timeout_ms` —
/// matches `agent_kernel::hooks::HOOK_TIMEOUT`.
pub const HOOK_DEFAULT_TIMEOUT_MS: u64 = 2_000;
/// Upper bound a manifest `timeout_ms` is clamped to — a hook sits in the
/// turn's critical path at two of the four events, so it can't stall a turn
/// for as long as it likes.
pub const HOOK_MAX_TIMEOUT_MS: u64 = 10_000;

/// Runtime kind — only meaningful when `entry` is present. A manifest that
/// declares no `entry` is a pure plugin (host-side capabilities like hooks):
/// there is no connection, so there is no kind to pick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    /// WASM in-process sandbox (Wasmtime; Stage-9 feature-gated).
    Wasm,
    /// MCP child process over stdio JSON-RPC.
    Mcp,
}

/// Declared capabilities — **exhaustive**: anything not here is denied.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PluginPermissions {
    /// Host allowlist for the host-side `fetch` fn (empty = no network).
    #[serde(default)]
    pub network: Vec<String>,
    /// `read:<path>` / `write:<path>` preopens (WASM) — absent = no fs.
    #[serde(default)]
    pub filesystem: Vec<String>,
}

impl PluginPermissions {
    /// `read:<path>`/`write:<path>` entries → (read-only, read-write) mount
    /// lists for the process sandbox. Bare paths without a prefix are read-
    /// only (a grant without a mode never widens to write).
    pub fn fs_mounts(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut ro = Vec::new();
        let mut rw = Vec::new();
        for e in &self.filesystem {
            match e.strip_prefix("write:").or_else(|| e.strip_prefix("rw:")) {
                Some(p) => rw.push(PathBuf::from(p)),
                None => match e.strip_prefix("read:").or_else(|| e.strip_prefix("ro:")) {
                    Some(p) => ro.push(PathBuf::from(p)),
                    None => ro.push(PathBuf::from(e)),
                },
            }
        }
        (ro, rw)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolDecl {
    pub name: String,
    pub description: String,
    /// JSON Schema object — validated at `register_plugin`.
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderDecl {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandDecl {
    pub name: String,
    pub description: String,
    /// `"tool:<name>"` → dispatch that tool; `"prompt:<text>"` → FeedToAgent.
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HookDecl {
    /// `before_tool_execute` / `after_tool_execute` / `on_user_input` /
    /// `on_state_transition`.
    pub event: String,
    /// Narrow the hook to one tool (`{"tool": "bash"}`) or one state
    /// (`{"state": "Failed"}`). Absent = every occurrence of the event.
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// The command to spawn — the hook's whole implementation. Required:
    /// interception happens by running this, so a declaration without one
    /// would be a hook that can never fire.
    #[serde(default)]
    pub run: Option<HookRun>,
    /// Latency budget; defaults to [`HOOK_DEFAULT_TIMEOUT_MS`], capped at
    /// [`HOOK_MAX_TIMEOUT_MS`].
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// How a hook is executed — a local command, same posture as an MCP child
/// (`mcp.rs`): declared env only, `kill_on_drop`, pdeathsig on Linux.
#[derive(Debug, Clone, Deserialize)]
pub struct HookRun {
    /// Executable. A relative path resolves against the plugin's own
    /// directory, so `"./guard.sh"` means the script shipped next to the
    /// manifest rather than something on `PATH`.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Literal values, plus `env:VAR` indirection into the host environment
    /// — secret-shaped host vars are refused (see `mcp::resolve_indirect`).
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl HookDecl {
    /// Effective latency budget — manifest value, defaulted and clamped.
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
            .unwrap_or(HOOK_DEFAULT_TIMEOUT_MS)
            .clamp(1, HOOK_MAX_TIMEOUT_MS)
    }
}

/// `manifest.json` — one per plugin directory. Two independent halves:
/// `entry` bridges to a server (MCP), `capabilities` extends the kernel in
/// the host (hooks today). A manifest may carry either or both — a plugin is
/// not a kind of MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    #[serde(default = "v1")]
    pub version: String,
    /// Which runtime `entry` runs under — absent defaults to MCP when an
    /// entry exists, meaningless without one.
    #[serde(default)]
    pub kind: Option<PluginKind>,
    /// The bridge to a server — wasm: file path; mcp: `{ "command": "npx",
    /// "args": [...] }` or `{ "url": ... }`. Absent = pure plugin: nothing to
    /// connect, only host-side capabilities.
    #[serde(default)]
    pub entry: Option<serde_json::Value>,
    /// `Some` means the manifest **declared** a permission set — the spawn
    /// paths then enforce it (sandboxed stdio child, HTTP host allowlist).
    /// `None` (key absent) keeps the legacy permissive posture: UI-registered
    /// servers write no `permissions` key and behave exactly as before.
    #[serde(default)]
    pub permissions: Option<PluginPermissions>,
    #[serde(default)]
    pub capabilities: Capabilities,
    /// MCP: run under the process sandbox when the server is local-safe.
    #[serde(default)]
    pub sandboxed: bool,
    /// Filesystem dir the manifest lives in (set by discovery).
    #[serde(skip)]
    pub dir: PathBuf,
}

fn v1() -> String {
    "1.0.0".into()
}

impl PluginManifest {
    /// Whether the spawn path must run under the process sandbox — an
    /// explicit `sandboxed` flag, or a declared `permissions` block (a
    /// capability grant is meaningless unless the sandbox enforces it).
    pub fn wants_sandbox(&self) -> bool {
        self.sandboxed || self.permissions.is_some()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub tools: Vec<ToolDecl>,
    #[serde(default)]
    pub context_providers: Vec<ProviderDecl>,
    #[serde(default)]
    pub commands: Vec<CommandDecl>,
    #[serde(default)]
    pub hooks: Vec<HookDecl>,
}

impl PluginManifest {
    /// Validate structural rules (hook declarations, schema validity).
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("manifest id empty".into());
        }
        // A manifest that neither bridges to a server nor extends the kernel
        // is dead weight — refuse it rather than loading an inert entry.
        let c = &self.capabilities;
        if self.entry.is_none()
            && c.tools.is_empty()
            && c.context_providers.is_empty()
            && c.commands.is_empty()
            && c.hooks.is_empty()
        {
            return Err("manifest needs an `entry` or a declared capability".into());
        }
        // Hooks are LOCAL commands, so they are not bound to the plugin's
        // runtime kind — an MCP plugin declares them just as freely, because
        // interception happens in the host, not over the MCP connection.
        for h in &self.capabilities.hooks {
            if !HOOK_EVENTS.contains(&h.event.as_str()) {
                return Err(format!(
                    "hook event `{}` is not one of {HOOK_EVENTS:?}",
                    h.event
                ));
            }
            let Some(run) = &h.run else {
                return Err(format!(
                    "hook `{}` declares no `run` command — a hook with nothing \
                     to execute can never fire",
                    h.event
                ));
            };
            if run.command.trim().is_empty() {
                return Err(format!("hook `{}` has an empty `run.command`", h.event));
            }
            // A filter key that no event consults would read as "narrowed to
            // nothing" while silently matching everything — refuse it.
            if let Some(filter) = &h.filter {
                let Some(obj) = filter.as_object() else {
                    return Err(format!("hook `{}` filter must be an object", h.event));
                };
                for (k, v) in obj {
                    let expected = match h.event.as_str() {
                        "before_tool_execute" | "after_tool_execute" => "tool",
                        "on_state_transition" => "state",
                        _ => return Err(format!("hook `{}` takes no filter (got `{k}`)", h.event)),
                    };
                    if k != expected {
                        return Err(format!(
                            "hook `{}` filter key `{k}` is not `{expected}`",
                            h.event
                        ));
                    }
                    if !v.is_string() {
                        return Err(format!("hook `{}` filter `{k}` must be a string", h.event));
                    }
                }
                if obj.is_empty() {
                    return Err(format!("hook `{}` filter is empty", h.event));
                }
            }
        }
        // Tool parameter schemas must be objects.
        for t in &self.capabilities.tools {
            if !t.parameters.is_object() {
                return Err(format!(
                    "tool `{}` parameters must be a JSON Schema object",
                    t.name
                ));
            }
        }
        Ok(())
    }

    /// Synthesize a manifest from a `[mcp_servers.*]` TOML entry — the
    /// community-compatible shape (Claude Desktop config paste).
    pub fn from_mcp_server(id: &str, e: &McpServerEntry) -> Self {
        Self {
            id: id.to_string(),
            name: id.to_string(),
            version: "mcp".into(),
            kind: Some(PluginKind::Mcp),
            entry: Some(serde_json::json!({
                "command": e.command, "args": e.args, "env": e.env,
            })),
            permissions: None,
            capabilities: Capabilities::default(),
            sandboxed: e.sandboxed.unwrap_or(false),
            dir: PathBuf::new(),
        }
    }
}

/// `[mcp_servers.<id>]` TOML row.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerEntry {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub sandboxed: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with(hooks: serde_json::Value) -> PluginManifest {
        serde_json::from_value(serde_json::json!({
            "id": "p", "name": "p", "kind": "mcp",
            "entry": {"command": "npx"},
            "capabilities": {"hooks": hooks},
        }))
        .expect("manifest parses")
    }

    /// An MCP plugin may declare hooks: interception is a local command, so
    /// the MCP connection has nothing to do with it. (The old rule rejected
    /// every MCP hook outright.)
    #[test]
    fn mcp_plugin_may_declare_a_hook() {
        let m = manifest_with(serde_json::json!([
            {"event": "before_tool_execute",
             "run": {"command": "./guard.sh"},
             "filter": {"tool": "bash"}}
        ]));
        assert!(m.validate().is_ok());
        assert_eq!(
            m.capabilities.hooks[0].timeout_ms(),
            HOOK_DEFAULT_TIMEOUT_MS
        );
    }

    /// A declaration with nothing to execute can never fire — refuse it
    /// rather than registering a hook that is silently dead.
    #[test]
    fn hook_without_run_is_refused() {
        let m = manifest_with(serde_json::json!([{"event": "on_user_input"}]));
        assert!(m.validate().unwrap_err().contains("no `run`"));
    }

    #[test]
    fn unknown_event_is_refused() {
        let m = manifest_with(serde_json::json!([
            {"event": "before_model_call", "run": {"command": "x"}}
        ]));
        assert!(m.validate().unwrap_err().contains("not one of"));
    }

    /// A filter key the event never consults would match everything while
    /// reading as narrowed — the worst of both.
    #[test]
    fn filter_keys_are_checked_against_the_event() {
        for (event, filter, needle) in [
            (
                "before_tool_execute",
                serde_json::json!({"state": "Failed"}),
                "`tool`",
            ),
            (
                "on_state_transition",
                serde_json::json!({"tool": "bash"}),
                "`state`",
            ),
            (
                "on_user_input",
                serde_json::json!({"tool": "bash"}),
                "no filter",
            ),
        ] {
            let m = manifest_with(serde_json::json!([
                {"event": event, "run": {"command": "x"}, "filter": filter}
            ]));
            let err = m.validate().unwrap_err();
            assert!(err.contains(needle), "event {event}: {err}");
        }
        // …and the legitimate shapes pass.
        assert!(manifest_with(serde_json::json!([
            {"event": "on_state_transition",
             "run": {"command": "x"}, "filter": {"state": "Failed"}}
        ]))
        .validate()
        .is_ok());
    }

    /// The timeout is bounded on both ends — a manifest can't ask for a
    /// hook that outlives the turn.
    #[test]
    fn timeout_is_defaulted_and_clamped() {
        let m = manifest_with(serde_json::json!([
            {"event": "on_user_input", "run": {"command": "x"}, "timeout_ms": 999_999}
        ]));
        assert_eq!(m.capabilities.hooks[0].timeout_ms(), HOOK_MAX_TIMEOUT_MS);

        let m = manifest_with(serde_json::json!([
            {"event": "on_user_input", "run": {"command": "x"}, "timeout_ms": 0}
        ]));
        assert_eq!(m.capabilities.hooks[0].timeout_ms(), 1);
    }

    /// `run` carries args + env like an MCP entry does.
    #[test]
    fn run_command_parses_args_and_env() {
        let m = manifest_with(serde_json::json!([
            {"event": "after_tool_execute",
             "run": {"command": "python3", "args": ["h.py"], "env": {"MODE": "strict"}}}
        ]));
        assert!(m.validate().is_ok());
        let run = m.capabilities.hooks[0].run.as_ref().unwrap();
        assert_eq!(run.command, "python3");
        assert_eq!(run.args, vec!["h.py".to_string()]);
        assert_eq!(run.env.get("MODE").map(String::as_str), Some("strict"));
    }

    /// A plugin is not a kind of MCP server: hooks-only manifests carry no
    /// `kind` and no `entry` — there is no runtime and nothing to connect.
    #[test]
    fn hooks_only_manifest_needs_neither_kind_nor_entry() {
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "guard", "name": "Guard",
            "capabilities": {"hooks": [
                {"event": "on_user_input", "run": {"command": "./h.sh"}}
            ]},
        }))
        .unwrap();
        assert!(m.kind.is_none() && m.entry.is_none());
        assert!(m.validate().is_ok());
    }

    /// …but a manifest with NOTHING — no bridge, no capability — is dead
    /// weight, and dead weight gets refused instead of silently inert.
    #[test]
    fn empty_manifest_is_refused() {
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "nothing", "name": "Nothing",
        }))
        .unwrap();
        assert!(m
            .validate()
            .unwrap_err()
            .contains("entry` or a declared capability"));
    }
}

#[cfg(test)]
mod declared_sandbox_tests {
    use super::*;

    /// The shape `add_mcp` writes for a local stdio server must load as a
    /// declared, sandboxed plugin. Without `permissions` the child runs naked.
    #[test]
    fn ui_added_stdio_manifest_loads_sandboxed() {
        let m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "fs", "name": "fs", "kind": "mcp",
            "entry": { "command": "npx", "args": ["-y", "server"] },
            "permissions": {},
        }))
        .unwrap();
        assert!(m.wants_sandbox());
        assert!(m.permissions.is_some());
    }
}
