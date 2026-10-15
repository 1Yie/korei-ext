//! `PluginManager` — manifest validation → runtime build → tool routing.
//!
//! Contract (plugin-system.md §PluginManager):
//! - `register_plugin`: validate manifest → build runtime → `export_tools`
//!   → populate `tool_router`. Tools are namespaced `plugin_id__tool`, both
//!   halves sanitized into the wire charset (see [`wire_tool_name`]) — the
//!   `plugin_id:tool` spelling this used to advertise is rejected outright by
//!   strict upstreams, because `:` is not a legal `function.name` character.
//! - `dispatch_tool_call`: route → `plugin.call_tool` → **same 40 KB
//!   truncation budget as built-ins** (plugin output is not exempt).
//! - `collect_dynamic_contexts`: fan out `provide_context` with per-plugin
//!   2 s timeout, tagged `<plugin_context id="…">`.
//! - Repo-local plugins inert until trusted (path-keyed consent store).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_paths::AppPaths;
use anyhow::Result;
use serde_json::Value;
use tracing::{info, warn};

use crate::hooks::{hooks_from_manifest, CommandHook};
use crate::manifest::PluginKind;
use crate::{McpClient, McpPlugin, Plugin, PluginManifest};

/// Tool result cap — same as built-ins (kernel-architecture.md §truncation).
const PLUGIN_OUTPUT_CAP: usize = 40 * 1024;
/// Per-plugin `provide_context` budget.
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(2);

/// Path-keyed trust store — repo-local plugins are inert until approved.
///
/// Keyed `<plugin_id>@<repo_path>` and persisted as a JSON array of those
/// keys in the app config dir: consent has to outlive the process, or a
/// repo-local plugin would have to be re-approved on every boot (a plugin
/// hook runs local code, so the gate is worth having).
#[derive(Default)]
pub struct TrustStore {
    /// `<plugin_id>@<repo_path>` → the content hash that was reviewed. A grant
    /// is only honoured while the plugin still hashes to this value.
    trusted: HashMap<String, String>,
}

impl TrustStore {
    /// `<id>@<canonical repo>`. The repo is canonicalized so every spelling of
    /// one directory (trailing slash, `..`, symlink alias) keys the same grant.
    /// A path that cannot be canonicalized keeps its spelling — a missing repo
    /// simply has no grant.
    pub fn key(id: &str, repo: &Path) -> String {
        let canon = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
        format!("{}@{}", id, canon.display())
    }

    /// Grants recorded on disk. A missing or corrupt file is simply an empty
    /// store — reading consent is never a load-bearing parse.
    ///
    /// Two shapes are accepted. The current one is an object of key → hash.
    /// The legacy one is a bare array of keys, written before grants were
    /// bound to content; those map to an empty hash, which no real content
    /// ever produces, so they grant nothing and the user re-confirms once.
    pub fn load(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let trusted = if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&text) {
            map
        } else if let Ok(keys) = serde_json::from_str::<Vec<String>>(&text) {
            keys.into_iter().map(|k| (k, String::new())).collect()
        } else {
            HashMap::new()
        };
        Self { trusted }
    }

    /// Persist the grants. Best-effort: a read-only config dir must not make
    /// plugin loading fail.
    pub fn save(&self, path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let sorted: std::collections::BTreeMap<&String, &String> = self.trusted.iter().collect();
        if let Ok(text) = serde_json::to_string_pretty(&sorted) {
            let _ = std::fs::write(path, text);
        }
    }

    /// Grant trust for the manifest exactly as it is now.
    pub fn trust_content(&mut self, id: &str, repo: &Path, manifest: &PluginManifest) {
        self.trusted
            .insert(Self::key(id, repo), content_hash(manifest));
    }

    /// Trusted only while the plugin still hashes to what was reviewed.
    pub fn is_trusted_content(&self, id: &str, repo: &Path, manifest: &PluginManifest) -> bool {
        self.trusted
            .get(&Self::key(id, repo))
            .is_some_and(|h| !h.is_empty() && *h == content_hash(manifest))
    }

    pub fn untrust(&mut self, id: &str, repo: &Path) {
        self.trusted.remove(&Self::key(id, repo));
    }

    /// Whether a grant exists for this id and repo, whatever its content hash.
    /// Lets the refusal say "changed since you trusted it" rather than the
    /// first-time wording, which would read as a fresh install.
    pub fn has_grant(&self, id: &str, repo: &Path) -> bool {
        self.trusted
            .get(&Self::key(id, repo))
            .is_some_and(|h| !h.is_empty())
    }
}

/// SHA-256 over what the plugin will execute: its manifest (the declared
/// command, args, env, timeouts, permissions) plus the bytes of every hook
/// script that lives inside the plugin directory. A `run.command` that resolves
/// outside the plugin dir (a bare PATH name such as `python3`) cannot be
/// covered by content, so it is left out and the UI says so.

pub fn content_hash(manifest: &PluginManifest) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // The fields that decide what runs. `serde_json::Value` sorts object keys,
    // so the encoding does not depend on the on-disk key order.
    let hooks: Vec<serde_json::Value> = manifest
        .capabilities
        .hooks
        .iter()
        .map(|d| {
            serde_json::json!({
                "event": d.event,
                "filter": d.filter,
                "run": d.run.as_ref().map(|r| serde_json::json!({
                    "command": r.command, "args": r.args, "env": r.env,
                })),
                "timeout_ms": d.timeout_ms(),
            })
        })
        .collect();
    let canon = serde_json::json!({
        "entry": manifest.entry,
        "kind": manifest.kind.map(|k| format!("{k:?}")),
        "sandboxed": manifest.sandboxed,
        "permissions": manifest.permissions.as_ref().map(|p| serde_json::json!({
            "network": p.network, "filesystem": p.filesystem,
        })),
        "hooks": hooks,
    });
    h.update(canon.to_string().as_bytes());
    for hook in &manifest.capabilities.hooks {
        let Some(run) = &hook.run else { continue };
        let cmd = Path::new(&run.command);
        let rel = if cmd.is_absolute() {
            continue;
        } else {
            cmd.strip_prefix("./").unwrap_or(cmd)
        };
        let path = manifest.dir.join(rel);
        // Only files that really live inside the plugin directory count.
        let inside = path
            .canonicalize()
            .ok()
            .zip(manifest.dir.canonicalize().ok())
            .is_some_and(|(p, d)| p.starts_with(&d));
        if inside {
            if let Ok(bytes) = std::fs::read(&path) {
                h.update(b"\0script:");
                h.update(run.command.as_bytes());
                h.update(b"\0");
                h.update(&bytes);
            }
        }
    }
    format!("{:x}", h.finalize())
}

/// Where trust grants live — `<config>/<app>/plugin-trust.json`.
pub fn trust_store_path(paths: &AppPaths) -> PathBuf {
    paths.config_file("plugin-trust.json")
}

/// Where the user's enable/disable toggles live —
/// `<config>/<app>/plugin-state.json`, a JSON array of disabled plugin ids.
/// Separate from consent (a trusted plugin can still be off) and keyed by
/// plain id, not `id@repo` — disabling a global plugin disables it
/// everywhere, which is what the toggle reads as.
pub fn disabled_store_path(paths: &AppPaths) -> PathBuf {
    paths.config_file("plugin-state.json")
}

/// Ids the user turned off — persisted as a JSON array, same shape and
/// posture as [`TrustStore`]: a missing/corrupt file is an empty store, a
/// read-only config dir must not break plugin loading.
#[derive(Clone, Default)]
pub struct DisabledStore {
    disabled: HashSet<String>,
}

impl DisabledStore {
    pub fn load(path: &Path) -> Self {
        let ids: Vec<String> = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            disabled: ids.into_iter().collect(),
        }
    }

    pub fn save(&self, path: &Path) {
        let mut keys: Vec<&String> = self.disabled.iter().collect();
        keys.sort();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(&keys) {
            let _ = std::fs::write(path, text);
        }
    }

    pub fn is_disabled(&self, id: &str) -> bool {
        self.disabled.contains(id)
    }

    /// `true` = disabled.
    pub fn set(&mut self, id: &str, disabled: bool) {
        if disabled {
            self.disabled.insert(id.to_string());
        } else {
            self.disabled.remove(id);
        }
    }
}

pub struct PluginManager {
    /// Where the host keeps config and workspace-local state. The crate names
    /// no product, so the host supplies this.
    paths: AppPaths,
    /// Host-owned paths kept unreadable to sandboxed hooks and MCP servers.
    sandbox_deny_read: Vec<PathBuf>,
    plugins: HashMap<String, Arc<dyn Plugin>>,
    /// Every accepted manifest, keyed by id — INCLUDING pure plugins with no
    /// `entry` and bridges whose connection failed. Kernel-side capabilities
    /// (hooks) live at this level: interception runs in the host, so a dead
    /// or absent server entry can never take a plugin's hooks down with it.
    manifests: HashMap<String, PluginManifest>,
    /// Registration order — hook chain order is documented as discovery
    /// order, and a `HashMap` cannot supply one.
    order: Vec<String>,
    /// Advertised tool name → owning plugin. Keyed by the WIRE name
    /// ([`wire_tool_name`]), which is what the model echoes back on a call.
    tool_router: HashMap<String, Arc<dyn Plugin>>,
    /// Advertised name → the server's own tool name (`ui-skills__get_skill` →
    /// `get_skill`), so dispatch can reach the real tool after sanitization
    /// replaced characters the wire charset forbids.
    real_tool_names: HashMap<String, String>,
    /// plugin_id → enabled flag (persisted via `disabled`; disabled plugins
    /// unload).
    enabled: HashMap<String, bool>,
    /// Ids the user turned off — persisted to `plugin-state.json`, read at
    /// load to seed `enabled`. Keyed by plain id (not `id@repo`): the toggle
    /// means "off", not "off in this repo".
    disabled: DisabledStore,
    /// Why a plugin is not in `plugins` — set by `load_all` when registration
    /// fails (dead endpoint, timeout). Reported to the settings UI so a broken
    /// server can explain itself without a reconnect attempt.
    errors: HashMap<String, String>,
    /// Raw manifest text each id was registered from. A reload compares it to
    /// reuse a live connection whose manifest did not change.
    fingerprints: HashMap<String, String>,
    /// Live connections carried over from the previous manager during a
    /// reload, consumed by `register_plugin` instead of reconnecting.
    reusable: HashMap<String, Arc<dyn Plugin>>,
    pub trust: TrustStore,
}

impl PluginManager {
    /// Empty manager. `load_all` is the usual entry point.
    pub fn new(paths: AppPaths) -> Self {
        let sandbox_deny_read = std::iter::once(paths.config_dir.clone())
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
        Self {
            paths,
            sandbox_deny_read,
            plugins: HashMap::new(),
            manifests: HashMap::new(),
            order: Vec::new(),
            tool_router: HashMap::new(),
            real_tool_names: HashMap::new(),
            enabled: HashMap::new(),
            disabled: DisabledStore::default(),
            errors: HashMap::new(),
            fingerprints: HashMap::new(),
            reusable: HashMap::new(),
            trust: TrustStore {
                trusted: HashMap::new(),
            },
        }
    }

    /// Live status per plugin — identity and tool names captured during the
    /// boot handshake, plus the reason for any plugin that failed to load.
    /// Reads memory only: the settings pane polls this instead of reconnecting,
    /// which used to open a fresh MCP session on every visit (and trip the
    /// provider's rate limit).
    pub fn status(&self) -> Vec<Value> {
        // Registered manifests ∪ failed registrations — a pure plugin (no
        // `entry`) shows connected:false and no tools, which is correct:
        // there was never anything to connect.
        let mut ids: Vec<&String> = self.manifests.keys().chain(self.errors.keys()).collect();
        ids.sort();
        ids.dedup();
        ids.into_iter()
            .map(|id| {
                let plugin = self.plugins.get(id);
                let (name, version) = plugin.map(|p| p.server_info()).unwrap_or_default();
                serde_json::json!({
                    "id": id,
                    "connected": plugin.is_some(),
                    "enabled": self.enabled.get(id).copied().unwrap_or(false),
                    "serverName": name,
                    "serverVersion": version,
                    "tools": plugin.map(|p| p.tool_names()).unwrap_or_default(),
                    // Lifecycle hooks this plugin declares — a local command
                    // per event. Read from the manifest, not the runtime —
                    // a dead entry (or no entry at all) still shows them.
                    "hooks": self
                        .manifests
                        .get(id)
                        .map(|m| {
                            hooks_from_manifest(m, &self.sandbox_deny_read)
                                .iter()
                                .map(|h| {
                                    serde_json::json!({
                                        "event": h.event,
                                        "command": h.command(),
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    // Declared slash commands — `/x` in the composer — read
                    // from the manifest like hooks (a dead entry still
                    // shows them).
                    "commands": self
                        .manifests
                        .get(id)
                        .map(|m| {
                            m.capabilities
                                .commands
                                .iter()
                                .map(|c| {
                                    serde_json::json!({
                                        "name": c.name,
                                        "qualified": format!("{id}:{}", c.name),
                                        "description": c.description,
                                        "action": c.action,
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    "error": self.errors.get(id).cloned().unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Every hook declared by an ENABLED manifest, in discovery order. The
    /// kernel turns these into its `AgentHook` chain — a disabled plugin's
    /// hooks vanish with its tools. Hooks are manifest-level, so they keep
    /// working when the plugin's `entry` failed to connect or was never
    /// declared.
    pub fn hook_specs(&self) -> Vec<CommandHook> {
        let mut out = Vec::new();
        // Registration order, not `HashMap` order — two hooks that both
        // rewrite the same tool must apply in a predictable sequence.
        for id in &self.order {
            if !self.enabled.get(id).copied().unwrap_or(false) {
                continue;
            }
            if let Some(manifest) = self.manifests.get(id) {
                out.extend(hooks_from_manifest(manifest, &self.sandbox_deny_read));
            }
        }
        out
    }

    /// Every slash command declared by an ENABLED manifest, in discovery
    /// order — the same gate as `hook_specs`: a disabled plugin's `/x`
    /// disappears with its tools. Manifest-level, so commands survive a
    /// failed or absent `entry` (they're dispatched inside the kernel).
    pub fn commands(&self) -> Vec<PluginCommand> {
        let mut out = Vec::new();
        for id in &self.order {
            if !self.enabled.get(id).copied().unwrap_or(false) {
                continue;
            }
            if let Some(manifest) = self.manifests.get(id) {
                for c in &manifest.capabilities.commands {
                    out.push(PluginCommand {
                        plugin_id: id.clone(),
                        name: c.name.clone(),
                        description: c.description.clone(),
                        action: c.action.clone(),
                    });
                }
            }
        }
        out
    }

    /// Every enabled plugin's tools, named `plugin_id__tool` — exactly what the
    /// engine advertises to the model. Both halves pass through
    /// [`wire_tool_name`], so the result is a legal `function.name` on every
    /// OpenAI-shaped wire; the old `plugin_id:tool` spelling was rejected as
    /// `invalid_argument` by strict upstreams (`:` is outside the charset).
    pub fn exported_tools(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for (id, plugin) in &self.plugins {
            if !self.enabled.get(id).copied().unwrap_or(false) {
                continue;
            }
            for mut tool in plugin.export_tools() {
                let Some(name) = tool
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .map(String::from)
                else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                tool["function"]["name"] = Value::String(wire_tool_name(id, &name));
                out.push(tool);
            }
        }
        out
    }

    /// Register one manifest — validates, records its kernel-side
    /// capabilities, then bridges to a server ONLY when `entry` exists.
    /// `repo` is the workspace root for repo-local trust scoping.
    ///
    /// The order matters: manifest + hooks are live before the runtime
    /// attempt, so an MCP connection that times out or 404s fails the BRIDGE
    /// (`errors[id]`) while the plugin's hooks stay in the chain.
    pub async fn register_plugin(
        &mut self,
        manifest: PluginManifest,
        repo: &Path,
    ) -> Result<(), String> {
        let Some(manifest) = self.prepare_plugin(manifest, repo)? else {
            return Ok(());
        };
        let id = manifest.id.clone();
        let live = self.reusable.remove(&id);
        let plugin = connect_plugin(
            manifest,
            live,
            self.paths.app_name().to_string(),
            self.sandbox_deny_read.clone(),
        )
        .await?;
        self.finish_plugin(&id, plugin);
        Ok(())
    }

    /// Synchronous half of registration: validate, trust-gate, record the
    /// manifest (hooks live here). `Some(manifest)` means a runtime still has
    /// to be connected; `None` means the plugin is complete as it stands
    /// (pure plugin, or switched off).
    fn prepare_plugin(
        &mut self,
        manifest: PluginManifest,
        repo: &Path,
    ) -> Result<Option<PluginManifest>, String> {
        manifest.validate()?;
        let id = manifest.id.clone();

        // Repo-local plugins need explicit trust before they're live.
        if !manifest.dir.as_os_str().is_empty()
            && manifest.dir.starts_with(self.paths.workspace_dir(repo))
            && !self.trust.is_trusted_content(&id, repo, &manifest)
        {
            return Err(if self.trust.has_grant(&id, repo) {
                format!(
                    "plugin `{id}` is repo-local and its code changed since you trusted \
                     it — review it again to re-enable"
                )
            } else {
                format!("plugin `{id}` is repo-local — trust consent required before load")
            });
        }

        // Kernel-side capabilities are manifest-level: hooks intercept in the
        // host, so they register ahead of (and independently of) any entry.
        self.manifests.insert(id.clone(), manifest.clone());
        if !self.order.contains(&id) {
            self.order.push(id.clone());
        }
        self.enabled
            .insert(id.clone(), !self.disabled.is_disabled(&id));

        // No `entry` = pure plugin — nothing to connect, done.
        if manifest.entry.is_none() {
            info!(plugin = %id, "plugin registered (no entry — host-side only)");
            return Ok(None);
        }

        // A plugin the user switched off must not run: no subprocess, no
        // router entries. `enable` followed by a reload registers it again.
        if self.disabled.is_disabled(&id) {
            info!(plugin = %id, "plugin registered but disabled — runtime not started");
            return Ok(None);
        }
        Ok(Some(manifest))
    }

    /// Export tools → router, keyed by the SAME name `exported_tools` puts in
    /// the request. The two must agree exactly, or the model calls a name
    /// the router has never heard of.
    fn finish_plugin(&mut self, id: &str, plugin: Arc<dyn Plugin>) {
        for t in plugin.export_tools() {
            let name = t["function"]["name"].as_str().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let advertised = wire_tool_name(id, &name);
            self.real_tool_names.insert(advertised.clone(), name);
            self.tool_router.insert(advertised, plugin.clone());
        }
        self.plugins.insert(id.to_string(), plugin);
        info!(plugin = %id, "plugin registered");
    }

    /// Route a tool call → owning plugin → truncates to the 40 KB budget.
    ///
    /// Resolution order: the advertised wire name (`ui-skills__get_skill`),
    /// then a bare name (`get_skill`) when exactly one plugin owns it, then a
    /// legacy `plugin_id:tool` spelling from a snapshot written before the
    /// colon became wire-illegal. Whichever spelling matched, the SERVER is
    /// called with its own tool name, never with the advertised one.
    pub async fn dispatch_tool_call(&self, name: &str, args: Value) -> Result<String, String> {
        let (plugin, real) = self
            .tool_router
            .get(name)
            .map(|p| (p.clone(), name.to_string()))
            .or_else(|| self.resolve_bare(name))
            .or_else(|| self.resolve_legacy(name))
            .ok_or_else(|| self.tool_dispatch_error(name))?;
        // Defense in depth: even if a stale router entry survives (e.g. a
        // disable racing a registration), a disabled plugin never executes.
        if !self.enabled.get(plugin.id()).copied().unwrap_or(false) {
            return Err(format!("plugin `{}` is disabled", plugin.id()));
        }
        // The tool name the MCP server knows — the advertised name was passed
        // through the wire charset, which is lossy.
        let real = self.real_tool_names.get(&real).cloned().unwrap_or(real);

        let out = plugin
            .call_tool(&real, args)
            .await
            .map_err(|e| e.to_string())?;
        Ok(truncate(&out, PLUGIN_OUTPUT_CAP))
    }

    /// Why a `dispatch_tool_call` lookup missed. A plugin that DECLARED the
    /// tool but never reached the router (load failed — e.g. `wasm` feature
    /// off, spawn error) gets a message that says so, with the recorded
    /// failure; a genuinely unknown name keeps the generic wording.
    fn tool_dispatch_error(&self, name: &str) -> String {
        // Bare tool names can't be attributed without the router, so the
        // declaration scan compares both the wire spelling and a suffix
        // match for `id__tool`/`id:tool` callers.
        for (id, m) in &self.manifests {
            let declares = m
                .capabilities
                .tools
                .iter()
                .any(|t| t.name == name || wire_tool_name(id, &t.name) == name);
            if declares {
                let why = self
                    .errors
                    .get(id)
                    .map(|e| format!(" — {e}"))
                    .unwrap_or_default();
                return format!("plugin `{id}` declares `{name}` but isn't running{why}");
            }
        }
        format!("no plugin owns tool `{name}`")
    }

    /// A bare (`get_skill`) or legacy (`ui-skills:get_skill`) call name →
    /// owning plugin + the advertised name to look the real tool up under.
    /// Unique-ness is judged against `real_tool_names`, built at registration.
    fn resolve_bare(&self, name: &str) -> Option<(Arc<dyn Plugin>, String)> {
        let advertised = self
            .real_tool_names
            .iter()
            .filter(|(_, real)| real.as_str() == name)
            .map(|(adv, _)| adv.clone())
            .collect::<Vec<_>>();
        if advertised.len() != 1 {
            return None; // unknown, or ambiguous across plugins
        }
        let adv = advertised.into_iter().next()?;
        self.tool_router.get(&adv).map(|p| (p.clone(), adv))
    }

    /// `plugin_id:tool` → the sanitized advertised name. Snapshots persisted
    /// before the colon was removed still replay these names. The plugin id
    /// may itself contain colons (`ui:skills:list_skills`), so EVERY split
    /// point is tried rather than just the first.
    fn resolve_legacy(&self, name: &str) -> Option<(Arc<dyn Plugin>, String)> {
        for (i, _) in name.match_indices(':') {
            let (pid, tool) = (&name[..i], &name[i + 1..]);
            let adv = wire_tool_name(pid, tool);
            if let Some(p) = self.tool_router.get(&adv) {
                return Some((p.clone(), adv));
            }
        }
        None
    }

    /// `<plugin_context>` blocks appended after the workspace skeleton —
    /// per-plugin 2 s timeout, tagged with the provider id.
    pub async fn collect_dynamic_contexts(&self, workspace: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (id, plugin) in &self.plugins {
            if !self.enabled.get(id).copied().unwrap_or(false) {
                continue;
            }
            let ws = workspace.to_string();
            let p = plugin.clone();
            let ctx = tokio::time::timeout(CONTEXT_TIMEOUT, p.provide_context(&ws)).await;
            match ctx {
                Ok(Some(text)) => {
                    out.push(format!(
                        "<plugin_context id=\"{id}\">\n{text}\n</plugin_context>"
                    ));
                }
                Ok(None) => {}
                Err(_) => warn!(plugin = %id, "provide_context timed out"),
            }
        }
        out
    }

    /// Disable = persist the flag + purge the router (its tools vanish next
    /// request, and `hook_specs` skips it). The persisted set is what a
    /// reload reads, so toggling survives restarts.
    pub fn disable(&mut self, id: &str) {
        self.enabled.insert(id.to_string(), false);
        self.disabled.set(id, true);
        self.disabled.save(&disabled_store_path(&self.paths));
        self.tool_router.retain(|_, p| p.id() != id);
        // The advertised → real name map is keyed by the advertised name only,
        // so it must be purged alongside the router — a stale entry would let
        // `resolve_bare` match a tool the plugin no longer advertises.
        let plugin = self.plugins.get(id);
        if let Some(plugin) = plugin {
            for tool in plugin.export_tools() {
                if let Some(name) = tool["function"]["name"].as_str() {
                    self.real_tool_names.remove(&wire_tool_name(id, name));
                }
            }
        }
    }

    /// Whether the user turned this plugin off (persisted intent — separate
    /// from `enabled`, which additionally goes false on load failure).
    pub fn is_disabled(&self, id: &str) -> bool {
        self.disabled.is_disabled(id)
    }

    pub fn enable(&mut self, id: &str) {
        self.enabled.insert(id.to_string(), true);
        self.disabled.set(id, false);
        self.disabled.save(&disabled_store_path(&self.paths));
        // Re-registering rebuilds the router — tools reappear next request.
    }

    /// Plugin metadata for the settings panel.
    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .map(|(id, p)| PluginInfo {
                id: id.clone(),
                kind: "mcp".into(), // wasm when that runtime lands
                enabled: self.enabled.get(id).copied().unwrap_or(false),
                tool_count: self
                    .tool_router
                    .values()
                    .filter(|r| r.id() == p.id())
                    .count(),
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct PluginInfo {
    pub id: String,
    pub kind: String,
    pub enabled: bool,
    pub tool_count: usize,
}

/// The name a plugin tool is ADVERTISED under — `plugin_id__tool`, every
/// character outside `[A-Za-z0-9_-]` folded to `_`.
///
/// The `tools[].function.name` charset on every OpenAI-shaped wire is
/// `^[a-zA-Z0-9_-]{1,64}$`: a `:` separator (the old spelling,
/// `ui-skills:list_skills`) is not in it, and a strict upstream rejects the
/// ENTIRE request with `invalid_argument` before the model ever runs — which
/// is exactly how a registered MCP server bricked every turn. `/`, `.` and
/// spaces are just as illegal, and a server is free to name its tools that way.
///
/// `__` is the separator because a single `_` is already common inside tool
/// names (`list_skills`), so one underscore could not be told apart from the
/// namespace boundary when resolving a call. Both halves are folded and
/// truncated so the joined name stays inside 64 chars.
/// One declared slash command, flattened out of a plugin's
/// `capabilities.commands`. `qualified` (`plugin_id:name`) is the
/// collision-safe spelling the kernel's `/x` dispatch also accepts.
#[derive(Debug, Clone)]
pub struct PluginCommand {
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    /// `"tool:<name>"` → dispatch that plugin tool; `"prompt:<text>"` →
    /// feed the text to the agent with the typed args appended.
    pub action: String,
}

impl PluginCommand {
    /// `plugin_id:name` — unique even when two plugins ship a `name`
    /// they didn't coordinate on.
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.plugin_id, self.name)
    }
}

pub fn wire_tool_name(plugin_id: &str, tool: &str) -> String {
    const MAX: usize = 64;
    const SEP: &str = "__";
    let id = sanitize_name(plugin_id);
    let tool = sanitize_name(tool);
    // The tool half matters more for a human scanning a picker, so trim the
    // namespace (not the tool) when the pair overflows.
    if id.len() + SEP.len() + tool.len() <= MAX {
        return format!("{id}{SEP}{tool}");
    }
    let room = MAX.saturating_sub(SEP.len() + tool.len());
    // `room` is a byte budget and the sanitized half is ASCII, so this is also
    // a char boundary — no need for the `is_char_boundary` walk.
    let id = &id[..room.min(id.len())];
    format!("{id}{SEP}{tool}")
}

/// Fold every character the wire charset forbids to `_`. ASCII-only by
/// construction (a non-ASCII char is itself illegal on the wire).
fn sanitize_name(s: &str) -> String {
    let folded: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if folded.is_empty() {
        "_".to_string()
    } else {
        folded
    }
}

/// Discover manifests under the two install roots — plugins and MCP are
/// separate trees (`plugins/` for host-side hooks, `mcp/` for protocol
/// bridges), each with a global and a repo-local variant. The manifest
/// shape, not the tree, decides what a manifest IS.
pub fn discover(repo: &Path, paths: &AppPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.push(paths.config_dir.join("plugins"));
    dirs.push(paths.config_dir.join("mcp"));
    let ws = paths.workspace_dir(repo);
    dirs.push(ws.join("plugins"));
    dirs.push(ws.join("mcp"));
    let mut manifests = Vec::new();
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let m = e.path().join("manifest.json");
                if m.exists() {
                    manifests.push(m);
                }
            }
        }
    }
    manifests
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\n… [truncated {} bytes]", &s[..end], s.len() - end)
    }
}

/// Discover the standard plugin dirs and register every MCP server.
///
/// Bounded on purpose: a dead endpoint is logged and skipped, so one broken
/// server can neither stall the app's boot nor keep the other plugins from
/// loading. Called once at startup (see `SessionManager::spawn_at`).
pub async fn load_all(repo: &Path, paths: &AppPaths, deny_read: &[PathBuf]) -> PluginManager {
    reload_all(repo, paths, deny_read, None).await
}

/// Build the runtime for an entry-bearing manifest. Owns its inputs so many
/// can be in flight at once. A reload passes the previous `live` connection
/// of an unchanged manifest and nothing is handshaken again.
async fn connect_plugin(
    manifest: PluginManifest,
    live: Option<Arc<dyn Plugin>>,
    app_name: String,
    deny_read: Vec<PathBuf>,
) -> Result<Arc<dyn Plugin>, String> {
    if let Some(live) = live {
        return Ok(live);
    }
    let id = manifest.id.clone();
    // The `entry` shape IS the runtime declaration — an absent `kind`
    // means MCP, which is what every entry-bearing manifest is today.
    match manifest.kind.unwrap_or(PluginKind::Mcp) {
        PluginKind::Mcp => {
            let client = McpClient::start(&manifest, &app_name, &deny_read)
                .await
                .map_err(|e| format!("MCP `{id}` start: {e}"))?;
            Ok(Arc::new(McpPlugin { manifest, client }))
        }
        PluginKind::Wasm => {
            #[cfg(feature = "wasm")]
            {
                // Reading + Cranelift-compiling the module is seconds of
                // synchronous CPU — keep it off the async workers so it
                // can't stall the other plugins loading beside it.
                let loaded =
                    tokio::task::spawn_blocking(move || crate::wasm::WasmPlugin::load(manifest))
                        .await
                        .map_err(|e| format!("wasm `{id}` load: {e}"))?
                        .map_err(|e| format!("wasm `{id}` load: {e}"))?;
                Ok(Arc::new(loaded) as Arc<dyn Plugin>)
            }
            #[cfg(not(feature = "wasm"))]
            Err("WASM plugins not built (feature `wasm` off)".into())
        }
    }
}

/// `load_all` that keeps the live connection of every plugin whose manifest
/// text is unchanged since `prev` — only new or edited entries handshake
/// again. Everything else (trust, enabled flags, hooks) is re-read as usual.
pub async fn reload_all(
    repo: &Path,
    paths: &AppPaths,
    deny_read: &[PathBuf],
    prev: Option<&PluginManager>,
) -> PluginManager {
    let mut mgr = PluginManager::new(paths.clone());
    for path in deny_read {
        if !mgr.sandbox_deny_read.contains(path) {
            mgr.sandbox_deny_read.push(path.clone());
        }
    }
    // Consent recorded by earlier runs. Without it a repo-local plugin would
    // be refused on every boot, so the grant has to come from disk.
    mgr.trust = TrustStore::load(&trust_store_path(paths));
    mgr.disabled = DisabledStore::load(&disabled_store_path(paths));
    let mut pending: Vec<(String, PluginManifest, Option<Arc<dyn Plugin>>)> = Vec::new();
    for mpath in discover(repo, paths) {
        let Ok(text) = std::fs::read_to_string(&mpath) else {
            continue;
        };
        let Ok(mut manifest) = serde_json::from_str::<PluginManifest>(&text) else {
            continue;
        };
        // Where the manifest was found — `PluginManifest.dir` is `serde(skip)`,
        // so discovery is the only thing that can fill it. It drives the
        // repo-local trust scope below and a relative hook `run.command`.
        manifest.dir = mpath.parent().unwrap_or(Path::new("")).to_path_buf();
        let id = manifest.id.clone();
        if let Some(prev) = prev {
            if let (Some(old), Some(live)) = (prev.fingerprints.get(&id), prev.plugins.get(&id)) {
                if *old == text && prev.sandbox_deny_read == mgr.sandbox_deny_read {
                    mgr.reusable.insert(id.clone(), live.clone());
                }
            }
        }
        mgr.fingerprints.insert(id.clone(), text);
        match mgr.prepare_plugin(manifest, repo) {
            Ok(Some(m)) => {
                let live = mgr.reusable.remove(&id);
                pending.push((id, m, live));
            }
            Ok(None) => {}
            Err(e) => {
                warn!(plugin = %id, "plugin registration failed: {e}");
                mgr.errors.insert(id, e);
            }
        }
    }
    // Handshakes are network/subprocess waits — run them all at once so the
    // reload costs the slowest server, not the sum. Each keeps its own 8 s
    // bound; results are applied in discovery order so the tool router stays
    // deterministic.
    let app_name = mgr.paths.app_name().to_string();
    let deny = mgr.sandbox_deny_read.clone();
    let results = futures::future::join_all(pending.into_iter().map(|(id, m, live)| {
        let (app_name, deny) = (app_name.clone(), deny.clone());
        async move {
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(8),
                connect_plugin(m, live, app_name, deny),
            )
            .await;
            (id, r)
        }
    }))
    .await;
    for (id, r) in results {
        match r {
            Ok(Ok(plugin)) => mgr.finish_plugin(&id, plugin),
            Ok(Err(e)) => {
                warn!(plugin = %id, "plugin registration failed: {e}");
                mgr.errors.insert(id, e);
            }
            Err(_) => {
                warn!(plugin = %id, "plugin registration timed out (8s)");
                mgr.errors
                    .insert(id, "连接超时（8 秒）— 端点无响应".to_string());
            }
        }
    }
    mgr
}

#[cfg(test)]
mod tests {
    fn test_paths() -> agent_paths::AppPaths {
        let base = std::env::temp_dir().join("agent-plugin-test");
        agent_paths::AppPaths::new(base.join("config"), base.join("data"), ".husk")
    }

    use super::{sanitize_name, wire_tool_name};
    use crate::Plugin;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// The regression this whole module exists to prevent: an advertised tool
    /// name carrying a character outside `^[a-zA-Z0-9_-]{1,64}$` makes a strict
    /// upstream reject the ENTIRE request as `invalid_argument` — before the
    /// model runs, so the session simply cannot answer. The old spelling was
    /// `plugin_id:tool`.
    #[test]
    fn advertised_names_are_wire_legal() {
        let legal = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };

        assert!(legal(&wire_tool_name("ui-skills", "list_skills")));
        assert_eq!(
            wire_tool_name("ui-skills", "list_skills"),
            "ui-skills__list_skills"
        );

        // The reported shape — a colon is the character that broke it.
        assert!(!wire_tool_name("ui-skills", "list_skills").contains(':'));

        // Servers name tools with dots, slashes and spaces too.
        for (id, tool) in [
            ("github.com/server", "repos.list"),
            ("my plugin", "read file"),
            ("srv", "path/to/thing"),
            ("plugin", "配置"),
        ] {
            let out = wire_tool_name(id, tool);
            assert!(legal(&out), "illegal advertised name: {out:?}");
        }
    }

    /// Namespacing must not leak into the 64-char cap — an over-long pair is
    /// trimmed at the namespace, keeping the tool half intact.
    #[test]
    fn long_names_are_trimmed_at_the_namespace() {
        let long_id = "p".repeat(80);
        let out = wire_tool_name(&long_id, "do_the_thing");
        assert_eq!(out.len(), 64);
        assert!(out.ends_with("__do_the_thing"));
    }

    /// The sanitized halves round-trip: what `sanitize_name` produces is what
    /// `wire_tool_name` joins, so resolution can rebuild the same key.
    #[test]
    fn sanitize_folds_only_forbidden_chars() {
        assert_eq!(sanitize_name("ui-skills_2"), "ui-skills_2");
        assert_eq!(sanitize_name("a:b/c.d e"), "a_b_c_d_e");
        // Empty halves must still yield a usable segment.
        assert_eq!(sanitize_name(""), "_");
    }

    /// Dispatch reaches the SERVER's own tool name — the advertised name is
    /// lossy, so calling the server with it would 404 on the MCP side.
    #[tokio::test]
    async fn dispatch_resolves_advertised_and_bare_names() {
        use std::sync::Arc;

        struct Fake {
            id: String,
            tools: Vec<&'static str>,
            called: std::sync::Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl Plugin for Fake {
            fn id(&self) -> &str {
                &self.id
            }
            fn export_tools(&self) -> Vec<serde_json::Value> {
                self.tools
                    .iter()
                    .map(|t| serde_json::json!({"type":"function","function":{"name":t}}))
                    .collect()
            }
            async fn call_tool(
                &self,
                name: &str,
                _args: serde_json::Value,
            ) -> anyhow::Result<String> {
                self.called.lock().unwrap().push(name.to_string());
                Ok(format!("called {name}"))
            }
        }

        // A colon-bearing plugin id — the exact shape that used to break.
        let fake = Arc::new(Fake {
            id: "ui:skills".into(),
            tools: vec!["list_skills", "get_skill"],
            called: std::sync::Mutex::new(Vec::new()),
        });
        let advertised: Vec<String> = fake
            .export_tools()
            .iter()
            .map(|t| wire_tool_name(fake.id(), t["function"]["name"].as_str().unwrap()))
            .collect();
        assert_eq!(
            advertised,
            vec!["ui_skills__list_skills", "ui_skills__get_skill"]
        );

        // Drive the real registration/dispatch path via a manager.
        let mut mgr = super::PluginManager::new(test_paths());
        let plugin: Arc<dyn Plugin> = fake.clone();
        for (real, adv) in [
            ("list_skills", &advertised[0]),
            ("get_skill", &advertised[1]),
        ] {
            mgr.real_tool_names.insert(adv.clone(), real.to_string());
            mgr.tool_router.insert(adv.clone(), plugin.clone());
        }
        mgr.plugins.insert(fake.id().to_string(), plugin);
        mgr.enabled.insert(fake.id().to_string(), true);

        // Advertised spelling.
        assert_eq!(
            mgr.dispatch_tool_call("ui_skills__get_skill", serde_json::json!({}))
                .await
                .unwrap(),
            "called get_skill"
        );
        // Bare spelling (a model that drops the namespace).
        assert_eq!(
            mgr.dispatch_tool_call("list_skills", serde_json::json!({}))
                .await
                .unwrap(),
            "called list_skills"
        );
        // Legacy colon spelling from a pre-fix snapshot.
        assert_eq!(
            mgr.dispatch_tool_call("ui:skills:list_skills", serde_json::json!({}))
                .await
                .unwrap(),
            "called list_skills"
        );
        // An unknown tool is refused, not silently misrouted.
        assert!(mgr
            .dispatch_tool_call("nope", serde_json::json!({}))
            .await
            .is_err());
    }

    /// P4: a stale router entry for a disabled plugin must not execute.
    #[tokio::test]
    async fn dispatch_refuses_a_disabled_plugin() {
        struct Fake;
        #[async_trait::async_trait]
        impl Plugin for Fake {
            fn id(&self) -> &str {
                "off"
            }
            fn export_tools(&self) -> Vec<serde_json::Value> {
                vec![serde_json::json!({"type":"function","function":{"name":"echo"}})]
            }
            async fn call_tool(
                &self,
                _name: &str,
                _args: serde_json::Value,
            ) -> anyhow::Result<String> {
                panic!("a disabled plugin must never be called");
            }
        }
        let mut mgr = super::PluginManager::new(test_paths());
        let plugin: Arc<dyn Plugin> = Arc::new(Fake);
        let adv = wire_tool_name("off", "echo");
        mgr.real_tool_names.insert(adv.clone(), "echo".into());
        mgr.tool_router.insert(adv.clone(), plugin.clone());
        mgr.plugins.insert("off".into(), plugin);
        mgr.enabled.insert("off".into(), false);
        for name in [adv.as_str(), "echo"] {
            let err = mgr
                .dispatch_tool_call(name, serde_json::json!({}))
                .await
                .unwrap_err();
            assert!(err.contains("disabled"), "{err}");
        }
    }

    /// The hook chain is assembled from enabled plugins, in registration
    /// order — not `HashMap` order, which would make two hooks that both
    /// rewrite the same tool apply unpredictably.
    #[test]
    fn hook_specs_follow_registration_order_and_skip_disabled() {
        // Hooks are manifest-level now: registration needs no runtime, so the
        // fixture is manifests straight into the manager — no fake Plugin.
        let mk = |id: &str, event: &str| -> crate::PluginManifest {
            let mut m: crate::PluginManifest = serde_json::from_value(serde_json::json!({
                "id": id, "name": id,
                "capabilities": {"hooks": [{"event": event, "run": {"command": "./h.sh"}}]},
            }))
            .unwrap();
            m.dir = PathBuf::from("/plugins").join(id);
            m
        };

        let mut mgr = super::PluginManager::new(test_paths());
        for id in ["a", "b", "c"] {
            mgr.manifests
                .insert(id.into(), mk(id, "before_tool_execute"));
            mgr.order.push(id.into());
            mgr.enabled.insert(id.into(), true);
        }
        mgr.disable("b");

        let events: Vec<String> = mgr.hook_specs().iter().map(|h| h.id()).collect();
        assert_eq!(
            events,
            vec!["a:before_tool_execute", "c:before_tool_execute"]
        );

        // A plugin absent from the chain contributes nothing even if its
        // registration skipped `order` (the old bug shape).
        mgr.disable("a");
        mgr.disable("c");
        assert!(mgr.hook_specs().is_empty());

        // The settings card reads the same declarations: event + the command
        // it would run (what a trust decision has to see).
        mgr.enable("a");
        let status = mgr.status();
        let a = status.iter().find(|v| v["id"] == "a").unwrap();
        assert_eq!(a["hooks"][0]["event"], "before_tool_execute");
        assert_eq!(a["hooks"][0]["command"], "/plugins/a/h.sh");
    }

    /// Declared `capabilities.commands` surface through `commands()` in
    /// discovery order and through `status()` as manifest data — a disabled
    /// plugin's `/x` disappears from both.
    #[test]
    fn commands_follow_discovery_order_and_skip_disabled() {
        let mk = |id: &str, cmd_name: &str| -> crate::PluginManifest {
            let mut m: crate::PluginManifest = serde_json::from_value(serde_json::json!({
                "id": id, "name": id,
                "capabilities": {
                    "commands": [
                        {"name": cmd_name, "description": "d", "action": format!("tool:{cmd_name}")}
                    ]
                },
            }))
            .unwrap();
            m.dir = PathBuf::from("/plugins").join(id);
            m
        };

        let mut mgr = super::PluginManager::new(test_paths());
        for (id, cmd) in [("a", "foo"), ("b", "bar")] {
            mgr.manifests.insert(id.into(), mk(id, cmd));
            mgr.order.push(id.into());
            mgr.enabled.insert(id.into(), true);
        }
        mgr.disable("b");

        let cmds = mgr.commands();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].plugin_id, "a");
        assert_eq!(cmds[0].name, "foo");
        assert_eq!(cmds[0].qualified(), "a:foo");
        assert_eq!(cmds[0].action, "tool:foo");

        let status = mgr.status();
        let a = status.iter().find(|v| v["id"] == "a").unwrap();
        assert_eq!(a["commands"][0]["qualified"], "a:foo");
    }

    /// A declared-but-dead plugin's tool gets a *why* on dispatch failure —
    /// "declares X but isn't running: <load error>" — not a bare
    /// "no plugin owns tool" that looks like a typo.
    #[tokio::test]
    async fn dispatch_error_names_the_dead_plugin() {
        let mut mgr = super::PluginManager::new(test_paths());
        let mut m: crate::PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "wasm-x", "name": "x",
            "capabilities": {"tools": [{"name": "slugify", "description": "d", "parameters": {}}]},
        }))
        .unwrap();
        m.dir = PathBuf::from("/plugins/wasm-x");
        mgr.manifests.insert("wasm-x".into(), m);
        mgr.order.push("wasm-x".into());
        mgr.enabled.insert("wasm-x".into(), true);
        mgr.errors.insert(
            "wasm-x".into(),
            "WASM plugins not built (feature wasm off)".into(),
        );

        // Bare name resolves to the dead plugin, not a generic "unknown".
        let err = mgr
            .dispatch_tool_call("slugify", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("wasm-x"), "{err}");
        assert!(err.contains("WASM plugins not built"), "{err}");

        // Wire spelling gets the same attribution.
        let err = mgr
            .dispatch_tool_call("wasm-x__slugify", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("isn't running"), "{err}");

        // A name nobody declared stays generic.
        let err = mgr
            .dispatch_tool_call("nonexistent", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("no plugin owns tool"), "{err}");
    }

    /// A repo-local plugin is inert until trusted — and the gate is load
    /// bearing now that discovery fills `manifest.dir` (hook commands are
    /// local code, so an untrusted checkout must not run them).
    #[tokio::test]
    async fn repo_local_plugins_require_trust() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let plugin_dir = repo.join(".husk/plugins/local");
        std::fs::create_dir_all(&plugin_dir).unwrap();

        let mk = || {
            let mut m: crate::PluginManifest = serde_json::from_value(serde_json::json!({
                "id": "local", "name": "local", "kind": "wasm", "entry": "x.wasm",
            }))
            .unwrap();
            m.dir = plugin_dir.clone();
            m
        };

        let mut mgr = super::PluginManager::new(test_paths());
        let err = mgr.register_plugin(mk(), &repo).await.unwrap_err();
        assert!(err.contains("trust consent"), "{err}");
        assert!(!mgr.plugins.contains_key("local"));

        // With consent the gate passes (the kind check rejects WASM next,
        // which is exactly the proof that trust was satisfied).
        mgr.trust.trust_content("local", &repo, &mk());
        let err = mgr.register_plugin(mk(), &repo).await.unwrap_err();
        assert!(
            err.to_lowercase().contains("wasm"),
            "gate did not pass: {err}"
        );

        // Home-dir plugins (~/.config/husk/plugins) are never gated: they are
        // not inside the repo, so `dir` cannot start with `<repo>/.husk`.
        let home = dir.path().join("home/plugins/other");
        let mut m: crate::PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "other", "name": "other", "kind": "wasm", "entry": "x.wasm",
        }))
        .unwrap();
        m.dir = home;
        let err = mgr.register_plugin(m, &repo).await.unwrap_err();
        assert!(
            err.to_lowercase().contains("wasm"),
            "home plugin was gated: {err}"
        );
    }

    /// Consent has to survive a restart, or every boot re-refuses.
    #[test]
    fn trust_store_round_trips_through_disk() {
        use crate::PluginManifest;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/plugin-trust.json");
        let repo = Path::new("/ws/repo");
        let manifest = |id: &str| -> PluginManifest {
            let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
                "id": id, "name": id, "entry": { "command": "x" },
            }))
            .unwrap();
            m.dir = PathBuf::from("/nonexistent");
            m
        };

        let mut store = super::TrustStore::default();
        store.trust_content("a", repo, &manifest("a"));
        store.trust_content("b", repo, &manifest("b"));
        store.save(&path);

        let loaded = super::TrustStore::load(&path);
        assert!(loaded.is_trusted_content("a", repo, &manifest("a")));
        assert!(loaded.is_trusted_content("b", repo, &manifest("b")));
        // Scope is path-keyed: another checkout of the same plugin id is a
        // different grant.
        assert!(!loaded.is_trusted_content("a", Path::new("/other/repo"), &manifest("a")));

        let mut store = loaded;
        store.untrust("a", repo);
        store.save(&path);
        let loaded = super::TrustStore::load(&path);
        assert!(!loaded.is_trusted_content("a", repo, &manifest("a")));
        assert!(loaded.is_trusted_content("b", repo, &manifest("b")));

        // A missing file is an empty store, not an error.
        assert!(
            !super::TrustStore::load(&dir.path().join("nope.json")).is_trusted_content(
                "a",
                repo,
                &manifest("a")
            )
        );
        std::fs::write(&path, "{ not json").unwrap();
        assert!(!super::TrustStore::load(&path).is_trusted_content("b", repo, &manifest("b")));
    }

    /// End-to-end on the real manager (not hand-populated maps): registration
    /// builds the router from `export_tools`, and `exported_tools` — the exact
    /// array the engine puts in the request — must be wire-legal and must be
    /// dispatchable by the name it advertises.
    #[tokio::test]
    async fn registration_round_trips_every_advertised_name() {
        use std::sync::Arc;

        struct Fake {
            id: String,
            tools: Vec<&'static str>,
        }

        #[async_trait::async_trait]
        impl Plugin for Fake {
            fn id(&self) -> &str {
                &self.id
            }
            fn export_tools(&self) -> Vec<serde_json::Value> {
                self.tools
                    .iter()
                    .map(|t| serde_json::json!({"type":"function","function":{"name":t}}))
                    .collect()
            }
            async fn call_tool(&self, name: &str, _a: serde_json::Value) -> anyhow::Result<String> {
                Ok(name.to_string())
            }
        }

        // Two plugins, one with a colon in its id AND its tool names — every
        // character the wire forbids, in the place that used to break it.
        let mut mgr = super::PluginManager::new(test_paths());
        for (id, tools) in [
            ("ui:skills", vec!["list_skills", "get_skill"]),
            ("fs.reader", vec!["read/file", "list.dir"]),
        ] {
            let p: Arc<dyn Plugin> = Arc::new(Fake {
                id: id.into(),
                tools,
            });
            mgr.plugins.insert(id.into(), p.clone());
            mgr.enabled.insert(id.into(), true);
            for t in p.export_tools() {
                let real = t["function"]["name"].as_str().unwrap().to_string();
                let adv = wire_tool_name(id, &real);
                mgr.real_tool_names.insert(adv.clone(), real);
                mgr.tool_router.insert(adv, p.clone());
            }
        }

        let advertised = mgr.exported_tools();
        assert_eq!(advertised.len(), 4);
        for t in &advertised {
            let name = t["function"]["name"].as_str().unwrap();
            assert!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                "the engine would send an illegal function.name: {name:?}"
            );
            // …and the advertised name is actually callable.
            assert!(mgr
                .dispatch_tool_call(name, serde_json::json!({}))
                .await
                .is_ok());
        }
        assert!(advertised
            .iter()
            .any(|t| t["function"]["name"] == "ui_skills__list_skills"));

        // Disabling purges both maps — no phantom tool survives.
        mgr.disable("ui:skills");
        assert_eq!(mgr.exported_tools().len(), 2);
        assert!(mgr
            .dispatch_tool_call("ui_skills__list_skills", serde_json::json!({}))
            .await
            .is_err());
    }
}

#[cfg(test)]
mod trust_content_tests {
    fn test_paths() -> agent_paths::AppPaths {
        let base = std::env::temp_dir().join("agent-plugin-test");
        agent_paths::AppPaths::new(base.join("config"), base.join("data"), ".husk")
    }

    use super::*;

    /// A repo-local plugin with one hook whose script lives in its own dir.
    fn repo_plugin(repo: &Path, script_body: &str) -> PluginManifest {
        let dir = repo.join(".husk/plugins/guard");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("h.sh"), script_body).unwrap();
        let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "guard", "name": "guard",
            "capabilities": { "hooks": [{ "event": "on_user_input", "run": { "command": "./h.sh" } }] },
        }))
        .unwrap();
        m.dir = dir;
        m
    }

    /// Trust is granted for the content that was reviewed. Swapping the script
    /// afterwards must withdraw it — a `git pull` cannot silently change code
    /// the user already approved.
    #[tokio::test]
    async fn changed_script_loses_trust() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let mut mgr = PluginManager::new(test_paths());
        mgr.trust
            .trust_content("guard", &repo, &repo_plugin(&repo, "echo reviewed"));
        assert!(mgr
            .trust
            .is_trusted_content("guard", &repo, &repo_plugin(&repo, "echo reviewed")));

        // Same manifest, different script: no longer the reviewed content.
        assert!(!mgr
            .trust
            .is_trusted_content("guard", &repo, &repo_plugin(&repo, "echo swapped"),));
    }

    /// Unchanged content keeps its trust across a reload.
    #[tokio::test]
    async fn unchanged_content_stays_trusted() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let m = repo_plugin(&repo, "echo reviewed");

        let mut store = TrustStore::default();
        store.trust_content("guard", &repo, &m);
        let path = t.path().join("trust.json");
        store.save(&path);

        let loaded = TrustStore::load(&path);
        assert!(loaded.is_trusted_content("guard", &repo, &m));
    }

    /// Grants written before content hashes existed are a bare list of keys.
    /// They must not count as trust for any content — the user re-confirms once.
    #[test]
    fn legacy_key_list_grants_nothing() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let path = t.path().join("trust.json");
        std::fs::write(&path, format!(r#"["guard@{}"]"#, repo.display())).unwrap();

        let loaded = TrustStore::load(&path);
        let m = repo_plugin(&repo, "echo whatever");
        assert!(!loaded.is_trusted_content("guard", &repo, &m));
    }

    /// The hash covers what the manifest actually runs, so it changes when the
    /// declared command or args change, not only when the script bytes do.
    #[test]
    fn manifest_edits_change_the_hash() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let a = repo_plugin(&repo, "echo same");
        let mut b = repo_plugin(&repo, "echo same");
        b.capabilities.hooks[0].timeout_ms = Some(9_000);
        assert_ne!(
            content_hash(&a),
            content_hash(&b),
            "a manifest change must invalidate trust"
        );
    }
}

/// The manifest a repo-local plugin with `id` would load right now — read
/// from disk the way discovery reads it. Granting trust and checking it both
/// go through here, so they hash the same bytes the loader will run.
pub fn current_manifest(id: &str, repo: &Path, paths: &AppPaths) -> Option<PluginManifest> {
    discover(repo, paths).into_iter().find_map(|mpath| {
        let text = std::fs::read_to_string(&mpath).ok()?;
        let mut m: PluginManifest = serde_json::from_str(&text).ok()?;
        if m.id != id {
            return None;
        }
        m.dir = mpath.parent().unwrap_or(Path::new("")).to_path_buf();
        Some(m)
    })
}

#[cfg(test)]
mod changed_content_message_tests {
    fn test_paths() -> agent_paths::AppPaths {
        let base = std::env::temp_dir().join("agent-plugin-test");
        agent_paths::AppPaths::new(base.join("config"), base.join("data"), ".husk")
    }

    use super::*;

    /// A grant that no longer matches must read as "changed", not as a first
    /// install — otherwise the user has no reason to look at what moved.
    #[tokio::test]
    async fn changed_plugin_says_it_changed() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        let dir = repo.join(".husk/plugins/guard");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("h.sh"), "echo new").unwrap();
        // A pure hook plugin (no `entry`): the trust gate is the only thing
        // that can refuse it, so the assertion really tests the gate.
        let hook_manifest = || -> PluginManifest {
            let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
                "id": "guard", "name": "guard",
                "capabilities": { "hooks": [{ "event": "on_user_input", "run": { "command": "./h.sh" } }] },
            }))
            .unwrap();
            m.dir = dir.clone();
            m
        };
        let m = hook_manifest();

        // A grant exists, but for different content.
        let mut mgr = PluginManager::new(test_paths());
        mgr.trust.trust_content("guard", &repo, &m);
        std::fs::write(dir.join("h.sh"), "echo swapped").unwrap();
        let err = mgr.register_plugin(m, &repo).await.unwrap_err();
        assert!(err.contains("changed since you trusted"), "{err}");

        // No grant at all keeps the first-time wording.
        let err = PluginManager::new(test_paths())
            .register_plugin(hook_manifest(), &repo)
            .await
            .unwrap_err();
        assert!(err.contains("trust consent required"), "{err}");
    }
}

#[cfg(test)]
mod trust_key_spelling_tests {
    use super::*;

    /// One directory spelled several ways is one grant. A trailing slash, a
    /// `..` detour and a symlink alias used to read as "not trusted", which
    /// asked the user to approve the same checkout again.
    #[test]
    fn grant_survives_alternate_spellings_of_the_same_repo() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let alias = t.path().join("alias");
        std::os::unix::fs::symlink(&repo, &alias).unwrap();

        let mut m: PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "p", "name": "p", "entry": { "command": "x" },
        }))
        .unwrap();
        m.dir = repo.clone();

        let mut store = TrustStore::default();
        store.trust_content("p", &repo, &m);

        let spellings = [
            repo.clone(),
            PathBuf::from(format!("{}/", repo.display())),
            t.path().join("repo/../repo"),
            alias,
        ];
        for s in spellings {
            assert!(
                store.is_trusted_content("p", &s, &m),
                "same directory not trusted as {s:?}"
            );
        }
    }
}
