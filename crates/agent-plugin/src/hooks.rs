//! `hooks.rs` — command hooks: manifest-declared lifecycle interception.
//!
//! A plugin declares `capabilities.hooks[]` with a local `run` command. The
//! kernel spawns that command at the matching lifecycle event, hands it a JSON
//! payload on stdin, and reads a JSON verdict from stdout
//! (plugin-system.md §Hook wire contract).
//!
//! Interception happens in the HOST, so a hook is not tied to the plugin's
//! runtime kind — an MCP or HTTP plugin declares hooks exactly as freely as a
//! local one, and no MCP round trip is involved.
//!
//! Failure policy is the in-process chain's, verbatim: non-zero exit, timeout,
//! unparsable JSON, or an unknown `action` all degrade to `Continue`. A hook
//! can never approve a tool — `before_tool_execute` still runs ahead of the
//! permission gate — and never blocks a turn longer than its timeout.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use crate::manifest::HookDecl;
use crate::mcp::resolve_indirect;

/// stdout cap for one hook run. A verdict is a few hundred bytes; the cap is
/// what keeps a runaway hook from ballooning the host's memory before its
/// timeout lands.
const MAX_HOOK_OUTPUT: usize = 256 * 1024;
/// stderr kept for the failure log line — enough to be diagnosable.
const MAX_HOOK_STDERR: usize = 8 * 1024;

/// What `on_user_input` decided.
#[derive(Debug, PartialEq, Eq)]
pub enum InputVerdict {
    /// No-op — the turn proceeds with the input as typed.
    Continue,
    /// Refuse the turn; the reason is surfaced as a system message.
    Block(String),
    /// Add `note` to the system prompt and run the turn.
    Inject(String),
}

/// What `before_tool_execute` decided.
#[derive(Debug)]
pub enum ToolVerdict {
    Continue,
    /// Refuse this tool call; the reason reaches the model as the failed
    /// tool result.
    Veto(String),
    /// Replace the call's arguments before the permission gate sees them.
    Rewrite(Value),
}

/// One declared hook, ready to run.
pub struct CommandHook {
    /// The owning plugin — provenance for logs and for `id()`.
    pub plugin_id: String,
    /// One of `manifest::HOOK_EVENTS`.
    pub event: String,
    filter: Option<Value>,
    /// Executable: an absolute path, a path relative to the plugin dir
    /// (`./guard.sh`, `scripts/guard.sh`), or a bare name looked up on PATH.
    command: PathBuf,
    args: Vec<String>,
    env: HashMap<String, String>,
    timeout: Duration,
    /// Working directory for the child — the plugin's own directory, so a
    /// hook script's relative file access is predictable.
    dir: PathBuf,
    /// Process-sandbox config when the manifest asks for it (`sandboxed` or
    /// a declared `permissions` block). `trusted_env` carries this hook's own
    /// env — inside the sandbox it lands unfiltered like the declared block.
    sandbox: Option<agent_sandbox::SandboxConfig>,
}

impl CommandHook {
    /// Build from a declaration that `PluginManifest::validate` has already
    /// accepted. `dir` is the plugin's directory (`manifest.dir`).
    ///
    /// `None` for a declaration with no `run` command — validation refuses
    /// those, so this is the belt to that suspenders.
    pub fn new(plugin_id: &str, decl: &HookDecl, dir: &Path) -> Option<Self> {
        let run = decl.run.as_ref()?;
        if run.command.trim().is_empty() {
            return None;
        }
        Some(Self {
            plugin_id: plugin_id.to_string(),
            event: decl.event.clone(),
            filter: decl.filter.clone(),
            command: resolve_command(dir, &run.command),
            args: run.args.clone(),
            env: run
                .env
                .iter()
                .map(|(k, v)| (k.clone(), resolve_indirect(v, "hook env")))
                .collect(),
            timeout: Duration::from_millis(decl.timeout_ms()),
            dir: dir.to_path_buf(),
            sandbox: None,
        })
    }

    /// Attach the manifest's sandbox posture — `hooks_from_manifest` folds
    /// `wants_sandbox()` + `permissions` into this per-hook config.
    pub fn with_sandbox(mut self, cfg: agent_sandbox::SandboxConfig) -> Self {
        self.sandbox = Some(cfg);
        self
    }

    /// `<plugin_id>:<event>` — what the log line and the UI marker show.
    pub fn id(&self) -> String {
        format!("{}:{}", self.plugin_id, self.event)
    }

    /// The command this hook spawns — shown in the settings card, so a user
    /// deciding whether to trust a repo-local plugin can see what it runs.
    pub fn command(&self) -> String {
        let mut line = self.command.display().to_string();
        for a in &self.args {
            line.push(' ');
            line.push_str(a);
        }
        line
    }

    /// Does this hook apply to `subject` — a tool name for the tool events, a
    /// state name for transitions? No filter matches everything.
    pub fn matches(&self, subject: &str) -> bool {
        match self.filter_subject() {
            Some(want) => want == subject,
            None => true,
        }
    }

    /// The filter value the event consults (`tool` vs `state`), if declared.
    fn filter_subject(&self) -> Option<&str> {
        let key = match self.event.as_str() {
            "before_tool_execute" | "after_tool_execute" => "tool",
            "on_state_transition" => "state",
            _ => return None,
        };
        self.filter.as_ref()?.get(key)?.as_str()
    }

    /// `on_user_input` — build payload, run, map the verdict.
    pub async fn run_input(&self, input: &str) -> InputVerdict {
        let payload = json!({"event": self.event, "input": input});
        match self.fire(&payload).await {
            Some(v) => match v["action"].as_str() {
                Some("block") => InputVerdict::Block(reason(&v)),
                Some("inject") => InputVerdict::Inject(note(&v)),
                _ => InputVerdict::Continue,
            },
            None => InputVerdict::Continue,
        }
    }

    /// `before_tool_execute` — build payload, run, map the verdict.
    pub async fn run_before_tool(&self, tool: &str, args: &Value) -> ToolVerdict {
        let payload = json!({"event": self.event, "tool": tool, "args": args});
        match self.fire(&payload).await {
            Some(v) => match v["action"].as_str() {
                Some("veto") => ToolVerdict::Veto(reason(&v)),
                // A rewrite with nothing callable in it is not a rewrite —
                // degrade rather than hand the registry a non-object.
                Some("rewrite") if v["args"].is_object() => ToolVerdict::Rewrite(v["args"].clone()),
                _ => ToolVerdict::Continue,
            },
            None => ToolVerdict::Continue,
        }
    }

    /// `after_tool_execute` — `Some(new_output)` when the hook rewrote it.
    pub async fn run_after_tool(&self, tool: &str, args: &Value, output: &str) -> Option<String> {
        let payload = json!({
            "event": self.event, "tool": tool, "args": args, "output": output,
        });
        let v = self.fire(&payload).await?;
        match v["action"].as_str() {
            Some("rewrite_output") => v["output"].as_str().map(String::from),
            _ => None,
        }
    }

    /// `on_state_transition` — fire-and-forget; the verdict is not consulted.
    pub async fn run_transition(&self, old: &str, new: &str) {
        let _ = self
            .fire(&json!({"event": self.event, "old": old, "new": new}))
            .await;
    }

    /// `on_response` — the assistant's final text, mutable before it lands in
    /// history and on screen. `Some(new_text)` when the hook rewrote it.
    pub async fn run_response(&self, text: &str) -> Option<String> {
        let v = self
            .fire(&json!({"event": self.event, "text": text}))
            .await?;
        match v["action"].as_str() {
            Some("rewrite") => v["text"].as_str().map(String::from),
            _ => None,
        }
    }

    /// Spawn the command, write the payload, read the verdict.
    ///
    /// `None` is the single degrade path — every failure mode lands here, and
    /// the caller turns it into `Continue`.
    async fn fire(&self, payload: &Value) -> Option<Value> {
        // One frame, terminator included: the hook's stdin is framed by
        // newline, and a payload split across two writes could be interleaved
        // with a concurrent run's (a hook that appends stdin to a log would
        // then read a torn line).
        let mut body = serde_json::to_vec(payload).ok()?;
        body.push(b'\n');
        // Sandbox path: declared `permissions`/`sandboxed` wrap the spawn
        // in the process sandbox (fs mounts + net gate + trusted env). No
        // backend on this platform → loud warn and the legacy spawn — a
        // hook that cannot start degrades to Continue anyway.
        let mut cmd = match self.sandbox.as_ref().and_then(|cfg| {
            let (backend, _loud) = agent_sandbox::detect_backend();
            let arg_refs: Vec<&str> = self.args.iter().map(String::as_str).collect();
            backend.wrap_spawn(cfg, &self.command.to_string_lossy(), &arg_refs)
        }) {
            Some(c) => c,
            None => {
                if self.sandbox.is_some() {
                    warn!(
                        hook = %self.id(),
                        "manifest requests sandboxed spawn but no sandbox \
                         backend on this platform — running unsandboxed"
                    );
                }
                let mut c = tokio::process::Command::new(&self.command);
                // Child env = declared env only, never inherited — the same
                // posture as an MCP child (a hook is arbitrary local code).
                c.args(&self.args).env_clear().envs(&self.env);
                c
            }
        };
        cmd.current_dir(&self.dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        // Linux: PR_SET_PDEATHSIG — a hook can't outlive the host.
        #[cfg(target_os = "linux")]
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        // `ETXTBSY` (Linux): a sibling thread forked while the hook script's
        // write fd was still open, so exec is refused for a few microseconds.
        // Transient by nature — retry briefly rather than drop the hook.
        let mut attempts = 0u32;
        let mut child = loop {
            match cmd.spawn() {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(26) && attempts < 5 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(10 * u64::from(attempts))).await;
                }
                Err(e) => {
                    warn!(hook = %self.id(), "hook spawn failed: {e}");
                    return None;
                }
            }
        };

        // stdin is written from its own task: a hook that floods stdout before
        // reading stdin would otherwise deadlock against us until the timeout.
        let stdin = child.stdin.take();
        let writer = tokio::spawn(async move {
            if let Some(mut si) = stdin {
                let _ = si.write_all(&body).await;
                // EOF — hooks that read stdin to the end need this to proceed.
                let _ = si.shutdown().await;
            }
        });

        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let run = async {
            let mut out = Vec::new();
            let mut err = Vec::new();
            if let Some(so) = stdout.as_mut() {
                let _ = so.take(MAX_HOOK_OUTPUT as u64).read_to_end(&mut out).await;
            }
            if let Some(se) = stderr.as_mut() {
                let _ = se.take(MAX_HOOK_STDERR as u64).read_to_end(&mut err).await;
            }
            let status = child.wait().await;
            (out, err, status)
        };

        let (out, err, status) = match tokio::time::timeout(self.timeout, run).await {
            Ok(r) => r,
            Err(_) => {
                // Dropping the future drops `child` → `kill_on_drop` reaps it.
                warn!(hook = %self.id(), "hook timed out — degraded to continue");
                return None;
            }
        };
        // The writer task ends on its own; a hook that exited without reading
        // stdin makes the write fail, which is already swallowed there.
        writer.abort();

        let text = String::from_utf8_lossy(&out);
        match status {
            Ok(st) if st.success() => {}
            Ok(st) => {
                warn!(
                    hook = %self.id(),
                    "hook exited {st} — degraded to continue: {}",
                    String::from_utf8_lossy(&err).lines().next().unwrap_or("")
                );
                return None;
            }
            Err(e) => {
                warn!(hook = %self.id(), "hook wait failed: {e}");
                return None;
            }
        }

        match serde_json::from_str::<Value>(text.trim()) {
            Ok(v) if v.is_object() => Some(v),
            Ok(_) => {
                warn!(hook = %self.id(), "hook printed non-object JSON — ignored");
                None
            }
            Err(_) => {
                // Deliberately quiet at debug level only for empty output: a
                // hook that prints nothing is indistinguishable from one that
                // chose to continue.
                if !text.trim().is_empty() {
                    warn!(hook = %self.id(), "hook printed unparsable JSON — ignored");
                }
                None
            }
        }
    }
}

/// `reason` (or `note`) from a verdict, defaulted when the hook omitted it.
fn reason(v: &Value) -> String {
    v["reason"].as_str().unwrap_or("").to_string()
}

fn note(v: &Value) -> String {
    v["note"].as_str().unwrap_or("").to_string()
}

/// Where a declared command actually lives.
///
/// A bare name (`python3`, `guard`) goes to `PATH` lookup; anything that
/// names a path — absolute, `./x`, `sub/x` — resolves against the plugin's
/// own directory when it isn't already absolute.
fn resolve_command(dir: &Path, command: &str) -> PathBuf {
    let p = Path::new(command);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    if command.contains(['/', '\\']) {
        // `./guard.sh` is how a manifest says "next to me" — drop the marker
        // so the resolved path (and the settings tooltip) reads as a path.
        return dir.join(Path::new(command.strip_prefix("./").unwrap_or(command)));
    }
    PathBuf::from(command)
}

/// Every hook a manifest declares, ready to run — the one conversion from a
/// plugin's own declarations to the kernel's chain, shared by every runtime
/// kind (`McpPlugin::hooks` and a future WASM plugin both call this).
///
/// `from_decl` is total here: `PluginManifest::validate` already accepted the
/// declarations, and anything it did refuse is skipped rather than aborting
/// the plugin.
/// `deny_read` carries the host's private paths into sandboxed hooks.
pub fn hooks_from_manifest(
    manifest: &crate::PluginManifest,
    deny_read: &[PathBuf],
) -> Vec<CommandHook> {
    manifest
        .capabilities
        .hooks
        .iter()
        .filter_map(|d| CommandHook::new(&manifest.id, d, &manifest.dir))
        .map(|h| with_manifest_sandbox(h, manifest, deny_read))
        .collect()
}

/// Fold the manifest's sandbox posture into one hook's spawn config.
/// `trusted_env` carries this hook's declared env — inside the sandbox it
/// lands unfiltered (the manifest is the declaring authority; the env
/// denylist's job is host secrets, not the plugin's own literals).
fn with_manifest_sandbox(
    hook: CommandHook,
    manifest: &crate::PluginManifest,
    deny_read: &[PathBuf],
) -> CommandHook {
    if !manifest.wants_sandbox() {
        return hook;
    }
    let perms = manifest.permissions.clone().unwrap_or_default();
    let (ro, rw) = perms.fs_mounts();
    let trusted_env: Vec<(String, String)> = hook
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    hook.with_sandbox(agent_sandbox::SandboxConfig {
        workspace_dir: manifest.dir.clone(),
        deny_read: deny_read.to_vec(),
        allow_network: !perms.network.is_empty(),
        environment: agent_sandbox::plan::EnvironmentPolicy::Minimal,
        trusted_env,
        extra_ro_mounts: ro,
        extra_rw_mounts: rw,
        ..Default::default()
    })
}

#[cfg(test)]
mod sandbox_policy_tests {
    use super::*;

    #[test]
    fn manifest_hooks_protect_host_supplied_paths() {
        let manifest: crate::PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "protected-hook",
            "name": "Protected Hook",
            "sandboxed": true,
            "capabilities": {
                "hooks": [{
                    "event": "before_tool_execute",
                    "run": { "command": "check" }
                }]
            }
        }))
        .unwrap();
        let protected = vec![PathBuf::from("/private/product-config")];
        let hooks = hooks_from_manifest(&manifest, &protected);
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].sandbox.as_ref().unwrap().deny_read, protected);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Write an executable `/bin/sh` hook into `dir` and return its name.
    fn script(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
    }

    fn decl(event: &str, json: serde_json::Value) -> HookDecl {
        let mut obj = json.as_object().cloned().unwrap_or_default();
        obj.insert("event".into(), serde_json::json!(event));
        // These tests are about verdict parsing, not latency. A loaded machine
        // must not degrade a hook into `Continue` and look like a verdict bug,
        // so the budget is generous unless the case sets its own — the timeout
        // path has its own test.
        obj.entry("timeout_ms".to_string())
            .or_insert(serde_json::json!(10_000));
        serde_json::from_value(serde_json::Value::Object(obj)).unwrap()
    }

    fn hook(dir: &Path, event: &str, json: serde_json::Value) -> CommandHook {
        CommandHook::new("p", &decl(event, json), dir).expect("hook builds")
    }

    /// The verdict the hook printed is what the kernel acts on.
    #[tokio::test]
    async fn before_tool_verdicts_map_through() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        script(
            dir,
            "veto.sh",
            r#"echo '{"action":"veto","reason":"no git push"}'"#,
        );
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./veto.sh"},
            }),
        );
        match h
            .run_before_tool("bash", &serde_json::json!({"cmd": "git push"}))
            .await
        {
            ToolVerdict::Veto(r) => assert_eq!(r, "no git push"),
            other => panic!("expected veto, got {other:?}"),
        }

        script(
            dir,
            "rewrite.sh",
            r#"echo '{"action":"rewrite","args":{"cmd":"ls"}}'"#,
        );
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./rewrite.sh"},
            }),
        );
        match h
            .run_before_tool("bash", &serde_json::json!({"cmd": "rm -rf /"}))
            .await
        {
            ToolVerdict::Rewrite(args) => assert_eq!(args["cmd"], "ls"),
            other => panic!("expected rewrite, got {other:?}"),
        }

        script(dir, "pass.sh", r#"echo '{"action":"continue"}'"#);
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./pass.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));
    }

    /// The payload on stdin carries the event, the tool, and its arguments —
    /// and the child runs in the plugin's own directory (the relative
    /// `got.json` lands next to the manifest).
    #[tokio::test]
    async fn payload_is_delivered_and_cwd_is_the_plugin_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        script(
            dir,
            "dump.sh",
            "cat > got.json\necho '{\"action\":\"continue\"}'",
        );

        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./dump.sh"},
            }),
        );
        h.run_before_tool("read", &serde_json::json!({"path": "a.rs"}))
            .await;

        let got: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("got.json")).unwrap()).unwrap();
        assert_eq!(got["event"], "before_tool_execute");
        assert_eq!(got["tool"], "read");
        assert_eq!(got["args"]["path"], "a.rs");
    }

    /// `after_tool_execute` may rewrite the output; `on_state_transition`
    /// runs even though its verdict means nothing.
    #[tokio::test]
    async fn after_tool_rewrites_and_transition_fires() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        script(
            dir,
            "redact.sh",
            r#"echo '{"action":"rewrite_output","output":"[redacted]"}'"#,
        );
        let h = hook(
            dir,
            "after_tool_execute",
            serde_json::json!({
                "run": {"command": "./redact.sh"},
            }),
        );
        let out = h
            .run_after_tool("read", &serde_json::json!({}), "AKIA-secret")
            .await
            .unwrap();
        assert_eq!(out, "[redacted]");

        // A transition hook's stdout is ignored, but the command must run.
        script(
            dir,
            "mark.sh",
            "echo seen > marker.txt\necho 'not json at all'",
        );
        let h = hook(
            dir,
            "on_state_transition",
            serde_json::json!({
                "run": {"command": "./mark.sh"},
            }),
        );
        h.run_transition("Reasoning", "ExecutingTool").await;
        assert!(dir.join("marker.txt").exists(), "transition hook never ran");
    }

    /// Every failure mode degrades to `Continue` — the hook cannot break the
    /// turn, and a hung hook cannot hold it.
    #[tokio::test]
    async fn failures_degrade_to_continue() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Non-zero exit.
        script(dir, "fail.sh", "echo '{\"action\":\"veto\"}'\nexit 3");
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./fail.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));

        // Unparsable stdout.
        script(dir, "garbage.sh", "echo 'this is not JSON'");
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./garbage.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));

        // Unknown action.
        script(dir, "alien.sh", r#"echo '{"action":"approve"}'"#);
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./alien.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));

        // A rewrite with no usable args is not a rewrite.
        script(dir, "hollow.sh", r#"echo '{"action":"rewrite"}'"#);
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./hollow.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));

        // Missing executable.
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./not-here.sh"},
            }),
        );
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));
    }

    /// A hook that hangs is killed at its own budget and degrades — the turn
    /// is never held hostage. (Pure-shell spin: no PATH needed to hang.)
    #[tokio::test]
    async fn timeout_kills_and_degrades() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        script(dir, "spin.sh", "while :; do :; done");

        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "./spin.sh"},
                "timeout_ms": 150,
            }),
        );
        let started = std::time::Instant::now();
        assert!(matches!(
            h.run_before_tool("bash", &serde_json::json!({})).await,
            ToolVerdict::Continue
        ));
        let elapsed = started.elapsed();
        assert!(elapsed.as_millis() < 2_000, "timeout ignored: {elapsed:?}");
    }

    /// The filter narrows a hook to one tool/state; `on_user_input` takes none.
    #[test]
    fn filters_narrow_by_tool_or_state() {
        let dir = Path::new("/tmp");
        let h = hook(
            dir,
            "before_tool_execute",
            serde_json::json!({
                "run": {"command": "guard"},
                "filter": {"tool": "bash"},
            }),
        );
        assert!(h.matches("bash"));
        assert!(!h.matches("read"));

        let h = hook(
            dir,
            "on_state_transition",
            serde_json::json!({
                "run": {"command": "guard"},
                "filter": {"state": "Failed"},
            }),
        );
        assert!(h.matches("Failed"));
        assert!(!h.matches("Reasoning"));

        // No filter = every occurrence of the event.
        let h = hook(
            dir,
            "on_user_input",
            serde_json::json!({"run": {"command": "guard"}}),
        );
        assert!(h.matches("anything"));
    }

    /// A hook's env is declared-only — and an `env:VAR` indirection to a
    /// secret-shaped host variable resolves to nothing rather than handing
    /// credentials to a plugin.
    #[tokio::test]
    async fn secret_env_indirection_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::env::set_var("HOOK_TEST_PLAIN", "hello");
        std::env::set_var("HOOK_TEST_FAKE_TOKEN", "sekrit");

        // `$REFUSED:$PLAIN` — the refused var must come through empty.
        script(
            dir,
            "env.sh",
            r#"echo "{\"action\":\"rewrite_output\",\"output\":\"$REFUSED:$PLAIN\"}""#,
        );
        let h = hook(
            dir,
            "after_tool_execute",
            serde_json::json!({
                "run": {
                    "command": "./env.sh",
                    "env": {"REFUSED": "env:HOOK_TEST_FAKE_TOKEN", "PLAIN": "env:HOOK_TEST_PLAIN"},
                },
            }),
        );
        let out = h
            .run_after_tool("read", &serde_json::json!({}), "")
            .await
            .unwrap();
        assert_eq!(out, ":hello");
    }

    /// A bare command name goes to PATH; a path-shaped one resolves against
    /// the plugin directory.
    #[test]
    fn commands_resolve_by_shape() {
        let dir = Path::new("/plugins/p");
        assert_eq!(resolve_command(dir, "guard.sh"), PathBuf::from("guard.sh"));
        assert_eq!(resolve_command(dir, "./guard.sh"), dir.join("guard.sh"));
        assert_eq!(
            resolve_command(dir, "sub/guard.sh"),
            dir.join("sub/guard.sh")
        );
        assert_eq!(
            resolve_command(dir, "/usr/bin/guard"),
            PathBuf::from("/usr/bin/guard")
        );
    }

    /// A declaration without a command can't produce a hook (validation
    /// refuses it first).
    #[test]
    fn declaration_without_run_yields_nothing() {
        let d: HookDecl = serde_json::from_value(serde_json::json!({
            "event": "on_user_input",
        }))
        .unwrap();
        assert!(CommandHook::new("p", &d, Path::new("/tmp")).is_none());
    }
}
