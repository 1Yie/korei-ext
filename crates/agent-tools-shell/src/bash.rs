//! `bash` — sandboxed shell execution.
//!
//! Runs through the installed sandbox (`ctx.sandbox()` → `SandboxBackend::run_command`) — bwrap on Linux, the
//! loud `none` fallback elsewhere. The audit gate runs before dispatch and stamps the
//! risk tier on the result; the permission layer already gated the call.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use serde::Deserialize;

use crate::sandbox_cfg::sandbox_config;
use agent_capabilities::SandboxCtx;
use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Shell output cap per truncation table (~5k tok).
const MAX_OUTPUT_CHARS: usize = 20 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct BashArgs {
    /// Shell command to run inside the workspace.
    command: String,
    /// Timeout in seconds (default 120, max 600).
    timeout_secs: Option<u64>,
    /// Launch as a persistent background service instead of a one-shot:
    /// the command survives past this call (dev server, database, watcher)
    /// via the sandbox's `wrap_spawn` channel — same sandbox policy, no
    /// process-tree kill at call end. Returns a `svc-N` id + log path;
    /// manage it with the `service` tool. Dies when the agent exits.
    persistent: Option<bool>,
}

pub fn spec<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "bash",
        schema: schema_for::<BashArgs>(
            "Run a shell command in the workspace. Output is truncated to \
             20 KB (head 30% + tail 70%). Prefer dedicated tools \
             (smart_read/smart_grep/fuzzy_patch/apply_patch) for file IO —
             never `cat`/`echo`/`sed` to create or edit files; use apply_patch
             to create new files/folders, fuzzy_patch for in-place edits.
             bash is for builds, tests, and commands those don't cover.
             Set persistent=true for long-lived services (dev servers, DBs,
             watchers): the process survives across calls under the same
             sandbox, output goes to a log file, manage via the `service`
             tool. Network topology: recognized server commands (php -S,
             python -m http.server, npm run dev, nginx, redis-server, …)
             get shared host network so the host can connect; other
             persistent commands run in the private netns and can only
             reach out through the domain-allowlist proxy.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: Some(Arc::new(crate::risk::review::<C>)),
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

async fn exec<C: WorkspaceCtx + SandboxCtx>(
    args: Args,
    ctx: Arc<C>,
) -> Result<ToolResult, ToolError> {
    let parsed: BashArgs =
        serde_json::from_value(args).map_err(|e| ToolError::Args(format!("bash args: {e}")))?;
    let timeout = parsed
        .timeout_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TIMEOUT)
        .min(MAX_TIMEOUT);

    // Audit before spawn; its verdict becomes the result's risk tier.
    // Scoped to the workspace so out-of-scope writes flag ScopeViolation.
    let verdict = agent_sandbox::audit_command_scoped(&parsed.command, Some(ctx.root()?));

    let sandbox = ctx.sandbox()?;
    let cfg = sandbox_config(&verdict, ctx.root()?, timeout, &ctx.sandbox_limits());

    if parsed.persistent.unwrap_or(false) {
        return crate::services::spawn_persistent(&ctx, &cfg, &parsed.command).await;
    }

    let output = sandbox
        .run_command(&parsed.command, &[], &cfg)
        .await
        .map_err(|e| ToolError::Failed(e.to_string()))?;

    let mut raw = output.stdout;
    if !output.stderr.is_empty() {
        if !raw.is_empty() {
            raw.push_str("\n── stderr ──\n");
        }
        raw.push_str(&output.stderr);
    }

    let mut content = format!("── exit {} `{}` ──\n", output.status, parsed.command);
    if verdict.level > agent_sandbox::AuditLevel::Normal {
        content.push_str(&format!(
            "[audit {:?}: {}]\n",
            verdict.level,
            verdict.reasons.join("; ")
        ));
    }
    if output.is_timeout {
        content.push_str(&format!("[timeout {}s — tree killed]\n", timeout.as_secs()));
    }
    // Egress denials the proxy recorded — the model sees *which* host was
    // refused and can ask for escalation (or a narrower rerun) instead of
    // guessing at a generic "network unreachable".
    if !output.sandbox_denials.is_empty() {
        content.push_str("[sandbox network denials:\n");
        for d in &output.sandbox_denials {
            content.push_str(&format!("  {d}\n"));
        }
        content.push_str(
            "  → retry with a narrower command, or ask the user to widen the egress allowlist]\n",
        );
    }
    content.push_str(&fold_output(&raw));
    Ok(ToolResult::text(content))
}

/// Head 30% + `… [truncated N bytes] …` + tail 70% fold (errors land in tail).
fn fold_output(raw: &str) -> String {
    if raw.len() <= MAX_OUTPUT_CHARS {
        return raw.to_string();
    }
    let head = MAX_OUTPUT_CHARS * 3 / 10;
    let tail = MAX_OUTPUT_CHARS - head;
    let omitted = raw.len() - head - tail;
    let mut out = String::with_capacity(MAX_OUTPUT_CHARS + 80);
    // UTF-8-safe: byte-level head/tail clamps to char boundaries so CJK or
    // emoji in command output can't panic on a non-boundary index (P2).
    out.push_str(crate::util::head(raw, head));
    out.push_str(&format!("\n… [truncated {omitted} bytes] …\n"));
    out.push_str(crate::util::tail(raw, tail));
    out
}
