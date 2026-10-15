//! `smart_test_runner` — failure-only filter over test output.
//!
//! Contract (native-tools.md §B): stream-filter the sandboxed test process —
//! drop `passed`/progress noise, keep only failed test names + assertion
//! locations + panic backtrace frames. 20k-line log → ≤300 tok diagnostic.
//!
//! Spawning goes through `ctx.sandbox()` exactly like `bash`
//! (`sandbox_cfg::sandbox_config` + `SandboxBackend::run_command`), so a test
//! run gets the same audit-derived network/fs policy, env sanitization and
//! timeout tree-kill instead of a bare `sh -c` with a discarded child. The
//! tool's contract is the *filter*, not the spawn.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use serde::Deserialize;

use crate::sandbox_cfg::sandbox_config;
use agent_capabilities::SandboxCtx;
use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Failure-diagnostic budget (≤~300 tokens ≈ 1.2 KB of dense signal).
const MAX_DIAGNOSTIC_CHARS: usize = 4 * 1024;
const TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct TestRunnerArgs {
    /// Test command, e.g. `cargo test -p agent-kernel`, `pytest`, `vitest run`.
    command: String,
    /// Optional sub-filter: only keep output lines mentioning this (e.g. a
    /// test name) — applied to the failure sections, not the whole log.
    focus: Option<String>,
}

pub fn spec<C: WorkspaceCtx + SandboxCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "smart_test_runner",
        schema: schema_for::<TestRunnerArgs>(
            "Run a test command and return ONLY the failures: failed test \
             names, assertion diffs, panic backtrace frames. Passing noise is \
             dropped — a 20k-line log returns ~300 tokens of signal. Use for \
             `cargo test`, `pytest`, `vitest`/`jest`, `go test`.",
        ),
        readonly: false, // test runs can write caches/artifacts; gate via permissions
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
    let parsed: TestRunnerArgs = serde_json::from_value(args)
        .map_err(|e| ToolError::Args(format!("smart_test_runner args: {e}")))?;

    // Same dispatch as `bash`: audit first, derive the config, run through the
    // backend (which owns env sanitization, limits and timeout tree-kill).
    let verdict = agent_sandbox::audit_command_scoped(&parsed.command, Some(ctx.root()?));
    let sandbox = ctx.sandbox()?;
    let cfg = sandbox_config(&verdict, ctx.root()?, TIMEOUT, &ctx.sandbox_limits());

    let out = sandbox
        .run_command(&parsed.command, &[], &cfg)
        .await
        .map_err(|e| ToolError::Failed(e.to_string()))?;

    let mut raw = String::new();
    raw.push_str(&out.stdout);
    if !out.stderr.is_empty() {
        if !raw.is_empty() {
            raw.push_str("\n── stderr ──\n");
        }
        raw.push_str(&out.stderr);
    }

    let distilled = distill(&raw, parsed.focus.as_deref());
    let status = if out.status == 0 { "PASS" } else { "FAIL" };
    let mut content = format!("── {status} `{}` ──\n", parsed.command);
    if verdict.level > agent_sandbox::AuditLevel::Normal {
        content.push_str(&format!(
            "[audit {:?}: {}]\n",
            verdict.level,
            verdict.reasons.join("; ")
        ));
    }
    if out.is_timeout {
        content.push_str(&format!("[timeout {}s — tree killed]\n", TIMEOUT.as_secs()));
    }
    content.push_str(&distilled);
    if distilled.len() >= MAX_DIAGNOSTIC_CHARS {
        content.push_str("\n… [diagnostic truncated — rerun with a narrower test filter] …\n");
    }
    Ok(ToolResult::text(content))
}

/// Failure-only distillation. Framework-agnostic: keep lines that look like
/// failures/assertions/panics, plus the first summary block.
#[doc(hidden)]
pub fn test_distill_pub(raw: &str, focus: Option<&str>) -> String {
    distill(raw, focus)
}

fn distill(raw: &str, focus: Option<&str>) -> String {
    const KEEP_PATTERNS: &[&str] = &[
        "FAILED",
        "failed",
        "failures:",
        "error[",
        "error:",
        "panicked",
        "assertion failed",
        "assertion `",
        "FAILED:",
        "Error:",
        "FAIL ",
        "expected",
        "Expected",
        "left:",
        "right:",
        "diff <",
        "thread '",
        "not ok",
        "✗",
        "×",
        "Cannot find",
        "TypeError",
        "ReferenceError",
        "File \"",
        "line ",
        "at ",
    ];
    const DROP_PATTERNS: &[&str] = &[
        "... ok",
        "test result: ok",
        "Compiling",
        "Finished",
        "Running ",
        "Downloading",
        "Downloaded",
        "npm warn",
        "PASS ",
        "✓ ",
    ];

    let mut kept: Vec<&str> = Vec::new();
    let mut last_kept_idx = 0i64;
    let lines: Vec<&str> = raw.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        // Context glue: keep a line if it (a) matches a failure pattern, or
        // (b) directly follows one (assertion continuations, backtrace).
        let keep = KEEP_PATTERNS.iter().any(|p| l.contains(p))
            && !DROP_PATTERNS.iter().any(|p| l.contains(p))
            || (i as i64 - last_kept_idx <= 2
                && kept.last().is_some_and(|_| {
                    l.starts_with("at ") || l.starts_with('|') || l.starts_with("File ")
                }));
        if let Some(f) = focus {
            if keep
                && !f.is_empty()
                && !l.contains(f)
                && KEEP_PATTERNS.iter().any(|p| l.contains(p))
            {
                // focus filter: non-focused failures drop unless they're the summary
                if !l.contains("test result") && !l.contains("failures:") {
                    continue;
                }
            }
        }
        if keep {
            kept.push(line);
            last_kept_idx = i as i64;
        }
    }

    if kept.is_empty() {
        // Nothing matched — either clean pass or unrecognized output. Return
        // the last 20 lines as a fallback summary rather than silence.
        let tail: Vec<&str> = lines.iter().rev().take(20).copied().collect();
        let t: Vec<&str> = tail.into_iter().rev().collect();
        if t.is_empty() {
            return "(no output)\n".into();
        }
        return t.join("\n") + "\n";
    }

    let mut out = kept.join("\n");
    out.push('\n');
    if out.len() > MAX_DIAGNOSTIC_CHARS {
        // UTF-8-safe truncate — a byte cut mid-char would panic (P2).
        crate::util::truncate(&mut out, MAX_DIAGNOSTIC_CHARS);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_sandbox::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};
    use std::sync::Mutex;

    /// Answers with a canned `CommandOutput` and records what it was asked to
    /// run — the record is the proof that the tool dispatches through
    /// `ctx.sandbox()` rather than spawning `sh` itself.
    struct FakeBackend {
        calls: Mutex<Vec<String>>,
        status: i32,
        stdout: &'static str,
        stderr: &'static str,
        is_timeout: bool,
    }

    impl FakeBackend {
        fn new(
            status: i32,
            stdout: &'static str,
            stderr: &'static str,
            is_timeout: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                status,
                stdout,
                stderr,
                is_timeout,
            })
        }
    }

    #[async_trait::async_trait]
    impl SandboxBackend for FakeBackend {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn tier(&self) -> SandboxTier {
            SandboxTier::L2
        }
        async fn run_command(
            &self,
            cmd: &str,
            _args: &[&str],
            _cfg: &SandboxConfig,
        ) -> anyhow::Result<CommandOutput> {
            self.calls.lock().unwrap().push(cmd.to_string());
            Ok(CommandOutput {
                sandbox_denials: Vec::new(),
                status: self.status,
                stdout: self.stdout.to_string(),
                stderr: self.stderr.to_string(),
                is_timeout: self.is_timeout,
                peak_memory_mb: None,
                elapsed_ms: 3,
            })
        }
    }

    /// The command reaches the backend (not a private `sh -c`), stderr is
    /// merged into the distilled log, and passing noise is dropped.
    #[tokio::test]
    async fn dispatches_through_sandbox_and_keeps_only_failures() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FakeBackend::new(
            1,
            "running 3 tests\ntest ok_one ... ok\ntest boom ... FAILED\nassertion `left == right` failed\n",
            "error: could not compile `demo`\n",
            false,
        );
        let ctx = Arc::new(crate::TestCtx::with_sandbox(dir.path(), backend.clone()));
        let out = exec(serde_json::json!({"command": "cargo test -p demo"}), ctx)
            .await
            .unwrap();

        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            ["cargo test -p demo"]
        );
        assert!(
            out.content.starts_with("── FAIL `cargo test -p demo` ──"),
            "{}",
            out.content
        );
        assert!(
            out.content.contains("assertion `left == right` failed"),
            "{}",
            out.content
        );
        assert!(
            out.content.contains("error: could not compile `demo`"),
            "stderr not merged into the filter: {}",
            out.content
        );
        assert!(
            !out.content.contains("ok_one"),
            "passing noise survived: {}",
            out.content
        );
    }

    /// A timed-out run is reported as a killed tree — the old bare
    /// `tokio::time::timeout` dropped the future and left the child running.
    #[tokio::test]
    async fn timeout_is_reported_as_tree_killed() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FakeBackend::new(-1, "", "[timeout — process tree killed]", true);
        let ctx = Arc::new(crate::TestCtx::with_sandbox(dir.path(), backend));
        let out = exec(serde_json::json!({"command": "sleep 600"}), ctx)
            .await
            .unwrap();

        assert!(out.content.contains("── FAIL"), "{}", out.content);
        assert!(
            out.content.contains("[timeout 600s — tree killed]"),
            "{}",
            out.content
        );
    }
}
