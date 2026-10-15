//! `computer` — synthetic mouse and keyboard input.
//!
//! `ToolClass::Process`, never `readonly`: every call is a real side effect on
//! a live session, so `default` mode confirms each one, `dontAsk` denies, and
//! a headless subagent registry does not carry the tool at all (see
//! `session.rs`). Plan mode drops it with the rest of the non-readonly set —
//! `screenshot` is what survives, which is exactly "look but do not touch".
//!
//! Coordinates are **screenshot-space**: the grid of the last `screenshot`
//! PNG. The backend owns the mapping onto the real display, so the model never
//! needs the screen's true resolution.

use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;

use agent_capabilities::DesktopCtx;
use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Upper bound on `wait` — a model parking the turn for minutes is a bug, not
/// a strategy.
const MAX_WAIT_MS: u64 = 10_000;
/// Default wheel steps for `scroll` when the model omits the amount.
const DEFAULT_SCROLL_STEPS: i32 = 3;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ComputerArgs {
    /// The action to perform.
    action: String,

    /// Target `[x, y]` in screenshot coordinates (the `image` resolution the
    /// last `screenshot` reported). Required by the pointer actions.
    coordinate: Option<[i32; 2]>,

    /// `left_click_drag` only: where the drag starts.
    start_coordinate: Option<[i32; 2]>,

    /// `type`: the text to type (UI copy cannot be produced). `key` /
    /// `hold_key`: the key or chord, e.g. `"Return"`, `"ctrl+s"`, `"alt+Tab"`.
    text: Option<String>,

    /// `scroll` only: `up` | `down` | `left` | `right`.
    scroll_direction: Option<String>,

    /// `scroll` only: wheel steps (default 3).
    scroll_amount: Option<i32>,

    /// `wait`: milliseconds to pause. `hold_key`: how long to hold the chord.
    duration_ms: Option<u64>,
}

pub fn spec<C: WorkspaceCtx + DesktopCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "computer",
        schema: schema_for::<ComputerArgs>(
            "Drive the desktop: mouse, keyboard, scroll, wait. Coordinates are \
             `[x, y]` in the screenshot's pixel grid (call `screenshot` first — \
             it prints the grid size), never the real screen resolution; \
             out-of-range values clamp. Actions: `left_click`, `right_click`, \
             `middle_click`, `double_click`, `mouse_move` (`coordinate`), \
             `left_click_drag` (`start_coordinate` → `coordinate`), `type` \
             (`text`), `key` (`text`, e.g. `ctrl+s`), `hold_key` (`text` + \
             `duration_ms`), `scroll` (`scroll_direction` + `scroll_amount`), \
              `wait` (`duration_ms`), `cursor_position`, `launch` (`text` — the \
              program name + args, e.g. `kwrite` or `code ~/project`; runs \
              detached on the real display, never through the `bash` sandbox). \
              Each call is a real action on the user's screen and asks for \
              confirmation. Screenshot again afterwards to verify what \
              happened — this tool reports only that the input was delivered. \
              Never batch `screenshot` together with `computer` in one call: \
              the capture installs the coordinate scale the action reads — \
              run the screenshot first, then click.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::Process,
        network: false,
        staged: false,
        review: Some(Arc::new(review::<C>)),
        exec: Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

/// What the approval card and the gate need to know about one call, before the
/// user is asked: the one-line summary, the normalized action (the gate treats
/// `launch` differently), and the platform grant to acquire first — so the
/// system prompt comes ahead of the app card, not after the user already said
/// yes. A refusal ends the call: there is no point asking about an action that
/// cannot run.
fn review<C: DesktopCtx>(args: &Args, ctx: &Arc<C>) -> agent_tool::Review {
    let ctx = ctx.clone();
    agent_tool::Review {
        risk: agent_tool::CallRisk::Normal,
        summary: Some(describe(args)),
        action: Some(action_of(args)),
        prepare: Some(
            async move {
                let desktop = ctx.desktop().map_err(|e| e.to_string())?;
                desktop
                    .prepare()
                    .await
                    .map_err(|e| format!("computer control unavailable: {e:#}"))
            }
            .boxed(),
        ),
    }
}

async fn exec<C: WorkspaceCtx + DesktopCtx>(
    args: Args,
    ctx: Arc<C>,
) -> Result<ToolResult, ToolError> {
    let parsed: ComputerArgs =
        serde_json::from_value(args).map_err(|e| ToolError::Args(format!("computer args: {e}")))?;
    let action = parsed.action.trim().to_ascii_lowercase();

    // Every action goes through the desktop backend, `wait` included: on a
    // host with no desktop a wait is still a lie ("I waited for the screen").
    let done = match action.as_str() {
        "left_click" | "right_click" | "middle_click" => {
            let desktop = ctx.desktop()?;
            let at = need_coordinate(&parsed, &action)?;
            let button = match action.as_str() {
                "left_click" => agent_computer::MouseButton::Left,
                "right_click" => agent_computer::MouseButton::Right,
                _ => agent_computer::MouseButton::Middle,
            };
            desktop.click(button, at).await.map_err(fail)?;
            format!("clicked {action} at ({}, {})", at[0], at[1])
        }
        "double_click" => {
            let desktop = ctx.desktop()?;
            let at = need_coordinate(&parsed, &action)?;
            desktop.double_click(at).await.map_err(fail)?;
            format!("double-clicked at ({}, {})", at[0], at[1])
        }
        "mouse_move" => {
            let desktop = ctx.desktop()?;
            let at = need_coordinate(&parsed, &action)?;
            desktop.move_to(at).await.map_err(fail)?;
            format!("moved the pointer to ({}, {})", at[0], at[1])
        }
        "left_click_drag" => {
            let desktop = ctx.desktop()?;
            let to = need_coordinate(&parsed, &action)?;
            let from = parsed.start_coordinate.ok_or_else(|| {
                ToolError::Args(
                    "action `left_click_drag` needs `start_coordinate` [x, y] — the point to drag from"
                        .into(),
                )
            })?;
            desktop.drag(from, to).await.map_err(fail)?;
            format!(
                "dragged from ({}, {}) to ({}, {})",
                from[0], from[1], to[0], to[1]
            )
        }
        "type" => {
            let desktop = ctx.desktop()?;
            let text = need_text(&parsed, &action)?;
            desktop.type_text(text).await.map_err(fail)?;
            format!("typed {} characters", text.chars().count())
        }
        "key" => {
            let desktop = ctx.desktop()?;
            let combo = need_text(&parsed, &action)?;
            desktop.key(combo, None).await.map_err(fail)?;
            format!("pressed {combo}")
        }
        "hold_key" => {
            let desktop = ctx.desktop()?;
            let combo = need_text(&parsed, &action)?;
            let hold = parsed.duration_ms.ok_or_else(|| {
                ToolError::Args("action `hold_key` needs `duration_ms` — how long to hold".into())
            })?;
            if hold == 0 || hold > MAX_WAIT_MS {
                return Err(ToolError::Args(format!(
                    "`hold_key` duration_ms must be 1..={MAX_WAIT_MS}"
                )));
            }
            desktop.key(combo, Some(hold)).await.map_err(fail)?;
            format!("held {combo} for {hold}ms")
        }
        "scroll" => {
            let desktop = ctx.desktop()?;
            let dir = match parsed.scroll_direction.as_deref().map(str::trim) {
                Some("up") => agent_computer::ScrollDir::Up,
                Some("down") => agent_computer::ScrollDir::Down,
                Some("left") => agent_computer::ScrollDir::Left,
                Some("right") => agent_computer::ScrollDir::Right,
                other => {
                    return Err(ToolError::Args(format!(
                        "action `scroll` needs `scroll_direction` of up|down|left|right, got {:?}",
                        other.unwrap_or("<missing>")
                    )))
                }
            };
            let amount = parsed.scroll_amount.unwrap_or(DEFAULT_SCROLL_STEPS);
            desktop
                .scroll(dir, amount, parsed.coordinate)
                .await
                .map_err(fail)?;
            let at = parsed
                .coordinate
                .map(|c| format!(" at ({}, {})", c[0], c[1]))
                .unwrap_or_default();
            format!(
                "scrolled {amount} step(s) {}{at}",
                parsed.scroll_direction.as_deref().unwrap_or("")
            )
        }
        "wait" => {
            let desktop = ctx.desktop()?;
            let ms = parsed.duration_ms.ok_or_else(|| {
                ToolError::Args("action `wait` needs `duration_ms` — milliseconds to pause".into())
            })?;
            if ms == 0 || ms > MAX_WAIT_MS {
                return Err(ToolError::Args(format!(
                    "`wait` duration_ms must be 1..={MAX_WAIT_MS}"
                )));
            }
            // The backend gate still applies: a host with no desktop has no
            // screen to wait for, and pretending otherwise would let the model
            // report progress that never had a subject.
            desktop.cursor_position().await.map_err(fail)?;
            // Sliced so a user "stop" (the shared cancel flag) ends the wait
            // within ~100 ms instead of after up to MAX_WAIT_MS.
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
            while std::time::Instant::now() < deadline {
                if ctx
                    .cancel_flag()
                    .as_ref()
                    .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                {
                    return Err(ToolError::Failed("wait cancelled by user".into()));
                }
                let left = deadline - std::time::Instant::now();
                tokio::time::sleep(left.min(std::time::Duration::from_millis(100))).await;
            }
            format!("waited {ms}ms")
        }
        "cursor_position" => {
            let desktop = ctx.desktop()?;
            let at = desktop.cursor_position().await.map_err(fail)?;
            format!(
                "pointer at ({}, {}) in screenshot coordinates",
                at[0], at[1]
            )
        }
        "launch" => {
            let desktop = ctx.desktop()?;
            let cmd = need_text(&parsed, &action)?;
            desktop.launch_app(cmd).await.map_err(fail)?;
            format!("launched `{cmd}`")
        }
        other => {
            return Err(ToolError::Args(format!(
                "unknown action `{other}` — valid: left_click, right_click, middle_click, \
                 double_click, mouse_move, left_click_drag, type, key, hold_key, scroll, \
                 wait, cursor_position, launch (for a fresh view of the screen use the \
                 `screenshot` tool)"
            )))
        }
    };

    Ok(ToolResult::text(done))
}

/// The normalized `action` of a raw `computer` call — the same trim +
/// lowercase `exec` applies, so the gate and the summary agree with it.
pub fn action_of(args: &serde_json::Value) -> String {
    args.get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// One line saying exactly what a `computer` call will do — the text the
/// approval card shows. Without it the card carries only the bare action name
/// (`type`, `launch`), so "allow for this session" would approve whatever the
/// model types or starts next without the user ever seeing it. Strings use
/// `{:?}` so control characters (a trailing `\n` = Enter) stay visible.
/// Starts with the action name; the overlay HUD keys its label off that.
pub fn describe(args: &serde_json::Value) -> String {
    let action = action_of(args);
    let point = |k: &str| {
        let a = args.get(k)?.as_array()?;
        Some(format!(
            "({}, {})",
            a.first()?.as_i64()?,
            a.get(1)?.as_i64()?
        ))
    };
    let text = args.get("text").and_then(|v| v.as_str());
    let ms = args.get("duration_ms").and_then(|v| v.as_u64());
    let detail = match action.as_str() {
        "left_click" | "right_click" | "middle_click" | "double_click" | "mouse_move" => {
            point("coordinate")
        }
        "left_click_drag" => match (point("start_coordinate"), point("coordinate")) {
            (Some(a), Some(b)) => Some(format!("{a} → {b}")),
            _ => None,
        },
        "type" | "key" | "launch" => text.map(|t| format!("{t:?}")),
        "hold_key" => text.map(|t| format!("{t:?} {}ms", ms.unwrap_or(0))),
        "scroll" => {
            let dir = args
                .get("scroll_direction")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let n = args
                .get("scroll_amount")
                .and_then(|v| v.as_i64())
                .unwrap_or(DEFAULT_SCROLL_STEPS as i64);
            let at = point("coordinate")
                .map(|p| format!(" at {p}"))
                .unwrap_or_default();
            Some(format!("{dir} ×{n}{at}"))
        }
        "wait" => ms.map(|m| format!("{m}ms")),
        _ => None,
    };
    match detail {
        Some(d) => format!("{action} {d}"),
        None if action.is_empty() => "computer".to_string(),
        None => action,
    }
}

/// Backend errors are model-facing — keep the probe's teaching text intact.
fn fail(e: anyhow::Error) -> ToolError {
    ToolError::Failed(e.to_string())
}

/// Pointer actions cannot guess a target: a missing coordinate is an argument
/// error that names the fix, not a click at (0, 0).
fn need_coordinate(args: &ComputerArgs, action: &str) -> Result<[i32; 2], ToolError> {
    args.coordinate.ok_or_else(|| {
        ToolError::Args(format!(
            "action `{action}` needs `coordinate` [x, y] in screenshot coordinates"
        ))
    })
}

fn need_text<'a>(args: &'a ComputerArgs, action: &str) -> Result<&'a str, ToolError> {
    match args.text.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => Ok(t),
        None => Err(ToolError::Args(format!(
            "action `{action}` needs non-empty `text`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestCtx;

    fn ctx(dir: &std::path::Path) -> Arc<TestCtx> {
        Arc::new(TestCtx::with_desktop(
            dir,
            Arc::new(agent_computer::NoneBackend::new("no desktop in tests")),
        ))
    }

    /// The registry that looks tools up by name is the kernel's; here the spec's
    /// own exec is what it would have called, which is what these tests exercise.
    async fn call(args: serde_json::Value) -> Result<ToolResult, String> {
        let dir = tempfile::tempdir().unwrap();
        (spec::<TestCtx>().exec)(args, ctx(dir.path()))
            .await
            .map_err(|e| e.to_string())
    }

    /// Argument errors must teach: every action that needs a target names the
    /// exact key it is missing, and no call reaches the backend.
    #[tokio::test]
    async fn missing_arguments_teach_the_fix() {
        let e = call(serde_json::json!({"action": "left_click"}))
            .await
            .unwrap_err();
        assert!(e.contains("needs `coordinate`"), "{e}");

        let e = call(serde_json::json!({"action": "left_click_drag", "coordinate": [1, 2]}))
            .await
            .unwrap_err();
        assert!(e.contains("start_coordinate"), "{e}");

        let e = call(serde_json::json!({"action": "type", "text": ""}))
            .await
            .unwrap_err();
        assert!(e.contains("non-empty `text`"), "{e}");

        let e = call(serde_json::json!({"action": "key"}))
            .await
            .unwrap_err();
        assert!(e.contains("non-empty `text`"), "{e}");

        let e = call(serde_json::json!({"action": "hold_key", "text": "ctrl"}))
            .await
            .unwrap_err();
        assert!(e.contains("duration_ms"), "{e}");

        let e = call(serde_json::json!({"action": "scroll", "scroll_direction": "sideways"}))
            .await
            .unwrap_err();
        assert!(e.contains("scroll_direction"), "{e}");

        let e = call(serde_json::json!({"action": "wait"}))
            .await
            .unwrap_err();
        assert!(e.contains("duration_ms"), "{e}");
    }

    /// An unknown action lists the valid set — the model self-corrects on the
    /// next round instead of looping on a mystery.
    #[tokio::test]
    async fn unknown_action_lists_the_valid_set() {
        let e = call(serde_json::json!({"action": "screenshot"}))
            .await
            .unwrap_err();
        assert!(e.contains("unknown action `screenshot`"), "{e}");
        assert!(e.contains("left_click"), "{e}");
        assert!(e.contains("`screenshot` tool"), "{e}");
    }

    /// Bounds on the two time-taking actions.
    #[tokio::test]
    async fn time_arguments_are_bounded() {
        let e = call(serde_json::json!({"action": "wait", "duration_ms": 0}))
            .await
            .unwrap_err();
        assert!(e.contains("duration_ms must be"), "{e}");
        let e = call(serde_json::json!({"action": "wait", "duration_ms": 999_999}))
            .await
            .unwrap_err();
        assert!(e.contains("duration_ms must be"), "{e}");
        let e = call(serde_json::json!({"action": "hold_key", "text": "ctrl+s", "duration_ms": 0}))
            .await
            .unwrap_err();
        assert!(e.contains("duration_ms must be"), "{e}");
    }

    /// A well-formed call on a host with no desktop reports the probe's
    /// reason — including `wait`, which must not fake a screen to wait for.
    #[tokio::test]
    async fn backend_refusal_reaches_the_model() {
        let e = call(serde_json::json!({"action": "left_click", "coordinate": [3, 4]}))
            .await
            .unwrap_err();
        assert!(e.contains("no desktop in tests"), "{e}");
        let e = call(serde_json::json!({"action": "wait", "duration_ms": 10}))
            .await
            .unwrap_err();
        assert!(e.contains("no desktop in tests"), "{e}");
    }
    #[test]
    fn describe_shows_what_the_call_will_do() {
        let d = |v: serde_json::Value| describe(&v);
        assert_eq!(
            d(serde_json::json!({"action": "left_click", "coordinate": [12, 34]})),
            "left_click (12, 34)"
        );
        // A trailing newline is Enter — it must be visible on the card.
        assert_eq!(
            d(serde_json::json!({"action": "type", "text": "rm -rf ~\n"})),
            "type \"rm -rf ~\\n\""
        );
        assert_eq!(
            d(serde_json::json!({"action": " KEY ", "text": "ctrl+alt+t"})),
            "key \"ctrl+alt+t\""
        );
        assert_eq!(
            d(serde_json::json!({"action": "launch", "text": "code ~/p"})),
            "launch \"code ~/p\""
        );
        assert_eq!(
            d(
                serde_json::json!({"action": "left_click_drag", "start_coordinate": [1, 2], "coordinate": [3, 4]})
            ),
            "left_click_drag (1, 2) → (3, 4)"
        );
        assert_eq!(
            d(serde_json::json!({"action": "scroll", "scroll_direction": "down"})),
            "scroll down ×3"
        );
        // Missing/odd arguments still yield a usable line, never a panic.
        assert_eq!(d(serde_json::json!({"action": "type"})), "type");
        assert_eq!(d(serde_json::json!({})), "computer");
    }
    /// `wait` honors the shared cancel flag instead of sleeping it out.
    #[tokio::test]
    async fn wait_ends_early_when_cancelled() {
        struct Live;
        #[async_trait::async_trait]
        impl agent_computer::DesktopBackend for Live {
            fn id(&self) -> &'static str {
                "live"
            }
            async fn screenshot(
                &self,
                _d: &std::path::Path,
            ) -> anyhow::Result<agent_computer::ScreenshotMeta> {
                anyhow::bail!("n/a")
            }
            async fn click(
                &self,
                _b: agent_computer::MouseButton,
                _a: [i32; 2],
            ) -> anyhow::Result<()> {
                Ok(())
            }
            async fn double_click(&self, _a: [i32; 2]) -> anyhow::Result<()> {
                Ok(())
            }
            async fn move_to(&self, _a: [i32; 2]) -> anyhow::Result<()> {
                Ok(())
            }
            async fn drag(&self, _f: [i32; 2], _t: [i32; 2]) -> anyhow::Result<()> {
                Ok(())
            }
            async fn type_text(&self, _t: &str) -> anyhow::Result<()> {
                Ok(())
            }
            async fn key(&self, _c: &str, _h: Option<u64>) -> anyhow::Result<()> {
                Ok(())
            }
            async fn scroll(
                &self,
                _d: agent_computer::ScrollDir,
                _a: i32,
                _at: Option<[i32; 2]>,
            ) -> anyhow::Result<()> {
                Ok(())
            }
            async fn cursor_position(&self) -> anyhow::Result<[i32; 2]> {
                Ok([0, 0])
            }
            async fn launch_app(&self, _c: &str) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut ctx = TestCtx::with_desktop(dir.path(), Arc::new(Live));
        ctx.cancel = Some(cancel.clone());
        let flag = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let t = std::time::Instant::now();
        let e = (spec::<TestCtx>().exec)(
            serde_json::json!({"action": "wait", "duration_ms": 9000}),
            Arc::new(ctx),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("cancelled"), "{e}");
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
    }
}
