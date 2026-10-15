//! The `serena` meta-tool — one entry point for the whole Serena suite.
//!
//! Registering Serena's ~40 tools 1:1 would push the model's tool list past a
//! hundred entries and degrade selection for everything else. One namespaced
//! passthrough keeps the surface small while still exposing every capability
//! (`tool: "serena_list_tools"` discovers names, arguments, and schemas).

use std::sync::Arc;

use futures::FutureExt;
use serde_json::json;

use super::catalog::DETAIL_ACTION;
use super::manager::manager_for;
use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, ExecFn, ToolClass, ToolError, ToolResult, ToolSpec};

/// `serena` meta-tool args — call one Serena tool by name.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SerenaCallArgs {
    /// The Serena tool name (e.g. `find_symbol`, `read_file`,
    /// `replace_symbol_body`, `search_for_pattern`, `list_dir`), or
    /// `serena_list_tools` to discover them.
    tool: String,
    /// The tool's arguments as a JSON object. For `serena_list_tools`, pass
    /// `{"name": "<tool>"}` to print that tool's full JSON Schema.
    arguments: Option<serde_json::Value>,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    let exec: ExecFn<C> = Arc::new(|args, ctx| {
        let a: SerenaCallArgs = match serde_json::from_value(args) {
            Ok(a) => a,
            Err(e) => {
                return async move { Err(ToolError::Args(format!("serena args: {e}"))) }.boxed()
            }
        };
        // Scope every call to *this* workspace's server. A process-wide shared
        // bridge would run project B's `replace_symbol_body` against project
        // A's tree; the manager keys by root (and restarts a dead child).
        async move {
            let root = ctx.root()?.to_path_buf();
            let manager = manager_for(&root);

            // Discovery is a bridge concern, not a Serena tool.
            if a.tool == DETAIL_ACTION || a.tool == "list_tools" {
                let detail = a
                    .arguments
                    .as_ref()
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str());
                return Ok(ToolResult::text(
                    manager.render_catalog(&root, detail).await?,
                ));
            }

            let bridge = manager.bridge(&root).await.map_err(|e| {
                ToolError::Failed(format!(
                    "serena unavailable for {}: {e}\n(install: `uv tool install -p 3.13 \
                     serena-agent`, then `serena init`; `serena project health-check` \
                     diagnoses a project and `serena project index` builds its index)",
                    root.display()
                ))
            })?;
            let arguments = a.arguments.unwrap_or(json!({}));
            match bridge.call(&a.tool, arguments).await {
                Ok(out) => {
                    // The child can die right after answering — don't hand the
                    // dead handle to the next call.
                    if !bridge.is_healthy() {
                        manager.invalidate(&root).await;
                    }
                    Ok(ToolResult::text(out))
                }
                Err(e) => {
                    // A failed call on a dead server is not a Serena error:
                    // drop the bridge so the next attempt restarts it. No
                    // automatic retry — the call may have been a write that
                    // succeeded before the pipe broke.
                    if !bridge.is_healthy() {
                        manager.invalidate(&root).await;
                        return Err(ToolError::Failed(format!(
                            "{e}\n\nthe serena server for {} exited — its bridge was \
                             dropped and the next call restarts it. Safe to retry a \
                             read; for a write, check the result first.",
                            root.display()
                        )));
                    }
                    Err(e)
                }
            }
        }
        .boxed()
    });

    ToolSpec {
        name: "serena",
        schema: schema_for::<SerenaCallArgs>(
            "Call a Serena semantic code tool (IDE-level symbol/file ops —\n\
             find_symbol, read_file, replace_symbol_body, rename_symbol,\n\
             search_for_pattern, list_dir, …). Pass `tool` = the Serena tool\n\
             name and `arguments` = its JSON args. Call with\n\
             `tool: \"serena_list_tools\"` to discover the tools with their\n\
             argument names (add `arguments: {\"name\": \"<tool>\"}` for one\n\
             tool's full JSON Schema).",
        ),
        // Serena's suite writes files — keep the permission gate on it.
        readonly: false,
        class: ToolClass::WorkspaceMutation,
        // Execution is local stdio. The *bootstrap* (`uvx` fetching Serena
        // from git) does reach the network — this flag does not describe that
        // (see the module docs / `SerenaLaunch`), and batch accounting is the
        // only consumer today, which never sees this tool (WorkspaceMutation).
        network: false,
        staged: false,
        review: None,
        exec,
    }
}
