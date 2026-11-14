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
use super::manager::{manager_for, registry, SerenaRegistry, SerenaStatus};
use agent_capabilities::{SandboxCtx, WorkspaceCtx};
use agent_tool::{schema_for, ExecFn, ToolClass, ToolError, ToolResult, ToolSpec};

/// `serena` meta-tool args — call one Serena tool by name.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SerenaCallArgs {
    /// The Serena tool name (e.g. `find_symbol`, `read_file`,
    /// `replace_symbol_body`, `search_for_pattern`, `list_dir`), or
    /// `serena_list_tools` to discover them, `serena_status` to inspect the
    /// server without starting it, or `serena_stop` to stop it and wait for cleanup.
    tool: String,
    /// The tool's arguments as a JSON object. For `serena_list_tools`, pass
    /// `{"name": "<tool>"}` to print that tool's full JSON Schema.
    arguments: Option<serde_json::Value>,
}

async fn drop_bridge<C: WorkspaceCtx>(
    ctx: &C,
    root: &std::path::Path,
    session: Option<&Arc<SerenaRegistry>>,
) -> Result<(), ToolError> {
    if let Some(session) = session {
        session.stop(ctx).await
    } else {
        manager_for(root).stop(root).await
    }
}

pub fn spec<C>() -> ToolSpec<C>
where
    C: WorkspaceCtx + SandboxCtx,
{
    let exec: ExecFn<C> = Arc::new(|args, ctx| {
        let a: SerenaCallArgs = match serde_json::from_value(args) {
            Ok(a) => a,
            Err(e) => {
                return async move { Err(ToolError::Args(format!("serena args: {e}"))) }.boxed()
            }
        };
        // Unprepared calls share one server per workspace root. Prepared calls
        // use that session's registry, keyed by its private project and authorization.
        async move {
            let root = ctx.root()?.to_path_buf();
            let prepared = ctx.workspace_lease().is_some();
            let session = if prepared {
                Some(registry(&*ctx)?)
            } else {
                None
            };

            if a.tool == "serena_status" {
                let status = if let Some(session) = &session {
                    session.status(&*ctx).await?
                } else {
                    manager_for(&root).status(&root).await
                };
                let status = match status {
                    SerenaStatus::Stopped => "stopped",
                    SerenaStatus::Running => "running",
                    SerenaStatus::CleanupPending => "cleanup pending; use serena_stop",
                };
                return Ok(ToolResult::text(format!("serena: {status}")));
            }
            if a.tool == "serena_stop" {
                if let Some(session) = &session {
                    session.stop(&*ctx).await?;
                } else {
                    manager_for(&root).stop(&root).await?;
                }
                return Ok(ToolResult::text(
                    "serena stopped; process and stdio cleanup confirmed",
                ));
            }

            // Discovery is a bridge concern, not a Serena tool.
            if a.tool == DETAIL_ACTION || a.tool == "list_tools" {
                let detail = a
                    .arguments
                    .as_ref()
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str());
                let text = if let Some(session) = &session {
                    session.render_catalog(&*ctx, detail).await?
                } else {
                    manager_for(&root).render_catalog(&root, detail).await?
                };
                return Ok(ToolResult::text(text));
            }

            let bridge = if let Some(session) = &session {
                session.bridge(&*ctx).await
            } else {
                manager_for(&root).bridge(&root).await
            }
            .map_err(|e| {
                ToolError::Failed(format!(
                    "serena unavailable for {}: {e}\n(install: `uv tool install -p 3.13 \
                     serena-agent`, then `serena init`; `serena project health-check` \
                     diagnoses a project and `serena project index` builds its index)",
                    root.display()
                ))
            })?;
            let coverage = if let Some(session) = &session {
                session.coverage_notice(&*ctx).await?
            } else {
                None
            };
            let arguments = a.arguments.unwrap_or(json!({}));
            match bridge.call(&a.tool, arguments).await {
                Ok(mut out) => {
                    // The child can die right after answering — don't hand the
                    // dead handle to the next call.
                    if !bridge.is_healthy() {
                        drop_bridge(&*ctx, &root, session.as_ref()).await?;
                    }
                    if let Some(notice) = &coverage {
                        out.push_str(&format!("\n\n{notice}"));
                    }
                    Ok(ToolResult::text(out))
                }
                Err(e) => {
                    // A failed call on a dead server is not a Serena error:
                    // drop the bridge so the next attempt restarts it. No
                    // automatic retry — the call may have been a write that
                    // succeeded before the pipe broke.
                    if !bridge.is_healthy() {
                        drop_bridge(&*ctx, &root, session.as_ref()).await?;
                        return Err(ToolError::Failed(format!(
                            "{e}\n\nthe serena server for {} exited — its bridge was \
                             dropped and the next call restarts it. Safe to retry a \
                             read; for a write, check the result first.",
                            root.display()
                        )));
                    }
                    match &coverage {
                        Some(notice) => Err(ToolError::Failed(format!("{e}\n\n{notice}"))),
                        None => Err(e),
                    }
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
             tool's full JSON Schema). Use `tool: \"serena_status\"` to inspect\n\
             the server without starting it, or `tool: \"serena_stop\"` to stop\n\
             it and wait for process and stdio cleanup. A later semantic call\n\
             starts a new server.",
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
        cancel_aware: false,
        exec,
    }
}
