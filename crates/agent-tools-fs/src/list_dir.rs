//! `list_dir` — bounded directory listing with an entry budget.
//!
//! Truncation table: "entry budget — 'too large to list fully' marker".

use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;

use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Max entries returned before the fold marker — bounds the OUTPUT.
const MAX_ENTRIES: usize = 500;
/// Max entries consumed from the walker — bounds the WORK. Sorting one
/// giant dir level can still cost, but the iterator itself stops here.
const MAX_SCAN_ENTRIES: usize = 4_000;

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct ListDirArgs {
    /// Workspace-relative directory path (default "."). Absolute paths are
    /// accepted only when they still resolve inside the workspace.
    path: Option<String>,
    /// Recurse depth (default 1 = direct children only, max 4).
    #[schemars(range(min = 1, max = 4))]
    depth: Option<usize>,
    /// Include hidden entries (dotfiles like .github). Default false —
    /// hidden files are skipped.
    include_hidden: Option<bool>,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "list_dir",
        schema: schema_for::<ListDirArgs>(
            "List directory entries (dirs carry a trailing `/`). Respects \
             .gitignore. Bounded output — use smart_grep/smart_read for \
             targeted lookups instead of deep listings.",
        ),
        readonly: true,
        class: agent_tool::ToolClass::Observation,
        network: false,
        staged: false,
        review: None,
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

async fn exec<C: WorkspaceCtx>(args: Args, ctx: Arc<C>) -> Result<ToolResult, ToolError> {
    let parsed: ListDirArgs =
        serde_json::from_value(args).map_err(|e| ToolError::Args(format!("list_dir args: {e}")))?;
    let rel = parsed.path.as_deref().unwrap_or(".");
    let root = ctx.resolve(rel)?;
    if !root.is_dir() {
        return Err(ToolError::Failed(format!("not a directory: {rel}")));
    }
    let depth = parsed.depth.unwrap_or(1).clamp(1, 4); // deep listings waste tokens
    let include_hidden = parsed.include_hidden.unwrap_or(false);
    // Header echoes a normalized view of the path the model passed —
    // "./src/" should print "src/", not "./src//".
    let display = {
        let d = rel.trim_end_matches('/');
        let d = d.strip_prefix("./").unwrap_or(d);
        if d.is_empty() {
            "."
        } else {
            d
        }
    };

    let mut out = format!("{display}/\n");
    let mut count = 0usize;
    let mut scanned = 0usize;
    let mut errors = 0usize;
    let mut truncated = false;

    let mut builder = ignore::WalkBuilder::new(&root);
    builder
        // Symlinks are NOT followed (ignore's default) — a symlinked dir is
        // listed as a leaf, never descended into, so workspace containment
        // can't be escaped through it.
        .hidden(!include_hidden)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .max_depth(Some(depth))
        .sort_by_file_name(|a, b| a.cmp(b));

    for result in builder.build() {
        scanned += 1;
        if scanned > MAX_SCAN_ENTRIES {
            truncated = true;
            break;
        }
        let entry = match result {
            Ok(e) => e,
            // Count unreadable entries instead of swallowing them — a
            // listing that hides failures reads as "complete" when it isn't.
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        if count >= MAX_ENTRIES {
            truncated = true;
            break;
        }
        let rel_path = match entry.path().strip_prefix(&root) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let indent = "  ".repeat(entry.depth().saturating_sub(1));
        let mut name = rel_path.to_string_lossy().replace('\\', "/");
        match entry.file_type() {
            Some(ft) if ft.is_symlink() => name.push('@'),
            Some(ft) if ft.is_dir() => {
                if !name.ends_with('/') {
                    name.push('/');
                }
            }
            _ => {}
        }
        out.push_str(&format!("{indent}{name}\n"));
        count += 1;
    }

    if truncated {
        out.push_str("… [too large to list fully — narrow the path or use smart_grep] …\n");
    }
    if errors > 0 {
        out.push_str(&format!(
            "⚠ {errors} entr{} could not be read (permissions or I/O error) — listing is incomplete\n",
            if errors == 1 { "y" } else { "ies" }
        ));
    }
    Ok(ToolResult::text(out))
}
