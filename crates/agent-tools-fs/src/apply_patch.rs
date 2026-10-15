//! `apply_patch` — structured multi-file patch.
//!
//! The patch is the general-purpose file-edit primitive: `*** Add File` /
//! `*** Delete File` / `*** Update File` (with `*** Move to`) compose into
//! one transaction — the model expresses a whole workspace change in a
//! single call, and the engine shows the full diff on the approval card
//! before committing via `PendingWrite`. Exact matching only: a hunk that
//! can't anchor is a teaching error (approximate matching is
//! `fuzzy_patch`'s job). Grammar (tolerant subset of the codex format):
//!
//! ```text
//! *** Begin Patch
//! *** Add File: path/to/new.rs
//! +line one
//! *** Delete File: path/old.rs
//! *** Update File: path/existing.rs
//! @@ optional context marker text
//!  context line to keep
//! -line to remove
//! +line to add
//! *** End Patch
//! ```

use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;
use similar::TextDiff;

use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

use crate::commit::{commit_writes, FileWrite, WriteObserverSlot, WriteOp};

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct ApplyPatchArgs {
    /// The full patch text, `*** Begin Patch` … `*** End Patch`, containing
    /// one or more `*** Add File` / `*** Delete File` / `*** Update File`
    /// sections.
    patch: String,
}

/// Patches above this are refused — an unbounded arg is a memory footgun
/// the model shouldn't control.
const MAX_PATCH_BYTES: usize = 2 * 1024 * 1024;

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "apply_patch",
        schema: schema_for::<ApplyPatchArgs>(
            "Apply a structured patch to one or more workspace files.\n\
             Use `*** Update File` with unified hunks for precise contextual\n\
             edits, or `*** Add File` / `*** Delete File` / `*** Move to`\n\
             for structural file changes. Multiple file operations can be\n\
             composed in one patch. Prefer this when the edit is naturally\n\
             expressed as a patch or involves multiple hunks/files.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::WorkspaceMutation,
        network: false,
        staged: true,
        review: None,
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

/// One parsed file operation.
#[derive(Debug)]
enum FileOp {
    Add {
        path: String,
        content: String,
    },
    Delete {
        path: String,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Hunk>,
    },
}

/// In-memory per-path state for the patch pipeline — `original` is the
/// disk content at first touch (None = absent), `current` the running
/// result (None = deleted).
struct FileState {
    original: Option<String>,
    current: Option<String>,
}

/// One `@@` hunk inside an `*** Update File` section: the leading-char
/// lines (` ` context, `-` remove, `+` add). `context` is the `@@ …`
/// locator text — codex uses it to disambiguate a `before` pattern that
/// matches several spots; `eof` marks a `*** End of File` append hunk.
#[derive(Debug)]
struct Hunk {
    context: Option<String>,
    lines: Vec<String>,
    eof: bool,
}

impl Hunk {
    fn new(context: Option<String>) -> Self {
        Self {
            context,
            lines: Vec::new(),
            eof: false,
        }
    }
    fn implicit(line: String) -> Self {
        Self {
            context: None,
            lines: vec![line],
            eof: false,
        }
    }
}

async fn exec<C: WorkspaceCtx>(args: Args, ctx: Arc<C>) -> Result<ToolResult, ToolError> {
    let parsed: ApplyPatchArgs = serde_json::from_value(args)
        .map_err(|e| ToolError::Args(format!("apply_patch args: {e}")))?;
    if parsed.patch.len() > MAX_PATCH_BYTES {
        return Err(ToolError::Args(format!(
            "patch exceeds {MAX_PATCH_BYTES} bytes — split it into smaller patches"
        )));
    }

    let ops = parse_patch(&parsed.patch)?;
    if ops.is_empty() {
        return Err(ToolError::Args(
            "patch contained no file operations — expected `*** Add File:` / \
             `*** Delete File:` / `*** Update File:` sections"
                .into(),
        ));
    }

    // Virtual-fs pipeline: ops run against an in-memory view so repeated
    // ops on one path compose (Update → Update → Move) instead of each
    // reading stale disk content and last-write-wins losing earlier hunks.
    // One staged write is emitted per touched path at the end.
    let mut state: std::collections::HashMap<std::path::PathBuf, FileState> =
        std::collections::HashMap::new();
    let mut order: Vec<std::path::PathBuf> = Vec::new();
    let mut summary = String::new();

    for op in &ops {
        match op {
            FileOp::Add { path, content } => {
                let abs = ctx.resolve(path)?;
                let st = load_state(&mut state, &mut order, &abs).await?;
                if st.current.is_some() {
                    return Err(ToolError::Args(format!(
                        "Add File {path}: file already exists — use Update File                          (or Delete File first to recreate)"
                    )));
                }
                let mut content = content.clone();
                if !content.is_empty() && !content.ends_with('\n') {
                    content.push('\n');
                }
                let diff = unified_diff(st.original.as_deref().unwrap_or(""), &content);
                summary.push_str(&format!("added {path}\n\n{diff}\n"));
                st.current = Some(content);
            }
            FileOp::Delete { path } => {
                let abs = ctx.resolve(path)?;
                let st = load_state(&mut state, &mut order, &abs).await?;
                let old = st.current.clone().ok_or_else(|| {
                    ToolError::Failed(format!("Delete File {path}: does not exist"))
                })?;
                summary.push_str(&format!("deleted {path}\n\n{}\n", unified_diff(&old, "")));
                st.current = None;
            }
            FileOp::Update {
                path,
                move_to,
                hunks,
            } => {
                if hunks.is_empty() {
                    return Err(ToolError::Args(format!(
                        "Update File {path}: no `@@` hunks — each update needs                          at least one context/remove/add section"
                    )));
                }
                let abs = ctx.resolve(path)?;
                let old = {
                    let st = load_state(&mut state, &mut order, &abs).await?;
                    st.current.clone().ok_or_else(|| {
                        ToolError::Failed(format!(
                            "Update File {path}: does not exist — use Add File"
                        ))
                    })?
                };
                let new = apply_hunks(path, &old, hunks)?;
                summary.push_str(&format!("updated {path}\n\n{}\n", unified_diff(&old, &new)));
                if let Some(dest) = move_to {
                    let dest_abs = ctx.resolve(dest)?;
                    if dest_abs != abs {
                        {
                            let dst = load_state(&mut state, &mut order, &dest_abs).await?;
                            if dst.current.is_some() {
                                return Err(ToolError::Args(format!(
                                    "Move to {dest}: destination already exists"
                                )));
                            }
                            dst.current = Some(new);
                        }
                        let src_st = state.get_mut(&abs).expect("loaded");
                        src_st.current = None;
                        summary.push_str(&format!("moved {path} → {dest}\n"));
                        continue;
                    }
                }
                state.get_mut(&abs).expect("loaded").current = Some(new);
            }
        }
    }

    // Emit one staged write per touched path, in first-touch order.
    let mut writes: Vec<FileWrite> = Vec::new();
    for abs in order {
        let st = &state[&abs];
        match (&st.original, &st.current) {
            (Some(o), Some(c)) if o != c => writes.push(FileWrite {
                path: abs,
                content: c.clone().into_bytes(),
                op: WriteOp::Write,
                auto_mkdir: true,
            }),
            (None, Some(c)) => writes.push(FileWrite {
                path: abs,
                content: c.clone().into_bytes(),
                op: WriteOp::Write,
                auto_mkdir: true,
            }),
            (Some(_), None) => writes.push(FileWrite {
                path: abs,
                content: Vec::new(),
                op: WriteOp::Delete,
                auto_mkdir: false,
            }),
            _ => {} // unchanged, or never existed and still absent
        }
    }

    Ok(ToolResult {
        content: summary.trim_end().to_string(),
        ui_type: Some("diff"),
        fuzzy: false,
        commit: commit_writes(
            writes,
            ctx.service::<WriteObserverSlot>().map(|s| s.0.clone()),
        ),
        images: Vec::new(),
    })
}

/// Load a path into the virtual fs on first touch (disk → FileState).
async fn load_state<'a>(
    state: &'a mut std::collections::HashMap<std::path::PathBuf, FileState>,
    order: &mut Vec<std::path::PathBuf>,
    abs: &std::path::Path,
) -> Result<&'a mut FileState, ToolError> {
    if !state.contains_key(abs) {
        // Missing vs unreadable: read_to_string maps binary bytes AND io
        // errors to the same None, which `Add File` then treats as "no
        // file" — silently clobbering an existing binary. Read raw bytes
        // first so existence is honest, then gate on UTF-8.
        let disk = match tokio::fs::read(abs).await {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(ToolError::Failed(format!(
                    "{}: cannot read — {e}",
                    abs.display()
                )))
            }
            Ok(bytes) => Some(String::from_utf8(bytes).map_err(|_| {
                ToolError::Failed(format!(
                    "{}: not UTF-8 text — apply_patch edits text files only",
                    abs.display()
                ))
            })?),
        };
        state.insert(
            abs.to_path_buf(),
            FileState {
                original: disk.clone(),
                current: disk,
            },
        );
        order.push(abs.to_path_buf());
    }
    Ok(state.get_mut(abs).expect("just inserted"))
}

/// Split the patch envelope into file operations.
fn parse_patch(patch: &str) -> Result<Vec<FileOp>, ToolError> {
    let mut ops = Vec::new();
    let mut lines = patch.lines().peekable();

    // Skip to `*** Begin Patch` (tolerate a bare patch that omits the
    // envelope — the model sometimes drops the wrapper).
    let mut envelope = false;
    while let Some(l) = lines.peek() {
        if l.trim() == "*** Begin Patch" {
            lines.next();
            envelope = true;
            break;
        }
        if l.trim().starts_with("*** Add File:")
            || l.trim().starts_with("*** Delete File:")
            || l.trim().starts_with("*** Update File:")
        {
            break; // bare patch — start parsing here
        }
        lines.next();
    }

    let mut cur_path: Option<String> = None;
    let mut cur_op: Option<&'static str> = None; // "add" | "delete" | "update"
    let mut cur_move: Option<String> = None;
    let mut add_lines: Vec<String> = Vec::new();
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut cur_hunk: Option<Hunk> = None;
    let mut saw_end = false;

    // Flush the in-progress op into `ops`.
    macro_rules! flush {
        () => {
            if let Some(h) = cur_hunk.take() {
                hunks.push(h);
            }
            match cur_op.take() {
                Some("add") => {
                    if let Some(p) = cur_path.take() {
                        ops.push(FileOp::Add {
                            path: p,
                            content: add_lines.join("\n"),
                        });
                    }
                }
                Some("delete") => {
                    if let Some(p) = cur_path.take() {
                        ops.push(FileOp::Delete { path: p });
                    }
                }
                Some("update") => {
                    if let Some(p) = cur_path.take() {
                        ops.push(FileOp::Update {
                            path: p,
                            move_to: cur_move.take(),
                            hunks: std::mem::take(&mut hunks),
                        });
                    }
                }
                _ => {}
            }
            add_lines.clear();
            hunks.clear();
            // cur_move self-clears via take() in the Update arm — and it can
            // only be set under an Update op, so nothing leaks across ops.
        };
    }

    for raw in lines {
        let l = raw.trim_end();
        if l == "*** End Patch" {
            saw_end = true;
            break;
        }
        if let Some(rest) = l.strip_prefix("*** ") {
            // `*** End of File` marks the CURRENT hunk as an EOF append —
            // it does NOT flush the in-progress file op (no path of its
            // own), unlike Add/Delete/Update which each start a fresh op.
            if rest.starts_with("End of File") {
                if let Some(h) = cur_hunk.as_mut() {
                    h.eof = true;
                } else {
                    cur_hunk = Some(Hunk {
                        context: None,
                        lines: Vec::new(),
                        eof: true,
                    });
                }
                continue;
            }
            if let Some(p) = rest.strip_prefix("Move to:") {
                // `*** Move to:` continues the CURRENT Update op — it is
                // not a new file op, so no flush. Without a preceding
                // `*** Update File:` it is meaningless.
                if cur_op != Some("update") {
                    return Err(ToolError::Args(
                        "`*** Move to:` must follow `*** Update File:`".into(),
                    ));
                }
                if cur_move.is_some() {
                    return Err(ToolError::Args(
                        "duplicate `*** Move to:` in one Update File section".into(),
                    ));
                }
                cur_move = Some(p.trim().to_string());
                continue;
            }
            flush!();
            if let Some(p) = rest.strip_prefix("Add File:") {
                cur_op = Some("add");
                cur_path = Some(p.trim().to_string());
            } else if let Some(p) = rest.strip_prefix("Delete File:") {
                cur_op = Some("delete");
                cur_path = Some(p.trim().to_string());
            } else if let Some(p) = rest.strip_prefix("Update File:") {
                cur_op = Some("update");
                cur_path = Some(p.trim().to_string());
            }
            continue;
        }
        match cur_op {
            Some("add") => {
                // Add lines are `+`-prefixed; a bare line is tolerated too.
                add_lines.push(l.strip_prefix('+').unwrap_or(l).to_string());
            }
            Some("update") => {
                if l.starts_with("@@") {
                    if let Some(h) = cur_hunk.take() {
                        hunks.push(h);
                    }
                    // `@@ optional context marker` — keep the locator text;
                    // apply_hunks uses it to disambiguate a `before` that
                    // matches more than one spot.
                    let marker = l[2..].trim();
                    cur_hunk = Some(Hunk::new((!marker.is_empty()).then(|| marker.to_string())));
                } else if l.starts_with(' ') || l.starts_with('-') || l.starts_with('+') {
                    if let Some(h) = cur_hunk.as_mut() {
                        h.lines.push(l.to_string());
                    } else {
                        // No `@@` header — start an implicit hunk so a
                        // context-free update still parses.
                        cur_hunk = Some(Hunk::implicit(l.to_string()));
                    }
                }
            }
            _ => {} // delete carries no body; pre-op junk ignored
        }
    }
    flush!();
    // An opened envelope that never closes means the patch was truncated —
    // silently accepting it would apply half a patch.
    if envelope && !saw_end {
        return Err(ToolError::Args(
            "patch truncated — missing `*** End Patch`".into(),
        ));
    }
    Ok(ops)
}

/// Apply `*** Update File` hunks to `old`. Each hunk's `-`/` ` lines are
/// the "before" pattern, `+`/` ` the "after". Exact match only — a miss
/// is a teaching error (fuzzy matching is fuzzy_patch's job).
///
/// Errors name the file, the hunk index, and a preview of the `before`
/// pattern so a failed patch is diagnosable without re-reading the tool
/// call (native-tools.md: errors must teach the fix).
fn apply_hunks(path: &str, old: &str, hunks: &[Hunk]) -> Result<String, ToolError> {
    let mut src = old.replace("\r\n", "\n");
    for (idx, h) in hunks.iter().enumerate() {
        let hunk_desc = || format!("{path} hunk {}/{}", idx + 1, hunks.len());
        let mut before = String::new();
        let mut after = String::new();
        for l in &h.lines {
            match l.chars().next() {
                // `-` removes → before only. `+` adds → after only.
                // ` `/bare context → both. Each branch appends its own
                // `\n` so a `-` line can't leak a blank into `after`.
                Some('-') => {
                    before.push_str(&l[1..]);
                    before.push('\n');
                }
                Some('+') => {
                    after.push_str(&l[1..]);
                    after.push('\n');
                }
                _ => {
                    let ctx_line = l.strip_prefix(' ').unwrap_or(l);
                    before.push_str(ctx_line);
                    before.push('\n');
                    after.push_str(ctx_line);
                    after.push('\n');
                }
            }
        }
        let before = before.trim_end_matches('\n');
        let after = after.trim_end_matches('\n');

        // `*** End of File` — append `after` to the tail (no `before`
        // locator needed; codex uses it for trailing appends).
        if h.eof {
            if !src.is_empty() && !src.ends_with('\n') {
                src.push('\n');
            }
            src.push_str(after);
            if !after.is_empty() && !after.ends_with('\n') {
                src.push('\n');
            }
            continue;
        }

        if before.is_empty() {
            if after.is_empty() {
                return Err(ToolError::Args(format!(
                    "{} is empty — each hunk needs ` `, `-`, or `+` lines",
                    hunk_desc()
                )));
            }
            // Insert-only hunk (`@@ marker` + `+` lines): codex inserts the
            // `after` block right AFTER the marker line. Without a marker
            // there is no anchor — keep refusing.
            let marker = h.context.as_deref().ok_or_else(|| {
                ToolError::Args(format!(
                    "{} has only `+` lines and no `@@ marker` — \
                     an insert needs a context line to anchor to",
                    hunk_desc()
                ))
            })?;
            let mut off = 0usize;
            let mut hits: Vec<usize> = Vec::new();
            for l in src.split_inclusive('\n') {
                if l.trim_end() == marker {
                    hits.push(off + l.len());
                }
                off += l.len();
            }
            match hits.len() {
                1 => {
                    src.insert_str(hits[0], &format!("{after}\n"));
                }
                n if n > 1 => {
                    return Err(ToolError::Failed(format!(
                        "{}: `@@ {marker}` matched {n} lines — \
                         use a more specific marker",
                        hunk_desc()
                    )));
                }
                _ => {
                    return Err(ToolError::Failed(format!(
                        "{}: `@@ {marker}` not found in file",
                        hunk_desc()
                    )));
                }
            }
            continue;
        }
        let hits: Vec<usize> = src.match_indices(before).map(|(i, _)| i).collect();
        match hits.len() {
            1 => {
                // match_indices gave the byte offset — splice in place,
                // skipping replacen's second scan of the whole file.
                src.replace_range(hits[0]..hits[0] + before.len(), after);
            }
            n if n > 1 => {
                // Ambiguous `before` — the `@@ context` locator picks the
                // occurrence AT/AFTER the marker (codex semantics), else
                // report the ambiguity so the model adds context.
                let pick = h.context.as_deref().and_then(|marker| {
                    src.find(marker)
                        .and_then(|mpos| hits.iter().copied().find(|&i| i >= mpos))
                });
                match pick {
                    Some(i) => {
                        src.replace_range(i..i + before.len(), after);
                    }
                    None => {
                        return Err(ToolError::Failed(format!(
                            "{} matched {n} locations — add more context \
                             lines or an `@@ marker`. Pattern starts: {:?}",
                            hunk_desc(),
                            preview(before)
                        )));
                    }
                }
            }
            _ => {
                // No fuzzy fallback — apply_patch is the structured tool;
                // approximate matching belongs to fuzzy_patch. A miss is a
                // teaching error: the model adds context lines or an `@@`
                // marker instead of us guessing where the hunk lands.
                return Err(ToolError::Failed(format!(
                    "{}: context not found — add more ` ` context lines or \
                     an `@@ marker` so the hunk anchors uniquely. \
                     Pattern starts: {:?}",
                    hunk_desc(),
                    preview(before)
                )));
            }
        }
    }
    Ok(src)
}

/// First ~60 chars of a pattern, single-line, for error messages.
fn preview(s: &str) -> String {
    const MAX: usize = 60;
    let one_line = s.replace('\n', "⏎");
    match one_line.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}…", &one_line[..i]),
        None => one_line,
    }
}

fn unified_diff(old: &str, new: &str) -> String {
    TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header("a/file", "b/file")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_add_delete_update() {
        let patch = "\
*** Begin Patch
*** Add File: src/new.rs
+fn new() {}
*** Delete File: src/old.rs
*** Update File: src/lib.rs
@@
 context
-old_call()
+new_call()
*** End Patch";
        let ops = parse_patch(patch).unwrap();
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn update_hunks_patch_source() {
        let old = "fn a() {}\nfn b() {}\n";
        let hunks = vec![Hunk {
            lines: vec![
                " fn a() {}".into(),
                "-fn b() {}".into(),
                "+fn c() {}".into(),
            ],
            context: None,
            eof: false,
        }];
        let new = apply_hunks("src/lib.rs", old, &hunks).unwrap();
        assert!(new.contains("fn c()"));
        assert!(!new.contains("fn b()"));
    }

    #[test]
    fn update_error_names_file_hunk_and_pattern() {
        let old = "fn a() {}\nfn b() {}\n";
        let hunks = vec![
            Hunk {
                lines: vec![" fn a() {}".into()],
                context: None,
                eof: false,
            },
            Hunk {
                lines: vec!["-fn missing() {}".into(), "+fn c() {}".into()],
                context: None,
                eof: false,
            },
        ];
        let err = apply_hunks("src/lib.rs", old, &hunks)
            .unwrap_err()
            .to_string();
        assert!(err.contains("src/lib.rs"), "missing path: {err}");
        assert!(err.contains("hunk 2/2"), "missing hunk index: {err}");
        assert!(
            err.contains("fn missing()"),
            "missing pattern preview: {err}"
        );
    }

    #[test]
    fn ambiguous_hunk_error_names_location() {
        let old = "x\nx\n";
        let hunks = vec![Hunk {
            lines: vec!["-x".into(), "+y".into()],
            context: None,
            eof: false,
        }];
        let err = apply_hunks("f.txt", old, &hunks).unwrap_err().to_string();
        assert!(err.contains("f.txt hunk 1/1"), "missing location: {err}");
        assert!(err.contains("matched 2 locations"), "missing count: {err}");
    }

    #[test]
    fn context_marker_disambiguates_repeated_before() {
        // `before` ("x") appears twice — the `@@ second` marker picks the
        // occurrence at/after the marker instead of erroring.
        let old = "first\nx\nsecond\nx\n";
        let hunks = vec![Hunk {
            context: Some("second".into()),
            lines: vec!["-x".into(), "+y".into()],
            eof: false,
        }];
        let new = apply_hunks("f.txt", old, &hunks).unwrap();
        assert_eq!(new, "first\nx\nsecond\ny\n");
    }

    #[test]
    fn end_of_file_appends() {
        let old = "fn a() {}\n";
        let hunks = vec![Hunk {
            context: None,
            lines: vec!["+fn tail() {}".into()],
            eof: true,
        }];
        let new = apply_hunks("f.rs", old, &hunks).unwrap();
        assert_eq!(new, "fn a() {}\nfn tail() {}\n");
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        let patch = "*** Begin Patch\n*** Add File: a.rs\n+line\n"; // no End Patch
        let err = parse_patch(patch).unwrap_err().to_string();
        assert!(err.contains("End Patch"), "missing marker error: {err}");
        // Bare patches (no envelope) may legitimately end without it.
        let bare = "*** Add File: a.rs\n+line\n";
        assert!(parse_patch(bare).is_ok());
    }

    #[test]
    fn move_to_parses_and_requires_update() {
        let ok =
            "*** Begin Patch\n*** Update File: a.rs\n*** Move to: b.rs\n@@\n-x\n+y\n*** End Patch";
        match parse_patch(ok).unwrap().as_slice() {
            [FileOp::Update {
                move_to: Some(m), ..
            }] => assert_eq!(m, "b.rs"),
            other => panic!("expected update+move, got {} ops", other.len()),
        }
        let bad = "*** Begin Patch\n*** Add File: a.rs\n*** Move to: b.rs\n+x\n*** End Patch";
        assert!(parse_patch(bad).is_err());
    }

    #[test]
    fn insert_only_hunk_anchors_at_context() {
        let old = "fn a() {}\nfn b() {}\n";
        let hunks = vec![Hunk {
            context: Some("fn a() {}".into()),
            lines: vec!["+fn inserted() {}".into()],
            eof: false,
        }];
        let new = apply_hunks("f.rs", old, &hunks).unwrap();
        assert_eq!(new, "fn a() {}\nfn inserted() {}\nfn b() {}\n");

        // Ambiguous marker refuses instead of guessing.
        let dup = "x\nx\n";
        let hunks = vec![Hunk {
            context: Some("x".into()),
            lines: vec!["+y".into()],
            eof: false,
        }];
        assert!(apply_hunks("f.txt", dup, &hunks).is_err());
    }
}
