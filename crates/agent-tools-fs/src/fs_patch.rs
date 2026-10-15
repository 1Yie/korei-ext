//! `fuzzy_patch` — search/replace blocks, never diffs, never rewrites.
//!
//! Match pipeline, ordered, first success wins:
//! 1. Normalize `\r\n`→`\n` on source and both blocks.
//! 2. Exact match: 1 hit applies; >1 errors with guidance; 0 falls through.
//! 3. Per-line whitespace-tolerant match.
//! 4. Last resort: sliding-window similarity ≥0.9, flagged in the result so the
//!    approval card can say "matched approximately".
//! 5. `expected_hash` is checked before any match attempt — stale context is the
//!    top source of corrupted writes.

use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;
use similar::TextDiff;
use xxhash_rust::xxh3::xxh3_64;

use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

const FUZZY_THRESHOLD: f64 = 0.9;

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct FuzzyPatchArgs {
    /// Workspace-relative path.
    path: String,
    /// Exact source text to find. Must match uniquely — add surrounding
    /// context lines if it matches more than once.
    search: String,
    /// Replacement text.
    replace: String,
    /// Optional `content_hash` from `smart_read` — aborts the patch if the
    /// file drifted since it was read.
    expected_hash: Option<String>,
}

/// What a successful patch reports back (per native-tools.md §PatchResult).
#[derive(Debug)]
pub struct PatchResult {
    pub patched_content: String,
    pub unified_diff: String,
    pub matched_fuzzily: bool,
    pub match_line: usize,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "fuzzy_patch",
        schema: schema_for::<FuzzyPatchArgs>(
            "Make a targeted text replacement in one file. Use for changing \
             a small local section — replacing an existing block with \
             another block when the exact surrounding text is known. \
             `search` must match exactly one location (whitespace/fuzzy \
             fallback exists but exact is preferred). Pass `expected_hash` \
             from smart_read to guard against file drift.",
        ),
        readonly: false,
        class: agent_tool::ToolClass::WorkspaceMutation,
        network: false,
        staged: true,
        review: None,
        exec: std::sync::Arc::new(|args, ctx| exec(args, ctx).boxed()),
    }
}

async fn exec<C: WorkspaceCtx>(args: Args, ctx: Arc<C>) -> Result<ToolResult, ToolError> {
    let parsed: FuzzyPatchArgs = serde_json::from_value(args)
        .map_err(|e| ToolError::Args(format!("fuzzy_patch args: {e}")))?;
    let path = ctx.resolve(&parsed.path)?;
    let source = tokio::fs::read_to_string(&path).await?;

    // Tier 5 first: drift check precedes any matching work.
    if let Some(expected) = &parsed.expected_hash {
        let actual = format!("{:016x}", xxh3_64(source.as_bytes()));
        if &actual != expected {
            return Err(ToolError::Failed(format!(
                "file drifted — expected hash {expected}, current {actual}. Re-read with smart_read before patching."
            )));
        }
    }

    let res = apply(&source, &parsed.search, &parsed.replace)?;

    // The tool does not write — it returns the change as a staged `Commit`
    // and the ENGINE applies it after the permission decision. This makes the
    // side effect explicit, keeps the fuzzy flag honest on the approval card,
    // and lets the host record the hunk in one step (no read-after-write to
    // reconstruct what changed).
    let mut content = String::new();
    content.push_str(&format!(
        "patched {} (line {})",
        parsed.path, res.match_line
    ));
    if res.matched_fuzzily {
        content.push_str(" — matched approximately, review carefully");
    }
    content.push_str("\n\n");
    content.push_str(&res.unified_diff);

    Ok(ToolResult {
        content,
        ui_type: Some("diff"),
        fuzzy: res.matched_fuzzily,
        commit: crate::commit::commit_writes(
            vec![crate::commit::FileWrite::write(
                path,
                res.patched_content.into_bytes(),
            )],
            ctx.service::<crate::commit::WriteObserverSlot>()
                .map(|s| s.0.clone()),
        ),
        images: Vec::new(),
    })
}

/// Pure match+apply — testable without IO. Returns `Err` with a
/// self-teaching message on ambiguity or no-match.
pub fn apply(source: &str, search: &str, replace: &str) -> Result<PatchResult, ToolError> {
    let norm_src = source.replace("\r\n", "\n");
    let norm_search = search.replace("\r\n", "\n");
    let norm_replace = replace.replace("\r\n", "\n");

    if norm_search.is_empty() {
        return Err(ToolError::Args(
            "empty `search` block — to append, search for the file's tail lines".into(),
        ));
    }

    // Tier 2: exact.
    let hits: Vec<usize> = norm_src
        .match_indices(&norm_search)
        .map(|(i, _)| i)
        .collect();
    let (patched, match_byte, fuzzy) = match hits.len() {
        1 => (
            norm_src.replacen(&norm_search, &norm_replace, 1),
            hits[0],
            false,
        ),
        n if n > 1 => {
            return Err(ToolError::Failed(format!(
            "search block matched {n} locations — add surrounding context lines to make it unique"
        )))
        }
        _ => {
            // Tier 3: whitespace-tolerant line match.
            match whitespace_match(&norm_src, &norm_search) {
                WsMatch::Unique(byte_off, len) => {
                    let mut s = norm_src.clone();
                    s.replace_range(byte_off..byte_off + len, &norm_replace);
                    (s, byte_off, false)
                }
                WsMatch::Ambiguous(n) => {
                    return Err(ToolError::Failed(format!(
                        "search block matched {n} locations (whitespace-normalized) — add surrounding context lines"
                    )))
                }
                WsMatch::None => {
                    // Tier 4: fuzzy sliding window ≥0.9.
                    match fuzzy_match(&norm_src, &norm_search) {
                        Some((byte_off, len, _score)) => {
                            let mut s = norm_src.clone();
                            s.replace_range(byte_off..byte_off + len, &norm_replace);
                            (s, byte_off, true)
                        }
                        None => {
                            return Err(ToolError::Failed(
                                "search block not found — check indentation/content against smart_read output".into(),
                            ))
                        }
                    }
                }
            }
        }
    };

    let match_line = norm_src[..match_byte].matches('\n').count() + 1;
    let unified_diff = unified_diff(&norm_src, &patched);
    Ok(PatchResult {
        patched_content: patched,
        unified_diff,
        matched_fuzzily: fuzzy,
        match_line,
    })
}

enum WsMatch {
    Unique(usize, usize),
    Ambiguous(usize),
    None,
}

/// Tier 3: find a run of source lines whose per-line trimmed text equals the
/// search block's trimmed lines.
fn whitespace_match(src: &str, search: &str) -> WsMatch {
    let src_lines: Vec<&str> = src.lines().collect();
    let needle: Vec<&str> = search.lines().map(|l| l.trim()).collect();
    if needle.is_empty() || needle.len() > src_lines.len() {
        return WsMatch::None;
    }
    let mut matches = Vec::new();
    'outer: for start in 0..=src_lines.len() - needle.len() {
        for (k, want) in needle.iter().enumerate() {
            if src_lines[start + k].trim() != *want {
                continue 'outer;
            }
        }
        matches.push(start);
    }
    match matches.len() {
        0 => WsMatch::None,
        1 => {
            let start = matches[0];
            let byte_off = src_lines[..start].iter().map(|l| l.len() + 1).sum();
            let byte_len: usize = src_lines[start..start + needle.len()]
                .iter()
                .map(|l| l.len() + 1)
                .sum::<usize>()
                .saturating_sub(1);
            WsMatch::Unique(byte_off, byte_len)
        }
        n => WsMatch::Ambiguous(n),
    }
}

/// Tier 4: sliding-window similarity on line granularity.
fn fuzzy_match(src: &str, search: &str) -> Option<(usize, usize, f64)> {
    let src_lines: Vec<&str> = src.lines().collect();
    let needle_lines: Vec<&str> = search.lines().collect();
    if needle_lines.is_empty() || src_lines.is_empty() {
        return None;
    }
    let w = needle_lines.len();
    let mut best: Option<(usize, f64)> = None;
    for start in 0..=src_lines.len().saturating_sub(w) {
        let window = src_lines[start..start + w].join("\n");
        // Char-level normalized Levenshtein — line-ratio undercounts partial
        // line drift, which is exactly what fuzzy matching exists to absorb.
        let score = strsim::normalized_levenshtein(search, &window);
        if best.map(|(_, s)| score > s).unwrap_or(true) {
            best = Some((start, score));
        }
    }
    let (start, score) = best?;
    if score < FUZZY_THRESHOLD {
        return None;
    }
    let byte_off = src_lines[..start].iter().map(|l| l.len() + 1).sum();
    let byte_len: usize = src_lines[start..start + w]
        .iter()
        .map(|l| l.len() + 1)
        .sum::<usize>()
        .saturating_sub(1);
    Some((byte_off, byte_len, score))
}

/// `similar`-generated unified diff for the approval card.
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
    fn exact_match_applies() {
        let src = "fn a() {\n    old();\n}\nfn b() {}\n";
        let r = apply(src, "    old();", "    new();").unwrap();
        assert!(r.patched_content.contains("new();"));
        assert_eq!(r.match_line, 2);
        assert!(!r.matched_fuzzily);
    }

    #[test]
    fn crlf_source_lf_search() {
        let src = "fn a() {\r\n    old();\r\n}\r\n";
        let r = apply(src, "    old();\n}", "    new();\n}").unwrap();
        assert!(r.patched_content.contains("new();"));
    }

    #[test]
    fn ambiguous_teaches_context() {
        let src = "x();\nfoo();\nx();\n";
        let err = apply(src, "x();", "y();").unwrap_err();
        assert!(err.to_string().contains("matched 2 locations"));
        assert!(err.to_string().contains("context"));
    }

    #[test]
    fn whitespace_tier_handles_indent_drift() {
        let src = "fn a() {\n        old();\n}\n";
        // search has different indentation than source
        let r = apply(src, "  old();", "        new();").unwrap();
        assert!(r.patched_content.contains("new();"));
    }

    #[test]
    fn fuzzy_tier_flags_result() {
        // One char drift inside a large block — similarity >0.9, flagged fuzzy.
        let src = concat!(
            "fn render() {\n",
            "    let x = compute(a, b);\n",
            "    let y = blend(x, z);\n",
            "    let w = clamp(y, 0.0, 1.0);\n",
            "    draw(w);\n",
            "}\n",
        );
        // search has `blendd` instead of `blend` — one char off in ~120.
        let r = apply(
            src,
            "fn render() {\n    let x = compute(a, b);\n    let y = blendd(x, z);\n    let w = clamp(y, 0.0, 1.0);\n    draw(w);\n}",
            "fn render() {\n    let x = compute(a, b);\n    let y = blend(x, z);\n    let w = clamp(y, 0.0, 1.0);\n    draw(w);\n    log(w);\n}",
        )
        .unwrap();
        assert!(r.matched_fuzzily, "expected fuzzy flag, got {r:?}");
        assert!(r.patched_content.contains("log(w)"));
    }

    #[test]
    fn fuzzy_below_threshold_refused() {
        // Whole-block drift → under 0.9 → teaching error, not a bad patch.
        let err = apply(
            "fn render() {\n    let x = compute(a, b);\n    draw(x);\n}\n",
            "completely different\ntext block\nthat matches nothing\nhere\n",
            "x",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn no_match_is_teaching_error() {
        let err = apply("fn a() {}", "nonexistent block", "x").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn empty_search_rejected() {
        assert!(apply("abc", "", "x").is_err());
    }
}
