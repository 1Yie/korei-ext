//! `smart_grep` — in-process regex search via `grep-searcher`.
//!
//! Bounded observation: match cap (hard-limited), 5 MiB output cap, 8 MiB
//! file cap, 16 KiB line cap, 20 s wall-clock. The timeout arms a shared
//! cancel flag the sink + walker poll — `spawn_blocking` work actually
//! stops instead of just being detached. Scope-annotation ([inside impl X])
//! is a Phase-2 upgrade once tree-sitter grammars land.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use grep_regex::RegexMatcher;
use grep_searcher::sinks::UTF8;
use grep_searcher::SearcherBuilder;
use grep_searcher::SinkError;
use serde::Deserialize;

use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Stdout cap per truncation table.
const MAX_OUTPUT: usize = 5 * 1024 * 1024;
/// Default match cap before folding.
const MAX_HITS: usize = 300;
/// Hard ceiling on `max_hits` — resource control isn't the model's call.
const MAX_HITS_LIMIT: usize = 2_000;
/// Reject absurd patterns before they reach the regex compiler.
const MAX_PATTERN_LEN: usize = 4 * 1024;
/// Per-line truncation (UTF-8 boundary-safe) — one pathological line can't
/// eat the output budget.
const MAX_LINE_BYTES: usize = 16 * 1024;
/// Files larger than this are skipped — searching a 2 GB log burns the
/// whole timeout for nothing.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Search wall-clock budget.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Obvious-binary extensions skipped before search (cheap, deterministic).
/// Text-ish files like `.lock` stay searchable — Cargo.lock matters.
const BINARY_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "pdf", "zip", "gz", "tgz", "xz",
    "bz2", "7z", "rar", "zst", "wasm", "so", "dll", "dylib", "exe", "bin", "class", "jar", "o",
    "a", "db", "sqlite", "sqlite3", "pyc", "pdb", "mp3", "mp4", "mov", "avi", "mkv", "wav", "flac",
    "ogg", "webm", "ttf", "otf", "woff", "woff2", "eot",
];

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct GrepArgs {
    /// Regex or literal pattern (max 4 KiB).
    pattern: String,
    /// Subtree to search — workspace-relative (default workspace root).
    path: Option<String>,
    /// File-glob filter, e.g. `*.rs` or `src/**/*.rs` (default: all
    /// non-ignored files). `*` stays inside one path component.
    glob: Option<String>,
    /// Treat `pattern` as a literal string, not regex.
    literal: Option<bool>,
    /// Case-insensitive matching.
    ignore_case: Option<bool>,
    /// Include hidden files (dotfiles). Default false.
    include_hidden: Option<bool>,
    /// Max hits to list (default 300, max 2000).
    #[schemars(range(min = 1, max = 2000))]
    max_hits: Option<usize>,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "smart_grep",
        schema: schema_for::<GrepArgs>(
            "Regex/literal search across the workspace (ripgrep-engine, in-process). \
             Returns `path:line │ match` lines plus a match summary; respects \
             .gitignore. Prefer this over list_dir for locating code.",
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
    let parsed: GrepArgs = serde_json::from_value(args)
        .map_err(|e| ToolError::Args(format!("smart_grep args: {e}")))?;

    if parsed.pattern.len() > MAX_PATTERN_LEN {
        return Err(ToolError::Args(format!(
            "pattern exceeds {MAX_PATTERN_LEN} bytes"
        )));
    }
    let max_hits = parsed.max_hits.unwrap_or(MAX_HITS);
    if !(1..=MAX_HITS_LIMIT).contains(&max_hits) {
        return Err(ToolError::Args(format!(
            "max_hits must be between 1 and {MAX_HITS_LIMIT}"
        )));
    }

    let base = ctx.resolve(parsed.path.as_deref().unwrap_or("."))?;

    let mut builder = grep_regex::RegexMatcherBuilder::new();
    if parsed.ignore_case.unwrap_or(false) {
        builder.case_insensitive(true);
    }
    if parsed.literal.unwrap_or(false) {
        builder.fixed_strings(true);
    }
    let matcher = builder
        .build(&parsed.pattern)
        .map_err(|e| ToolError::Args(format!("bad pattern: {e}")))?;

    // Proper glob semantics: `*` never crosses `/`, `**` does. A pattern
    // without `/` means "basename match anywhere" — same as `**/<pat>`.
    let glob_matcher = parsed
        .glob
        .as_deref()
        .map(|g| {
            let pat = if g.contains('/') {
                g.to_string()
            } else {
                format!("**/{g}")
            };
            globset::GlobBuilder::new(&pat)
                .literal_separator(true)
                .build()
                .map(|g| g.compile_matcher())
        })
        .transpose()
        .map_err(|e| ToolError::Args(format!("bad glob: {e}")))?;

    let include_hidden = parsed.include_hidden.unwrap_or(false);
    let ws = ctx.root()?.to_path_buf();
    let ctx_cancel = ctx.cancel_flag();

    // Shared stop flag: the timeout arms it so the blocking search actually
    // halts at the next sink call / file — not just stops being awaited.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_task = Arc::clone(&stop);

    let handle = tokio::task::spawn_blocking(move || {
        search_sync(
            &base,
            &ws,
            &matcher,
            glob_matcher.as_ref(),
            include_hidden,
            max_hits,
            &stop_task,
            &ctx_cancel,
        )
    });
    match tokio::time::timeout(TIMEOUT, handle).await {
        Ok(Ok(res)) => res,
        Ok(Err(join_err)) => Err(ToolError::Failed(format!("search task: {join_err}"))),
        Err(_) => {
            stop.store(true, Ordering::Relaxed);
            Err(ToolError::Failed(format!(
                "search exceeded {}s — narrow `path` or `glob`",
                TIMEOUT.as_secs()
            )))
        }
    }
}

fn cancelled(stop: &AtomicBool, ctx_cancel: &Option<Arc<AtomicBool>>) -> bool {
    stop.load(Ordering::Relaxed)
        || ctx_cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
}

fn truncate_line(line: &str) -> String {
    let t = line.trim_end();
    if t.len() <= MAX_LINE_BYTES {
        return t.to_string();
    }
    let mut end = MAX_LINE_BYTES;
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [line truncated]", &t[..end])
}

fn search_sync(
    base: &std::path::Path,
    workspace: &std::path::Path,
    matcher: &RegexMatcher,
    glob_matcher: Option<&globset::GlobMatcher>,
    include_hidden: bool,
    max_hits: usize,
    stop: &AtomicBool,
    ctx_cancel: &Option<Arc<AtomicBool>>,
) -> Result<ToolResult, ToolError> {
    let mut out = String::new();
    let mut total = 0usize; // matches seen; counting stops at the cap
    let mut emitted = 0usize; // lines written to `out`
    let mut scanned = 0usize;
    let mut errors = 0usize;
    let mut skipped = 0usize; // binary-ext / oversize
    let mut bytes = 0usize;
    let mut stopped_early = false;
    let mut was_cancelled = false;

    let mut walker = ignore::WalkBuilder::new(base);
    walker
        .hidden(!include_hidden)
        .git_ignore(true)
        .git_exclude(true)
        .require_git(false)
        .sort_by_file_name(|a, b| a.cmp(b));

    'walk: for result in walker.build() {
        if cancelled(stop, ctx_cancel) {
            was_cancelled = true;
            break;
        }
        let entry = match result {
            Ok(e) => e,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        // Glob matches the workspace-RELATIVE path — an absolute match on
        // `src/**/*.rs` would hinge on where the workspace happens to sit.
        let rel_path = entry.path().strip_prefix(workspace).unwrap_or(entry.path());
        if let Some(m) = glob_matcher {
            if !m.is_match(rel_path) {
                continue;
            }
        }
        if entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| BINARY_EXTS.contains(&e.to_lowercase().as_str()))
        {
            skipped += 1;
            continue;
        }
        if entry
            .metadata()
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            skipped += 1;
            continue;
        }

        scanned += 1;
        let rel = rel_path.to_string_lossy().replace('\\', "/");

        // Shared counting INSIDE the sink: `total` and the shown-budget are
        // live during the scan, so `Ok(false)` aborts this file the moment
        // the cap is hit instead of buffering every hit then truncating.
        let mut hits: Vec<(u64, String)> = Vec::new();
        let mut searcher = SearcherBuilder::new().line_number(true).build();
        let sink = UTF8(|line_no, line| {
            if cancelled(stop, ctx_cancel) {
                return Err(SinkError::error_message("cancelled"));
            }
            total += 1;
            if emitted + hits.len() < max_hits {
                hits.push((line_no, truncate_line(line)));
            }
            Ok(total < max_hits)
        });
        match searcher.search_path(matcher, entry.path(), sink) {
            Ok(_) => {}
            Err(_) if cancelled(stop, ctx_cancel) => {
                was_cancelled = true;
            }
            Err(_) => errors += 1,
        }

        for (line_no, text) in hits {
            let line = format!("{rel}:{line_no} │ {text}\n");
            if bytes + line.len() > MAX_OUTPUT {
                out.push_str("… [5 MiB output cap reached] …\n");
                stopped_early = true;
                break 'walk;
            }
            bytes += line.len();
            emitted += 1;
            out.push_str(&line);
        }
        if was_cancelled || total >= max_hits {
            stopped_early = true;
            break 'walk;
        }
    }

    if total == 0 && !was_cancelled {
        out.push_str("no matches\n");
    } else {
        let plus = if stopped_early || was_cancelled {
            "+"
        } else {
            ""
        };
        let mut summary = format!("── {total}{plus} matches");
        if emitted < total {
            summary.push_str(&format!(", first {emitted} shown"));
        }
        summary.push_str(&format!("; {scanned} files scanned ──\n"));
        out.push_str(&summary);
    }
    if was_cancelled {
        out.push_str("⚠ search cancelled — results are partial\n");
    }
    if errors > 0 {
        out.push_str(&format!(
            "⚠ {errors} files could not be searched — results may be incomplete\n"
        ));
    }
    if skipped > 0 {
        out.push_str(&format!("({skipped} binary/oversize files skipped)\n"));
    }
    Ok(ToolResult::text(out))
}
