//! `smart_grep` — in-process regex search via `grep-searcher`.
//!
//! Bounded observation: match cap (hard-limited), 5 MiB output cap, 8 MiB
//! file cap, 16 KiB line cap, 20 s wall-clock. The timeout arms a shared
//! cancel flag the sink + walker poll — `spawn_blocking` work actually
//! stops instead of just being detached. Scope-annotation ([inside impl X])
//! is a Phase-2 upgrade once tree-sitter grammars land.
//!
//! `context` (the `grep -C` capability) is native here: the searcher reports
//! before/after lines through the same sink, so a hit and its surroundings
//! cost one call and one pass over the file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use grep_regex::RegexMatcher;
use grep_searcher::SinkError;
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use serde::Deserialize;

use agent_capabilities::{PathScope, WorkspaceCtx};
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// Stdout cap per truncation table.
const MAX_OUTPUT: usize = 5 * 1024 * 1024;
/// Default match cap before folding.
const MAX_HITS: usize = 300;
/// Hard ceiling on `max_hits` — resource control isn't the model's call.
const MAX_HITS_LIMIT: usize = 2_000;
/// Hard ceiling on `context` — the same reasoning as `max_hits`: one call
/// must stay bounded however the model spells it.
const MAX_CONTEXT: usize = 10;
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
    /// Subtree to search — workspace-relative (default workspace root), or an
    /// absolute path inside a linked workspace.
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
    /// Lines shown before and after each hit, like `grep -C` (default 0,
    /// max 10). Returns a hit with its surroundings in one call, which is
    /// what `grep -A/-B/-C` through bash is usually reaching for.
    context: Option<usize>,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "smart_grep",
        schema: schema_for::<GrepArgs>(
            "Search file contents across the workspace (in-process ripgrep engine, respects \
             .gitignore) — this is the search tool for anything inside the workspace, instead \
             of `grep` / `rg` / `find … | xargs grep` through bash. Returns `path:line │ text` \
             per hit plus a summary that says when hits were capped or files skipped. \
             `context: N` adds N lines before and after each hit (like `grep -C N`, max 10), so \
             a hit and its surroundings come back in ONE call. `path` narrows the subtree, \
             `glob` the file names. Several independent searches → ONE `batch_execute`. \
             Inside a linked workspace, hits are printed as absolute paths. Ignored trees \
             (node_modules, target) and paths outside the workspace and its linked \
             workspaces are bash's job.",
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

    let scope = ctx.scope_of(parsed.path.as_deref().unwrap_or("."))?;

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
    let context = parsed.context.unwrap_or(0).min(MAX_CONTEXT);
    // Globs match relative to the root the search sits in. Hits inside the
    // workspace print workspace-relative paths; hits in a linked workspace
    // print absolute ones, since a relative path always means the workspace.
    let (base, glob_root, absolute) = match scope {
        PathScope::Workspace(p) => (p, ctx.root()?.to_path_buf(), false),
        PathScope::Linked { path, root, .. } => (path, root, true),
        PathScope::Outside(_) => {
            return Err(ToolError::PathEscape(
                parsed.path.clone().unwrap_or_else(|| ".".into()),
            ))
        }
    };
    let ctx_cancel = ctx.cancel_flag();

    // Shared stop flag: the timeout arms it so the blocking search actually
    // halts at the next sink call / file — not just stops being awaited.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_task = Arc::clone(&stop);

    let handle = tokio::task::spawn_blocking(move || {
        search_sync(
            &base,
            &glob_root,
            absolute,
            &matcher,
            glob_matcher.as_ref(),
            include_hidden,
            context,
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

/// One rendered line from the searcher: a hit, a context line, or the `--`
/// break between two non-adjacent groups.
enum Line {
    Match(u64, String),
    Context(u64, String),
    Break,
}

/// Collects one file's hits — and, with `context`, the lines around them.
///
/// Returning `false` from a sink method stops the search: that is how the
/// match cap and the output budget abort a file early instead of buffering
/// everything and truncating afterwards. The budget is per file, so one huge
/// file cannot spend the whole output before the next one is reached.
struct Collector<'a> {
    total: &'a mut usize,
    max_hits: usize,
    context: usize,
    budget: usize,
    lines: &'a mut Vec<Line>,
    stop: &'a AtomicBool,
    ctx_cancel: &'a Option<Arc<AtomicBool>>,
}

impl Collector<'_> {
    /// Record a line unless the output budget is spent.
    fn push(&mut self, line: Line, len: usize) -> bool {
        if self.budget < len {
            return false;
        }
        self.budget -= len;
        self.lines.push(line);
        true
    }
}

impl Sink for Collector<'_> {
    type Error = std::io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        if cancelled(self.stop, self.ctx_cancel) {
            return Err(SinkError::error_message("cancelled"));
        }
        *self.total += 1;
        let text = text_of(mat.bytes());
        let len = text.len();
        let keep = self.push(Line::Match(mat.line_number().unwrap_or(0), text), len);
        Ok(keep && *self.total < self.max_hits)
    }

    fn context(
        &mut self,
        _searcher: &Searcher,
        ctx: &SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        if self.context == 0 || cancelled(self.stop, self.ctx_cancel) {
            return Ok(true);
        }
        let text = text_of(ctx.bytes());
        let len = text.len();
        Ok(self.push(Line::Context(ctx.line_number().unwrap_or(0), text), len))
    }

    fn context_break(&mut self, _searcher: &Searcher) -> Result<bool, Self::Error> {
        // A break before the first line would render a leading `--`.
        if self.context > 0 && !self.lines.is_empty() {
            self.lines.push(Line::Break);
        }
        Ok(true)
    }
}

/// A sink line's text: lossy UTF-8, right-trimmed, per-line capped.
fn text_of(bytes: &[u8]) -> String {
    truncate_line(&String::from_utf8_lossy(bytes))
}

fn search_sync(
    base: &std::path::Path,
    glob_root: &std::path::Path,
    absolute: bool,
    matcher: &RegexMatcher,
    glob_matcher: Option<&globset::GlobMatcher>,
    include_hidden: bool,
    context: usize,
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

        // Glob matches the root-RELATIVE path — an absolute match on
        // `src/**/*.rs` would hinge on where the workspace happens to sit.
        let rel_path = entry.path().strip_prefix(glob_root).unwrap_or(entry.path());
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
        let shown = if absolute { entry.path() } else { rel_path };
        let rel = shown.to_string_lossy().replace('\\', "/");

        // Counting and the output budget live INSIDE the sink, so `Ok(false)`
        // aborts this file the moment either runs out instead of buffering
        // every hit and truncating afterwards.
        let mut searcher = SearcherBuilder::new()
            .line_number(true)
            .before_context(context)
            .after_context(context)
            .build();
        let mut file_total = 0usize;
        let mut lines: Vec<Line> = Vec::new();
        let collected = Collector {
            total: &mut file_total,
            max_hits,
            context,
            budget: MAX_OUTPUT,
            lines: &mut lines,
            stop,
            ctx_cancel,
        };
        match searcher.search_path(matcher, entry.path(), collected) {
            Ok(()) => {}
            Err(_) if cancelled(stop, ctx_cancel) => was_cancelled = true,
            Err(_) => errors += 1,
        }
        total += file_total;

        for line in lines {
            let (is_match, rendered) = match line {
                Line::Match(n, text) => (true, format!("{rel}:{n} │ {text}\n")),
                Line::Context(n, text) => (false, format!("{rel}-{n} │ {text}\n")),
                Line::Break => (false, "--\n".to_string()),
            };
            if bytes + rendered.len() > MAX_OUTPUT {
                out.push_str("… [5 MiB output cap reached] …\n");
                stopped_early = true;
                break 'walk;
            }
            bytes += rendered.len();
            if is_match {
                emitted += 1;
            }
            out.push_str(&rendered);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the real search over an on-disk tree. `context` is the only knob
    /// under test; every other bound is the default.
    fn search(root: &std::path::Path, pattern: &str, context: usize) -> String {
        let matcher = grep_regex::RegexMatcherBuilder::new()
            .build(pattern)
            .expect("pattern");
        let stop = AtomicBool::new(false);
        search_sync(
            root, root, false, &matcher, None, false, context, MAX_HITS, &stop, &None,
        )
        .expect("search")
        .content
    }

    fn tree(lines: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let body: String = (1..=lines).map(|i| format!("line{i}\n")).collect();
        std::fs::write(dir.path().join("a.txt"), body).unwrap();
        dir
    }

    /// Without `context` the output is exactly what it was before the option
    /// existed: one `path:line │ text` row per hit.
    #[test]
    fn no_context_keeps_the_flat_hit_list() {
        let dir = tree(20);
        let out = search(dir.path(), "line5$", 0);
        assert!(out.starts_with("a.txt:5 │ line5\n"), "{out}");
        assert!(!out.contains("a.txt-"), "{out}");
        assert!(out.contains("── 1 matches"), "{out}");
    }

    /// `context` surrounds the hit the way `grep -C` does: hits keep `:`,
    /// neighbours get `-`.
    #[test]
    fn context_surrounds_the_hit_with_grep_marks() {
        let dir = tree(20);
        let out = search(dir.path(), "line10$", 2);
        let want = "a.txt-8 │ line8\na.txt-9 │ line9\na.txt:10 │ line10\n\
                    a.txt-11 │ line11\na.txt-12 │ line12\n";
        assert!(out.starts_with(want), "{out}");
        assert!(out.contains("── 1 matches"), "{out}");
    }

    /// Overlapping groups merge into one block instead of repeating lines
    /// around a `--` break; distant groups keep the break.
    #[test]
    fn adjacent_hits_merge_and_distant_ones_break() {
        let dir = tree(30);
        let out = search(dir.path(), "line(10|12)$", 1);
        assert!(
            !out.contains("--\n"),
            "overlapping groups must merge:\n{out}"
        );
        let out = search(dir.path(), "line(2|25)$", 1);
        assert_eq!(out.matches("--\n").count(), 1, "{out}");
    }

    /// A search in a linked workspace prints absolute paths (a relative one
    /// would name the workspace) while the glob still matches relative to
    /// that root.
    #[test]
    fn linked_root_hits_are_absolute_and_globbed_relative_to_it() {
        let dir = tree(3);
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/b.rs"), "line2\n").unwrap();
        let matcher = grep_regex::RegexMatcherBuilder::new().build("line2$").unwrap();
        let glob = globset::Glob::new("src/*.rs").unwrap().compile_matcher();
        let stop = AtomicBool::new(false);
        let out = search_sync(&root, &root, true, &matcher, Some(&glob), false, 0, MAX_HITS, &stop, &None)
            .unwrap()
            .content;
        assert!(out.starts_with(&format!("{}/src/b.rs:1 │ line2\n", root.display())), "{out}");
        assert!(out.contains("── 1 matches"), "{out}");
    }
}
