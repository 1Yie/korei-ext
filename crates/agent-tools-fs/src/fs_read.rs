//! `smart_read` — structured file reads that never `cat`.
//!
//! Three modes (native-tools.md): `outline` (signature skeleton — a regex-
//! based Phase-1 extractor; tree-sitter grammars land with Phase 2),
//! `range` (numbered lines + `content_hash`), `search` (matching lines).
//!
//! Every response carries `content_hash` — xxh3 of the **full file** — so
//! `fuzzy_patch` can detect drift between read and write. (Full-file hash,
//! not window: the patcher verifies nothing else changed anywhere.)

use std::fmt::Write;
use std::sync::Arc;

use futures::FutureExt;
use serde::Deserialize;
use xxhash_rust::xxh3::xxh3_64;

use agent_capabilities::WorkspaceCtx;
use agent_tool::{schema_for, Args, ToolError, ToolResult, ToolSpec};

/// `range` mode hard cap per the truncation table (1000 lines).
const MAX_RANGE_LINES: usize = 1000;
/// `search` mode cap on matching lines returned.
const MAX_SEARCH_HITS: usize = 200;
/// `outline` mode cap before truncation.
const MAX_OUTLINE_ITEMS: usize = 400;
/// Max extra lines a multi-line signature may absorb (`fn (\n args…\n) ->`).
const MAX_SIG_SPAN: usize = 4;

#[derive(Debug, serde::Serialize, Deserialize, schemars::JsonSchema)]
struct SmartReadArgs {
    /// Workspace-relative path to the file.
    path: String,
    /// `outline` | `range` | `search` (default `range` when start/end given).
    mode: Option<String>,
    /// 1-based first line for `range` mode.
    start: Option<usize>,
    /// 1-based last line for `range` mode (inclusive).
    end: Option<usize>,
    /// Substring or regex pattern for `search` mode.
    pattern: Option<String>,
}

pub fn spec<C: WorkspaceCtx>() -> ToolSpec<C> {
    ToolSpec {
        name: "smart_read",
        schema: schema_for::<SmartReadArgs>(
            "Read ONE file structurally: `outline` returns a signature skeleton \
             (~100 tokens for large files), `range` returns numbered lines with \
             a content_hash for patch anchoring, `search` returns matching \
             lines with numbers. Prefer outline→range over dumping whole files. \
             When you already know 2+ independent files/ranges to inspect, do \
             NOT call smart_read repeatedly — send them as ONE batch_execute. \
             Call smart_read directly only for a single read, or when the next \
             read's target depends on this read's result.",
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
    let parsed: SmartReadArgs = serde_json::from_value(args)
        .map_err(|e| ToolError::Args(format!("smart_read args: {e}")))?;
    let path = ctx.resolve(&parsed.path)?;
    let content = tokio::fs::read_to_string(&path).await?;
    let hash = format!("{:016x}", xxh3_64(content.as_bytes()));

    let mode = parsed.mode.as_deref().unwrap_or_else(|| {
        if parsed.pattern.is_some() {
            "search"
        } else {
            "range"
        }
    });

    // Collect once — O(1) random access for range + outline's look-back and
    // signature-span peeking (no per-line `content.lines().nth()` rescan).
    let lines: Vec<&str> = content.lines().collect();

    match mode {
        "outline" => Ok(ToolResult::text(outline(
            &parsed.path,
            &content,
            &lines,
            &hash,
        ))),
        "search" => {
            let pat = parsed
                .pattern
                .as_deref()
                .ok_or_else(|| ToolError::Args("search mode requires 'pattern'".into()))?;
            Ok(ToolResult::text(search(&parsed.path, &lines, pat, &hash)))
        }
        _ => Ok(ToolResult::text(range(
            &parsed.path,
            &lines,
            parsed.start,
            parsed.end,
            &hash,
        ))),
    }
}

fn header(path: &str, hash: &str) -> String {
    format!("{path}  (content_hash: {hash})\n")
}

/// `range` mode: numbered `NNNN │ code` lines, hard cap + continuation hint.
/// Guards empty files and out-of-bounds slices — `start`/`end` clamped to
/// `1..=total`, `s > e` returns a friendly error rather than panicking.
fn range(
    path: &str,
    lines: &[&str],
    start: Option<usize>,
    end: Option<usize>,
    hash: &str,
) -> String {
    let total = lines.len();
    let mut out = header(path, hash);
    if total == 0 {
        out.push_str("(empty file)\n");
        return out;
    }
    let s = start.unwrap_or(1).max(1).min(total + 1); // 1..=total, allow past-EOF msg
    if s > total {
        let _ = writeln!(
            out,
            "{path}: {total} lines total; requested start {s} is past EOF"
        );
        return out;
    }
    let req_end = end.unwrap_or(total).min(total);
    if req_end < s {
        let _ = writeln!(out, "invalid range: start ({s}) > end ({req_end})");
        return out;
    }
    let e = req_end.min(s + MAX_RANGE_LINES - 1);
    for (i, line) in lines[s - 1..e].iter().enumerate() {
        let _ = writeln!(out, "{:>4} │ {}", s + i, line);
    }
    if e < total {
        let _ = writeln!(
            out,
            "… [truncated — {total} lines total, continue with start={}] …",
            e + 1
        );
    }
    out
}

/// `search` mode: matching lines with numbers, capped.
fn search(path: &str, lines: &[&str], pattern: &str, hash: &str) -> String {
    let re = regex::Regex::new(pattern).ok();
    let mut out = header(path, hash);
    let mut hits = 0usize;
    for (i, line) in lines.iter().enumerate() {
        let matched = match &re {
            Some(r) => r.is_match(line),
            None => line.contains(pattern),
        };
        if matched {
            hits += 1;
            if hits <= MAX_SEARCH_HITS {
                let _ = writeln!(out, "{:>4} │ {}", i + 1, line);
            }
        }
    }
    if hits == 0 {
        out.push_str("no matches\n");
    } else if hits > MAX_SEARCH_HITS {
        let _ = writeln!(
            out,
            "… [{hits} matches total, first {MAX_SEARCH_HITS} shown] …"
        );
    }
    out
}

/// `outline` mode: signature skeleton. O(n) — indexes into the pre-collected
/// `lines` slice for the doc-comment look-back and multi-line signature span,
/// never rescans `content`. Absorbs up to `MAX_SIG_SPAN` continuation lines
/// for a signature that doesn't end `{`/`;` on its first line.
fn outline(path: &str, content: &str, lines: &[&str], hash: &str) -> String {
    let mut out = header(path, hash);
    // Tree-sitter path (feature-gated): AST-precise when the grammar is
    // compiled in; `None` — unknown ext, parse failure, no items — falls
    // through to the heuristic below.
    #[cfg(not(feature = "tree-sitter"))]
    let _ = content;
    #[cfg(feature = "tree-sitter")]
    if let Some(ts) = crate::outline_ts::outline_treesitter(path, content) {
        out.push_str(&ts);
        return out;
    }
    let mut emitted = 0usize;
    let total = lines.len();
    let mut i = 0;
    while i < total {
        let t = lines[i].trim_end();
        if looks_like_signature(t) {
            // Attach a doc comment directly above (O(1) index — not nth()).
            if i > 0 {
                let prev = lines[i - 1].trim();
                if prev.starts_with("///")
                    || prev.starts_with("**")
                    || prev.starts_with('*')
                    || (prev.starts_with("//") && !prev.starts_with("////"))
                {
                    let _ = writeln!(out, "{:>4} │ {}", i, prev);
                }
            }
            // Absorb continuation lines for a signature that doesn't close on
            // line 1 — `pub async fn f(\n    &self,\n    x: T,\n) -> R {`.
            let mut end = i;
            let mut sig = t.to_string();
            while end + 1 < total
                && end - i < MAX_SIG_SPAN
                && !sig.trim_end().ends_with('{')
                && !sig.trim_end().ends_with(';')
                && !sig.trim_end().ends_with('}')
            {
                end += 1;
                sig.push(' ');
                sig.push_str(lines[end].trim());
            }
            let _ = writeln!(out, "{:>4} │ {}", i + 1, sig);
            emitted += 1;
            i = end; // skip the absorbed continuation lines
            if emitted >= MAX_OUTLINE_ITEMS {
                out.push_str("… [outline truncated] …\n");
                break;
            }
        }
        i += 1;
    }
    if emitted == 0 {
        out.push_str("(no recognizable signatures — use mode=range)\n");
    }
    out
}

/// Phase-1 heuristic: does this line open a named item?
fn looks_like_signature(trimmed: &str) -> bool {
    let t = trimmed.trim_start();
    if t.starts_with("//") || (t.starts_with('#') && !t.starts_with("#[")) {
        return false;
    }
    const PREFIXES: &[&str] = &[
        "pub fn",
        "pub async fn",
        "async fn",
        "fn ",
        "pub struct",
        "struct ",
        "pub enum",
        "enum ",
        "pub trait",
        "trait ",
        "impl ",
        "pub impl",
        "pub const",
        "pub static",
        "pub type",
        "pub mod",
        "mod ",
        // Python / Ruby / Elixir
        "def ",
        "class ",
        "async def ",
        // JS / TypeScript
        "function ",
        "const ",
        "export ",
        "interface ",
        "type ",
        // Go / Swift / Kotlin
        "func ",
        "func(",
        "fun ",
        "var ",
        "val ",
        "package ",
        "extension ",
        "protocol ",
        "data class",
        "object ",
        // Java / C# / C-family
        "public ",
        "private ",
        "protected ",
        "static ",
        "final ",
        "abstract ",
        "synchronized ",
        "native ",
        "typedef ",
        "namespace ",
        "module ",
    ];
    PREFIXES.iter().any(|p| t.starts_with(p))
        || t.starts_with("#[")
        // impl blocks without `pub`: `impl Foo {`, `impl Trait for Foo`
        || (t.starts_with("impl") && t.contains('{'))
}

// `regex` isn't a workspace dep — use grep-regex's matcher or plain substring.
// Kept tiny: try `grep_regex` through a thin shim so `search` mode gets real
// regex without pulling another crate into the dep graph.
mod regex {
    /// Minimal wrapper: compile as regex, expose `is_match`.
    pub struct Regex(grep_regex::RegexMatcher);

    impl Regex {
        pub fn new(pat: &str) -> Result<Self, ()> {
            grep_regex::RegexMatcher::new(pat)
                .map(Regex)
                .map_err(|_| ())
        }

        pub fn is_match(&self, line: &str) -> bool {
            use grep_matcher::Matcher;
            self.0.is_match(line.as_bytes()).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<&str> {
        s.lines().collect()
    }

    #[test]
    fn range_empty_file_is_friendly() {
        let out = range("e.rs", &lines(""), Some(1), Some(10), "h");
        assert!(out.contains("(empty file)"));
    }

    #[test]
    fn range_past_eof_is_friendly() {
        let out = range("t.rs", &lines("a\nb\nc"), Some(5), Some(10), "h");
        assert!(out.contains("past EOF"));
    }

    #[test]
    fn range_start_gt_end_is_friendly() {
        let out = range("t.rs", &lines("a\nb\nc"), Some(3), Some(1), "h");
        assert!(out.contains("invalid range"));
    }

    #[test]
    fn outline_multiline_signature_is_absorbed() {
        let code = "/// Service entry\npub async fn bootstrap(\n    port: u16,\n    host: &str,\n) -> anyhow::Result<()> {\n    body()\n}\n";
        let out = outline("s.rs", code, &lines(code), "h");
        assert!(out.contains("/// Service entry"));
        assert!(out
            .contains("pub async fn bootstrap( port: u16, host: &str, ) -> anyhow::Result<()> {"));
    }

    #[test]
    fn outline_single_line_signature_unchanged() {
        let code = "fn foo() {\n    x()\n}\nfn bar() {}\n";
        let out = outline("s.rs", code, &lines(code), "h");
        assert!(out.contains("fn foo() {"));
        assert!(out.contains("fn bar() {}"));
    }

    /// The prefix table must cover the mainstream languages — the outline
    /// is a heuristic skeleton, but a Go/Python/Java file that renders
    /// empty is a broken feature, not a soft one.
    #[test]
    fn outline_catches_mainstream_languages() {
        let go = "package main\n\nfunc serve(port int) error {\n\treturn nil\n}\n\ntype Config struct {\n\tPort int\n}\n";
        let out = outline("s.go", go, &lines(go), "h");
        assert!(out.contains("func serve"), "{out}");
        assert!(out.contains("type Config"), "{out}");

        let py = "class App:\n    pass\n\nasync def main():\n    pass\n";
        let out = outline("s.py", py, &lines(py), "h");
        assert!(out.contains("class App"), "{out}");
        assert!(out.contains("async def main"), "{out}");

        let java =
            "public class Main {\n    public static void run() {}\n}\nfinal class Const {}\n";
        let out = outline("s.java", java, &lines(java), "h");
        assert!(out.contains("public class Main"), "{out}");
        assert!(out.contains("final class Const"), "{out}");

        let ts = "export interface Opt { x: number }\ntype Id = string\n";
        let out = outline("s.ts", ts, &lines(ts), "h");
        assert!(out.contains("export interface Opt"), "{out}");

        let kt = "data class User(val name: String)\nfun main() {}\n";
        let out = outline("s.kt", kt, &lines(kt), "h");
        assert!(out.contains("data class User"), "{out}");
        assert!(out.contains("fun main"), "{out}");
    }
}
