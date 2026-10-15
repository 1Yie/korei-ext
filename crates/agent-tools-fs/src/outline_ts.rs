//! `outline_ts.rs` — tree-sitter outline extractor, behind
//! `feature = "tree-sitter"` (grammar crates pull a C toolchain — off the
//! default build; `fs_read`'s heuristic stays the fallback).
//!
//! Contract: returns `Some(items)` when the file extension maps to a known
//! grammar AND parsing yields at least one named top-level item — the
//! caller falls back to the regex outline on `None`, so an exotic parse
//! failure never degrades into an empty outline.
//!
//! Node coverage is per-language (the query lists the named top-level
//! definition kinds); depth-1 nodes only — nested impl methods etc. stay
//! out, matching the heuristic's top-of-file skeleton shape.

#![cfg(feature = "tree-sitter")]

use tree_sitter::{Language, Parser};

fn language_for(path: &str) -> Option<Language> {
    let ext = path.rsplit('.').next()?;
    Some(match ext {
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        "py" | "pyi" => tree_sitter_python::LANGUAGE.into(),
        "ts" | "mts" | "cts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "js" | "jsx" | "mjs" | "cjs" => tree_sitter_javascript::LANGUAGE.into(),
        _ => return None,
    })
}

/// Node kinds that count as outline items per language family — these are
/// the named definitions a reader scans a file for.
const RUST_KINDS: &[&str] = &[
    "function_item",
    "struct_item",
    "enum_item",
    "trait_item",
    "impl_item",
    "mod_item",
    "type_item",
    "const_item",
    "static_item",
    "macro_definition",
];
const PY_KINDS: &[&str] = &[
    "function_definition",
    "class_definition",
    "decorated_definition",
];
const JS_TS_KINDS: &[&str] = &[
    "function_declaration",
    "function_signature",
    "class_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "export_statement",
    "lexical_declaration",
    "abstract_class_declaration",
    "module",
];

fn kinds_for(path: &str) -> &'static [&'static str] {
    match path.rsplit('.').next().unwrap_or("") {
        "rs" => RUST_KINDS,
        "py" | "pyi" => PY_KINDS,
        _ => JS_TS_KINDS,
    }
}

/// `Some(outline)` when tree-sitter can produce one — `None` ⇒ caller
/// falls back to the heuristic extractor.
pub fn outline_treesitter(path: &str, content: &str) -> Option<String> {
    let lang = language_for(path)?;
    let mut parser = Parser::new();
    parser.set_language(&lang).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    let kinds = kinds_for(path);

    let mut items: Vec<String> = Vec::new();
    // Top-level named definitions only — iterate root children; for
    // `export_statement`/`lexical_declaration`/`decorated_definition`
    // unwrap one level to the inner definition node.
    let mut cursor = root.walk();
    for node in root.children(&mut cursor) {
        let inner = if matches!(
            node.kind(),
            "export_statement"
                | "lexical_declaration"
                | "decorated_definition"
                | "variable_declaration"
                | "ambient_declaration"
        ) {
            // Wrapper node: text (and line) come from the outer node so the
            // `export`/decorator prefix survives; kind comes from the inner.
            node.named_child(0).unwrap_or(node)
        } else {
            node
        };
        if !kinds.contains(&inner.kind()) {
            continue;
        }
        // Signature = up to the body boundary: first `{` (inclusive) or a
        // line ending in `:`/`;`/`}`, collapsed to one line like the
        // heuristic emits.
        let text = node.utf8_text(content.as_bytes()).ok()?;
        let mut sig = String::new();
        let mut iter = text.lines();
        let first = iter.next().unwrap_or("").trim();
        // One-line node → the whole line (`fn bar() {}`, `interface X { … }`
        // keeps its body); multi-line signature → absorb until the body
        // boundary.
        if first.contains('{')
            || first.ends_with(':')
            || first.ends_with(';')
            || first.ends_with('}')
        {
            sig.push_str(first);
        } else {
            sig.push_str(first);
            sig.push(' ');
            for l in iter {
                let lt = l.trim();
                if let Some((head, _)) = lt.split_once('{') {
                    sig.push_str(head.trim_end());
                    sig.push_str(" {");
                    break;
                }
                sig.push_str(lt);
                if lt.ends_with(':') || lt.ends_with(';') || lt.ends_with('}') {
                    break;
                }
                sig.push(' ');
            }
        }
        let line = node.start_position().row + 1;
        // Doc comment directly above — same look-back as the heuristic.
        if line > 1 {
            if let Some(prev) = content.lines().nth(line - 2).map(str::trim) {
                if prev.starts_with("///")
                    || prev.starts_with("**")
                    || prev.starts_with('*')
                    || prev.starts_with("/**")
                    || (prev.starts_with("//") && !prev.starts_with("////"))
                {
                    items.push(format!("{:>4} │ {}", line - 1, prev));
                }
            }
        }
        items.push(format!("{:>4} │ {}", line, sig.trim_end()));
        if items.len() >= 200 {
            break;
        }
    }
    if items.is_empty() {
        return None;
    }
    let mut out = String::new();
    for it in items {
        out.push_str(&it);
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_outline_finds_items() {
        let src = "fn helper() {}\n\npub struct S { x: i32 }\n\npub fn main() {}\n";
        let out = outline_treesitter("a.rs", src).unwrap();
        assert!(out.contains("helper"), "{out}");
        assert!(out.contains("struct S"), "{out}");
        assert!(out.contains("main"), "{out}");
    }

    #[test]
    fn unknown_ext_returns_none() {
        assert!(outline_treesitter("a.xyz", "fn f() {}").is_none());
    }
}
