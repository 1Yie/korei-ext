//! The skill backend every surface shares.
//!
//! The prompt catalog, `$name` / `/{name}` expansion, the `skill` tool, `/skills`
//! and the composer picker all come through here, so exactly one place decides
//! what a load means (fresh body, shared frame).
//!
//! Caching: the catalog is cached against a change stamp, the body never is. The
//! catalog is charged to every turn, so it is re-rendered only when the skill tree
//! moves; a body is read when used, so an edited skill never serves stale text.

use std::path::{Path, PathBuf};

use super::loader::{self, LoadError, LoadedSkill};
use super::prompt;
use super::scanner::{self, SkillMetadata};

/// How many "did you mean" candidates an unknown-name error offers.
const SUGGESTIONS: usize = 3;
/// How many names the fallback list shows when nothing is close enough.
const FALLBACK_NAMES: usize = 24;

pub struct SkillManager {
    root: PathBuf,
    /// `(stamp, rendered)` — the catalog and the tree state it was rendered
    /// from.
    catalog: Option<(u64, String)>,
}

impl SkillManager {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            catalog: None,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The system-prompt catalog. Returns the block only when it changed since
    /// the last call, so the per-turn caller can skip rewriting the prompt
    /// region (and the scan) entirely.
    pub fn refresh(&mut self) -> Option<&str> {
        let stamp = scanner::skills_stamp(&self.root);
        if self.catalog.as_ref().map(|(s, _)| *s) == Some(stamp) {
            return None;
        }
        let block = prompt::catalog_lines(
            &scanner::scan_all_skills(&self.root),
            prompt::CATALOG_LIMIT,
            prompt::DESC_CHARS,
        );
        self.catalog = Some((stamp, block));
        self.catalog.as_ref().map(|(_, b)| b.as_str())
    }

    /// The catalog as of now, rendering it if this is the first call.
    pub fn catalog(&mut self) -> &str {
        if self.catalog.is_none() {
            self.refresh();
        }
        self.catalog.as_ref().map(|(_, b)| b.as_str()).unwrap_or("")
    }

    /// Every installed skill (metadata only) — the pickers and `list`.
    pub fn list(&self) -> Vec<SkillMetadata> {
        scanner::scan_all_skills(&self.root)
    }

    /// Load one skill with free-form text arguments (`$name …`).
    pub fn load(&self, name: &str, arguments: Option<&str>) -> Result<LoadedSkill, String> {
        self.resolve(name, |meta| loader::load(meta, arguments))
    }

    /// Load one skill with a structured `args` object, validated against the
    /// manifest's declarations.
    pub fn load_named(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<LoadedSkill, String> {
        self.resolve(name, |meta| loader::load_named(meta, arguments))
    }

    /// Shared lookup + error shaping: unknown names get suggestions, argument
    /// mismatches pass the loader's own message through.
    fn resolve(
        &self,
        name: &str,
        load: impl FnOnce(&SkillMetadata) -> Result<LoadedSkill, LoadError>,
    ) -> Result<LoadedSkill, String> {
        let want = name.trim();
        if want.is_empty() {
            return Err("`skill` needs a name (or `list: true` for the catalog)".into());
        }
        let all = self.list();
        let Some(meta) = all.iter().find(|s| s.name.eq_ignore_ascii_case(want)) else {
            return Err(unknown_message(want, &all));
        };
        load(meta).map_err(|e| match e {
            LoadError::Unknown(_) => unknown_message(want, &all),
            LoadError::Io(m) | LoadError::Args(m) => m,
        })
    }

    /// The pre-rendered catalog for the two audiences that show it verbatim:
    /// `skill {"list": true}` and `/skills`.
    pub fn catalog_listing(&self) -> String {
        let skills = self.list();
        if skills.is_empty() {
            return "No skills installed — a skill is \
                    `<workspace>/.agents/skills/<name>/SKILL.md`."
                .to_string();
        }
        let lines: Vec<String> = skills
            .iter()
            .map(|s| prompt::line(s, prompt::DESC_CHARS))
            .collect();
        // One header for both audiences: the user reading `/skills` needs the
        // invocation form, the model needs to know a name is a `skill` arg.
        format!(
            "{} skills — `/name` or `$name` to invoke, `skill {{\"name\": …}}` to load:\n- {}",
            skills.len(),
            lines.join("\n- ")
        )
    }
}

/// What the agent sees after guessing a name that does not exist: the closest
/// installed names when there are any (a typo like `frontned` should land on
/// `frontend`, not on an arbitrary list), otherwise what is installed.
fn unknown_message(want: &str, all: &[SkillMetadata]) -> String {
    let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
    let close = suggest(names.iter().copied(), want, SUGGESTIONS);
    if !close.is_empty() {
        return format!(
            "unknown skill `{want}` — did you mean: {}? (`list: true` shows all {}).",
            close.join(", "),
            all.len()
        );
    }
    if names.is_empty() {
        return format!("unknown skill `{want}` — no skills are installed");
    }
    let more = names.len().saturating_sub(FALLBACK_NAMES);
    let shown = &names[..names.len().min(FALLBACK_NAMES)];
    format!(
        "unknown skill `{want}` — available: {}{}",
        shown.join(", "),
        if more > 0 {
            format!(" …(+{more} more)")
        } else {
            String::new()
        }
    )
}

/// Closest names to a miss, best first. Edit distance alone ranks `gsap-core`
/// and `gsap-utils` equally for `gsap`; a prefix/substring bonus puts the
/// family head first, which is what a guess usually means.
pub fn suggest<'a>(
    names: impl IntoIterator<Item = &'a str>,
    want: &str,
    limit: usize,
) -> Vec<String> {
    let want_l = want.to_lowercase();
    let mut scored: Vec<(f64, &str)> = names
        .into_iter()
        .map(|n| {
            let lower = n.to_lowercase();
            let score = if lower.starts_with(&want_l) || want_l.starts_with(&lower) {
                1.0
            } else if lower.contains(&want_l) || want_l.contains(&lower) {
                0.8
            } else {
                strsim::normalized_levenshtein(&want_l, &lower)
            };
            (score, n)
        })
        .filter(|(score, _)| *score >= 0.7)
        .collect();
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.cmp(b.1))
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(_, n)| n.to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_skill(root: &Path, name: &str, desc: &str, body: &str) {
        let dir = root.join(".agents/skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {desc}\n---\n\n{body}\n"),
        )
        .unwrap();
    }

    #[test]
    fn catalog_renders_once_per_change() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "one", "first", "Body one.");
        let mut mgr = SkillManager::new(dir.path());

        // First call renders; an unchanged tree must not re-render.
        assert!(mgr.refresh().is_some());
        assert!(mgr.refresh().is_none(), "an unchanged tree re-rendered");
        assert!(mgr.catalog().contains("`one`"));

        std::thread::sleep(std::time::Duration::from_millis(10));
        write_skill(dir.path(), "two", "second", "Body two.");
        let block = mgr.refresh().expect("new skill must re-render");
        assert!(block.contains("`two`"), "{block}");
        assert!(mgr.refresh().is_none());
    }

    /// The load path must not depend on the catalog being rendered first — the
    /// tool calls it cold, with no session prompt behind it.
    #[test]
    fn load_works_without_a_prior_catalog_render() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "review", "code review", "Look for bugs.");
        let mgr = SkillManager::new(dir.path());
        let loaded = mgr
            .load("REVIEW", Some("src/x.rs"))
            .expect("case-insensitive");
        assert_eq!(loaded.body, "Look for bugs.");
        assert_eq!(
            loaded.arguments,
            Some(loader::SkillArguments::Text("src/x.rs".into()))
        );
    }

    #[test]
    fn unknown_names_suggest_the_closest_installed_ones() {
        let names = ["frontend", "frontend-review", "rust-review", "gsap-core"];
        assert_eq!(suggest(names, "frontned", 3), vec!["frontend"]);
        // A prefix guess should surface the whole family, head first.
        assert_eq!(
            suggest(names, "front", 3),
            vec!["frontend", "frontend-review"]
        );
        assert!(suggest(names, "totally-unrelated-thing", 3).is_empty());

        // Names are unique per run: `scan_all_skills` also reads `$HOME`, so a
        // generic name ("frontend") could collide with a real global skill and
        // make the ranking assertions machine-dependent.
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "husk-test-frontend", "ui work", "Body.");
        let mgr = SkillManager::new(dir.path());
        let err = mgr.load("husk-test-frontned", None).expect_err("typo");
        assert!(err.contains("did you mean: husk-test-frontend"), "{err}");

        // Nothing close: the reply still has to say what exists.
        let err = mgr
            .load("zzqq-nothing-remotely-similar", None)
            .expect_err("no close match");
        assert!(!err.contains("did you mean"), "{err}");
        assert!(
            err.contains("available:") || err.contains("no skills are installed"),
            "{err}"
        );
        assert!(
            mgr.load("  ", None).is_err(),
            "blank name is an argument error"
        );
    }

    #[test]
    fn listing_reports_the_catalog_for_the_pickers() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "alpha", "first", "A.");
        let mgr = SkillManager::new(dir.path());
        // `scan_all_skills` also reads the developer's `$HOME`, so the count is
        // machine-dependent — assert on our entries, not the total.
        assert!(mgr.list().iter().any(|s| s.name == "alpha"));
        let listing = mgr.catalog_listing();
        assert!(
            listing.contains("skills — `/name` or `$name` to invoke"),
            "{listing}"
        );
        assert!(
            listing.contains("- `alpha` — first (workspace)"),
            "{listing}"
        );

        // The empty case is asserted on the workspace-only scan: a manager
        // pointing at a bare directory still lists the machine's global skills,
        // which is the point of the full scan.
        let bare = scanner::scan_skills(&dir.path().join("nope"));
        assert!(bare.is_empty(), "{bare:?}");
        assert!(prompt::catalog_lines(&bare, 40, 120).contains("No skills installed"));
    }
}
