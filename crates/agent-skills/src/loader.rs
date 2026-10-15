//! Loading one skill's instructions.
//!
//! The body is read **fresh on every load**. The catalog in the system prompt
//! is cached metadata; the body is the authoritative text, so a SKILL.md
//! edited mid-session must take effect the next time it is loaded — an agent
//! that follows a stale procedure because a cache said so is worse than one
//! that pays a file read.

use std::path::Path;

use super::scanner::{parse_manifest, SkillArgument, SkillMetadata};

/// A skill that has been loaded for use, with its arguments.
#[derive(Debug, Clone)]
pub struct LoadedSkill {
    pub name: String,
    pub description: String,
    /// The manifest this came from — named in the instructions so supporting
    /// files next to it are discoverable (workspace skills; user-level ones
    /// live outside the sandbox's readable roots).
    pub path: std::path::PathBuf,
    pub global: bool,
    pub body: String,
    /// What the manifest says it accepts (empty = free-form).
    pub declared: Vec<SkillArgument>,
    /// What the caller passed, in declaration order where the skill declares
    /// one.
    pub arguments: Option<SkillArguments>,
}

/// Invocation arguments. Both shapes coexist on purpose: `$review src/x.rs` is
/// a string, `skill {"name":"review","args":{"path":"src/x.rs"}}` is an object,
/// and they must end up in the same instruction frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillArguments {
    /// Free-form text — the composer's `$name …` path, or a string `args`.
    Text(String),
    /// Named values, validated against the manifest's declarations.
    Named(Vec<(String, String)>),
}

impl SkillArguments {
    /// The section the instruction frame appends. Free-form text stays inline
    /// (`Skill arguments: src/x.rs`, exactly what the composer path always
    /// produced); named arguments become a list so the model can see which
    /// value belongs to which declared name.
    pub fn render_section(&self) -> String {
        match self {
            SkillArguments::Text(text) => format!("Skill arguments: {text}"),
            SkillArguments::Named(pairs) => format!(
                "Skill arguments:\n{}",
                pairs
                    .iter()
                    .map(|(name, value)| format!("- {name}: {value}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        }
    }

    /// Split free-form text into the declared argument names, in declaration
    /// order (`$review src/x.rs security` → `path=src/x.rs`, `focus=security`).
    /// Only used when the skill actually declares arguments — otherwise the
    /// text is passed through untouched.
    pub fn from_text_for(text: &str, declared: &[SkillArgument]) -> Self {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if declared.is_empty() || parts.is_empty() {
            return SkillArguments::Text(text.trim().to_string());
        }
        let named: Vec<(String, String)> = declared
            .iter()
            .zip(parts.iter())
            .map(|(arg, value)| (arg.name.clone(), (*value).to_string()))
            .collect();
        // More words than declared names: keep the remainder as text so nothing
        // is silently dropped.
        if parts.len() > declared.len() {
            let tail = parts[declared.len()..].join(" ");
            let mut named = named;
            named.push(("rest".to_string(), tail));
            return SkillArguments::Named(named);
        }
        SkillArguments::Named(named)
    }
}

/// Validate a structured `args` object against the declarations. Unknown keys
/// and missing required arguments are errors — the agent can fix either in one
/// step, which is the whole reason to declare them.
pub fn parse_named_args(
    value: &serde_json::Value,
    declared: &[SkillArgument],
) -> Result<SkillArguments, String> {
    let Some(object) = value.as_object() else {
        return Err(format!(
            "`args` must be an object of named arguments{}",
            if declared.is_empty() {
                String::new()
            } else {
                format!(" — declared: {}", declared_names(declared))
            }
        ));
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (key, raw) in object {
        if !declared.is_empty() && !declared.iter().any(|a| a.name == *key) {
            return Err(format!(
                "unknown argument `{key}` — this skill declares: {}",
                declared_names(declared)
            ));
        }
        pairs.push((key.clone(), value_to_string(raw)));
    }
    for arg in declared.iter().filter(|a| a.required) {
        if !object.contains_key(&arg.name) {
            return Err(format!(
                "missing required argument `{}` ({})",
                arg.name,
                if arg.description.is_empty() {
                    "declared by the skill"
                } else {
                    &arg.description
                }
            ));
        }
    }
    // Declared order, unknown-name skills keep insertion order.
    if !declared.is_empty() {
        pairs.sort_by_key(|(name, _)| {
            declared
                .iter()
                .position(|a| a.name == *name)
                .unwrap_or(usize::MAX)
        });
    }
    Ok(SkillArguments::Named(pairs))
}

fn declared_names(declared: &[SkillArgument]) -> String {
    declared
        .iter()
        .map(|a| {
            if a.required {
                format!("{}*", a.name)
            } else {
                a.name.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One JSON value as the model reads it: bare strings stay bare, everything
/// else keeps its JSON shape so an array/number isn't mangled into `"[1,2]"`.
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[derive(Debug)]
pub enum LoadError {
    /// No such skill. Suggestions are the caller's business (see
    /// `skills::manager`), because only it knows the whole catalog.
    Unknown(String),
    /// The manifest was found but could not be read.
    Io(String),
    /// Arguments did not match what the skill declares.
    Args(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Unknown(name) => write!(f, "unknown skill `{name}`"),
            LoadError::Io(e) => write!(f, "{e}"),
            LoadError::Args(e) => write!(f, "{e}"),
        }
    }
}

/// Read a skill's body — the whole manifest, frontmatter stripped.
///
/// `arguments` is raw text (the `$name …` path). Structured objects go through
/// [`load_named`]; both end up as [`SkillArguments`] on the loaded skill.
pub fn load(meta: &SkillMetadata, arguments: Option<&str>) -> Result<LoadedSkill, LoadError> {
    let mut loaded = read(meta)?;
    if let Some(text) = arguments.map(str::trim).filter(|t| !t.is_empty()) {
        loaded.arguments = Some(SkillArguments::from_text_for(text, &loaded.declared));
    }
    Ok(loaded)
}

/// Read a skill's body with structured arguments, validated against what the
/// manifest declares.
pub fn load_named(
    meta: &SkillMetadata,
    arguments: &serde_json::Value,
) -> Result<LoadedSkill, LoadError> {
    let mut loaded = read(meta)?;
    loaded.arguments =
        Some(parse_named_args(arguments, &loaded.declared).map_err(LoadError::Args)?);
    Ok(loaded)
}

fn read(meta: &SkillMetadata) -> Result<LoadedSkill, LoadError> {
    let text = std::fs::read_to_string(&meta.path)
        .map_err(|e| LoadError::Io(format!("skill {}: {e}", meta.path.display())))?;
    let parsed = parse_manifest(&text);
    Ok(LoadedSkill {
        name: meta.name.clone(),
        // Frontmatter is the catalog's copy; a manifest edited since the scan
        // may disagree, and the file wins.
        description: parsed
            .description
            .unwrap_or_else(|| meta.description.clone()),
        path: meta.path.clone(),
        global: meta.global,
        body: parsed.body,
        // Declarations come from the file too — a skill that grew a new
        // argument since the scan must validate against the current schema.
        declared: if parsed.arguments.is_empty() {
            meta.arguments.clone()
        } else {
            parsed.arguments
        },
        arguments: None,
    })
}

/// Read directly by path — used when the caller already resolved the manifest.
pub fn load_path(
    path: &Path,
    name: &str,
    arguments: Option<&str>,
) -> Result<LoadedSkill, LoadError> {
    load(
        &SkillMetadata {
            name: name.to_string(),
            description: String::new(),
            path: path.to_path_buf(),
            global: false,
            arguments: Vec::new(),
        },
        arguments,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::scan_skills;

    fn write_skill(root: &Path, name: &str, body: &str) {
        let dir = root.join(".agents/skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: first draft\n---\n\n{body}\n"),
        )
        .unwrap();
    }

    #[test]
    fn body_is_read_and_frontmatter_stripped() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "review", "Look for bugs.");
        let meta = scan_skills(dir.path()).remove(0);
        let loaded = load(&meta, None).unwrap();
        assert_eq!(loaded.body, "Look for bugs.");
        assert_eq!(loaded.arguments, None);
    }

    /// The whole point of not caching bodies: an edit lands on the next load,
    /// even while the prompt catalog still shows the old description.
    #[test]
    fn an_edited_manifest_loads_its_new_body_and_description() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "review", "Look for bugs.");
        let meta = scan_skills(dir.path()).remove(0);

        std::fs::write(
            meta.path.clone(),
            "---\nname: review\ndescription: rewritten\n---\n\nLook for races.\n",
        )
        .unwrap();

        let loaded = load(&meta, None).unwrap();
        assert_eq!(loaded.body, "Look for races.");
        assert_eq!(
            loaded.description, "rewritten",
            "the file wins over the cached metadata"
        );
    }

    #[test]
    fn arguments_are_trimmed_and_blanks_dropped() {
        let dir = tempfile::tempdir().unwrap();
        write_skill(dir.path(), "review", "Body.");
        let meta = scan_skills(dir.path()).remove(0);
        assert_eq!(
            load(&meta, Some("  src/engine.rs  ")).unwrap().arguments,
            Some(SkillArguments::Text("src/engine.rs".into()))
        );
        assert_eq!(load(&meta, Some("   ")).unwrap().arguments, None);
    }
}
