//! Skill rendering: the catalog the system prompt carries, and the instruction
//! frame a loaded skill arrives in.
//!
//! Two entry points exist — the user typing `$review`, and the model calling
//! `skill {"name": "review"}` — and they must converge on **one** frame, or a
//! skill would behave differently depending on who invoked it. Everything here
//! is pure string work over [`super::scanner`]/[`super::loader`] output.

use super::loader::{LoadedSkill, SkillArguments};
use super::scanner::SkillMetadata;

/// How many skills the prompt catalog lists, and how much of each description
/// survives. A skill tree is unbounded and the system prompt is charged to
/// every turn: ~4 KB for 29 skills at 120 chars, measured — and the model can
/// ask for the rest (`skill {"list": true}`) or load one for its full body.
pub const CATALOG_LIMIT: usize = 40;
pub const DESC_CHARS: usize = 120;

/// The catalog body — one bullet per skill, workspace entries first,
/// descriptions clipped. Pure over a scan, so the layout is testable without
/// touching `$HOME`.
pub fn catalog_lines(skills: &[SkillMetadata], limit: usize, desc_chars: usize) -> String {
    if skills.is_empty() {
        return "No skills installed — a skill is `<root>/.agents/skills/<name>/SKILL.md`."
            .to_string();
    }
    let shown = skills.len().min(limit);
    let mut out = String::new();
    if skills.len() > shown {
        out.push_str(&format!(
            "{shown} of {} listed — `skill {{\"list\": true}}` for the rest.\n",
            skills.len()
        ));
    }
    for skill in &skills[..shown] {
        out.push_str(&format!("- {}\n", line(skill, desc_chars)));
    }
    out.trim_end().to_string()
}

/// One catalog line, `- `name` — description (origin; args: …)`. The declared
/// names ride along because they are what the model needs to call the skill
/// correctly on the first try — discovering them from an "unknown argument"
/// error costs a round trip.
pub fn line(skill: &SkillMetadata, desc_chars: usize) -> String {
    let desc = skill
        .description
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let desc = if desc.is_empty() {
        "(no description)".to_string()
    } else if desc.chars().count() > desc_chars {
        let cut: String = desc.chars().take(desc_chars.saturating_sub(1)).collect();
        format!("{}…", cut.trim_end())
    } else {
        desc
    };
    let origin = if skill.global { "global" } else { "workspace" };
    if skill.arguments.is_empty() {
        return format!("`{}` — {desc} ({origin})", skill.name);
    }
    let args: Vec<String> = skill
        .arguments
        .iter()
        .map(|a| {
            if a.required {
                format!("{}*", a.name)
            } else {
                a.name.clone()
            }
        })
        .collect();
    format!(
        "`{}` — {desc} ({origin}; args: {})",
        skill.name,
        args.join(", ")
    )
}

/// The shared frame: a provenance line, the body fenced, then any arguments.
/// Both entry points go through here, so the model always sees the skill's real
/// text in a stable shape.
fn frame(provenance: &str, body: &str, arguments: Option<&SkillArguments>) -> String {
    let mut out = format!("{provenance}\n\n---\n{body}\n---");
    if let Some(args) = arguments {
        out.push_str(&format!("\n\n{}", args.render_section()));
    }
    out
}

/// User-invoked (`$review` / `/review` in the composer).
pub fn for_user(skill: &LoadedSkill, trigger: &str) -> String {
    frame(
        &format!("The user invoked the `{trigger}` skill. Follow its instructions exactly."),
        &skill.body,
        skill.arguments.as_ref(),
    )
}

/// Model-invoked (the `skill` tool). Same frame; the provenance names the
/// manifest and promises nothing about authority — a skill's text can shape
/// *instructions*, never permissions.
pub fn for_model(skill: &LoadedSkill) -> String {
    frame(
        &format!(
            "Skill `{}` — follow its instructions exactly.\n(source: {})",
            skill.name,
            skill.path.display()
        ),
        &skill.body,
        skill.arguments.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::SkillArgument;
    use std::path::PathBuf;

    fn meta(name: &str, desc: &str, global: bool) -> SkillMetadata {
        SkillMetadata {
            name: name.into(),
            description: desc.into(),
            path: PathBuf::from(format!("/x/{name}/SKILL.md")),
            global,
            arguments: Vec::new(),
        }
    }

    fn loaded(name: &str, body: &str, args: Option<&str>) -> LoadedSkill {
        LoadedSkill {
            name: name.into(),
            description: "d".into(),
            path: PathBuf::from(format!("/x/{name}/SKILL.md")),
            global: false,
            body: body.into(),
            declared: Vec::new(),
            arguments: args.map(|a| SkillArguments::Text(a.to_string())),
        }
    }

    #[test]
    fn catalog_clips_caps_and_tags_origin() {
        let long = "x".repeat(DESC_CHARS + 50);
        let skills = vec![
            meta("alpha", "does a thing", false),
            meta("beta", &long, true),
            meta("gamma", "", false),
        ];
        let out = catalog_lines(&skills, 40, DESC_CHARS);
        assert!(out.contains("`alpha` — does a thing (workspace)"), "{out}");
        assert!(out.contains("(global)"), "{out}");
        assert!(
            out.contains(&format!("{}…", "x".repeat(DESC_CHARS - 1))),
            "{out}"
        );
        assert!(out.contains("(no description)"), "{out}");

        let capped = catalog_lines(&skills, 2, DESC_CHARS);
        assert!(capped.starts_with("2 of 3 listed"), "{capped}");
        assert!(!capped.contains("gamma"), "{capped}");

        assert!(catalog_lines(&[], 40, DESC_CHARS).contains("No skills installed"));

        // Declared arguments ride along, `*` marking required ones — that is
        // where the model reads how to call the skill.
        let mut with_args = meta("with-args", "takes args", false);
        with_args.arguments = vec![
            SkillArgument {
                name: "path".into(),
                description: String::new(),
                required: true,
            },
            SkillArgument {
                name: "focus".into(),
                description: String::new(),
                required: false,
            },
        ];
        let out = catalog_lines(&[with_args], 40, DESC_CHARS);
        assert!(out.contains("(workspace; args: path*, focus)"), "{out}");
    }

    /// The invariant both entry points rest on: identical invocation data ⇒
    /// identical instruction text.
    #[test]
    fn both_frames_carry_the_same_body_and_arguments() {
        let skill = loaded("review", "Look for bugs.", Some("src/engine.rs"));
        for frame in [for_user(&skill, "$review"), for_model(&skill)] {
            assert!(frame.contains("\n---\nLook for bugs.\n---"), "{frame}");
            assert!(frame.contains("Skill arguments: src/engine.rs"), "{frame}");
        }

        // Named arguments render as a list, through the same frame.
        let named = LoadedSkill {
            arguments: Some(SkillArguments::Named(vec![
                ("path".into(), "src/engine.rs".into()),
                ("focus".into(), "security".into()),
            ])),
            ..loaded("review", "Look for bugs.", None)
        };
        let frame = for_model(&named);
        assert!(
            frame.contains("Skill arguments:\n- path: src/engine.rs\n- focus: security"),
            "{frame}"
        );
    }
}
