//! Skill discovery — **metadata only**.
//!
//! A scan answers "which skills exist, and what do they claim to do", never
//! "what is in them": manifests are read up to their frontmatter, so building
//! the catalog (every `/skills` call, every prompt refresh, every unknown-name
//! suggestion) costs a few KB instead of the ~330 KB of bodies a normal skill
//! tree carries. Bodies are [`super::loader`]'s job, on demand.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Workspace-relative directories scanned for manifests, in priority order —
/// first hit wins when a name is duplicated. `.agents/skills` is the canonical
/// root (agentskills convention); `.claude/skills` and `.pi/skills` are the
/// Claude-Code / pi aliases so existing skill trees register natively.
pub const WORKSPACE_SKILL_DIRS: [&str; 5] = [
    ".agents/skills",
    ".agent/skills",
    ".skills",
    ".claude/skills",
    ".pi/skills",
];

/// User-level skill roots (under `dirs::home_dir()`) — scanned after the
/// workspace dirs, so a project skill always shadows a global one.
pub const GLOBAL_SKILL_DIRS: [&str; 3] = [".agents/skills", ".claude/skills", ".pi/agent/skills"];

/// How much of a manifest a scan reads. Frontmatter lives at the top; the cap
/// only bites on a manifest with an absurdly long preamble, which then reads
/// as "no frontmatter" — the name falls back to the directory.
const FRONTMATTER_HEAD: u64 = 8 * 1024;

/// One installed skill as the catalog knows it.
#[derive(Debug, Clone)]
pub struct SkillMetadata {
    pub name: String,
    pub description: String,
    pub path: PathBuf,
    /// Found under a user-level dir rather than the workspace. Workspace
    /// entries always win the name dedup.
    pub global: bool,
    /// Arguments the manifest declares — empty means free-form.
    pub arguments: Vec<SkillArgument>,
}

/// One argument a skill accepts, as its frontmatter declares it.
///
/// ```yaml
/// arguments:
///   <path>: File or directory to review   # angle brackets = required
///   focus:                                # description optional
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// A parsed manifest: frontmatter fields plus whatever follows it.
#[derive(Debug, Default)]
pub struct ParsedManifest {
    pub name: Option<String>,
    pub description: Option<String>,
    /// Declared arguments, in the order the manifest lists them.
    pub arguments: Vec<SkillArgument>,
    /// The instruction body — populated only when the whole file was read
    /// (the loader); a metadata scan discards it.
    pub body: String,
}

/// Parse a manifest's frontmatter: `name:`, `description:` and `arguments:`;
/// everything else is ignored and the body passes through verbatim.
///
/// `description:` accepts YAML block scalars (`>-`, `>`, `|`, `|-`) — reading only
/// the indicator's line is how a skill ends up advertised as `>-` in the prompt.
/// `arguments:` is a nested block of `name: description` lines; the declared names
/// are what the `skill` tool validates a structured `args` object against.
pub fn parse_manifest(text: &str) -> ParsedManifest {
    let trimmed = text.trim_start();
    let Some(fm) = trimmed.strip_prefix("---") else {
        return ParsedManifest {
            body: text.to_string(),
            ..Default::default()
        };
    };
    let Some(end) = fm.find("\n---") else {
        return ParsedManifest {
            body: text.to_string(),
            ..Default::default()
        };
    };
    let mut out = ParsedManifest {
        body: fm[end + 4..].trim().to_string(),
        ..Default::default()
    };
    let lines: Vec<&str> = fm[..end].lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if let Some(v) = line.strip_prefix("name:") {
            out.name = Some(v.trim().trim_matches('"').trim_matches('\'').to_string());
        } else if let Some(v) = line.strip_prefix("description:") {
            let head = v.trim();
            if head.starts_with('>') || head.starts_with('|') {
                let folded = head.starts_with('>');
                let mut parts: Vec<String> = Vec::new();
                let mut j = i + 1;
                while j < lines.len() {
                    let raw = lines[j];
                    if raw.trim().is_empty() {
                        j += 1;
                        continue;
                    }
                    if raw.starts_with(char::is_whitespace) {
                        parts.push(raw.trim().to_string());
                        j += 1;
                    } else {
                        break;
                    }
                }
                out.description = Some(if folded {
                    parts.join(" ")
                } else {
                    parts.join("\n")
                });
                i = j;
                continue;
            }
            out.description = Some(head.trim_matches('"').trim_matches('\'').to_string());
        } else if line == "arguments:" || line == "args:" {
            let mut j = i + 1;
            while j < lines.len() {
                let raw = lines[j];
                if raw.trim().is_empty() {
                    j += 1;
                    continue;
                }
                // The block ends at the next top-level key.
                if !raw.starts_with(char::is_whitespace) {
                    break;
                }
                let entry = raw.trim();
                let (key, value) = entry.split_once(':').unwrap_or((entry, ""));
                let key = key.trim();
                if key.is_empty() {
                    j += 1;
                    continue;
                }
                let required = key.starts_with('<') && key.ends_with('>');
                out.arguments.push(SkillArgument {
                    name: key.trim_matches(|c| c == '<' || c == '>').to_string(),
                    description: value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string(),
                    required,
                });
                j += 1;
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Every skill root, tagged `global`, in scan order — workspace dirs first.
pub fn skill_base_dirs(root: &Path) -> Vec<(PathBuf, bool)> {
    let mut out: Vec<(PathBuf, bool)> = WORKSPACE_SKILL_DIRS
        .iter()
        .map(|d| (root.join(d), false))
        .collect();
    if let Some(home) = dirs::home_dir() {
        out.extend(GLOBAL_SKILL_DIRS.iter().map(|d| (home.join(d), true)));
    }
    out
}

/// Absolute user-level skill roots, in scan order.
///
/// The sandbox mounts these read-only. The catalog and the `skill` tool read
/// them from the kernel process, but a sandboxed command sees a mount-namespace
/// view: without this, the instructions a skill just delivered would point at
/// sibling files (`references/`, `scripts/`) the command cannot open.
pub fn global_skill_roots() -> Vec<PathBuf> {
    match dirs::home_dir() {
        Some(home) => GLOBAL_SKILL_DIRS.iter().map(|d| home.join(d)).collect(),
        None => Vec::new(),
    }
}

/// Workspace skills only — hermetic (no `$HOME` reads) so tests stay
/// reproducible; callers wanting the full surface use [`scan_all_skills`].
pub fn scan_skills(root: &Path) -> Vec<SkillMetadata> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let dirs: Vec<PathBuf> = WORKSPACE_SKILL_DIRS.iter().map(|d| root.join(d)).collect();
    scan_skill_dirs(&dirs, false, &mut seen, &mut out);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Workspace + user-level skills — the surface `/skills`, `/{name}`/`${name}`
/// dispatch, the `skill` tool, and the composer pickers all share.
pub fn scan_all_skills(root: &Path) -> Vec<SkillMetadata> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let dirs: Vec<PathBuf> = skill_base_dirs(root).into_iter().map(|(d, _)| d).collect();
    let ws = WORKSPACE_SKILL_DIRS.len();
    scan_skill_dirs(&dirs[..ws], false, &mut seen, &mut out);
    scan_skill_dirs(&dirs[ws..], true, &mut seen, &mut out);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Look up one skill by name (`/{name}` / `${name}` dispatch, `skill` tool).
pub fn find_skill(root: &Path, name: &str) -> Option<SkillMetadata> {
    let want = name.to_lowercase();
    scan_all_skills(root)
        .into_iter()
        .find(|s| s.name.to_lowercase() == want)
}

/// Newest mtime across the skill roots and their entries — the catalog's
/// change detector. A new or removed skill dir bumps a root; an edited
/// manifest bumps its own mtime.
pub fn skills_stamp(root: &Path) -> u64 {
    fn millis(t: std::io::Result<std::time::SystemTime>) -> u64 {
        t.ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    let mut newest = 0u64;
    for (base, _) in skill_base_dirs(root) {
        newest = newest.max(millis(std::fs::metadata(&base).and_then(|m| m.modified())));
        let Ok(rd) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // A skill's content is its manifest, not the directory.
                newest = newest.max(millis(
                    std::fs::metadata(p.join("SKILL.md")).and_then(|m| m.modified()),
                ));
            } else {
                newest = newest.max(millis(entry.metadata().and_then(|m| m.modified())));
            }
        }
    }
    newest
}

/// Read at most [`FRONTMATTER_HEAD`] bytes — enough for any real frontmatter.
/// Lossy on a cut code point: the caller only wants the fields, and the tail
/// of an over-long preamble is not worth an error.
fn read_head(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(FRONTMATTER_HEAD).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// One-level scan of `dirs` for `<name>/SKILL.md` or bare `<name>.md`
/// manifests, appending to `out`/`seen` (dedup across batches — earlier dirs
/// win).
fn scan_skill_dirs(
    dirs: &[PathBuf],
    global: bool,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<SkillMetadata>,
) {
    for base in dirs {
        let Ok(rd) = std::fs::read_dir(base) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let manifest = if p.is_dir() {
                let m = p.join("SKILL.md");
                if m.is_file() {
                    m
                } else {
                    continue;
                }
            } else if p.extension().is_some_and(|e| e == "md") {
                p.clone()
            } else {
                continue;
            };
            let Some(head) = read_head(&manifest) else {
                continue;
            };
            let parsed = parse_manifest(&head);
            let name = parsed.name.unwrap_or_else(|| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .or_else(|| {
                        manifest
                            .file_stem()
                            .map(|n| n.to_string_lossy().into_owned())
                    })
                    .unwrap_or_default()
            });
            if name.is_empty() || !seen.insert(name.clone()) {
                continue;
            }
            out.push(SkillMetadata {
                name,
                description: parsed.description.unwrap_or_default(),
                path: manifest,
                global,
                arguments: parsed.arguments,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    /// The sandbox mounts exactly these roots; a drift here silently hides
    /// skills from `bash` again.
    #[test]
    fn global_skill_roots_are_the_documented_user_level_dirs() {
        let Some(home) = dirs::home_dir() else { return };
        let roots = global_skill_roots();
        let expected: Vec<PathBuf> = GLOBAL_SKILL_DIRS.iter().map(|d| home.join(d)).collect();
        assert_eq!(roots, expected);
        assert!(roots.iter().all(|p| p.is_absolute()));
    }

    use super::*;

    fn write_manifest(root: &Path, rel: &str, text: &str) {
        let dir = root.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), text).unwrap();
    }

    #[test]
    fn block_scalar_descriptions_are_read_not_stored_as_the_indicator() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(
            dir.path(),
            ".agents/skills/folded",
            "---\nname: folded\ndescription: >-\n  A folded summary\n  across two lines.\nlicense: MIT\n---\n\nBody.\n",
        );
        write_manifest(
            dir.path(),
            ".agents/skills/literal",
            "---\nname: literal\ndescription: |\n  line one\n  line two\n---\n\nBody.\n",
        );

        let found = scan_skills(dir.path());
        let get = |n: &str| found.iter().find(|s| s.name == n).expect("skill");
        assert_eq!(
            get("folded").description,
            "A folded summary across two lines."
        );
        assert_eq!(get("literal").description, "line one\nline two");
    }

    /// A scan must not pay for bodies: the same tree reads a few hundred bytes
    /// of frontmatter instead of every instruction block.
    #[test]
    fn scanning_reads_only_the_frontmatter() {
        let dir = tempfile::tempdir().unwrap();
        let body = "x".repeat(200_000);
        write_manifest(
            dir.path(),
            ".agents/skills/heavy",
            &format!("---\nname: heavy\ndescription: big body\n---\n\n{body}\n"),
        );
        let parsed =
            parse_manifest(&read_head(&dir.path().join(".agents/skills/heavy/SKILL.md")).unwrap());
        assert_eq!(parsed.name.as_deref(), Some("heavy"));
        assert_eq!(parsed.description.as_deref(), Some("big body"));
        assert!(
            parsed.body.len() < FRONTMATTER_HEAD as usize,
            "head read pulled the body"
        );
        // The metadata path never even looks at it.
        assert_eq!(scan_skills(dir.path())[0].name, "heavy");
    }

    /// `arguments:` is a nested block: it must stop at the next top-level key,
    /// keep declaration order, and read `<name>` as required.
    #[test]
    fn declared_arguments_parse_with_required_markers_and_stop_at_the_next_key() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(
            dir.path(),
            ".agents/skills/review",
            "---\nname: review\ndescription: review code\narguments:\n  <path>: file or directory\n  focus: what to look for\n  severity:\nlicense: MIT\n---\n\nBody.\n",
        );
        let meta = &scan_skills(dir.path())[0];
        let names: Vec<(&str, bool)> = meta
            .arguments
            .iter()
            .map(|a| (a.name.as_str(), a.required))
            .collect();
        assert_eq!(
            names,
            vec![("path", true), ("focus", false), ("severity", false)]
        );
        assert_eq!(meta.arguments[0].description, "file or directory");
        assert_eq!(meta.arguments[2].description, "", "a bare name is allowed");
        // `license:` after the block is not an argument.
        assert_eq!(meta.arguments.len(), 3, "{:?}", meta.arguments);
    }

    #[test]
    fn frontmatter_is_optional_and_names_fall_back_to_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(dir.path(), ".agents/skills/bare", "Just instructions.\n");
        let found = scan_skills(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "bare");
        assert_eq!(found[0].description, "");
    }

    #[test]
    fn agent_and_claude_and_pi_dirs_all_register_and_dedupe() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(
            dir.path(),
            ".agents/skills/shared",
            "---\nname: shared\ndescription: canonical\n---\n\nA.\n",
        );
        write_manifest(
            dir.path(),
            ".claude/skills/shared",
            "---\nname: shared\ndescription: shadowed\n---\n\nB.\n",
        );
        write_manifest(
            dir.path(),
            ".pi/skills/pi-only",
            "---\nname: pi-only\ndescription: from pi\n---\n\nC.\n",
        );
        let found = scan_skills(dir.path());
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found
                .iter()
                .find(|s| s.name == "shared")
                .unwrap()
                .description,
            "canonical"
        );
    }

    #[test]
    fn stamp_moves_when_the_tree_changes() {
        let dir = tempfile::tempdir().unwrap();
        write_manifest(
            dir.path(),
            ".agents/skills/one",
            "---\nname: one\n---\n\nA.\n",
        );
        let before = skills_stamp(dir.path());
        // mtime granularity can be coarse on some filesystems; a fresh write
        // must still move the stamp once the filesystem records it.
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_manifest(
            dir.path(),
            ".agents/skills/two",
            "---\nname: two\n---\n\nB.\n",
        );
        assert!(
            skills_stamp(dir.path()) > before,
            "adding a skill must move the stamp"
        );
        assert_eq!(
            find_skill(dir.path(), "TWO").map(|s| s.name),
            Some("two".into())
        );
    }
}
