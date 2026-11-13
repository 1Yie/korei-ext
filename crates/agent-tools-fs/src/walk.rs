use std::fs::{FileType, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_capabilities::{WorkspaceCtx, WorkspaceIo};
use agent_tool::ToolError;
use grep_matcher::{Captures, Matcher};
use grep_regex::RegexMatcher;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

pub(crate) enum Entry {
    Native(ignore::DirEntry),
    Leased {
        path: PathBuf,
        metadata: Metadata,
        depth: usize,
    },
}

impl Entry {
    pub fn path(&self) -> &Path {
        match self {
            Self::Native(entry) => entry.path(),
            Self::Leased { path, .. } => path,
        }
    }
    pub fn depth(&self) -> usize {
        match self {
            Self::Native(entry) => entry.depth(),
            Self::Leased { depth, .. } => *depth,
        }
    }
    pub fn file_type(&self) -> Option<FileType> {
        match self {
            Self::Native(entry) => entry.file_type(),
            Self::Leased { metadata, .. } => Some(metadata.file_type()),
        }
    }
    pub fn metadata(&self) -> Result<Metadata, ToolError> {
        match self {
            Self::Native(entry) => entry
                .metadata()
                .map_err(|e| ToolError::Failed(e.to_string())),
            Self::Leased { metadata, .. } => Ok(metadata.clone()),
        }
    }
}

/// Native traversal keeps ignore's ordinary behavior; leased traversal reads
/// both entries and ignore rules exclusively through the file capability.
pub(crate) fn walk<C: WorkspaceCtx>(
    io: WorkspaceIo<C>,
    base: &Path,
    hidden: bool,
    max_depth: Option<usize>,
) -> Result<Box<dyn Iterator<Item = Result<Entry, ToolError>> + Send>, ToolError> {
    if !io.is_leased() {
        let mut builder = ignore::WalkBuilder::new(base);
        builder
            .hidden(!hidden)
            .git_ignore(true)
            .git_exclude(true)
            .require_git(false)
            .max_depth(max_depth)
            .sort_by_file_name(|a, b| a.cmp(b));
        return Ok(Box::new(builder.build().map(|result| {
            result
                .map(Entry::Native)
                .map_err(|error| ToolError::Failed(error.to_string()))
        })));
    }
    let mut rules = Rules::default();
    load_global(&io, &mut rules)?;
    let source = io.source_path(base)?;
    let parents: Vec<_> = source.ancestors().skip(1).collect();
    for directory in parents.into_iter().rev() {
        load_rules(&io, directory, &mut rules)?;
    }
    Ok(Box::new(LeasedWalk {
        io,
        pending: vec![(base.to_path_buf(), 0, Arc::new(rules))],
        hidden,
        max_depth,
    }))
}

#[derive(Clone, Default)]
struct Rules {
    global: Vec<Gitignore>,
    exclude: Vec<Gitignore>,
    git: Vec<Gitignore>,
    ignore: Vec<Gitignore>,
}

impl Rules {
    fn ignored(&self, path: &Path, directory: bool) -> Option<bool> {
        for rules in [&self.ignore, &self.git, &self.exclude, &self.global] {
            for rule in rules.iter().rev() {
                let matched = rule.matched(path, directory);
                if !matched.is_none() {
                    return Some(matched.is_ignore());
                }
            }
        }
        None
    }
}

fn excludes_path(bytes: &[u8]) -> Result<Option<PathBuf>, ToolError> {
    let matcher = RegexMatcher::new(r#"(?im)^\s*excludesfile\s*=\s*"?([^"\n]+)"?\s*$"#)
        .map_err(|error| ToolError::Failed(error.to_string()))?;
    let mut captures = matcher
        .new_captures()
        .map_err(|error| ToolError::Failed(error.to_string()))?;
    if !matcher
        .captures(bytes, &mut captures)
        .map_err(|error| ToolError::Failed(error.to_string()))?
    {
        return Ok(None);
    }
    let Some(capture) = captures.get(1) else {
        return Ok(None);
    };
    let Ok(value) = std::str::from_utf8(&bytes[capture.start()..capture.end()]) else {
        return Ok(None);
    };
    Ok(Some(if let Some(relative) = value.strip_prefix("~/") {
        home_dir()
            .map(|home| home.join(relative))
            .unwrap_or_else(|| PathBuf::from(value))
    } else {
        PathBuf::from(value)
    }))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

fn check_reference<C: WorkspaceCtx>(
    io: &WorkspaceIo<C>,
    config: &Path,
    path: PathBuf,
    select: impl Fn(&[u8]) -> Result<Option<PathBuf>, ToolError>,
) -> Result<PathBuf, ToolError> {
    let cwd = std::env::current_dir()?;
    let path = cwd.join(path);
    if io.resolve(&path, false).is_err() {
        let baseline = io.read_ignore_config_baseline(config)?;
        let trusted = baseline
            .as_deref()
            .map(select)
            .transpose()?
            .flatten()
            .map(|path| cwd.join(path));
        if trusted.as_ref() != Some(&path) {
            return Err(ToolError::Failed(
                "private ignore configuration cannot authorize a new Host file".into(),
            ));
        }
    }
    Ok(path)
}

fn load_global<C: WorkspaceCtx>(io: &WorkspaceIo<C>, rules: &mut Rules) -> Result<(), ToolError> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let home = home_dir();
    let user = if let Some(global) = std::env::var_os("GIT_CONFIG_GLOBAL") {
        vec![PathBuf::from(global)]
    } else {
        home.iter()
            .map(|home| home.join(".gitconfig"))
            .chain(xdg.iter().map(|xdg| xdg.join("git/config")))
            .collect()
    };
    let system = if std::env::var_os("GIT_CONFIG_NOSYSTEM").is_some() {
        None
    } else {
        Some(
            std::env::var_os("GIT_CONFIG_SYSTEM")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/etc/gitconfig")),
        )
    };
    for config in user.into_iter().chain(system) {
        let Some(bytes) = io.read_ignore_config(&config)? else {
            continue;
        };
        let Some(path) = excludes_path(&bytes)? else {
            continue;
        };
        let path = check_reference(io, &config, path, excludes_path)?;
        return load_rule(io, Path::new(""), &path, &mut rules.global);
    }
    let default = xdg
        .map(|xdg| xdg.join("git/ignore"))
        .or_else(|| home.map(|home| home.join(".config/git/ignore")));
    if let Some(path) = default {
        load_rule(io, Path::new(""), &path, &mut rules.global)?;
    }
    Ok(())
}

fn load_rules<C: WorkspaceCtx>(
    io: &WorkspaceIo<C>,
    dir: &Path,
    rules: &mut Rules,
) -> Result<(), ToolError> {
    let marker = dir.join(".git");
    // require_git(false) does not follow gitdir files to an external exclude file.
    if io.read_ignore_config(&marker)?.is_none() {
        load_rule(io, dir, &marker.join("info/exclude"), &mut rules.exclude)?;
    }
    load_rule(io, dir, &dir.join(".gitignore"), &mut rules.git)?;
    load_rule(io, dir, &dir.join(".ignore"), &mut rules.ignore)
}

fn load_rule<C: WorkspaceCtx>(
    io: &WorkspaceIo<C>,
    dir: &Path,
    path: &Path,
    rules: &mut Vec<Gitignore>,
) -> Result<(), ToolError> {
    if let Some(bytes) = io.read_ignore_config(path)? {
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| ToolError::Failed(format!("{}: {e}", path.display())))?;
        let mut builder = GitignoreBuilder::new(dir);
        for line in text.lines() {
            builder
                .add_line(Some(path.to_path_buf()), line)
                .map_err(|e| ToolError::Failed(e.to_string()))?;
        }
        rules.push(
            builder
                .build()
                .map_err(|e| ToolError::Failed(e.to_string()))?,
        );
    }
    Ok(())
}

struct LeasedWalk<C> {
    io: WorkspaceIo<C>,
    pending: Vec<(PathBuf, usize, Arc<Rules>)>,
    hidden: bool,
    max_depth: Option<usize>,
}

impl<C: WorkspaceCtx> Iterator for LeasedWalk<C> {
    type Item = Result<Entry, ToolError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (path, depth, rules) = self.pending.pop()?;
            let metadata = match self.io.metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => return Some(Err(error)),
            };
            if depth > 0 {
                let source = match self.io.source_path(&path) {
                    Ok(source) => source,
                    Err(error) => return Some(Err(error)),
                };
                if rules
                    .ignored(&source, metadata.is_dir())
                    .unwrap_or_else(|| {
                        !self.hidden
                            && path
                                .file_name()
                                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                    })
                {
                    continue;
                }
            }
            if metadata.is_dir() && self.max_depth.is_none_or(|max| depth < max) {
                let mut rules = (*rules).clone();
                let source = match self.io.source_path(&path) {
                    Ok(source) => source,
                    Err(error) => return Some(Err(error)),
                };
                if let Err(error) = load_rules(&self.io, &source, &mut rules) {
                    return Some(Err(error));
                }
                let rules = Arc::new(rules);
                let mut children = match self.io.read_dir(&path) {
                    Ok(children) => children,
                    Err(error) => return Some(Err(error)),
                };
                children.sort();
                self.pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|path| (path, depth + 1, rules.clone())),
                );
            }
            return Some(Ok(Entry::Leased {
                path,
                metadata,
                depth,
            }));
        }
    }
}
