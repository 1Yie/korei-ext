//! Audit engine — turns a parsed command into an `AuditResult` the policy
//! engine + approval card consume. NOT a security boundary: it explains
//! risk and proposes capabilities; the sandbox enforces regardless of what
//! audit missed. Replaces the old string-blacklist matcher — now driven by
//! `shell_ast` → `capability` extraction → risk classification.

use std::path::PathBuf;

use crate::capability::{extract, risk_of, Capability, RiskLevel};
use crate::shell_ast::{parse, Node};
use crate::traits::SnapshotMode;

/// Risk tier surfaced to the approval card + sandbox config — kept for
/// back-compat with the engine/UI; maps 1:1 onto `RiskLevel` + the legacy
/// `NetworkMutating`/`ScopeViolation` distinctions the card already renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditLevel {
    /// Normal — permission mode decides.
    Normal,
    /// Package-manager mutation; also forces `allow_network` prompt.
    NetworkMutating,
    /// Confirmation required in every mode incl. `acceptEdits`.
    Elevated,
    /// Red card — only runs after explicit approve + forced `Required` CoW.
    Critical,
    /// Command targets paths outside the sandbox — deny unless widened.
    ScopeViolation,
}

/// What the audit produced — capabilities + risk + human-readable reasons.
/// `capabilities` is the authoritative description of what the command will
/// need; `risk` is its danger tier; `reasons` are the strings the approval
/// card lists ("deletes /etc/passwd", "escalates via sudo"…).
#[derive(Debug, Clone)]
pub struct AuditResult {
    /// Extracted capabilities (resource+op+scope), in order.
    pub capabilities: Vec<Capability>,
    /// Aggregate risk (max over the capability set).
    pub risk: RiskLevel,
    /// Human-readable reasons for the risk — the card's bullet list.
    pub reasons: Vec<String>,
    /// Legacy level for the existing approval-card rendering.
    pub level: AuditLevel,
    /// Audit-mandated snapshot upgrade (Critical forces Required).
    pub force_snapshot: Option<SnapshotMode>,
    /// Whether a network-access prompt must accompany confirmation.
    pub needs_network_prompt: bool,
}

/// Back-compat alias — the engine calls `audit_command`; it now returns the
/// richer `AuditResult`.
pub type AuditVerdict = AuditResult;

/// Audit one command line: parse → extract capabilities → classify risk →
/// build reasons. Never fails (parse degrades to a raw Simple node).
pub fn audit_command(cmd: &str) -> AuditResult {
    audit_command_scoped(cmd, None)
}

/// Audit with a workspace root — out-of-scope writes/deletes get flagged.
/// `workspace` is the canonical sandbox root; absolute paths outside it +
/// `$HOME`/etc/system dirs raise `ScopeViolation`/elevated risk.
pub fn audit_command_scoped(cmd: &str, workspace: Option<&std::path::Path>) -> AuditResult {
    audit_command_rooted(cmd, workspace, &[], &[])
}

/// [`audit_command_scoped`] with the roots a host granted beyond the
/// workspace: a read inside `readable` or `writable` is in scope, a write only
/// inside `writable`. The sensitive system set stays out of scope regardless.
pub fn audit_command_rooted(
    cmd: &str,
    workspace: Option<&std::path::Path>,
    readable: &[std::path::PathBuf],
    writable: &[std::path::PathBuf],
) -> AuditResult {
    let ast = parse(cmd);
    let mut caps = extract(&ast);

    // Mark out-of-scope file caps — a write/delete/read outside the
    // granted roots is a scope violation, not a generic file op.
    if let Some(ws) = workspace {
        for c in &mut caps {
            let (path, write) = match c {
                Capability::WriteFile { path }
                | Capability::AppendFile { path }
                | Capability::DeleteFile { path, .. }
                | Capability::CreateFile { path }
                | Capability::CreateDirectory { path } => (Some(path.clone()), true),
                Capability::ReadFile { path } => (Some(path.clone()), false),
                _ => (None, false),
            };
            if let Some(p) = path {
                let out = if write {
                    is_out_of_scope(&p, ws, writable.iter())
                } else {
                    is_out_of_scope(&p, ws, readable.iter().chain(writable))
                };
                if out {
                    *c = Capability::OutOfScope { path: p };
                }
            }
        }
    }

    let risk = risk_of(&caps);
    let reasons = reasons_for(&caps);
    // Separate the package-install tier from generic network — a `git push`
    // or `curl` is Elevated (network), NOT a package-manager mutation.
    let is_package_install = caps
        .iter()
        .any(|c| matches!(c, Capability::PackageInstall { .. }));
    let is_network = caps.iter().any(|c| matches!(c, Capability::Network { .. }));
    let needs_network = is_network || is_package_install;
    let scope_violation = caps
        .iter()
        .any(|c| matches!(c, Capability::OutOfScope { .. }));

    let level = match risk {
        RiskLevel::Critical => AuditLevel::Critical,
        RiskLevel::High if scope_violation => AuditLevel::ScopeViolation,
        RiskLevel::High if is_package_install => AuditLevel::NetworkMutating,
        RiskLevel::High => AuditLevel::Elevated,
        RiskLevel::Medium | RiskLevel::Low => AuditLevel::Normal,
    };

    AuditResult {
        capabilities: caps,
        risk,
        reasons,
        level,
        force_snapshot: if risk == RiskLevel::Critical {
            Some(SnapshotMode::Required)
        } else {
            None
        },
        needs_network_prompt: needs_network,
    }
}

/// The paths `cmd` writes, creates, moves or deletes outside the workspace and
/// the `writable` roots — what an unsandboxed run could change that the host
/// never granted. Reads are not listed: reading a dependency's source is
/// ordinary shell work.
pub fn writes_out_of_scope(
    cmd: &str,
    workspace: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let node = parse(cmd);
    for p in walk_writes(&node, workspace, writable) {
        if is_out_of_scope(&p, workspace, writable.iter()) {
            out.push(p);
        }
    }
    out
}

/// The paths the command writes, in order, with `cd` tracked — `cd /w && rm f`
/// writes `/w/f`, not the workspace's `f`. Capability extraction alone cannot
/// say that: it sees one flat set of operations and no working directory.
fn walk_writes(
    node: &Node,
    workspace: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let _ = step(node, workspace, writable, &mut out);
    out
}

/// One node, returning the working directory the following segment inherits.
fn step(
    node: &Node,
    workspace: &std::path::Path,
    writable: &[std::path::PathBuf],
    out: &mut Vec<PathBuf>,
) -> PathBuf {
    match node {
        Node::And(a, b) | Node::Or(a, b) | Node::Seq(a, b) => {
            let cwd = step(a, workspace, writable, out);
            step(b, &cwd, writable, out);
            cwd
        }
        // A pipeline's segments see the same directory; only the last one's
        // `cd` could matter and it does not escape the pipeline anyway.
        Node::Pipe(cmds) => {
            let mut cwd = workspace.to_path_buf();
            for c in cmds {
                cwd = step(c, &cwd, writable, out);
            }
            cwd
        }
        Node::Subshell(inner) => {
            step(inner, workspace, writable, out);
            workspace.to_path_buf()
        }
        Node::Simple(cmd) => simple_writes(cmd, workspace, writable, out),
    }
}

/// Binaries whose non-flag arguments are files they overwrite, move or remove.
const WRITE_VERBS: &[&str] = &[
    "rm", "rmdir", "mv", "cp", "touch", "mkdir", "ln", "dd", "install", "truncate", "tee",
];

fn simple_writes(
    cmd: &crate::shell_ast::Command,
    workspace: &std::path::Path,
    _writable: &[std::path::PathBuf],
    out: &mut Vec<PathBuf>,
) -> PathBuf {
    let mut cwd = workspace.to_path_buf();
    if cmd.program == "cd" {
        if let Some(target) = cmd.args.first() {
            cwd = resolve_against(target, &cwd);
        }
        return cwd;
    }
    // Redirects are writes wherever the verb points.
    for r in &cmd.redirects {
        if r.write {
            out.push(resolve_against(&r.target, &cwd));
        }
    }
    // Modelled verbs (and the two in-place editors, whose flag is the only
    // difference between reading and rewriting a file).
    let in_place_editor = matches!(cmd.program.as_str(), "sed" | "perl" | "ruby")
        && cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("-pi"));
    if WRITE_VERBS.contains(&cmd.program.as_str()) || in_place_editor {
        for a in &cmd.args {
            if a.starts_with('-') || a.contains("://") {
                continue;
            }
            out.push(resolve_against(a, &cwd));
        }
    }
    cwd
}

/// A shell word → the path it names, with `~` expanded and relatives placed
/// under `cwd`. Good enough to compare scopes; it never touches the fs.
fn resolve_against(word: &str, cwd: &std::path::Path) -> PathBuf {
    let w = word.trim_matches(['\'', '"']);
    if w == "~" || w.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(w.trim_start_matches("~/"));
        }
    }
    let p = PathBuf::from(w);
    if p.is_absolute() {
        return p;
    }
    let joined = cwd.join(p);
    // Normalize `..` lexically — the target may not exist.
    let mut norm = PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                norm.pop();
            }
            std::path::Component::CurDir => {}
            c => norm.push(c),
        }
    }
    norm
}

/// Every path the command *names*, whatever verb it applies to it.
///
/// The audit's blind spot is a form it did not classify as a write (`sed -i`,
/// `tee`, `patch`, `git checkout`, an arbitrary program), never a path it
/// failed to see. [`writes_out_of_scope`] answers "which recognized writes
/// escape"; this answers "which places does this line reach at all" — the
/// fallback for a caller that has no other way to contain the command.
pub fn paths_named(cmd: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_named(&parse(cmd), &mut out);
    out
}

fn collect_named(node: &Node, out: &mut Vec<PathBuf>) {
    match node {
        Node::And(a, b) | Node::Or(a, b) | Node::Seq(a, b) => {
            collect_named(a, out);
            collect_named(b, out);
        }
        Node::Pipe(cmds) => {
            for c in cmds {
                collect_named(c, out);
            }
        }
        Node::Subshell(inner) => collect_named(inner, out),
        Node::Simple(cmd) => {
            for word in std::iter::once(&cmd.program).chain(cmd.args.iter()) {
                push_path_word(word, out);
            }
            for r in &cmd.redirects {
                push_path_word(&r.target, out);
            }
            for sub in &cmd.substitutions {
                collect_named(sub, out);
            }
        }
    }
}

/// A word may be a path, carry one (`--target=/x/y`), or embed one inside a
/// quoted payload (`python -c 'open("/w/x","w")'`). All three count: the point
/// is to notice the place, not to understand the program.
fn push_path_word(word: &str, out: &mut Vec<PathBuf>) {
    // A URL is not a path; `https://…` would otherwise read as `/…`.
    if word.contains("://") {
        return;
    }
    let after_eq = word.split_once('=').map(|(_, v)| v).unwrap_or(word);
    if let Some(p) = as_path(after_eq) {
        out.push(p);
        return;
    }
    // Embedded in a payload: take every `/…` or `~/…` run out of it.
    for (i, _) in word.match_indices('/') {
        let head = &word[..i];
        let boundary = head.is_empty()
            || head.ends_with(['\'', '"', '(', ',', ';', '=', '|', ' ']);
        let root_ish = i > 0 && word[..i].ends_with('~');
        if !(boundary || root_ish) {
            continue;
        }
        let start = if root_ish { i - 1 } else { i };
        let rest = &word[start..];
        let end = rest
            .find(['\'', '"', ')', ',', ';', '|', ' '])
            .unwrap_or(rest.len());
        let frag = &rest[..end];
        if frag.len() > 1 {
            out.push(PathBuf::from(frag));
        }
    }
}

/// A word as a path: absolute, `~/`-rooted, or a `..`-relative climb.
fn as_path(word: &str) -> Option<PathBuf> {
    let w = word.trim_matches(['\'', '"']);
    if w.starts_with('/') && w.len() > 1 {
        return Some(PathBuf::from(w));
    }
    if w == "~" || w.starts_with("~/") {
        return Some(PathBuf::from(w));
    }
    if w.starts_with("../") || w == ".." {
        return Some(PathBuf::from(w));
    }
    None
}

/// Human-readable reasons for the approval card, derived from capabilities.
fn reasons_for(caps: &[Capability]) -> Vec<String> {
    let mut out = Vec::new();
    for c in caps {
        let r = match c {
            Capability::DeleteFile { path, recursive } => format!(
                "deletes {}{}",
                path.display(),
                if *recursive { " recursively" } else { "" }
            ),
            Capability::WriteFile { path } | Capability::AppendFile { path } => {
                format!("writes {}", path.display())
            }
            Capability::CreateFile { path } | Capability::CreateDirectory { path } => {
                format!("creates {}", path.display())
            }
            Capability::RenameFile { from, to } => {
                format!("moves {} → {}", from.display(), to.display())
            }
            Capability::ExecuteScript => "executes a script".to_string(),
            Capability::Network { target } => format!(
                "network access{}",
                target
                    .as_ref()
                    .map(|t| format!(" to {t}"))
                    .unwrap_or_default()
            ),
            Capability::PackageInstall { manager } => format!("installs packages via {manager}"),
            Capability::PrivilegeEscalation => "escalates privileges (sudo)".to_string(),
            Capability::DeviceAccess { path } => format!("accesses device {}", path.display()),
            Capability::ProcessControl => "controls processes".to_string(),
            Capability::DestructiveVcs { operation } => {
                format!("rewrites/discards git state ({operation})")
            }
            Capability::OutOfScope { path } => {
                format!("touches {} (outside the workspace)", path.display())
            }
            Capability::Runtime { toolchain } => format!("needs the {toolchain:?} toolchain"),
            Capability::ReadFile { .. } | Capability::Execute { .. } => continue,
        };
        out.push(r);
    }
    out
}

/// Is `path` outside `workspace` and every `granted` root? Resolves a relative
/// path against the workspace root and normalizes `.`/`..` components so
/// `../../etc/shadow` can't sneak through as "relative".
fn is_out_of_scope<'a>(
    path: &std::path::Path,
    workspace: &std::path::Path,
    mut granted: impl Iterator<Item = &'a std::path::PathBuf>,
) -> bool {
    use std::path::{Component, PathBuf};
    // Resolve relative paths against the workspace, then normalize so a
    // `..` can't climb above the root.
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let mut normalized = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            c => normalized.push(c),
        }
    }
    let s = normalized.to_string_lossy();
    // Sensitive system + secret dirs are always out of scope.
    let sensitive = [
        "/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev", "/root", "/var", "/lib",
    ];
    if sensitive
        .iter()
        .any(|d| s == *d || s.starts_with(&format!("{d}/")))
        || s.contains("/.ssh")
        || s.contains("/.gnupg")
        || s.contains("/.aws")
    {
        return true;
    }
    // Component-wise prefix check (not string prefix — `/proj_evil` must not
    // match `/proj`).
    !normalized.starts_with(workspace) && !granted.any(|r| normalized.starts_with(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rm_rf_root_is_critical_with_required_snapshot() {
        let v = audit_command("rm -rf /");
        assert_eq!(v.level, AuditLevel::Critical);
        assert_eq!(v.risk, RiskLevel::Critical);
        assert_eq!(v.force_snapshot, Some(SnapshotMode::Required));
    }

    #[test]
    fn force_push_is_destructive_vcs_elevated() {
        // git push --force → DestructiveVcs + Network → High → Elevated
        // (NOT NetworkMutating — that's the package-install tier).
        let v = audit_command("git push --force origin main");
        assert_eq!(v.level, AuditLevel::Elevated);
        assert_eq!(v.risk, RiskLevel::High);
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::DestructiveVcs { .. })));
    }

    #[test]
    fn git_reset_hard_is_destructive() {
        let v = audit_command("git reset --hard HEAD~3");
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::DestructiveVcs { .. })));
        assert_eq!(v.risk, RiskLevel::High);
    }

    #[test]
    fn npm_install_needs_network_prompt() {
        let v = audit_command("npm install lodash");
        assert_eq!(v.risk, RiskLevel::High);
        assert!(v.needs_network_prompt);
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::PackageInstall { .. })));
    }

    #[test]
    fn clean_command_is_normal() {
        assert_eq!(audit_command("cargo test").level, AuditLevel::Normal);
        assert_eq!(audit_command("ls -la").level, AuditLevel::Normal);
    }

    #[test]
    fn out_of_scope_write_is_flagged() {
        let ws = PathBuf::from("/home/u/proj");
        let v = audit_command_scoped("cat a > /etc/out", Some(&ws));
        assert_eq!(v.level, AuditLevel::ScopeViolation);
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::OutOfScope { .. })));
    }

    #[test]
    fn relative_traversal_is_out_of_scope() {
        // ../../etc/shadow escapes the workspace even though it's "relative".
        let ws = PathBuf::from("/home/u/proj");
        let v = audit_command_scoped("cat ../../etc/shadow", Some(&ws));
        assert!(
            v.capabilities
                .iter()
                .any(|c| matches!(c, Capability::OutOfScope { .. })),
            "relative traversal must flag OutOfScope"
        );
    }

    #[test]
    fn prefix_sibling_is_out_of_scope() {
        // /home/u/proj_evil must NOT match workspace /home/u/proj —
        // Path::starts_with is component-wise, not a string prefix.
        let ws = PathBuf::from("/home/u/proj");
        let v = audit_command_scoped("cat /home/u/proj_evil/x", Some(&ws));
        assert!(
            v.capabilities
                .iter()
                .any(|c| matches!(c, Capability::OutOfScope { .. })),
            "/proj_evil must not match /proj"
        );
    }

    #[test]
    fn granted_roots_are_in_scope_by_access() {
        let ws = PathBuf::from("/home/u/proj");
        let rw = vec![PathBuf::from("/home/u/kernel")];
        let ro = vec![PathBuf::from("/home/u/docs")];
        let scoped = |cmd: &str| {
            audit_command_rooted(cmd, Some(&ws), &ro, &rw)
                .capabilities
                .iter()
                .any(|c| matches!(c, Capability::OutOfScope { .. }))
        };
        assert!(!scoped("cat /home/u/kernel/a.rs"));
        assert!(!scoped("echo x > /home/u/kernel/a.rs"));
        assert!(!scoped("cat /home/u/docs/a.md"));
        assert!(scoped("echo x > /home/u/docs/a.md"), "read-only root takes no writes");
        assert!(scoped("cat /home/u/other/a"));
        // `/kernel_evil` is not `/kernel`.
        assert!(scoped("cat /home/u/kernel_evil/a"));
    }

    #[test]
    fn sensitive_dirs_stay_out_of_scope_even_when_granted() {
        let ws = PathBuf::from("/home/u/proj");
        let v = audit_command_rooted("cat /etc/passwd", Some(&ws), &[], &[PathBuf::from("/etc")]);
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::OutOfScope { .. })));
    }

    #[test]
    fn writes_out_of_scope_lists_ungranted_writes_only() {
        let ws = PathBuf::from("/home/u/proj");
        let rw = vec![PathBuf::from("/home/u/kernel")];
        assert!(writes_out_of_scope("cat /home/u/other/a", &ws, &rw).is_empty());
        assert!(writes_out_of_scope("echo x > out.txt", &ws, &rw).is_empty());
        assert!(writes_out_of_scope("echo x > /home/u/kernel/a", &ws, &rw).is_empty());
        assert_eq!(
            writes_out_of_scope("echo x > /home/u/other/a", &ws, &rw),
            [PathBuf::from("/home/u/other/a")]
        );
        assert!(!writes_out_of_scope("rm -rf ../other", &ws, &rw).is_empty());
    }

    #[test]
    fn rm_recursive_flag_variants() {
        for cmd in [
            "rm -rf /tmp/x",
            "rm --recursive /tmp/x",
            "rm -r /tmp/x",
            "rm -Rf /tmp/x",
        ] {
            let v = audit_command(cmd);
            assert!(
                v.capabilities.iter().any(|c| matches!(
                    c,
                    Capability::DeleteFile {
                        recursive: true,
                        ..
                    }
                )),
                "{cmd} should mark recursive"
            );
        }
    }

    #[test]
    fn python_dash_and_bash_s_are_scripts() {
        assert!(audit_command("python - < x.py")
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::ExecuteScript)));
        assert!(audit_command("bash -s < x.sh")
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::ExecuteScript)));
    }

    #[test]
    fn sudo_escalates() {
        let v = audit_command("sudo apt update");
        assert!(v
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::PrivilegeEscalation)));
        assert_eq!(v.risk, RiskLevel::High);
    }
}
