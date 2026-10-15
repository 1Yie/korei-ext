//! Audit engine — turns a parsed command into an `AuditResult` the policy
//! engine + approval card consume. NOT a security boundary: it explains
//! risk and proposes capabilities; the sandbox enforces regardless of what
//! audit missed. Replaces the old string-blacklist matcher — now driven by
//! `shell_ast` → `capability` extraction → risk classification.

use crate::capability::{extract, risk_of, Capability, RiskLevel};
use crate::shell_ast::parse;
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
    let ast = parse(cmd);
    let mut caps = extract(&ast);

    // Mark out-of-scope file caps — a write/delete/read outside the
    // workspace root is a scope violation, not a generic file op.
    if let Some(ws) = workspace {
        for c in &mut caps {
            let path = match c {
                Capability::WriteFile { path }
                | Capability::AppendFile { path }
                | Capability::DeleteFile { path, .. }
                | Capability::CreateFile { path }
                | Capability::CreateDirectory { path }
                | Capability::ReadFile { path } => Some(path.clone()),
                _ => None,
            };
            if let Some(p) = path {
                if is_out_of_scope(&p, ws) {
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

/// Is `path` outside `workspace`? Resolves a relative path against the
/// workspace root and normalizes `.`/`..` components so `../../etc/shadow`
/// can't sneak through as "relative".
fn is_out_of_scope(path: &std::path::Path, workspace: &std::path::Path) -> bool {
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
    !normalized.starts_with(workspace)
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
