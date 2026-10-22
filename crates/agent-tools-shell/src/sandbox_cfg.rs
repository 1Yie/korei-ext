//! Shared audit → sandbox-config derivation.
//!
//! Both `bash` and `smart_test_runner` run a shell command through
//! `ctx.sandbox()`; the mount/network/resource policy must be identical between
//! them (a test run is not a lesser command), so the derivation lives here
//! instead of in either tool.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_capabilities::{RootAccess, SandboxCtx, WorkspaceCtx};
use agent_tool::ToolError;

/// The context's linked roots, split by access: `(readable, writable)`.
pub fn linked_mounts<C: WorkspaceCtx>(ctx: &C) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut read = Vec::new();
    let mut write = Vec::new();
    for r in ctx.linked_roots().iter() {
        match r.access {
            RootAccess::Read => read.push(r.path.clone()),
            RootAccess::ReadWrite => write.push(r.path.clone()),
        }
    }
    (read, write)
}

/// Is anything actually containing the command's reach? The `none` backend —
/// what the host installs when the sandbox is off or unavailable — is not.
pub fn is_unconfined<C: SandboxCtx>(ctx: &C) -> bool {
    ctx.sandbox().map(|s| s.id() == "none").unwrap_or(true)
}

/// Refuse a shell command that writes outside every granted root when nothing
/// can contain it.
///
/// The file tools answer a path outside their reach with `PathEscape`; without
/// a sandbox the shell has to answer the same way, or "the workspace boundary"
/// would mean two different things depending on which tool the model picked —
/// and the shell would be the way around every grant this host hands out.
/// Reads are left alone: reading a dependency's source outside the tree is
/// ordinary shell work, and the sandbox-less run may still do it.
pub fn refuse_unconfined_write<C: WorkspaceCtx + SandboxCtx>(
    ctx: &C,
    command: &str,
) -> Result<(), ToolError> {
    if !is_unconfined(ctx) {
        return Ok(());
    }
    let root = ctx.root()?;
    let (_, writable) = linked_mounts(ctx);
    let outside = agent_sandbox::writes_out_of_scope(command, root, &writable);
    if outside.is_empty() {
        return Ok(());
    }
    let list = outside
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(ToolError::Failed(format!(
        "refused — no sandbox is active, so a write outside the workspace cannot be contained: \
         {list} is outside it and outside every read-write linked workspace. Use the file tools, \
         or ask the user to link that directory."
    )))
}

/// Audit `command` against the workspace and its linked roots and derive the
/// run's sandbox config — the one path every process tool takes, so a linked
/// workspace is in scope and mounted the same way for `bash`, the test runner,
/// background jobs and office.
pub fn prepare<C: WorkspaceCtx + SandboxCtx>(
    ctx: &C,
    command: &str,
    timeout: Duration,
) -> Result<(agent_sandbox::AuditResult, agent_sandbox::SandboxConfig), ToolError> {
    let root = ctx.root()?;
    let (read, write) = linked_mounts(ctx);
    let verdict = agent_sandbox::audit_command_rooted(command, Some(root), &read, &write);
    let mut limits = ctx.sandbox_limits();
    for p in read {
        if !limits.extra_ro_mounts.contains(&p) {
            limits.extra_ro_mounts.push(p);
        }
    }
    for p in write {
        if !limits.extra_rw_mounts.contains(&p) {
            limits.extra_rw_mounts.push(p);
        }
    }
    let cfg = sandbox_config(&verdict, root, timeout, &limits);
    Ok((verdict, cfg))
}

/// Audit verdict → sandbox configuration.
///
/// Policy → SandboxPlan → SandboxConfig: the plan derives network/fs limits
/// from the audit's capabilities (Network/PackageInstall flips `allow_network`;
/// High+ risk forces a CoW snapshot), and the L2 backend consumes the config.
/// Split out from the tools' `exec` so the mount policy is assertable without
/// spawning anything.
pub fn sandbox_config(
    verdict: &agent_sandbox::AuditResult,
    workspace_root: &Path,
    timeout: Duration,
    limits: &agent_sandbox::SandboxLimits,
) -> agent_sandbox::SandboxConfig {
    // Canonicalize before the plan: the deny_write set must match the path
    // spelling the backend binds (it canonicalizes too).
    let workspace_root = &workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let plan = agent_sandbox::plan::SandboxPlan::from_audit(
        verdict,
        workspace_root.clone(),
        std::env::temp_dir().join(format!("agent-sandbox-{:x}", std::process::id())),
    );
    // AllowHosts maps to proxied egress (not "allow all"): the host-side
    // proxy enforces the domain list; `allow_network` stays false so the
    // backend still unshares the net and the proxy socket is the only way
    // out. `Allow` keeps full shared network.
    let (allow_network, allowed_domains) = match &plan.network {
        agent_sandbox::plan::NetworkPolicy::Allow => (true, Vec::new()),
        agent_sandbox::plan::NetworkPolicy::AllowHosts(h) => (false, h.clone()),
        agent_sandbox::plan::NetworkPolicy::Deny => (false, Vec::new()),
    };
    let mut cfg = agent_sandbox::SandboxConfig {
        workspace_dir: workspace_root.to_path_buf(),
        allow_network,
        allowed_domains,
        deny_read: plan.filesystem.deny.clone(),
        deny_write: plan.filesystem.deny_write.clone(),
        max_memory_mb: plan.processes.max_memory_mb,
        max_processes: plan.processes.max_processes,
        timeout_secs: timeout.as_secs(),
        snapshot: plan.snapshot,
        environment: plan.environment.clone(),
        ..Default::default()
    };
    // Host-supplied read-only mounts (e.g. the user's skill roots, which live
    // outside the workspace) and user overrides from the settings UI fold in last. — a forced network
    // policy / memory / process cap beats the audit plan's defaults.
    agent_sandbox::apply_limits(&mut cfg, limits);
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only mounts are host policy: whatever the host injects must reach
    /// the sandbox verbatim, and the kernel adds none of its own. Skill roots
    /// are read-only on purpose — a skill must not rewrite its instructions.
    #[test]
    fn sandbox_config_mounts_host_injected_roots_read_only() {
        let root = Path::new("/tmp/ws");
        let verdict = agent_sandbox::audit_command_scoped("ls", Some(root));
        let skills = vec![std::path::PathBuf::from("/home/u/.skills")];
        let limits = agent_sandbox::SandboxLimits {
            extra_ro_mounts: skills.clone(),
            ..Default::default()
        };
        let cfg = sandbox_config(&verdict, root, Duration::from_secs(30), &limits);

        assert_eq!(cfg.extra_ro_mounts, skills);
        assert!(
            cfg.extra_rw_mounts.is_empty(),
            "skills must not be writable"
        );
        assert_eq!(cfg.workspace_dir, root);
    }

    /// No host injection means no extra mounts: the kernel does not reach for
    /// `$HOME` on its own.
    #[test]
    fn sandbox_config_without_host_mounts_adds_none() {
        let root = Path::new("/tmp/ws");
        let verdict = agent_sandbox::audit_command_scoped("ls", Some(root));
        let cfg = sandbox_config(
            &verdict,
            root,
            Duration::from_secs(30),
            &agent_sandbox::SandboxLimits::default(),
        );
        assert!(cfg.extra_ro_mounts.is_empty());
    }

    /// Linked roots reach the mounts by access, and a read-write one is in
    /// scope for the audit.
    #[test]
    fn prepare_mounts_linked_roots_by_access() {
        use agent_capabilities::{LinkedRoot, LinkedRoots};
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let [ws, rw, ro] = ["ws", "rw", "ro"].map(|n| base.join(n));
        for d in [&ws, &rw, &ro] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir_all(rw.join(".git/hooks")).unwrap();
        let roots = std::sync::Arc::new(LinkedRoots::default());
        roots.set(vec![
            LinkedRoot {
                path: rw.clone(),
                access: RootAccess::ReadWrite,
            },
            LinkedRoot {
                path: ro.clone(),
                access: RootAccess::Read,
            },
        ]);
        let mut ctx = crate::TestCtx::with_sandbox(&ws, std::sync::Arc::new(agent_sandbox::NoneBackend));
        ctx.install_linked_roots(roots);
        let cmd = format!("echo x > {}/a.txt", rw.display());
        let (verdict, cfg) = prepare(&ctx, &cmd, Duration::from_secs(5)).unwrap();
        assert_ne!(verdict.level, agent_sandbox::AuditLevel::ScopeViolation);
        assert_eq!(cfg.extra_rw_mounts, [rw.clone()]);
        assert_eq!(cfg.extra_ro_mounts, [ro.clone()]);
        assert!(cfg.deny_write.contains(&rw.join(".git/hooks")));
        let cmd = format!("echo x > {}/a.txt", ro.display());
        let (verdict, _) = prepare(&ctx, &cmd, Duration::from_secs(5)).unwrap();
        assert_eq!(verdict.level, agent_sandbox::AuditLevel::ScopeViolation);
    }

    fn unconfined_ctx(ws: &std::path::Path) -> crate::TestCtx {
        crate::TestCtx::with_sandbox(ws, std::sync::Arc::new(agent_sandbox::NoneBackend))
    }

    /// The complaint this rule exists for: with no sandbox, `bash` used to be
    /// able to edit another workspace silently. It now refuses — the same
    /// answer the file tools give — and names the workspace it would have
    /// reached, so the model can ask for a link instead of guessing.
    #[test]
    fn an_unconfined_shell_refuses_writes_outside_the_granted_roots() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let [ws, other] = ["ws", "other"].map(|n| base.join(n));
        for d in [&ws, &other] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f.rs"), "x\n").unwrap();
        }
        let ctx = unconfined_ctx(&ws);
        let other_file = other.join("f.rs");
        // A write the audit recognized is refused outright: with nothing to
        // contain it, running it would edit another workspace silently.
        for cmd in [
            format!("echo pwned > {}", other_file.display()),
            format!("cd {} && rm f.rs", other.display()),
            format!("sed -i s/x/y/ {}", other_file.display()),
            format!("cp {0} {0}.bak", other_file.display()),
        ] {
            let err = refuse_unconfined_write(&ctx, &cmd)
                .expect_err(&format!("must refuse: {cmd}"))
                .to_string();
            assert!(err.contains("refused"), "{cmd}: {err}");
            assert!(err.contains(&*other.display().to_string()), "{cmd}: {err}");
            assert!(err.contains("link"), "{cmd}: {err}");
        }
        // Reads and workspace-local work stay allowed — the rule is about
        // writing somewhere this process cannot be contained.
        for cmd in [
            format!("cat {}", other_file.display()),
            format!("grep -n x {}", other_file.display()),
            "cargo test --offline".to_string(),
            "echo hi > notes.txt".to_string(),
            format!("echo hi > {}/notes.txt", ws.display()),
        ] {
            assert!(
                refuse_unconfined_write(&ctx, &cmd).is_ok(),
                "must allow: {cmd}"
            );
        }

        // A verb the audit does not model (`sed -i`, `tee`, `patch`) cannot be
        // proven harmless, so the permission gate asks instead of refusing —
        // the user's click is the authorization, and a legitimate read through
        // the same kind of verb never turns into an edit.
        for cmd in [
            format!("patch -p0 < {}", other_file.display()),
        ] {
            assert!(
                refuse_unconfined_write(&ctx, &cmd).is_ok(),
                "not refused, it must ask: {cmd}"
            );
            assert_eq!(
                crate::risk::classify_in(&cmd, &ctx),
                agent_tool::CallRisk::RequiresApproval,
                "must ask: {cmd}"
            );
        }
        // A read through the readonly verbs is not a question.
        assert_eq!(
            crate::risk::classify_in(&format!("cat {}", other_file.display()), &ctx),
            agent_tool::CallRisk::Readonly
        );
    }

    /// A linked read-write root is inside the boundary again — the grant is
    /// what makes cross-repository work possible without a sandbox.
    #[test]
    fn a_linked_root_lifts_the_refusal_for_writes() {
        use agent_capabilities::{LinkedRoot, LinkedRoots, RootAccess};
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let [ws, kernel] = ["ws", "kernel"].map(|n| base.join(n));
        for d in [&ws, &kernel] {
            std::fs::create_dir_all(d).unwrap();
        }
        let roots = std::sync::Arc::new(LinkedRoots::default());
        roots.set(vec![LinkedRoot {
            path: kernel.clone(),
            access: RootAccess::ReadWrite,
        }]);
        let mut ctx = unconfined_ctx(&ws);
        ctx.install_linked_roots(roots);
        let cmd = format!("echo hi > {}/lib.rs", kernel.display());
        assert!(refuse_unconfined_write(&ctx, &cmd).is_ok(), "{cmd}");

        // A read-only link still refuses the write, but reads it.
        let roots = std::sync::Arc::new(LinkedRoots::default());
        roots.set(vec![LinkedRoot {
            path: kernel.clone(),
            access: RootAccess::Read,
        }]);
        let mut ctx = unconfined_ctx(&ws);
        ctx.install_linked_roots(roots);
        assert!(refuse_unconfined_write(&ctx, &cmd).is_err());
    }
}
