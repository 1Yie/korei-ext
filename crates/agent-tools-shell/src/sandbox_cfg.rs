//! Shared audit → sandbox-config derivation.
//!
//! Both `bash` and `smart_test_runner` run a shell command through
//! `ctx.sandbox()`; the mount/network/resource policy must be identical between
//! them (a test run is not a lesser command), so the derivation lives here
//! instead of in either tool.

use std::path::Path;
use std::time::Duration;

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
}
