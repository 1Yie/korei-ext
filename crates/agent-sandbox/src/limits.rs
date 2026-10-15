//! The override layer over [`SandboxConfig`]: what the user turned on, off or
//! capped, as opposed to what the command's audit plan derived.
//!
//! It lives beside `SandboxConfig` because it is the same domain. The *policy*
//! — which limits are live process-wide, and the master switch that names them
//! — stays with the host that owns the settings UI.

use crate::traits::SandboxConfig;

/// User overrides for sandboxed command execution.
#[derive(Debug, Clone, Default)]
pub struct SandboxLimits {
    /// Master switch — `Some(true)` = sandboxed; `None`/`Some(false)` =
    /// every process tool runs through the loud `none` backend instead
    /// (no fs/net containment, no rlimits — the same contract as machines
    /// without bwrap). Absent means the user never turned it on.
    pub enabled: Option<bool>,
    /// `None` → the command's audit plan decides (default);
    /// `Some(true)` → force-allow network; `Some(false)` → force-deny.
    pub network: Option<bool>,
    /// Per-command resident memory cap (MB) — overrides the plan's 2048.
    pub max_memory_mb: Option<u64>,
    /// Fork-bomb guard (max spawned processes) — overrides the plan's 256.
    pub max_processes: Option<u32>,
    /// Standing egress allowlist — merged into every run's
    /// `SandboxConfig.allowed_domains` on top of what the audit derived.
    pub allowed_domains: Vec<String>,
    /// Standing egress denylist — wins over every allowlist entry.
    pub denied_domains: Vec<String>,
    /// Host-chosen directories mounted read-only into every sandboxed run
    /// (e.g. the user's skill roots). Kernel never picks these itself.
    pub extra_ro_mounts: Vec<std::path::PathBuf>,
}

impl SandboxLimits {
    /// Default is OFF — a `None` slot means "the user never turned it on".
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// `"auto"` / `"allow"` / `"deny"` label for persistence + the settings UI.
    pub fn network_label(&self) -> &'static str {
        match self.network {
            Some(true) => "allow",
            Some(false) => "deny",
            None => "auto",
        }
    }
}

/// Parse a persisted/settings label back into the tri-state.
pub fn network_from_label(s: &str) -> Option<bool> {
    match s {
        "allow" => Some(true),
        "deny" => Some(false),
        _ => None,
    }
}

/// `apply_to` over an explicit snapshot — pure, so the precedence rules are
/// testable without touching the process-global overrides.
pub fn apply_limits(cfg: &mut SandboxConfig, l: &SandboxLimits) {
    if let Some(net) = l.network {
        cfg.allow_network = net;
    }
    if let Some(m) = l.max_memory_mb {
        cfg.max_memory_mb = m;
    }
    if let Some(p) = l.max_processes {
        cfg.max_processes = p;
    }
    if l.network == Some(false) {
        // Forced deny is authoritative: a non-empty allowlist makes the
        // backend route through the egress proxy instead of cutting the
        // network, so the plan's hosts must go too.
        cfg.allowed_domains.clear();
    } else {
        for d in &l.allowed_domains {
            if !cfg.allowed_domains.contains(d) {
                cfg.allowed_domains.push(d.clone());
            }
        }
    }
    for d in &l.denied_domains {
        if !cfg.denied_domains.contains(d) {
            cfg.denied_domains.push(d.clone());
        }
    }
    for m in &l.extra_ro_mounts {
        if !cfg.extra_ro_mounts.contains(m) {
            cfg.extra_ro_mounts.push(m.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An audit plan that granted package-manager hosts (`npm install`).
    fn cfg_with_plan_hosts() -> SandboxConfig {
        SandboxConfig {
            allow_network: false,
            allowed_domains: vec!["registry.npmjs.org".into()],
            ..Default::default()
        }
    }

    /// S2: "始终禁止" must mean no egress at all. Leaving the plan's host
    /// list in place makes the backend route through the proxy instead of
    /// cutting the network, so the forced deny was not a deny.
    #[test]
    fn forced_deny_drops_plan_and_standing_allowlists() {
        let mut cfg = cfg_with_plan_hosts();
        let limits = SandboxLimits {
            network: Some(false),
            allowed_domains: vec!["github.com".into()],
            ..Default::default()
        };
        apply_limits(&mut cfg, &limits);
        assert!(!cfg.allow_network);
        assert!(
            cfg.allowed_domains.is_empty(),
            "deny must leave nothing for the backend to proxy: {:?}",
            cfg.allowed_domains
        );
    }

    /// Control: auto keeps the plan's hosts and merges the standing list.
    #[test]
    fn auto_merges_allowlists_and_keeps_denylist() {
        let mut cfg = cfg_with_plan_hosts();
        let limits = SandboxLimits {
            allowed_domains: vec!["github.com".into()],
            denied_domains: vec!["evil.example".into()],
            ..Default::default()
        };
        apply_limits(&mut cfg, &limits);
        assert_eq!(cfg.allowed_domains, ["registry.npmjs.org", "github.com"]);
        assert_eq!(cfg.denied_domains, ["evil.example"]);
    }
}
