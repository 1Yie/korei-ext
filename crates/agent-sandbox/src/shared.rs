//! `shared.rs` — platform-common pieces of the srt-derived model.
//!
//! The fs deny sets, writable cache list, run dir, global egress proxy
//! and proxy-env builder are identical in intent on Linux (bwrap) and
//! macOS (seatbelt) — they differ only in *mechanism* (bind-mounts vs
//! SBPL rules, unix-socket + socat vs loopback TCP). Keeping the policy
//! data here prevents the two backends drifting on "what counts as
//! sensitive".

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::netpolicy::EgressPolicy;
use crate::proxy::SandboxProxy;
use crate::traits::SandboxConfig;

/// Sensitive dirs/files under HOME that must not be readable inside the
/// sandbox — bwrap masks them, seatbelt denies them last-match.
pub(crate) const SENSITIVE_NAMES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".bash_history",
    ".zsh_history",
    ".history",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".npmrc",
    ".netrc",
    // Agent-harness state: credentials (and, for pi, every session
    // transcript) live next to the skills these sandboxes expose.
    ".pi/agent/auth.json",
    ".pi/agent/.env",
    ".pi/agent/sessions",
    ".claude/.credentials.json",
    ".codex/auth.json",
    // Mounted-by-name caches whose subtrees hold real credentials.
    ".cache/mozilla",
    ".cache/firefox",
    ".cache/google-chrome",
    ".cache/chromium",
    ".cache/gcloud",
    ".cache/hub",
    ".cache/gh",
    ".cache/msal",
    ".cache/azure",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    ".config/yarn/config.yml",
    ".config/gh",
    ".config/gcloud",
    ".docker",
    ".git-credentials",
    ".pypirc",
    ".gem/credentials",
    ".terraform.d",
    ".local/share/keyrings",
    ".password-store",
];

/// Writable toolchain caches under HOME — package installs must land
/// somewhere; caches are content-addressable junk, not source of truth.
/// Sensitive children are masked/denied afterwards.
pub(crate) const WRITABLE_CACHE_DIRS: &[&str] = &[
    ".cache",
    ".npm",
    ".cargo/registry",
    ".cargo/git",
    "go/pkg",
    ".local/share/uv",
    ".local/share/pnpm",
    ".bun/install/cache",
    ".m2/repository",
];

pub(crate) fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Sensitive paths that exist on host and must be hidden — the built-in
/// denyRead set.
pub(crate) fn sensitive_masks() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = dirs_home() {
        for name in SENSITIVE_NAMES {
            let p = home.join(name);
            if p.exists() {
                out.push(p);
            }
        }
    }
    out
}

/// Writable toolchain caches that exist.
pub(crate) fn cache_mounts() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = dirs_home() {
        for name in WRITABLE_CACHE_DIRS {
            let p = home.join(name);
            if p.is_dir() {
                out.push(p);
            }
        }
    }
    out
}

/// Per-run scratch dir. Linux uses the tmpfs-scoped XDG runtime dir
/// (auto-cleaned on logout); elsewhere falls back to the system temp.
pub(crate) fn run_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let uid = libc_uid();
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
        let dir = xdg.join(format!("agent-run-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
    #[cfg(not(target_os = "linux"))]
    {
        let dir = std::env::temp_dir().join(format!("agent-run-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}

/// `getuid` without pulling libc — read `/proc/self/status`'s Uid line.
#[cfg(target_os = "linux")]
fn libc_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(1000)
}

/// The one process-global egress proxy — its unix socket lives in the
/// run dir (bind-mounted into bwrap sandboxes); macOS children reach it
/// over the loopback TCP port directly, no bridging needed.
static PROXY: OnceLock<Option<Arc<SandboxProxy>>> = OnceLock::new();

pub(crate) fn global_proxy(dir: &Path) -> Option<Arc<SandboxProxy>> {
    PROXY
        .get_or_init(|| match SandboxProxy::new(dir) {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                tracing::warn!(?e, "sandbox egress proxy failed to bind");
                None
            }
        })
        .clone()
}

/// A registered proxied run: the key carries into the child's proxy env
/// vars; `unregister` + `denials_for` pair with it when the run ends.
pub(crate) struct ProxiedRun {
    pub proxy: Arc<SandboxProxy>,
    pub key: String,
    pub user: String,
    pub pass: String,
}

/// How a run's network is provided. Deny always beats allow, so a denylist
/// can only be honored by a path that inspects traffic — the egress proxy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NetMode {
    /// Shared host network, no policy (`allow_network` and no denylist).
    Open,
    /// Own netns / no network rules, nothing reachable.
    Closed,
    /// Only reachable through the egress proxy.
    Proxied,
}

pub(crate) fn net_mode(cfg: &SandboxConfig) -> NetMode {
    if cfg.allow_network {
        if cfg.denied_domains.is_empty() {
            NetMode::Open
        } else {
            // "allow everything except …" cannot be expressed by sharing the
            // host network — that would ignore the denylist entirely.
            NetMode::Proxied
        }
    } else if cfg.allowed_domains.is_empty() {
        NetMode::Closed
    } else {
        NetMode::Proxied
    }
}

/// The allowlist the proxy enforces for a `Proxied` run: the configured hosts,
/// or everything (`*`) when the run was allowed network and only has a denylist.
pub(crate) fn egress_allow_list(cfg: &SandboxConfig) -> Vec<String> {
    if cfg.allow_network {
        vec!["*".to_string()]
    } else {
        cfg.allowed_domains.clone()
    }
}

/// `Proxied` run → register this run's egress policy on the
/// global proxy. `None` means "degrade to full deny + warn" (proxy dead,
/// bad pattern, or no tokio runtime to host accept loops) — callers turn
/// that into their platform's deny plan, never silently allow.
pub(crate) fn register_egress(cfg: &SandboxConfig) -> Option<ProxiedRun> {
    let dir = run_dir();
    let proxy = global_proxy(&dir)?;
    let policy = match EgressPolicy::from_strs(&egress_allow_list(cfg), &cfg.denied_domains) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(?e, "sandbox: bad domain pattern — degrading to full deny");
            return None;
        }
    };
    let key = proxy.register(policy)?;
    let (user, pass) = proxy.auth(&key);
    Some(ProxiedRun {
        proxy,
        key,
        user,
        pass,
    })
}

/// `*_PROXY` env vars for a proxied run — port of srt's
/// `generateProxyEnvVars`. `endpoint` is `host:port` of the proxy from
/// the child's viewpoint: `localhost:3128` on Linux (in-sandbox socat),
/// `127.0.0.1:<tcp_port>` on macOS (loopback reaches the mux directly,
/// and one port serves both protocols since the mux sniffs the wire).
/// `ssh_proxy` carries the platform's git-over-ssh ProxyCommand (Linux
/// socat PROXY); `None` omits `GIT_SSH_COMMAND` entirely.
pub(crate) fn proxy_env_vars(
    user: &str,
    pass: &str,
    endpoint: &str,
    ssh_proxy: Option<&str>,
) -> Vec<(String, String)> {
    let http = format!("http://{user}:{pass}@{endpoint}");
    let socks = format!("socks5h://{user}:{pass}@{endpoint}");
    let no_proxy = "localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

    let mut v = vec![
        ("AGENT_SANDBOXED".into(), "1".into()),
        ("NO_PROXY".into(), no_proxy.into()),
        ("no_proxy".into(), no_proxy.into()),
        ("HTTP_PROXY".into(), http.clone()),
        ("HTTPS_PROXY".into(), http.clone()),
        ("http_proxy".into(), http.clone()),
        ("https_proxy".into(), http.clone()),
        // HTTP (not socks5h) on the general-purpose vars: httpx eagerly
        // imports socksio on socks5h://, gRPC only speaks CONNECT — same
        // reasoning as srt. The mux sniffs the wire; either protocol
        // reaches the right handler.
        ("ALL_PROXY".into(), http.clone()),
        ("all_proxy".into(), http.clone()),
        ("GRPC_PROXY".into(), http.clone()),
        ("grpc_proxy".into(), http.clone()),
        ("FTP_PROXY".into(), socks.clone()),
        ("ftp_proxy".into(), socks),
        ("DOCKER_HTTP_PROXY".into(), http.clone()),
        ("DOCKER_HTTPS_PROXY".into(), http.clone()),
        // git never gets a 407 → never invokes a credential helper for the
        // proxy URL. The single quotes are literal — git config syntax.
        (
            "GIT_CONFIG_PARAMETERS".into(),
            "'http.proxyAuthMethod=basic'".into(),
        ),
    ];
    if let Some(pxy) = ssh_proxy {
        v.push(("GIT_SSH_COMMAND".into(), pxy.into()));
    }
    // CLOUDSDK wants decomposed fields.
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        v.push(("CLOUDSDK_PROXY_TYPE".into(), "http".into()));
        v.push(("CLOUDSDK_PROXY_ADDRESS".into(), host.into()));
        v.push(("CLOUDSDK_PROXY_PORT".into(), port.into()));
    }
    v
}

/// `"host:port — reason"` strings for `CommandOutput.sandbox_denials` —
/// the escalation channel both backends surface to the model.
pub(crate) fn format_denials(denials: &[crate::proxy::Denial]) -> Vec<String> {
    denials
        .iter()
        .map(|d| format!("{}:{} — {}", d.host, d.port, d.reason))
        .collect()
}

#[cfg(test)]
mod net_mode_tests {
    use super::*;

    fn cfg(allow: bool, allowed: &[&str], denied: &[&str]) -> SandboxConfig {
        SandboxConfig {
            allow_network: allow,
            allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
            denied_domains: denied.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn denylist_forces_the_proxy_even_when_network_is_allowed() {
        assert_eq!(net_mode(&cfg(true, &[], &[])), NetMode::Open);
        assert_eq!(net_mode(&cfg(true, &[], &["evil.com"])), NetMode::Proxied);
        assert_eq!(net_mode(&cfg(false, &[], &["evil.com"])), NetMode::Closed);
        assert_eq!(net_mode(&cfg(false, &["a.com"], &[])), NetMode::Proxied);
    }

    #[test]
    fn allow_all_with_denylist_is_wildcard_minus_denied() {
        let c = cfg(true, &[], &["evil.com"]);
        let pol = EgressPolicy::from_strs(&egress_allow_list(&c), &c.denied_domains).unwrap();
        assert!(matches!(
            pol.decide("evil.com", 443),
            crate::netpolicy::Decision::Deny(_)
        ));
        assert_eq!(
            pol.decide("example.org", 443),
            crate::netpolicy::Decision::Allow
        );
    }
}
