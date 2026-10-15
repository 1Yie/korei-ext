//! SandboxPlan — the structured OS-restriction set a `Policy` produces from
//! an `AuditResult`. It sits between policy ("is this allowed?") and the
//! platform backend ("how does the OS enforce it"): a plan is a portable
//! description of filesystem/network/process/device/syscall limits that a
//! Linux bwrap, macOS seatbelt, or landlock backend each translate to their
//! own mechanism. Policy never calls a Linux API directly.

use crate::capability::{Capability, RiskLevel};
use std::path::PathBuf;

/// Filesystem access the sandbox grants — the only writable roots.
#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    /// Read-write mounts (the workspace + a per-run tmp dir).
    pub rw: Vec<PathBuf>,
    /// Read-only mounts (system libs, toolchains).
    pub ro: Vec<PathBuf>,
    /// Explicitly denied paths (ssh keys, secrets, system dirs).
    pub deny: Vec<PathBuf>,
    /// Write-denied paths *inside* writable roots — config a sandboxed
    /// command could edit to widen its own access (git hooks/config/HEAD,
    /// shell rc files, agent settings, `.mcp.json`, IDE task dirs).
    /// Ported from srt's mandatory deny set (`DANGEROUS_FILES` +
    /// `DANGEROUS_DIRECTORIES` + nested `.git` scan at depth ≤ 3).
    pub deny_write: Vec<PathBuf>,
}

/// Network policy — on/off plus an optional allowlist of hosts.
#[derive(Debug, Clone)]
pub enum NetworkPolicy {
    /// No network (the default — `--unshare-net` / `deny network*`).
    Deny,
    /// Full network (a `Network`/`PackageInstall` capability flipped it on).
    Allow,
    /// Only these hosts reachable — routed through `crate::proxy` on
    /// backends that can filter (bwrap, seatbelt); the rest fall back to
    /// `Allow` with a loud note.
    AllowHosts(Vec<String>),
}

/// Process/resource limits.
#[derive(Debug, Clone)]
pub struct ProcessPolicy {
    pub max_memory_mb: u64,
    pub timeout_secs: u64,
    /// Kill the whole process tree on timeout (cgroup/pgid scope).
    pub tree_kill: bool,
    /// Max spawned processes (fork-bomb guard).
    pub max_processes: u32,
}

/// Device node access — `/dev` is denied except the standard null/zero/urandom.
#[derive(Debug, Clone)]
pub enum DevicePolicy {
    /// Standard devices only (`/dev/null`, `/dev/zero`, `/dev/urandom`, tty).
    Standard,
    /// Extra device path allowed (rare — a DeviceAccess capability asked).
    AllowDevice(PathBuf),
}

/// Syscall filtering level (seccomp).
#[derive(Debug, Clone)]
pub enum SyscallPolicy {
    /// Baseline POSIX set — file I/O, process, memory, signals.
    Baseline,
    /// Baseline + network syscalls (when NetworkPolicy allows).
    Networked,
}

/// Environment surface the sandbox exposes — derived from the command's
/// `Runtime` capabilities (the agent asks for "a node runtime", never
/// for raw env names; the policy derives which bins/vars that means).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentPolicy {
    /// Baseline env — sanitized allowlist vars + system PATH only. No dev
    /// bins, no toolchain vars. For commands with no runtime needs.
    Minimal,
    /// Full dev toolchain — every discovered dev bin on PATH + toolchain
    /// vars (`VOLTA_HOME`, `CARGO_HOME`, …). The default while the sandbox
    /// is dev-friendly: a `Runtime` capability confirms the need, but
    /// plain commands keep it too (a `make` can invoke `cargo` internally
    /// — detection can't see inside build scripts).
    DevToolchain,
    /// Only the named toolchains — strict mode. `Vec` of lowercase toolchain
    /// names (`"node"`, `"bun"`, `"rust"`).
    Select(Vec<String>),
}

/// The full plan a policy hands to a backend.
#[derive(Debug, Clone)]
pub struct SandboxPlan {
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub processes: ProcessPolicy,
    pub devices: DevicePolicy,
    pub syscalls: SyscallPolicy,
    /// Environment surface — vars + PATH the spawn receives.
    pub environment: EnvironmentPolicy,
    /// CoW snapshot — critical-risk commands force `Required`.
    pub snapshot: crate::traits::SnapshotMode,
}

impl SandboxPlan {
    /// Build a plan from an `AuditResult`'s capabilities + risk. Workspace
    /// is always rw; the system dirs are always denied; capabilities toggle
    /// network/device/process on demand. This is the bridge between "what
    /// the command needs" and "what the OS will permit".
    pub fn from_audit(
        audit: &crate::audit::AuditResult,
        workspace: PathBuf,
        tmp_dir: PathBuf,
    ) -> Self {
        let needs_network = audit.capabilities.iter().any(|c| {
            matches!(
                c,
                Capability::Network { .. } | Capability::PackageInstall { .. }
            )
        });
        let network_host = audit.capabilities.iter().find_map(|c| match c {
            Capability::Network { target: Some(t) } => Some(t.clone()),
            _ => None,
        });
        // Package installs narrow egress to the ecosystem's registries —
        // `npm install` reaches npmjs.org and nothing else.
        let package_hosts: Vec<String> = audit
            .capabilities
            .iter()
            .filter_map(|c| match c {
                Capability::PackageInstall { manager } => Some(registry_domains(manager)),
                _ => None,
            })
            .flatten()
            .map(|s| s.to_string())
            .collect();

        // Credential dirs the sandbox always masks — capability-driven
        // policy can't widen these (OutOfScope/PrivilegeEscalation/Deny
        // capabilities keep them denied even when approved). srt leaves
        // denyRead to user config entirely; we keep a small built-in
        // secrets set — reading a key is useless without egress anyway,
        // but belt-and-suspenders is cheap.
        let mut deny: Vec<PathBuf> = Vec::new();
        for sub in [".ssh", ".gnupg", ".aws"] {
            if let Some(p) = shellexpand_home(sub) {
                deny.push(p);
            }
        }

        // Mandatory write-deny inside writable roots — srt's mandatory set:
        // dangerous files, dangerous dirs, .git internals (hooks/config/
        // HEAD), plus a shallow scan of nested repos at depth ≤ 3
        // (`mandatoryDenySearchDepth`).
        let deny_write = mandatory_deny_write(&workspace);

        Self {
            filesystem: FilesystemPolicy {
                rw: vec![workspace, tmp_dir],
                ro: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                ],
                deny,
                deny_write,
            },
            network: if needs_network {
                if let Some(h) = network_host {
                    NetworkPolicy::AllowHosts(vec![h])
                } else if !package_hosts.is_empty() {
                    NetworkPolicy::AllowHosts(package_hosts)
                } else {
                    NetworkPolicy::Allow
                }
            } else {
                NetworkPolicy::Deny
            },
            processes: ProcessPolicy {
                // 0 = no rlimit. Codex/Claude cap neither memory nor procs:
                // `ulimit -v` measures virtual size (breaks jemalloc/forks)
                // and `ulimit -u` counts per-UID *system-wide*, so a cap can
                // trip on the user's own desktop session. Isolation relies
                // on the pid namespace + die-with-parent instead.
                max_memory_mb: 0,
                timeout_secs: 60,
                tree_kill: true,
                max_processes: 0,
            },
            devices: match audit.capabilities.iter().find_map(|c| match c {
                Capability::DeviceAccess { path } => Some(path.clone()),
                _ => None,
            }) {
                Some(p) => DevicePolicy::AllowDevice(p),
                None => DevicePolicy::Standard,
            },
            syscalls: if needs_network {
                SyscallPolicy::Networked
            } else {
                SyscallPolicy::Baseline
            },
            // Dev toolchain by default — a `Runtime` cap is confirmatory
            // signal, not a gate: detection can't see inside build scripts
            // (`make` can run `cargo`), so default-open is the correct
            // mode for a dev agent. `Minimal`/`Select` exist for future
            // strict callers that trust detection end-to-end.
            environment: EnvironmentPolicy::DevToolchain,
            snapshot: audit
                .force_snapshot
                .unwrap_or(if audit.risk >= RiskLevel::High {
                    crate::traits::SnapshotMode::Cow
                } else {
                    crate::traits::SnapshotMode::Off
                }),
        }
    }
}

fn shellexpand_home(sub: &str) -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(sub))
}

/// Registry hosts a package manager needs for install — the egress
/// allowlist a `PackageInstall` capability translates to.
fn registry_domains(manager: &str) -> &'static [&'static str] {
    match manager {
        "npm" | "yarn" | "pnpm" | "bun" => {
            &["registry.npmjs.org", "*.npmjs.org", "registry.yarnpkg.com"]
        }
        "cargo" => &["index.crates.io", "static.crates.io", "crates.io"],
        "pip" | "pip3" | "uv" | "poetry" | "pipenv" => {
            &["pypi.org", "*.pypi.org", "files.pythonhosted.org"]
        }
        "go" => &["proxy.golang.org", "sum.golang.org", "*.golang.org"],
        "gem" | "bundler" => &["rubygems.org", "*.rubygems.org", "index.rubygems.org"],
        "composer" => &["packagist.org", "repo.packagist.org", "*.packagist.org"],
        "dotnet" | "nuget" => &["api.nuget.org", "*.nuget.org"],
        "maven" | "mvn" | "gradle" => &[
            "repo.maven.apache.org",
            "repo1.maven.org",
            "plugins.gradle.org",
        ],
        "brew" => &["formulae.brew.sh", "ghcr.io", "*.githubusercontent.com"],
        // System package managers talk to user-configured mirrors — too
        // varied to enumerate; they get full egress.
        _ => &[],
    }
}

/// Names srt write-denies wherever they appear inside a writable root
/// (`DANGEROUS_FILES`) — config that self-modifies the sandbox or the next
/// shell the user opens.
const DANGEROUS_FILE_NAMES: &[&str] = &[
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
];

/// Directories srt write-denies (relative to the writable root) — IDE task
/// runners and agent config a command could poison, including configuration
/// directories such as `.pi`, `.agents`, and `.codex`.
const DANGEROUS_DIR_NAMES: &[&str] = &[
    ".vscode",
    ".idea",
    ".claude/commands",
    ".claude/agents",
    ".pi",
    ".agents",
    ".codex",
];

/// Max depth for the nested scan (`mandatoryDenySearchDepth` = 3 in srt):
/// `sub/sub2/repo/.git/hooks` is caught, deeper is not.
const MANDATORY_DENY_DEPTH: usize = 3;

/// Skip-list for the shallow walk — dependency/build trees where a `.git`
/// or rc-file match is noise and the walk cost is real.
const SCAN_SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".next",
    ".cache",
    ".git",
];

/// The mandatory `deny_write` set for a workspace: every dangerous name
/// that exists at the root or nested ≤ 3 deep, plus `.git` internals
/// (`hooks`, `config`, `HEAD`, `modules`) for every `.git` *directory*
/// found — worktrees (`$ws/.git` a file) have no `hooks/` to deny.
fn mandatory_deny_write(workspace: &PathBuf) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Iterative walk so no recursion plumbing is needed.
    let mut stack: Vec<(PathBuf, usize)> = vec![(workspace.clone(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

            // Dangerous names at any visited level.
            if DANGEROUS_FILE_NAMES.contains(&name.as_str())
                && seen.insert(path.clone())
                && path.exists()
            {
                out.push(path.clone());
            }
            // Dangerous dirs (single-segment ones match nested too — same as
            // srt's `**/${dirName}/**` glob).
            for d in DANGEROUS_DIR_NAMES {
                if !d.contains('/') && name == *d && seen.insert(path.clone()) && path.exists() {
                    out.push(path.clone());
                }
            }

            if !is_dir {
                continue;
            }
            // A `.git` *directory* => repo: protect its internals. srt
            // denies HEAD only for nested repos (top-level `git switch`
            // legitimately rewrites it) — match that.
            if name == ".git" {
                let nested = dir != *workspace;
                let mut subs = vec!["hooks", "config", "modules"];
                if nested {
                    subs.push("HEAD");
                }
                for sub in subs {
                    let p = path.join(sub);
                    if seen.insert(p.clone()) && p.exists() {
                        out.push(p);
                    }
                }
                continue; // never descend into .git
            }
            // Multi-segment dangerous dirs nested (`sub/.claude/commands`).
            if name == ".claude" {
                for sub in ["commands", "agents"] {
                    let p = path.join(sub);
                    if seen.insert(p.clone()) && p.exists() {
                        out.push(p);
                    }
                }
            }
            if depth < MANDATORY_DENY_DEPTH && !SCAN_SKIP_DIRS.contains(&name.as_str()) {
                stack.push((path, depth + 1));
            }
        }
    }

    // Multi-segment dangerous dirs at the workspace root (`.claude/commands`
    // etc.) — matched by the walker only via their last component when
    // nested, so add the root spellings explicitly.
    for d in DANGEROUS_DIR_NAMES {
        let p = workspace.join(d);
        if seen.insert(p.clone()) && p.exists() {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_deny_write_finds_git_internals_and_rc_files() {
        let ws = std::env::temp_dir().join(format!("plan-dw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".git/hooks")).unwrap();
        std::fs::write(ws.join(".git/HEAD"), "ref").unwrap();
        std::fs::write(ws.join(".git/config"), "").unwrap();
        std::fs::write(ws.join(".bashrc"), "").unwrap();
        std::fs::write(ws.join(".mcp.json"), "{}").unwrap();
        std::fs::create_dir_all(ws.join(".vscode")).unwrap();
        // nested repo at depth 2 — nested repos get HEAD denied too
        std::fs::create_dir_all(ws.join("sub/repo/.git/hooks")).unwrap();
        std::fs::write(ws.join("sub/repo/.git/HEAD"), "ref").unwrap();
        // deeper than the scan depth — must NOT appear
        std::fs::create_dir_all(ws.join("a/b/c/d/repo/.git/hooks")).unwrap();

        let got = mandatory_deny_write(&ws);
        let has = |s: &str| got.iter().any(|p| p.ends_with(s));
        assert!(has(".git/hooks"));
        assert!(has(".git/config"));
        // top-level HEAD stays writable (git switch); nested repos' is denied
        assert!(!got.iter().any(|p| *p == ws.join(".git/HEAD")));
        assert!(got.iter().any(|p| *p == ws.join("sub/repo/.git/HEAD")));
        assert!(has(".bashrc"));
        assert!(has(".mcp.json"));
        assert!(has(".vscode"));
        assert!(has("sub/repo/.git/hooks"));
        assert!(!has("a/b/c/d/repo/.git/hooks"), "depth >3 must not scan");

        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn package_install_narrows_to_registry() {
        let audit = crate::audit::AuditResult {
            capabilities: vec![Capability::PackageInstall {
                manager: "npm".into(),
            }],
            risk: RiskLevel::Medium,
            reasons: vec![],
            level: crate::audit::AuditLevel::Normal,
            force_snapshot: None,
            needs_network_prompt: false,
        };
        let plan =
            SandboxPlan::from_audit(&audit, PathBuf::from("/tmp/ws"), PathBuf::from("/tmp/run"));
        match plan.network {
            NetworkPolicy::AllowHosts(h) => {
                assert!(h.iter().any(|d| d.contains("npmjs.org")), "{h:?}")
            }
            other => panic!("npm install should narrow to registries: {other:?}"),
        }
    }
}
