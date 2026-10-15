//! The `SandboxBackend` trait + shared config/output types.
//!
//! Contract (sandbox-model.md): every agent command runs inside an enforced
//! boundary; a missing backend degrades **loudly** (`id() == "none"`), never
//! silently. Three tiers: L1 WASM (plugin-system), L2 native process
//! (this crate), L3 microVM (future impl of the same trait).

use std::path::PathBuf;

/// Which isolation tier a backend implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTier {
    /// In-process WASM (plugin tools).
    L1,
    /// Native process sandbox (bwrap / sandbox-exec / job-object).
    L2,
    /// MicroVM (Firecracker/QEMU) — exceptional workloads only.
    L3,
}

/// Filesystem snapshot behavior for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotMode {
    /// Write directly to the real workspace.
    Off,
    /// Clone-on-write: agent mutates a reflink copy, merge back on success.
    Cow,
    /// Every write-bearing command must run against a CoW snapshot.
    Required,
}

/// Per-run configuration — the caller builds this per tool call.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Canonical workspace root — the only rw mount inside the sandbox.
    pub workspace_dir: PathBuf,
    /// Whether the sandboxed process may reach the network.
    pub allow_network: bool,
    /// Egress allowlist (srt `allowedDomains` semantics: `example.com`,
    /// `*.example.com`, `host:443`, IP literals). When `allow_network` is
    /// false and this is non-empty, capable backends route egress through
    /// the per-process [`crate::proxy::SandboxProxy`] instead of cutting
    /// the network outright — the command reaches the listed hosts and
    /// nothing else. Empty + `allow_network: false` = full deny.
    pub allowed_domains: Vec<String>,
    /// Egress denylist — checked before the allowlist, always wins.
    pub denied_domains: Vec<String>,
    /// Extra read-deny paths beyond the backend's built-in secrets set
    /// (srt `denyRead`). Backends mask these — a denied dir reads as empty.
    pub deny_read: Vec<PathBuf>,
    /// Re-allowed reads inside denied regions (srt `allowRead` —
    /// narrower path wins over a covering deny).
    pub allow_read: Vec<PathBuf>,
    /// Write-denied paths *inside* writable roots (srt `denyWrite` —
    /// `.git/hooks`, shell rc files, agent config dirs). Re-bound
    /// read-only after the rw binds so they win the overlap.
    pub deny_write: Vec<PathBuf>,
    /// Max virtual memory (MB) via `ulimit -v`. 0 (default) = no cap —
    /// `-v` measures virtual size (jemalloc/mmap-heavy tools trip it);
    /// callers that want a cap set it via prefs.
    pub max_memory_mb: u64,
    /// Max spawned processes (fork-bomb guard) — backends that can enforce
    /// it do (bwrap: `--unshare-pid` + `ulimit -u`); 0 = no explicit cap.
    pub max_processes: u32,
    /// Wall-clock timeout (s) — caller may raise to ≤ 600.
    pub timeout_secs: u64,
    /// Extra env vars to inject *after* sanitization (e.g. PATH overrides).
    pub env_vars: Vec<(String, String)>,
    /// Vars appended to the spawn env **unfiltered** — the plugin manifest's
    /// own declared `env` block. It bypasses the denylist on purpose: the
    /// manifest IS the trust authority (a literal `API_KEY=…` written into
    /// `manifest.json` is an intentional grant, not injected host state),
    /// so stripping `_TOKEN`-shaped names would silently break plugin auth.
    /// `env:VAR` indirection is refused upstream, before landing here.
    pub trusted_env: Vec<(String, String)>,
    /// Environment surface — the plan's decision on vars + PATH
    /// (`Minimal` vs `DevToolchain`). Backends pass it to
    /// `env_sanitize::apply_environment_policy` with their mount roots.
    pub environment: crate::plan::EnvironmentPolicy,
    /// CoW snapshot behavior.
    pub snapshot: SnapshotMode,
    /// Extra read-only mounts inside the sandbox.
    pub extra_ro_mounts: Vec<PathBuf>,
    /// Extra read-write mounts inside the sandbox.
    pub extra_rw_mounts: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            workspace_dir: PathBuf::from("."),
            allow_network: false,
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            deny_read: Vec::new(),
            allow_read: Vec::new(),
            deny_write: Vec::new(),
            max_memory_mb: 0,
            max_processes: 0,
            timeout_secs: 60,
            env_vars: Vec::new(),
            trusted_env: Vec::new(),
            environment: crate::plan::EnvironmentPolicy::DevToolchain,
            snapshot: SnapshotMode::Off,
            extra_ro_mounts: Vec::new(),
            extra_rw_mounts: Vec::new(),
        }
    }
}

/// What a sandboxed run produced.
#[derive(Debug)]
pub struct CommandOutput {
    /// Process exit status.
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    /// True when the wall timeout fired (tree killed).
    pub is_timeout: bool,
    /// Hosts/ports the egress proxy refused during this run — the raw
    /// material for the "command needed network X, approve to widen"
    /// escalation path. Empty when the run never hit the allowlist
    /// (or the backend has no proxy).
    pub sandbox_denials: Vec<String>,
    /// Peak RSS if the platform reports it.
    pub peak_memory_mb: Option<u64>,
    /// Wall-clock elapsed.
    pub elapsed_ms: u64,
}

/// One sandbox backend. `run_command` is the only entry — all four control
/// dimensions (fs isolation, network, resource limits, env sanitization)
/// live behind it.
#[async_trait::async_trait]
pub trait SandboxBackend: Send + Sync {
    /// Stable id for telemetry/UI (`"bwrap"`, `"landlock"`, `"none"`…).
    fn id(&self) -> &'static str;
    /// Isolation tier.
    fn tier(&self) -> SandboxTier;
    /// Run `cmd` with `args` inside the sandbox. The backend applies env
    /// sanitization + resource limits + timeout-tree-kill itself — callers
    /// must not pre-sanitize.
    async fn run_command(
        &self,
        cmd: &str,
        args: &[&str],
        cfg: &SandboxConfig,
    ) -> anyhow::Result<CommandOutput>;

    /// Build a long-lived `Command` that runs `cmd args` inside the sandbox
    /// — for servers the caller keeps alive (MCP stdio children, plugin
    /// hooks). Unlike `run_command` nothing pipes output or enforces a
    /// timeout; the caller wires its own stdio and lifetime. `None` means
    /// the backend cannot wrap spawns — the caller decides whether that is
    /// a hard error (declared sandbox policy) or a loud fallback.
    fn wrap_spawn(
        &self,
        _cfg: &SandboxConfig,
        _cmd: &str,
        _args: &[&str],
    ) -> Option<tokio::process::Command> {
        None
    }
}
