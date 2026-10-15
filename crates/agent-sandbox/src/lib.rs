//! agent-sandbox — L2 process sandbox.
//!
//! `detect_backend()` picks the best implemented backend — bwrap on Linux — and
//! otherwise returns the loud `none` backend. Every spawn gets env sanitization,
//! resource limits and tree-kill on timeout regardless of backend.

pub mod audit;
pub mod env_sanitize;
#[cfg(target_os = "linux")]
pub mod limits;
pub mod linux_bwrap;
#[cfg(target_os = "linux")]
pub mod linux_landlock;
#[cfg(target_os = "macos")]
pub mod mac_sandbox_exec;
pub mod netpolicy;
pub mod none;
#[cfg(unix)]
pub mod proxy;
#[cfg(unix)]
mod shared;
pub mod traits;
#[cfg(target_os = "windows")]
pub mod windows_job;

pub use audit::{audit_command, audit_command_scoped, AuditLevel, AuditResult, AuditVerdict};
pub use env_sanitize::{is_denied, sanitize_env};
pub use limits::{apply_limits, network_from_label, SandboxLimits};
#[cfg(target_os = "linux")]
pub use linux_bwrap::LinuxBwrap;
#[cfg(target_os = "linux")]
pub use linux_landlock::{landlock_supported, LinuxLandlock};
#[cfg(target_os = "macos")]
pub use mac_sandbox_exec::{sandbox_exec_on_path, MacSandboxExec};
pub use none::NoneBackend;
pub use traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier, SnapshotMode};
#[cfg(target_os = "windows")]
pub use windows_job::WindowsJob;

/// Pick the best backend for this platform at startup.
///
/// Linux → bwrap (full mount-ns) → landlock (fs+jail, no net filtering —
/// flagged loud since `allow_network:false` can't be honored there).
/// macOS → `sandbox-exec` (Seatbelt profile, last-match-denies secrets).
/// Windows → Job Object (resource limits + tree-kill only — fs/net stay
/// open, so it reports loud rather than pretend containment).
///
/// Returns the backend + a `loud` flag — `none` must surface the
/// `UNSANDBOXED` chip and force-confirm every `bash` call.
pub fn detect_backend() -> (Box<dyn SandboxBackend>, bool) {
    #[cfg(target_os = "linux")]
    {
        if bwrap_on_path() {
            return (Box::new(LinuxBwrap), false);
        }
        // bwrap absent → landlock is the honest fallback: fs scoping +
        // seccomp denylist, but the network gate is unenforceable, so the
        // loud flag stays on (any `allow_network:false` would be a lie).
        if landlock_supported() {
            return (Box::new(LinuxLandlock), true);
        }
        (Box::new(NoneBackend), true)
    }
    #[cfg(target_os = "macos")]
    {
        if sandbox_exec_on_path() {
            return (Box::new(MacSandboxExec), false);
        }
        (Box::new(NoneBackend), true)
    }
    #[cfg(target_os = "windows")]
    {
        // Job Object is always available — but it only enforces resource
        // limits + tree-kill; fs/network stay wide open, so it counts as
        // loud rather than a containment claim.
        (Box::new(WindowsJob), true)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        (Box::new(NoneBackend), true)
    }
}

#[cfg(target_os = "linux")]
fn bwrap_on_path() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Shell AST — structural parse of a command line (parser layer of the
/// sandbox pipeline; safety decisions live in capability/audit/policy).
pub mod shell_ast;

/// Capability IR + extractor — `shell_ast` → `Vec<Capability>` + `RiskLevel`.
pub mod capability;

/// SandboxPlan — the OS-portable restriction set policy hands to a backend.
pub mod plan;
