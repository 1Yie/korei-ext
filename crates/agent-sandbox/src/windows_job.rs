//! `windows_job.rs` — Windows backend: a Job Object for resource limits +
//! kill-on-close. Scope: PROCESS/RESOURCE control only — Job Objects don't
//! express filesystem or network policy (that needs WDAC/AppContainer,
//! a much bigger surface than this backend promises). What the backend
//! DOES deliver on Windows:
//!   - kill the whole process tree when the job closes (KILL_ON_JOB_CLOSE)
//!   - `max_memory_mb` / `max_processes` caps
//! The `id()` is `"job"` — callers can tell real containment (bwrap/seatbelt)
//! from resource-limits-only Windows.
//!
//! UNTESTED-on-CI note: cfg-gated to Windows; the FFI surface is the stable
//! kernel32 Job Object API (documented since Windows XP), hand-declared so
//! no `windows-sys` dep is needed.

#![cfg(target_os = "windows")]

use std::os::windows::raw::HANDLE;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::env_sanitize::sanitize_env;
use crate::traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};

#[allow(non_camel_case_types)]
type BOOL = i32;

#[allow(non_snake_case)]
#[repr(C)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    LimitFlags: u32,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct IO_COUNTERS {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[allow(non_snake_case)]
#[repr(C)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

const JOB_OBJECT_EXT_LIMIT: i32 = 9; // JobObjectExtendedLimitInformation
const LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
const LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;

#[allow(non_snake_case)]
extern "system" {
    fn CreateJobObjectW(attr: *const core::ffi::c_void, name: *const u16) -> HANDLE;
    fn SetInformationJobObject(
        job: HANDLE,
        info: i32,
        data: *const core::ffi::c_void,
        len: u32,
    ) -> BOOL;
    fn AssignProcessToJobObject(job: HANDLE, proc: HANDLE) -> BOOL;
    fn CloseHandle(h: HANDLE) -> BOOL;
}

/// Owned job handle — `CloseHandle` on drop (KILL_ON_JOB_CLOSE does the rest).
struct Job(HANDLE);
impl Drop for Job {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
unsafe impl Send for Job {}

fn create_limited_job(max_memory_mb: u64, max_processes: u32) -> Result<Job> {
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        anyhow::bail!("CreateJobObjectW failed");
    }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = LIMIT_KILL_ON_JOB_CLOSE;
    if max_processes > 0 {
        info.BasicLimitInformation.LimitFlags |= LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = max_processes;
    }
    if max_memory_mb > 0 {
        info.BasicLimitInformation.LimitFlags |= LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = (max_memory_mb as usize).saturating_mul(1024 * 1024);
    }
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JOB_OBJECT_EXT_LIMIT,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        unsafe { CloseHandle(job) };
        anyhow::bail!("SetInformationJobObject failed");
    }
    Ok(Job(job))
}

pub struct WindowsJob;

#[async_trait::async_trait]
impl SandboxBackend for WindowsJob {
    fn id(&self) -> &'static str {
        "job"
    }

    fn tier(&self) -> SandboxTier {
        SandboxTier::L2
    }

    async fn run_command(
        &self,
        cmd: &str,
        _args: &[&str],
        cfg: &SandboxConfig,
    ) -> Result<CommandOutput> {
        let started = Instant::now();
        let timeout = std::time::Duration::from_secs(cfg.timeout_secs.min(600));
        let mut envs = sanitize_env(&cfg.env_vars);
        for (k, v) in &cfg.trusted_env {
            envs.push((k.clone(), v.clone()));
        }

        let job = create_limited_job(cfg.max_memory_mb, cfg.max_processes)?;

        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg(cmd)
            .current_dir(&cfg.workspace_dir)
            .env_clear()
            .envs(envs)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let child = command.spawn().context("spawn cmd")?;
        if let Some(h) = child.raw_handle() {
            let ok = unsafe { AssignProcessToJobObject(job.0, h) };
            if ok == 0 {
                return Err(std::io::Error::last_os_error()).context("AssignProcessToJobObject");
            }
        }
        let status = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let elapsed = started.elapsed().as_millis() as u64;
        let (out, err, code, is_timeout) = match status {
            Ok(Ok(o)) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.code().unwrap_or(-1),
                false,
            ),
            Ok(Err(e)) => (String::new(), e.to_string(), -1, false),
            Err(_) => (
                String::new(),
                "[timeout — job closed, tree killed]".to_string(),
                -1,
                true,
            ),
        };
        drop(job); // closes the job → the whole tree dies on timeout
        Ok(CommandOutput {
            status: code,
            stdout: out,
            stderr: err,
            is_timeout,
            sandbox_denials: Vec::new(),
            peak_memory_mb: None,
            elapsed_ms: elapsed,
        })
    }

    /// `wrap_spawn` can't take a `Command` — the job must be assigned AFTER
    /// spawn via `AssignProcessToJobObject`, which a plain `Command` offers
    /// no hook for (Windows has no pre-exec). A surrogate-helper exe is the
    /// real answer and is deliberately not faked — sandboxed MCP/hook
    /// spawns refuse on Windows rather than pretend.
    fn wrap_spawn(
        &self,
        _cfg: &SandboxConfig,
        _cmd: &str,
        _args: &[&str],
    ) -> Option<tokio::process::Command> {
        None
    }
}
