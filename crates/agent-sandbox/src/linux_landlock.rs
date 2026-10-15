//! `linux_landlock.rs` — bwrap-less Linux fallback: Landlock filesystem
//! scoping + a seccomp-BPF escape-syscall denylist, applied inside the child
//! via `pre_exec` (fork → restrict → exec).
//!
//! Coverage vs `LinuxBwrap`: this backend does NOT do mount namespaces —
//! the fs boundary is Landlock rules, network stays unfiltered (no
//! `--unshare-net`; Landlock can gate socket binds on newer ABIs but the
//! denylist approach keeps the honest `allow_network` contract: `false`
//! just can't be enforced here — callers see `id() == "landlock"` for
//! telemetry, and nothing claims a network sandbox that doesn't exist).
//!
//! Why raw `libc::syscall`/`prctl`: Landlock and seccomp are stable kernel
//! ABIs — no crate needed (the landlock ruleset is 3 syscalls, the BPF
//! filter is a byte array), which keeps the dep graph C-toolchain-free.
//!
//! Landlock ABI: create_ruleset(444)/add_rule(445)/restrict_self(446),
//! stable since Linux 5.13 — probed once (`landlock_supported`).
//!
//! seccomp-BPF: denylist — execution-affecting syscalls (mounts, namespaces,
//! kexec, module loading, ptrace, userfaultfd, BPF itself) return EPERM;
//! everything else passes (a default-deny allowlist would take ~200
//! syscalls to keep glibc working — a wrong entry bricks every child).

#![cfg(target_os = "linux")]

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

use crate::env_sanitize::sanitize_env;
use crate::traits::{CommandOutput, SandboxBackend, SandboxConfig, SandboxTier};

pub struct LinuxLandlock;

// ---- Landlock constants (ABI v1, stable since Linux 5.13) ----

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

/// ABI-v1 handled rights — every fs action the ruleset can mediate.
/// Individual bits are kept for readability of the masks below.
#[allow(dead_code)]
const FS_EXECUTE: u64 = 1 << 0;
#[allow(dead_code)]
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
#[allow(dead_code)]
const FS_REMOVE_DIR: u64 = 1 << 4;
#[allow(dead_code)]
const FS_REMOVE_FILE: u64 = 1 << 5;
#[allow(dead_code)]
const FS_MAKE_CHAR: u64 = 1 << 6;
#[allow(dead_code)]
const FS_MAKE_DIR: u64 = 1 << 7;
#[allow(dead_code)]
const FS_MAKE_REG: u64 = 1 << 8;
#[allow(dead_code)]
const FS_MAKE_SOCK: u64 = 1 << 9;
#[allow(dead_code)]
const FS_MAKE_FIFO: u64 = 1 << 10;
#[allow(dead_code)]
const FS_MAKE_BLOCK: u64 = 1 << 11;
#[allow(dead_code)]
const FS_MAKE_SYM: u64 = 1 << 12;
#[allow(dead_code)]
const FS_REFER: u64 = 1 << 13;
#[allow(dead_code)]
const FS_TRUNCATE: u64 = 1 << 14;
const FS_ALL_V1: u64 = 0x7FFF;
const FS_READ_ONLY: u64 = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Kernel supports Landlock ABI v1 — probe once; ENOSYS/EINVAL means no.
pub fn landlock_supported() -> bool {
    let attr = RulesetAttr {
        handled_access_fs: FS_ALL_V1,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    };
    if fd < 0 {
        return false;
    }
    unsafe {
        libc::close(fd as libc::c_int);
    }
    true
}

/// Build the Landlock ruleset fd for this config. Called inside `pre_exec`
/// (the ruleset must be created+restricted in the child, not the parent —
/// `restrict_self` applies to the calling thread).
fn landlock_restrict(ws: &Path, ro: &[PathBuf], rw: &[PathBuf]) -> std::io::Result<()> {
    let attr = RulesetAttr {
        handled_access_fs: FS_ALL_V1,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0,
        )
    } as RawFd;
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let grant = |path: &Path, rights: u64| -> std::io::Result<()> {
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path with NUL"))?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rule = PathBeneathAttr {
            allowed_access: rights,
            parent_fd: fd,
        };
        let ok = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if ok < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };

    // Read-only roots: system libs + config the child needs to run at all.
    for p in [
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys", "/dev",
    ] {
        let p = Path::new(p);
        if p.exists() {
            grant(p, FS_READ_ONLY)?;
        }
    }
    // /dev needs write for null/urandom — re-grant with write on top
    // (later rules add, never subtract).
    if Path::new("/dev").exists() {
        grant(Path::new("/dev"), FS_ALL_V1)?;
    }
    for p in ["/tmp", "/var/tmp", "/run", "/var/run"] {
        let p = Path::new(p);
        if p.exists() {
            grant(p, FS_ALL_V1)?;
        }
    }
    for p in ro {
        if p.exists() {
            grant(p, FS_READ_ONLY)?;
        }
    }
    for p in rw {
        if p.exists() {
            grant(p, FS_ALL_V1)?;
        }
    }
    if ws.exists() {
        grant(ws, FS_ALL_V1)?;
    }

    // prctl(NO_NEW_PRIVS) is a landlock prerequisite.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::close(ruleset_fd) };
    Ok(())
}

// ---- seccomp-BPF denylist ----

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
// SECCOMP_MODE_DISABLED=0 / STRICT=1 / FILTER=2 — 1 is STRICT (read/write/
// exit only, everything else SIGKILL): passing it by mistake makes the
// child die on its first real syscall. This must be 2.
const SECCOMP_MODE_FILTER: usize = 2;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
const EPERM: u32 = 1;

/// `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }` — 8 bytes.
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// `struct sock_fprog { u16 len; sock_filter* filter; }`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn jump(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// `seccomp_data` offsets: `nr` @0 (u32), `arch` @4 (u32).
const SECCOMP_OFF_NR: u32 = 0;
const SECCOMP_OFF_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: u32 = 0;

/// Syscalls that only exist for namespace/mount escape, kernel-module or
/// tracing abuse — denied outright under the sandbox.
#[cfg(target_arch = "x86_64")]
const DENY_NRS: &[u32] = &[
    libc::SYS_mount as u32,
    libc::SYS_umount2 as u32,
    libc::SYS_pivot_root as u32,
    libc::SYS_swapon as u32,
    libc::SYS_swapoff as u32,
    libc::SYS_init_module as u32,
    libc::SYS_finit_module as u32,
    libc::SYS_delete_module as u32,
    libc::SYS_kexec_load as u32,
    libc::SYS_kexec_file_load as u32,
    libc::SYS_bpf as u32,
    libc::SYS_userfaultfd as u32,
    libc::SYS_ptrace as u32,
    libc::SYS_perf_event_open as u32,
    libc::SYS_keyctl as u32,
    libc::SYS_unshare as u32,
    libc::SYS_setns as u32,
    libc::SYS_chroot as u32,
    libc::SYS_move_mount as u32,
    libc::SYS_open_tree as u32,
    libc::SYS_fsopen as u32,
    libc::SYS_fsconfig as u32,
    libc::SYS_fsmount as u32,
    libc::SYS_fspick as u32,
    libc::SYS_quotactl as u32,
    libc::SYS_acct as u32,
    libc::SYS_reboot as u32,
    libc::SYS_syslog as u32,
];

/// Assemble the denylist program. Layout:
///   LD arch → JEQ AUDIT_ARCH else KILL (wrong arch = never trust `nr`)
///   LD nr
///   JEQ each denied nr → jump to RET ERRNO
///   RET ALLOW | RET ERRNO|EPERM | RET KILL
fn seccomp_prog() -> Vec<SockFilter> {
    let kill_at = 3 + DENY_NRS.len() + 2;
    // index 1: arch JEQ — miss ⇒ jump straight to RET KILL (never trust a
    // syscall number decoded under the wrong arch).
    let arch_miss = (kill_at - 2) as u8;
    let mut ins: Vec<SockFilter> = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0, arch_miss, AUDIT_ARCH),
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_OFF_NR),
    ];
    let base = ins.len();
    let allow_at = base + DENY_NRS.len();
    let errno_at = allow_at + 1;
    for (i, nr) in DENY_NRS.iter().enumerate() {
        let at = base + i;
        let jt = (errno_at - (at + 1)) as u8;
        ins.push(jump(BPF_JMP | BPF_JEQ | BPF_K, jt, 0, *nr));
    }
    ins.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    ins.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    ins.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    ins
}

/// Apply the seccomp filter in the child (after landlock).
fn seccomp_apply() -> std::io::Result<()> {
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut prog = seccomp_prog();
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    if unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Everything the child restricts itself with — computed pre-fork so the
/// `pre_exec` closure only does syscalls (allocation in pre_exec is fine,
/// but keeping it minimal narrows the unsafe surface).
fn apply_restrictions(
    ws: PathBuf,
    ro: Vec<PathBuf>,
    rw: Vec<PathBuf>,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        landlock_restrict(&ws, &ro, &rw)?;
        seccomp_apply()?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SandboxBackend for LinuxLandlock {
    fn id(&self) -> &'static str {
        "landlock"
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
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let mut envs = sanitize_env(&cfg.env_vars);
        for (k, v) in &cfg.trusted_env {
            envs.push((k.clone(), v.clone()));
        }
        let denied = vec![ws.clone()];
        crate::env_sanitize::apply_environment_policy(&mut envs, &cfg.environment, None, &denied);
        let ro = cfg.extra_ro_mounts.clone();
        let rw = cfg.extra_rw_mounts.clone();

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(cmd)
            .current_dir(&ws)
            .env_clear()
            .envs(envs)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        command.process_group(0);
        unsafe {
            command.pre_exec(apply_restrictions(ws, ro, rw));
        }
        let child = command.spawn().context("spawn sh")?;
        let child_id = child.id();
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
            Err(_) => {
                if let Some(id) = child_id {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &format!("-{id}")])
                        .status();
                }
                (
                    String::new(),
                    "[timeout — process tree killed]".into(),
                    -1,
                    true,
                )
            }
        };
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

    fn wrap_spawn(
        &self,
        cfg: &SandboxConfig,
        cmd: &str,
        args: &[&str],
    ) -> Option<tokio::process::Command> {
        let ws = cfg
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| cfg.workspace_dir.clone());
        let mut c = tokio::process::Command::new(cmd);
        c.args(args);
        let mut envs = sanitize_env(&cfg.env_vars);
        for (k, v) in &cfg.trusted_env {
            envs.push((k.clone(), v.clone()));
        }
        c.env_clear().envs(envs);
        let ro = cfg.extra_ro_mounts.clone();
        let rw = cfg.extra_rw_mounts.clone();
        unsafe {
            c.pre_exec(apply_restrictions(ws, ro, rw));
        }
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_prog_layout() {
        let prog = seccomp_prog();
        // deny JEQ jumps must land on the ERRNO return, not past it.
        for (i, ins) in prog.iter().enumerate() {
            if ins.code == (BPF_JMP | BPF_JEQ | BPF_K) && ins.jt > 0 {
                let target = i + 1 + ins.jt as usize;
                assert_eq!(
                    prog[target].k,
                    SECCOMP_RET_ERRNO | EPERM,
                    "deny jump at {i} misses the EPERM return"
                );
            }
        }
    }

    #[test]
    fn landlock_abi_probe_does_not_panic() {
        // On kernels <5.13 this returns false — the detect path falls
        // through to `none`, which is the loud-correct answer either way.
        let _ = landlock_supported();
    }

    /// Real containment — granted roots (system libs, /tmp) are readable,
    /// but HOME is NOT in the grant set, so anything under it is denied.
    /// Skip when the kernel has no Landlock ABI (detect falls to `none`).
    #[tokio::test]
    async fn landlock_denies_home_and_allows_workspace() {
        if !landlock_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        // Inside the sandbox the workspace is readable; HOME is off-grant.
        let cfg = SandboxConfig {
            workspace_dir: ws.to_path_buf(),
            ..Default::default()
        };
        let backend = LinuxLandlock;
        let probe_home = backend
            .run_command(
                // `ls` opens the dir → landlock's READ_DIR hook denies it.
                // (`test -r`/`access(2)` is NOT landlock-mediated — the
                // check must go through open().)
                "ls \"$HOME\" >/dev/null 2>&1 && echo HOME_READABLE || echo HOME_DENIED",
                &[],
                &cfg,
            )
            .await
            .unwrap();
        assert_eq!(
            probe_home.stdout.trim(),
            "HOME_DENIED",
            "landlock should deny reads outside its grant set: {probe_home:?}"
        );
        let probe_ws = backend
            .run_command("touch marker && echo W_OK", &[], &cfg)
            .await
            .unwrap();
        assert_eq!(probe_ws.stdout.trim(), "W_OK");
        assert!(ws.join("marker").exists());
    }

    /// The seccomp denylist — `unshare` must return EPERM inside the jail
    /// (namespace creation is exactly what a sandbox must refuse).
    #[tokio::test]
    async fn seccomp_denies_unshare() {
        if !landlock_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig {
            workspace_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let out = LinuxLandlock
            .run_command("unshare --mount true 2>&1; echo rc=$?", &[], &cfg)
            .await
            .unwrap();
        assert!(
            out.stdout.contains("rc=1") || out.stderr.contains("rc=1"),
            "unshare should fail inside the sandbox: {out:?}"
        );
    }

    /// `wrap_spawn` produces a Command — the caller (MCP/hook) owns its
    /// stdio; the restriction applies pre-exec in the child.
    #[tokio::test]
    async fn wrap_spawn_restricts_child() {
        if !landlock_supported() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig {
            workspace_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let Some(mut c) = LinuxLandlock.wrap_spawn(
            &cfg,
            "sh",
            &[
                "-c",
                "ls \"$HOME\" >/dev/null 2>&1 && echo HOME_READABLE || echo HOME_DENIED",
            ],
        ) else {
            panic!("landlock must wrap spawns");
        };
        let out = c
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "HOME_DENIED");
    }
}
