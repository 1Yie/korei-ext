use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

struct Launch {
    process_limit: u32,
    executable: PathBuf,
    args: Vec<OsString>,
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Launch> {
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--max-processes")) {
        bail!("expected --max-processes");
    }
    let number = args.next().context("missing task allowance")?;
    let number = number.to_str().context("task allowance must be ASCII")?;
    if number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("task allowance must be a positive canonical decimal");
    }
    let tasks = number.parse::<u32>().context("task allowance overflow")?;
    let process_limit = tasks
        .checked_add(1)
        .context("task allowance plus PID1 overflows")?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
        bail!("expected -- before the target executable");
    }
    let executable = PathBuf::from(args.next().context("missing target executable")?);
    if !executable.is_absolute() {
        bail!("target executable must be absolute");
    }
    let args: Vec<_> = args.collect();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if executable.as_os_str().as_bytes().contains(&0)
            || args.iter().any(|arg| arg.as_bytes().contains(&0))
        {
            bail!("NUL in target executable or argument");
        }
    }
    Ok(Launch {
        process_limit,
        executable,
        args,
    })
}

#[cfg(target_os = "linux")]
fn run(launch: Launch) -> Result<()> {
    use std::fs;
    use std::os::unix::process::CommandExt;

    fn task_ids(path: &str) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(path).with_context(|| format!("read {path}"))? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str() {
                if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
                    ids.push(name.parse().context("proc task ID overflow")?);
                }
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn status(path: &str, uid: libc::uid_t) -> Result<()> {
        let text = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        let mut identities = 0;
        let mut capabilities = std::collections::BTreeSet::new();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("Uid:") {
                identities += 1;
                let values: Vec<_> = value.split_whitespace().collect();
                if values.len() != 4
                    || values
                        .iter()
                        .any(|value| value.parse::<libc::uid_t>().ok() != Some(uid))
                {
                    bail!("PID1 and target must share one stable UID");
                }
            }
            if let Some((field, value)) = line.split_once(':') {
                if ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].contains(&field) {
                    if !capabilities.insert(field)
                        || u64::from_str_radix(value.trim(), 16).ok() != Some(0)
                    {
                        bail!("capabilities are not cleared in {path}");
                    }
                }
            }
        }
        if identities != 1 || capabilities.len() != 5 {
            bail!("incomplete UID/capability status in {path}");
        }
        Ok(())
    }

    if unsafe { libc::getpid() } != 2 || unsafe { libc::getppid() } != 1 {
        bail!("expected bwrap PID1 and launcher PID2");
    }
    let proc = fs::File::open("/proc").context("open procfs")?;
    use std::os::fd::AsRawFd;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect procfs");
    }
    if filesystem.f_type != libc::PROC_SUPER_MAGIC
        || fs::read_link("/proc/self")? != PathBuf::from("2")
        || task_ids("/proc")? != [1, 2]
        || task_ids("/proc/1/task")? != [1]
        || task_ids("/proc/2/task")? != [2]
    {
        bail!("unexpected PID namespace task topology");
    }
    let uid = unsafe { libc::getuid() };
    status("/proc/1/status", uid)?;
    status("/proc/2/status", uid)?;
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // Linux capability ABI v3 returns two 32-bit capability words.
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut capabilities: [CapabilityData; 2] = Default::default();
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, capabilities.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read kernel capabilities");
    }
    if capabilities
        .iter()
        .any(|word| word.effective != 0 || word.permitted != 0 || word.inheritable != 0)
    {
        bail!("kernel capabilities are not cleared");
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set no_new_privs");
    }
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs < 0 {
        return Err(std::io::Error::last_os_error()).context("read back no_new_privs");
    }
    if no_new_privs != 1 {
        bail!("no_new_privs readback failed");
    }
    let limit = libc::rlim_t::from(launch.process_limit);
    let mut inherited: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut inherited) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read inherited task allowance");
    }
    if limit > inherited.rlim_cur || limit > inherited.rlim_max {
        bail!("inherited task allowance is insufficient");
    }
    let requested = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &requested) } != 0 {
        return Err(std::io::Error::last_os_error()).context("set hard/soft task allowance");
    }
    let mut actual: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut actual) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read back task allowance");
    }
    if actual.rlim_cur != limit || actual.rlim_max != limit {
        bail!("hard/soft task allowance readback differs");
    }
    // The verified namespace contains exactly one single-threaded PID1.
    // exec retains PID2, leaving the remaining allowance for the target tree.
    Err(std::process::Command::new(launch.executable)
        .args(launch.args)
        .exec())
    .context("exec target")
}

#[cfg(not(target_os = "linux"))]
fn run(launch: Launch) -> Result<()> {
    let Launch {
        process_limit,
        executable,
        args,
    } = launch;
    drop((process_limit, executable, args));
    bail!("agent-sandbox-launcher is supported only on Linux");
}

fn main() {
    if let Err(error) = parse(std::env::args_os().skip(1)).and_then(run) {
        eprintln!("agent-sandbox-launcher: {error:#}");
        std::process::exit(126);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn task_allowance_counts_one_verified_init_task() {
        let target = if cfg!(windows) {
            r"C:\target"
        } else {
            "/target"
        };
        for (tasks, total) in [("1", 2), ("4", 5), ("4294967294", u32::MAX)] {
            let launch = parse(arguments(&[
                "--max-processes",
                tasks,
                "--",
                target,
                "--literal",
            ]))
            .unwrap();
            assert_eq!(launch.process_limit, total);
            assert_eq!(launch.executable, PathBuf::from(target));
            assert_eq!(launch.args, [OsString::from("--literal")]);
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_refuses_execution() {
        let error = run(Launch {
            process_limit: 2,
            executable: PathBuf::from("unused-target"),
            args: Vec::new(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("supported only on Linux"));
    }

    #[test]
    fn malformed_or_overflowing_protocol_is_rejected() {
        for values in [
            vec![],
            vec!["--max-processes"],
            vec!["--other", "1", "--", "/target"],
            vec!["--max-processes", "1", "--extra", "--", "/target"],
            vec!["--max-processes", "1", "/target"],
            vec!["--max-processes", "1", "--"],
            vec!["--max-processes", "1", "--", "relative"],
        ] {
            assert!(parse(arguments(&values)).is_err(), "{values:?}");
        }
        for number in [
            "",
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "１",
            "4294967295",
            "4294967296",
            "18446744073709551616",
        ] {
            assert!(
                parse(arguments(&["--max-processes", number, "--", "/target"])).is_err(),
                "{number:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_target_paths_and_arguments_remain_lossless() {
        use std::os::unix::ffi::OsStringExt;
        let target = OsString::from_vec(b"/target-\xff".to_vec());
        let arg = OsString::from_vec(b"arg-\xfe".to_vec());
        let launch = parse(
            [
                OsString::from("--max-processes"),
                OsString::from("1"),
                OsString::from("--"),
                target.clone(),
                arg.clone(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(launch.executable.as_os_str(), &target);
        assert_eq!(launch.args, [arg]);
        assert!(parse(
            [
                OsString::from("--max-processes"),
                OsString::from("1"),
                OsString::from("--"),
                OsString::from_vec(b"/bad\0path".to_vec())
            ]
            .into_iter()
        )
        .is_err());
        assert!(parse(
            [
                OsString::from("--max-processes"),
                OsString::from("1"),
                OsString::from("--"),
                target,
                OsString::from_vec(b"bad\0argument".to_vec())
            ]
            .into_iter()
        )
        .is_err());
    }
}
