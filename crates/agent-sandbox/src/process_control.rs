use std::io;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::task::Poll;

#[cfg(unix)]
use std::time::Duration;

/// A control capability invalidated before its owner can release process identity.
#[derive(Clone)]
pub struct ProcessControl(Arc<Mutex<Target>>);

enum Target {
    Native {
        pid: u32,
        tree: bool,
    },
    #[cfg(target_os = "linux")]
    Cgroup {
        freeze: std::fs::File,
        events: std::fs::File,
    },
    Closed,
}

impl ProcessControl {
    pub(crate) fn closed() -> Self {
        Self(Arc::new(Mutex::new(Target::Closed)))
    }

    pub(crate) fn native(pid: Option<u32>, tree: bool) -> Self {
        Self(Arc::new(Mutex::new(match pid {
            Some(pid) => Target::Native { pid, tree },
            None => Target::Closed,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn bind_native(&self, pid: u32) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) =
            Target::Native { pid, tree: false };
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bind_cgroup(&self, freeze: std::fs::File, events: std::fs::File) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) =
            Target::Cgroup { freeze, events };
    }

    pub(crate) fn close(&self) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Target::Closed;
    }

    pub(crate) fn observe_exit(
        &self,
        observe: impl FnOnce() -> io::Result<Option<ExitStatus>>,
    ) -> io::Result<Option<ExitStatus>> {
        let mut target = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let result = observe();
        if !matches!(result, Ok(None)) {
            *target = Target::Closed;
        }
        result
    }

    pub(crate) fn poll_exit(
        &self,
        poll: impl FnOnce() -> Poll<io::Result<ExitStatus>>,
    ) -> Poll<io::Result<ExitStatus>> {
        let mut target = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let result = poll();
        if result.is_ready() {
            *target = Target::Closed;
        }
        result
    }

    pub fn set_paused(&self, paused: bool) -> io::Result<()> {
        let mut target = self.0.lock().unwrap_or_else(|error| error.into_inner());
        match &mut *target {
            Target::Native { pid, tree } => pause_native(*pid, *tree, paused),
            #[cfg(target_os = "linux")]
            Target::Cgroup { freeze, events } => pause_cgroup(freeze, events, paused),
            Target::Closed => Err(io::Error::other("process cleanup has started or finished")),
        }
    }
}

#[cfg(unix)]
fn pause_native(pid: u32, tree: bool, paused: bool) -> io::Result<()> {
    let signal = if paused { libc::SIGSTOP } else { libc::SIGCONT };
    let pid = pid as libc::pid_t;
    if tree && unsafe { libc::getpgid(pid) } == pid {
        if unsafe { libc::kill(-pid, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
    } else if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    if tree {
        for child in descendants(pid as u32) {
            if unsafe { libc::kill(child as libc::pid_t, signal) } != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    for _ in 0..40 {
        if process_stopped(pid)? == paused {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "process pause state was not confirmed",
    ))
}

#[cfg(not(unix))]
fn pause_native(_: u32, _: bool, _: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pause/resume is not supported on this platform",
    ))
}

#[cfg(target_os = "macos")]
fn process_stopped(pid: libc::pid_t) -> io::Result<bool> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as libc::c_int;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if read != size {
        return Err(io::Error::last_os_error());
    }
    if info.pbi_pid != pid as u32 || info.pbi_status == libc::SZOMB {
        return Err(io::Error::other("process is no longer running"));
    }
    Ok(info.pbi_status == libc::SSTOP)
}

#[cfg(target_os = "linux")]
fn process_stopped(pid: libc::pid_t) -> io::Result<bool> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let state = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().next())
        .ok_or_else(|| io::Error::other("process state is unavailable"))?;
    if state == "Z" || state == "X" {
        return Err(io::Error::other("process is no longer running"));
    }
    Ok(state == "T" || state == "t")
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_stopped(_: libc::pid_t) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process pause state cannot be confirmed on this platform",
    ))
}

#[cfg(target_os = "linux")]
fn descendants(root: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut queue = vec![root];
    while let Some(pid) = queue.pop() {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let Ok(children) = std::fs::read_to_string(task.path().join("children")) else {
                continue;
            };
            for token in children.split_whitespace() {
                let Ok(child) = token.parse::<u32>() else {
                    continue;
                };
                if child != root && !out.contains(&child) {
                    out.push(child);
                    queue.push(child);
                }
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn pause_cgroup(
    freeze: &mut std::fs::File,
    events: &mut std::fs::File,
    paused: bool,
) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    freeze.seek(SeekFrom::Start(0))?;
    freeze.write_all(if paused { b"1" } else { b"0" })?;
    let expected = if paused { "frozen 1" } else { "frozen 0" };
    for _ in 0..40 {
        events.seek(SeekFrom::Start(0))?;
        let mut status = String::new();
        events.read_to_string(&mut status)?;
        if status.lines().any(|line| line == expected) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "cgroup pause state was not confirmed",
    ))
}
