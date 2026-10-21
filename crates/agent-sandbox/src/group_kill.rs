//! Tree-kill when a running command is abandoned.
//!
//! `kill_on_drop` only reaches the direct child (`sh`); a build it started
//! lives on as an orphan. Backends that put the child in its own process
//! group (`process_group(0)`) hold a [`GroupGuard`] across the wait, so a
//! dropped future — the kernel racing a tool against the user's cancel —
//! takes the whole group with it. bwrap does not need it: `--unshare-pid
//! --die-with-parent` already ends the namespace with its init. Elsewhere
//! (Windows: no process groups) the guard is a no-op.

/// SIGKILLs the process group `pgid` on drop unless [`disarm`](Self::disarm)ed.
///
/// Safe against pid reuse: the guard is disarmed as soon as the wait returns,
/// and until then the group leader has not been reaped, so the id still names
/// this group.
pub(crate) struct GroupGuard {
    pgid: Option<u32>,
}

impl GroupGuard {
    /// Guard the group led by `pgid` — the child's own pid under
    /// `process_group(0)`. `None` (the child already gone) guards nothing.
    pub(crate) fn new(pgid: Option<u32>) -> Self {
        Self { pgid }
    }

    /// The wait returned on its own: whatever the command left behind is no
    /// longer this call's to kill, and the id may soon be reused.
    pub(crate) fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid.take() {
            // SAFETY: `kill` takes plain integers and has no memory-safety
            // contract; a group that is already gone yields ESRCH.
            unsafe {
                libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    /// Whether `pid` is still a running (non-zombie) process.
    fn running(pid: i32) -> bool {
        // SAFETY: signal 0 only probes for existence.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        // A killed process may linger as a zombie until its parent reaps it.
        !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit(')')
                    .next()
                    .map(|r| r.trim_start().starts_with('Z'))
            })
            .unwrap_or(false)
    }

    /// The guard reaches a grandchild, which `kill_on_drop` alone does not.
    #[tokio::test]
    async fn dropping_the_guard_kills_the_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep 30 & echo $! > {}; wait", pidfile.display()))
            .kill_on_drop(true)
            .process_group(0)
            .spawn()
            .unwrap();
        let guard = GroupGuard::new(child.id());
        let grandchild = loop {
            if let Some(pid) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(running(grandchild));

        drop(child);
        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(5);
        while running(grandchild) {
            assert!(
                Instant::now() < deadline,
                "grandchild {grandchild} survived"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn a_disarmed_guard_kills_nothing() {
        // Its own group: a guard that wrongly fired must not hit the runner.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let mut guard = GroupGuard::new(Some(child.id()));
        guard.disarm();
        drop(guard);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            child.try_wait().unwrap().is_none(),
            "the child must live on"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
