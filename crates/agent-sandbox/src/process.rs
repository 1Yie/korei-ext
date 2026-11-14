//! Tool-facing pipes and control for native and isolated process owners.

use std::io;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::spawn::SandboxedChild;

pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

pub type ProcessInput = Box<dyn AsyncWrite + Unpin + Send>;
pub type ProcessOutput = Box<dyn AsyncRead + Unpin + Send>;

/// Retains the actual child owner while its pipes are used by a tool or service.
pub struct ManagedChild {
    pub stdin: Option<ProcessInput>,
    pub stdout: Option<ProcessOutput>,
    pub stderr: Option<ProcessOutput>,
    // The group guard must drop before its unreaped child owner.
    group: Option<crate::group_kill::GroupGuard>,
    owner: Owner,
}

enum Owner {
    Native(tokio::process::Child),
    Isolated(SandboxedChild),
}

impl From<tokio::process::Child> for ManagedChild {
    fn from(mut child: tokio::process::Child) -> Self {
        Self {
            stdin: child
                .stdin
                .take()
                .map(|pipe| Box::new(pipe) as ProcessInput),
            stdout: child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as ProcessOutput),
            stderr: child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as ProcessOutput),
            group: None,
            owner: Owner::Native(child),
        }
    }
}

impl From<SandboxedChild> for ManagedChild {
    fn from(mut child: SandboxedChild) -> Self {
        Self {
            stdin: child
                .stdin
                .take()
                .map(|pipe| Box::new(pipe) as ProcessInput),
            stdout: child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as ProcessOutput),
            stderr: child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as ProcessOutput),
            group: None,
            owner: Owner::Isolated(child),
        }
    }
}

impl ManagedChild {
    /// Adopt a native child started with `process_group(0)` on Unix.
    pub fn from_process_group(child: tokio::process::Child) -> Self {
        let mut process = Self::from(child);
        process.group = Some(crate::group_kill::GroupGuard::new(process.id()));
        process
    }

    pub fn is_isolated(&self) -> bool {
        matches!(self.owner, Owner::Isolated(_))
    }

    pub fn id(&self) -> Option<u32> {
        match &self.owner {
            Owner::Native(child) => child.id(),
            Owner::Isolated(child) => child.id(),
        }
    }

    /// Observe owner completion, including isolated process-tree cleanup.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match &mut self.owner {
            Owner::Native(child) => {
                let status = child.try_wait()?;
                if status.is_some() {
                    if let Some(group) = &mut self.group {
                        group.disarm();
                    }
                }
                Ok(status)
            }
            Owner::Isolated(child) => child.try_wait(),
        }
    }

    pub fn start_kill(&mut self) -> io::Result<()> {
        drop(self.group.take());
        match &mut self.owner {
            Owner::Native(child) => child.start_kill(),
            Owner::Isolated(child) => child.start_kill(),
        }
    }

    /// Wait for the retained owner rather than a PID-based liveness estimate.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.owner {
            Owner::Native(child) => {
                let status = child.wait().await?;
                if let Some(group) = &mut self.group {
                    group.disarm();
                }
                Ok(status)
            }
            Owner::Isolated(child) => child.wait().await,
        }
    }

    pub async fn kill(&mut self) -> io::Result<ExitStatus> {
        self.start_kill()?;
        self.wait().await
    }

    /// Drain bounded stdout/stderr while supervising timeout and actual cleanup.
    pub async fn output(mut self, timeout: Duration) -> io::Result<crate::CommandOutput> {
        let started = Instant::now();
        self.stdin.take();
        let stdout = self.stdout.take();
        let stderr = self.stderr.take();
        let captured = AtomicUsize::new(0);
        let wait = async {
            match tokio::time::timeout(timeout, self.wait()).await {
                Ok(status) => status.map(|status| (status, false)),
                Err(_) => self.kill().await.map(|status| (status, true)),
            }
        };
        let result =
            tokio::try_join!(wait, capture(stdout, &captured), capture(stderr, &captured),);
        let ((status, is_timeout), stdout, stderr) = match result {
            Ok(output) => output,
            Err(error) => {
                self.kill().await?;
                return Err(error);
            }
        };
        if matches!(&self.owner, Owner::Isolated(child) if child.rss_limit_exceeded()) {
            return Err(io::Error::other(
                "isolated process exceeded its memory limit",
            ));
        }
        Ok(crate::CommandOutput {
            status: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            is_timeout,
            sandbox_denials: Vec::new(),
            peak_memory_mb: None,
            elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        })
    }
}

async fn capture(pipe: Option<ProcessOutput>, captured: &AtomicUsize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let Some(mut pipe) = pipe else {
        return Ok(output);
    };
    let mut buffer = [0; 8192];
    loop {
        let read = pipe.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if captured.fetch_add(read, Ordering::Relaxed) > MAX_CAPTURE_BYTES.saturating_sub(read) {
            return Err(io::Error::other(format!(
                "process output exceeds capture budget ({MAX_CAPTURE_BYTES} bytes)"
            )));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn native_pipes_status_and_reaping_remain_available() {
        #[cfg(windows)]
        let mut command = {
            let mut command = tokio::process::Command::new("cmd.exe");
            command.args(["/c", "echo native-stdout&echo native-stderr 1>&2"]);
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = tokio::process::Command::new("/bin/sh");
            command.args(["-c", "printf native-stdout; printf native-stderr >&2"]);
            command
        };
        let mut child = ManagedChild::from(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap(),
        );
        assert!(!child.is_isolated());
        assert!(child.id().is_some());
        child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let mut out = String::new();
        let mut err = String::new();
        let (status, out_result, err_result) = tokio::join!(
            child.wait(),
            stdout.read_to_string(&mut out),
            stderr.read_to_string(&mut err),
        );
        assert!(status.unwrap().success());
        out_result.unwrap();
        err_result.unwrap();
        assert_eq!(out.trim(), "native-stdout");
        assert_eq!(err.trim(), "native-stderr");
        assert!(child.try_wait().unwrap().unwrap().success());
        assert!(child.id().is_none());
    }

    #[cfg(unix)]
    fn shell(script: &str) -> ManagedChild {
        tokio::process::Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
            .into()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_times_out_and_reaps_before_returning_partial_output() {
        let child = shell("printf ready; while :; do :; done");
        let pid = child.id().unwrap();
        let output = child.output(Duration::from_millis(50)).await.unwrap();
        assert!(output.is_timeout);
        assert_eq!(output.stdout, "ready");
        assert_ne!(output.status, 0);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_budget_counts_both_streams_and_stops_the_process() {
        let child = shell("printf '%0600000d' 0; printf '%0600000d' 0 >&2; while :; do :; done");
        let pid = child.id().unwrap();
        let error = child.output(Duration::from_secs(5)).await.unwrap_err();
        assert!(error.to_string().contains("exceeds capture budget"));
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }
}
