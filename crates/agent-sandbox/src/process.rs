//! Tool-facing pipes and control for native and isolated process owners.

use std::io;
use std::process::ExitStatus;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::spawn::SandboxedChild;

pub type ProcessInput = Box<dyn AsyncWrite + Unpin + Send>;
pub type ProcessOutput = Box<dyn AsyncRead + Unpin + Send>;

/// Retains the actual child owner while its pipes are used by a tool or service.
pub struct ManagedChild {
    pub stdin: Option<ProcessInput>,
    pub stdout: Option<ProcessOutput>,
    pub stderr: Option<ProcessOutput>,
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
            owner: Owner::Isolated(child),
        }
    }
}

impl ManagedChild {
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
            Owner::Native(child) => child.try_wait(),
            Owner::Isolated(child) => child.try_wait(),
        }
    }

    pub fn start_kill(&mut self) -> io::Result<()> {
        match &mut self.owner {
            Owner::Native(child) => child.start_kill(),
            Owner::Isolated(child) => child.start_kill(),
        }
    }

    /// Wait for the retained owner rather than a PID-based liveness estimate.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.owner {
            Owner::Native(child) => child.wait().await,
            Owner::Isolated(child) => child.wait().await,
        }
    }

    pub async fn kill(&mut self) -> io::Result<ExitStatus> {
        self.start_kill()?;
        self.wait().await
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
}
