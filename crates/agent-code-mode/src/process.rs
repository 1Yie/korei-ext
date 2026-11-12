use crate::{CodeModeError, ErrorKind};
use async_trait::async_trait;
use std::io;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    process::Child,
};

/// Owns the native child, including any resource supervisor, until it is reaped.
#[async_trait]
pub trait WorkerProcess: Send + 'static {
    /// Supervise until exit and reap. Return success only for a successful exit.
    /// Runtime pins this future once throughout execution, including startup and
    /// stdout draining. After cancellation or failure it may call wait again.
    async fn wait(&mut self) -> Result<(), CodeModeError>;

    /// Initiate termination without reaping or releasing native child ownership.
    /// Calling this after exit must never signal a reused process identifier.
    fn start_kill(&mut self) -> io::Result<()>;
}

/// Framed worker pipes and the complete child adapter. The launcher supplies
/// sandbox policy; this endpoint carries no launch or registry authority.
pub struct ProcessEndpoint {
    pub process: Box<dyn WorkerProcess>,
    pub stdin: Box<dyn AsyncWrite + Send + Unpin>,
    pub stdout: Box<dyn AsyncRead + Send + Unpin>,
    pub stderr: Box<dyn AsyncRead + Send + Unpin>,
}

#[async_trait]
impl WorkerProcess for Child {
    async fn wait(&mut self) -> Result<(), CodeModeError> {
        let status = Child::wait(self).await.map_err(|error| {
            CodeModeError::new(
                ErrorKind::WorkerCrash,
                format!("failed to reap worker: {error}"),
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(CodeModeError::new(
                ErrorKind::WorkerCrash,
                format!("worker exited with {status}"),
            ))
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        Child::start_kill(self)
    }
}

impl TryFrom<Child> for ProcessEndpoint {
    type Error = CodeModeError;

    /// Take piped stdio while retaining the entire Tokio child as its adapter.
    fn try_from(mut child: Child) -> Result<Self, CodeModeError> {
        // Retain kill/reap ownership even when pipe extraction fails.
        let pipes = child
            .stdin
            .take()
            .zip(child.stdout.take())
            .zip(child.stderr.take());
        match pipes {
            Some(((stdin, stdout), stderr)) => Ok(Self {
                process: Box::new(child),
                stdin: Box::new(stdin),
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
            }),
            None => {
                drop(OwnedProcess(Some(Box::new(child))));
                Err(CodeModeError::new(
                    ErrorKind::Protocol,
                    "child stdio must be piped",
                ))
            }
        }
    }
}

pub(crate) struct OwnedProcess(pub Option<Box<dyn WorkerProcess>>);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}
