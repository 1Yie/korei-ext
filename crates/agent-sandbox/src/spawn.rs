//! Restricted process launch. No host environment is inherited.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;

use anyhow::{bail, Context, Result};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::process_control::ProcessControl;
use crate::snapshot::{RootId, SnapshotLease, WorkerScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEnforcement {
    /// Linux address-space limit or Windows Job committed-memory limit.
    OsHard,
    /// macOS sampled RSS; the VM must independently enforce its heap limit.
    MonitoredRss,
}

pub enum ExecutionScope {
    Snapshot(Arc<SnapshotLease>),
    Worker(WorkerScope),
}

impl From<SnapshotLease> for ExecutionScope {
    fn from(lease: SnapshotLease) -> Self {
        Self::Snapshot(Arc::new(lease))
    }
}

impl From<Arc<SnapshotLease>> for ExecutionScope {
    fn from(lease: Arc<SnapshotLease>) -> Self {
        Self::Snapshot(lease)
    }
}

impl From<WorkerScope> for ExecutionScope {
    fn from(scope: WorkerScope) -> Self {
        Self::Worker(scope)
    }
}

impl ExecutionScope {
    fn register_owner(&self, grants: &Arc<crate::EffectiveOsGrants>) {
        match self {
            Self::Snapshot(lease) => lease.register_owner(grants),
            Self::Worker(scope) => scope.register_owner(grants),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Snapshot(lease) => lease.validate(),
            Self::Worker(scope) => scope.directory().map(|_| ()),
        }
    }

    pub(crate) fn cwd(&self, request: &IsolatedSpawn) -> Result<&Path> {
        match self {
            Self::Snapshot(lease) => {
                lease.working_root(request.root.context("missing snapshot root")?)
            }
            Self::Worker(scope) => scope.directory(),
        }
    }

    pub(crate) fn writable_roots(&self) -> Result<Vec<PathBuf>> {
        match self {
            Self::Snapshot(lease) => lease
                .roots()
                .map(|root| lease.working_root(root).map(Path::to_owned))
                .collect(),
            Self::Worker(_) => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionKind {
    Worker,
    Tool,
}

/// All paths and environment entries are explicit host grants, never guest
/// input. Read grants must contain only the executable and runtime libraries.
#[derive(Debug, Clone)]
pub struct IsolatedSpawn {
    pub executable: PathBuf,
    /// Trusted host-supplied agent-sandbox-launcher ELF file, required on Linux.
    /// Its dynamic libraries use the explicit read_only grants.
    pub linux_launcher: Option<PathBuf>,
    /// Trusted delegated cgroup v2 parent with migration and cgroup.kill access.
    /// Required on Linux; other platforms do not consume this field.
    pub linux_cgroup_parent: Option<PathBuf>,
    pub args: Vec<std::ffi::OsString>,
    pub root: Option<RootId>,
    pub kind: ExecutionKind,
    pub read_only: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_write: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub memory_enforcement: MemoryEnforcement,
    /// Required for tools. Host policy is mapped through the live lease.
    pub tool_policy: Option<crate::SandboxConfig>,
}

/// Controlled pipes and cancellation-safe completion of an owned execution.
pub struct SandboxedChild {
    #[cfg(unix)]
    pub stdin: Option<tokio::process::ChildStdin>,
    #[cfg(unix)]
    pub stdout: Option<tokio::process::ChildStdout>,
    #[cfg(unix)]
    pub stderr: Option<tokio::process::ChildStderr>,
    #[cfg(windows)]
    pub stdin: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    #[cfg(windows)]
    pub stdout: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    #[cfg(windows)]
    pub stderr: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    pid: u32,
    effective_grants: Arc<crate::EffectiveOsGrants>,
    cancel: Arc<AtomicBool>,
    rss_exceeded: Arc<AtomicBool>,
    control: ProcessControl,
    completion: tokio::sync::watch::Receiver<Option<Result<std::process::ExitStatus, String>>>,
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        self.control.close();
        self.cancel.store(true, Ordering::Release);
    }
}

impl SandboxedChild {
    pub fn effective_grants(&self) -> Option<Arc<crate::EffectiveOsGrants>> {
        Some(Arc::clone(&self.effective_grants))
    }

    pub fn control(&self) -> ProcessControl {
        self.control.clone()
    }

    /// Observe completion only after the owner has finished scope cleanup.
    pub fn try_wait(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let closed = self.completion.has_changed().is_err();
        match self.completion.borrow().as_ref() {
            Some(result) => result.clone().map(Some).map_err(std::io::Error::other),
            None if closed => Err(std::io::Error::other("execution owner lost completion")),
            None => Ok(None),
        }
    }

    /// Wait for quiescence and scope release. Dropping this future only stops waiting.
    /// An owner error retains the scope whenever quiescence could not be proved.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(result) = self.completion.borrow().as_ref() {
                return result.clone().map_err(std::io::Error::other);
            }
            self.completion
                .changed()
                .await
                .map_err(|_| std::io::Error::other("execution owner lost completion"))?;
        }
    }

    pub async fn kill(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.start_kill()?;
        self.wait().await
    }

    pub fn start_kill(&mut self) -> std::io::Result<()> {
        self.control.close();
        self.cancel.store(true, Ordering::Release);
        Ok(())
    }

    pub fn id(&self) -> Option<u32> {
        if self.completion.borrow().is_none() {
            Some(self.pid)
        } else {
            None
        }
    }

    pub fn rss_limit_exceeded(&self) -> bool {
        self.rss_exceeded.load(Ordering::Acquire)
    }
}

#[cfg(windows)]
type Child = crate::windows_isolated::WindowsIsolatedChild;

struct ExecutionOwner {
    effective_grants: Arc<crate::EffectiveOsGrants>,
    scope: Option<ExecutionScope>,
    child: Option<Child>,
    control: ProcessControl,
    #[cfg(target_os = "macos")]
    group: crate::group_kill::GroupGuard,
    #[cfg(target_os = "linux")]
    cgroup: Option<crate::linux_cgroup::Cgroup>,
}

impl ExecutionOwner {
    fn cleanup(&mut self) -> Result<()> {
        self.control.close();
        #[cfg(target_os = "linux")]
        if let Some(group) = self.cgroup.as_mut() {
            group.kill()?;
            while group.populated()? {
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(child) = self.child.as_mut() {
                child.wait()?;
            }
            group.remove_empty()?;
            self.cgroup.take();
            return Ok(());
        }
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none() {
                #[cfg(unix)]
                child.kill()?;
                #[cfg(windows)]
                child.start_kill()?;
                while child.try_wait()?.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        #[cfg(target_os = "macos")]
        self.group.disarm();
        Ok(())
    }

    fn release(&mut self) {
        self.control.close();
        // Windows pins must close before the child's runtime scope is removed.
        self.effective_grants.close_pins();
        drop(self.child.take());
        drop(self.scope.take());
        self.effective_grants.released();
    }

    fn supervise(
        &mut self,
        cancel: &AtomicBool,
        rss_exceeded: &AtomicBool,
        memory_limit: u64,
    ) -> Result<std::process::ExitStatus> {
        #[cfg(target_os = "linux")]
        {
            let _ = (rss_exceeded, memory_limit);
            let child = self.child.as_mut().context("execution has no child")?;
            loop {
                let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id(),
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("observe isolated monitor");
                }
                if unsafe { info.si_pid() } != 0 || cancel.load(Ordering::Acquire) {
                    self.control.close();
                    let group = self.cgroup.as_mut().context("execution has no cgroup")?;
                    group.kill()?;
                    while group.populated()? {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    let status = child.wait()?;
                    group.remove_empty()?;
                    self.cgroup.take();
                    return Ok(status);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let child = self.child.as_mut().context("execution has no child")?;
        #[cfg(not(target_os = "linux"))]
        let mut killed = false;
        #[cfg(not(target_os = "linux"))]
        loop {
            if let Some(status) = self.control.observe_exit(|| child.try_wait())? {
                #[cfg(target_os = "macos")]
                self.group.disarm();
                return Ok(status);
            }
            #[cfg(target_os = "macos")]
            if !killed {
                match resident_bytes(child.id()) {
                    Ok(bytes) if bytes > memory_limit => {
                        rss_exceeded.store(true, Ordering::Release);
                        cancel.store(true, Ordering::Release);
                    }
                    Ok(_) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(error) => return Err(error).context("sample isolated process RSS"),
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (rss_exceeded, memory_limit);
            if cancel.load(Ordering::Acquire) && !killed {
                self.control.close();
                #[cfg(target_os = "macos")]
                child.kill()?;
                #[cfg(windows)]
                child.start_kill()?;
                killed = true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn start_owner(
    scope: ExecutionScope,
    memory_limit: u64,
    spawn: impl FnOnce(&mut ExecutionOwner) -> Result<Child> + Send + 'static,
) -> Result<SandboxedChild> {
    let handle = tokio::runtime::Handle::try_current().context("isolated I/O requires Tokio")?;
    let (started, startup) = std::sync::mpsc::sync_channel(1);
    let (completion, receiver) = tokio::sync::watch::channel(None);
    let cancel = Arc::new(AtomicBool::new(false));
    let rss_exceeded = Arc::new(AtomicBool::new(false));
    let owner_cancel = Arc::clone(&cancel);
    let owner_rss = Arc::clone(&rss_exceeded);
    let effective_grants = Arc::new(crate::EffectiveOsGrants::default());
    scope.register_owner(&effective_grants);
    std::thread::Builder::new()
        .name("sandbox-execution".into())
        .spawn(move || {
            // Only proved quiescence may drop capabilities, including during unwinding.
            let mut owner = std::mem::ManuallyDrop::new(ExecutionOwner {
                effective_grants,
                scope: Some(scope),
                child: None,
                control: ProcessControl::closed(),
                #[cfg(target_os = "macos")]
                group: crate::group_kill::GroupGuard::new(None),
                #[cfg(target_os = "linux")]
                cgroup: None,
            });
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
                    let entered = handle.enter();
                    owner.child = Some(spawn(&mut owner)?);
                    #[cfg(target_os = "macos")]
                    {
                        let pid = owner.child.as_ref().map(Child::id);
                        owner.group = crate::group_kill::GroupGuard::new(pid);
                    }
                    let control = owner.control.clone();
                    #[cfg(target_os = "linux")]
                    {
                        let group = owner
                            .cgroup
                            .as_ref()
                            .context("execution owner has no cgroup")?;
                        let (freeze, events) = group.freeze_control()?;
                        control.bind_cgroup(freeze, events);
                    }
                    let child = owner.child.as_mut().unwrap();
                    #[cfg(unix)]
                    let pid = child.id();
                    #[cfg(windows)]
                    let pid = child.id().context("isolated process has no PID")?;
                    #[cfg(not(target_os = "linux"))]
                    control.bind_native(pid);
                    let endpoint = SandboxedChild {
                        #[cfg(unix)]
                        stdin: child
                            .stdin
                            .take()
                            .map(tokio::process::ChildStdin::from_std)
                            .transpose()?,
                        #[cfg(unix)]
                        stdout: child
                            .stdout
                            .take()
                            .map(tokio::process::ChildStdout::from_std)
                            .transpose()?,
                        #[cfg(unix)]
                        stderr: child
                            .stderr
                            .take()
                            .map(tokio::process::ChildStderr::from_std)
                            .transpose()?,
                        #[cfg(windows)]
                        stdin: child.stdin.take(),
                        #[cfg(windows)]
                        stdout: child.stdout.take(),
                        #[cfg(windows)]
                        stderr: child.stderr.take(),
                        pid,
                        effective_grants: Arc::clone(&owner.effective_grants),
                        cancel,
                        rss_exceeded,
                        control,
                        completion: receiver,
                    };
                    drop(entered);
                    drop(handle);
                    if let Err(endpoint) = started.send(Ok(endpoint)) {
                        drop(endpoint);
                        owner_cancel.store(true, Ordering::Release);
                    }
                    owner.supervise(&owner_cancel, &owner_rss, memory_limit)
                }));
            match outcome {
                Ok(Ok(status)) => {
                    owner.release();
                    unsafe { std::mem::ManuallyDrop::drop(&mut owner) };
                    completion.send_replace(Some(Ok(status)));
                }
                failure => {
                    let message = match failure {
                        Ok(Err(error)) => format!("execution owner failed: {error:#}"),
                        Err(_) => "execution owner panicked".into(),
                        _ => unreachable!(),
                    };
                    let cleaned =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.cleanup()));
                    let message = match cleaned {
                        Ok(Ok(())) => {
                            owner.release();
                            unsafe { std::mem::ManuallyDrop::drop(&mut owner) };
                            let _ = started.send(Err(anyhow::anyhow!(message.clone())));
                            completion.send_replace(Some(Err(message)));
                            return;
                        }
                        Ok(Err(error)) => {
                            format!("{message}; cleanup failed: {error:#}; scope remains occupied")
                        }
                        Err(_) => format!("{message}; cleanup panicked; scope remains occupied"),
                    };
                    let _ = started.send(Err(anyhow::anyhow!(message.clone())));
                    completion.send_replace(Some(Err(message.clone())));
                    let _ = std::panic::catch_unwind(|| tracing::error!("{message}"));
                    // A failed proof of quiescence keeps every capability in this owner.
                    loop {
                        std::thread::park();
                        std::hint::black_box(&owner);
                    }
                }
            }
        })
        .context("start execution owner thread")?;
    startup.recv().context("execution owner lost startup")?
}

#[cfg(target_os = "macos")]
fn resident_bytes(pid: u32) -> std::io::Result<u64> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_taskinfo>() };
    let size = std::mem::size_of_val(&info) as i32;
    let result = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    if result != size {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info.pti_resident_size)
}

#[cfg(all(test, unix))]
mod owner_tests {
    use super::*;
    use crate::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
    use std::os::unix::fs::PermissionsExt;

    fn snapshot() -> (tempfile::TempDir, WorkspaceSnapshot) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("source");
        let storage = root.join("storage");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&storage).unwrap();
        std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = WorkspaceSnapshot::prepare(
            &[source],
            &storage,
            SnapshotBudget {
                max_bytes: 1024,
                max_entries: 16,
                max_depth: 4,
            },
            SnapshotPreference::NativePreferred,
        )
        .unwrap();
        (temp, snapshot)
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn lost_reaping_proof_keeps_the_actual_lease_after_owner_failure() {
        let (_temp, mut snapshot) = snapshot();
        fn lose_reaping_proof(owner: &mut ExecutionOwner) -> Result<Child> {
            let child = Command::new("/usr/bin/true").spawn()?;
            let pid = child.id();
            owner.child = Some(child);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid as i32, &mut status, 0) },
                pid as i32
            );
            panic!("injected owner panic after loss of exclusive reaping");
        }
        let result = start_owner(
            snapshot.lease().unwrap().into(),
            u64::MAX,
            lose_reaping_proof,
        );
        assert!(result.is_err());
        let grants = snapshot.effective_grants();
        assert_eq!(grants.len(), 1);
        assert!(!grants[0].is_quiescent());
        let candidate = _temp.path().canonicalize().unwrap().join("candidate");
        std::fs::create_dir(&candidate).unwrap();
        assert!(snapshot
            .append_roots_checked(&[candidate], |source, working| {
                grants[0].check_root_addition(source, working)
            })
            .is_err());
        assert!(snapshot.seal().is_err());
        let worker =
            WorkerScope::prepare(&_temp.path().canonicalize().unwrap().join("storage")).unwrap();
        let observer = worker.clone();
        assert!(start_owner(worker.into(), u64::MAX, lose_reaping_proof).is_err());
        let worker_grants = observer.effective_grants();
        assert_eq!(worker_grants.len(), 1);
        assert!(!worker_grants[0].is_quiescent());
        assert!(worker_grants[0]
            .check_root_addition(
                &_temp.path().canonicalize().unwrap(),
                &_temp.path().canonicalize().unwrap()
            )
            .is_err());
    }

    #[cfg(target_os = "linux")]
    fn delegated_parent() -> PathBuf {
        std::env::var_os("KOREI_TEST_CGROUP_PARENT")
            .map(PathBuf::from)
            .expect("native Linux tests require a writable delegated cgroup v2 parent")
    }

    #[cfg(target_os = "linux")]
    fn grouped_command(
        owner: &mut ExecutionOwner,
        parent: &Path,
        command: &mut Command,
    ) -> Result<PathBuf> {
        use std::os::fd::AsRawFd;
        owner.cgroup = Some(crate::linux_cgroup::Cgroup::create(parent)?);
        let join = owner.cgroup.as_ref().unwrap().join_file()?;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", join.as_raw_fd()))?
            .parent()
            .unwrap()
            .to_owned();
        crate::linux_cgroup::attach(command, join);
        Ok(path)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cgroup_finishes_double_fork_setsid_on_exit_cancel_and_endpoint_drop() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let parent = delegated_parent();
        let (temp, _) = snapshot();
        let executable = temp.path().join("cgroup-probe");
        let output = Command::new("cc")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/cgroup_probe.c"
            ))
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for mode in ["exit", "cancel", "drop"] {
            let (_temp, mut snapshot) = snapshot();
            let lease = snapshot.lease().unwrap();
            let marker = lease
                .working_root(lease.roots().next().unwrap())
                .unwrap()
                .join("marker");
            let mut command = Command::new(&executable);
            command
                .args([std::ffi::OsStr::new(mode), marker.as_os_str()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped());
            let parent = parent.clone();
            let (paths, path) = std::sync::mpsc::sync_channel(1);
            let mut endpoint = start_owner(lease.into(), u64::MAX, move |owner| {
                paths.send(grouped_command(owner, &parent, &mut command)?)?;
                Ok(command.spawn()?)
            })
            .unwrap();
            let group = path.recv().unwrap();
            let mut output = BufReader::new(endpoint.stdout.take().unwrap());
            let mut ready = String::new();
            tokio::time::timeout(Duration::from_secs(5), output.read_line(&mut ready))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(ready, "ready\n");
            if mode == "drop" {
                assert!(snapshot.seal().is_err());
                drop(endpoint);
            } else {
                if mode == "cancel" {
                    assert!(snapshot.seal().is_err());
                    assert!(
                        tokio::time::timeout(Duration::from_millis(25), endpoint.wait())
                            .await
                            .is_err()
                    );
                    endpoint.start_kill().unwrap();
                }
                let status = tokio::time::timeout(Duration::from_secs(5), endpoint.wait())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(status.success(), mode == "exit");
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while snapshot.seal().is_err() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "cgroup did not finish"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!group.exists(), "execution cgroup was not removed");
            let bytes = std::fs::read(&marker).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(
                std::fs::read(marker).unwrap(),
                bytes,
                "descendant wrote after seal"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cgroup_setup_exec_and_migration_failures_prevent_target_and_release_only_empty_groups()
    {
        use std::os::fd::AsRawFd;
        for failure in ["setup", "exec", "migration"] {
            let (_temp, mut snapshot) = snapshot();
            let lease = snapshot.lease().unwrap();
            let marker = lease
                .working_root(lease.roots().next().unwrap())
                .unwrap()
                .join("executed");
            let target = marker.clone();
            let parent = delegated_parent();
            let (paths, path) = std::sync::mpsc::sync_channel(1);
            let result = start_owner(lease.into(), u64::MAX, move |owner| {
                let mut command = Command::new(if failure == "exec" {
                    "/korei-missing-executable"
                } else {
                    "/bin/sh"
                });
                command
                    .arg("-c")
                    .arg("echo executed > \"$1\"")
                    .arg("probe")
                    .arg(target);
                owner.cgroup = Some(crate::linux_cgroup::Cgroup::create(&parent)?);
                let join = owner.cgroup.as_ref().unwrap().join_file()?;
                let group = std::fs::read_link(format!("/proc/self/fd/{}", join.as_raw_fd()))?;
                paths.send(group.parent().unwrap().to_owned())?;
                let fd = join.as_raw_fd();
                unsafe {
                    command.pre_exec(move || {
                        if failure == "setup" {
                            return Err(std::io::Error::from_raw_os_error(libc::EACCES));
                        }
                        if failure == "migration" {
                            libc::close(fd);
                        }
                        Ok(())
                    });
                }
                crate::linux_cgroup::attach(&mut command, join);
                Ok(command.spawn()?)
            });
            assert!(result.is_err());
            assert!(!marker.exists());
            assert!(!path.recv().unwrap().exists());
            snapshot.seal().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cgroup_cleanup_error_retains_the_actual_lease_and_reports_failure() {
        let (_temp, mut snapshot) = snapshot();
        let parent = delegated_parent();
        let result = start_owner(snapshot.lease().unwrap().into(), u64::MAX, move |owner| {
            let mut command = Command::new("/bin/true");
            grouped_command(owner, &parent, &mut command)?;
            let child = command.spawn()?;
            let pid = child.id();
            owner.child = Some(child);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid as i32, &mut status, 0) },
                pid as i32
            );
            bail!("injected loss of exclusive reaping");
        });
        assert!(result.is_err());
        assert!(snapshot.seal().is_err());
    }
}

/// Starts an already-confined process with piped stdin/stdout/stderr. A valid
/// tool lease is mandatory; workers may use an empty private WorkerScope.
pub fn spawn_isolated(
    scope: impl Into<ExecutionScope>,
    request: &IsolatedSpawn,
) -> Result<SandboxedChild> {
    let scope = scope.into();
    scope.validate()?;
    let mut request = request.clone();
    if request.kind == ExecutionKind::Tool {
        let ExecutionScope::Snapshot(lease) = &scope else {
            bail!("tool execution requires a live snapshot lease");
        };
        let policy = request
            .tool_policy
            .as_ref()
            .context("tool execution requires its original SandboxConfig")?;
        if policy.allow_network
            || !policy.allowed_domains.is_empty()
            || !policy.allow_read.is_empty()
        {
            bail!("isolated tool network/allow-read exceptions are unsupported");
        }
        let map = |path: &Path| -> Result<PathBuf> {
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                policy.workspace_dir.join(path)
            };
            let (root, relative) = lease.map_source(&path)?;
            Ok(lease.working_root(root)?.join(relative))
        };
        lease.map_source(&policy.workspace_dir)?;
        for path in &policy.extra_rw_mounts {
            map(path)?;
        }
        request.deny_read.extend(
            policy
                .deny_read
                .iter()
                .map(|p| {
                    if p.is_absolute() && lease.map_source(p).is_err() {
                        Ok(p.clone())
                    } else {
                        map(p)
                    }
                })
                .collect::<Result<Vec<_>>>()?,
        );
        request.deny_write.extend(
            policy
                .deny_write
                .iter()
                .map(|p| map(p))
                .collect::<Result<Vec<_>>>()?,
        );
        for path in &policy.extra_ro_mounts {
            if let Ok(mapped) = map(path) {
                request.deny_write.push(mapped);
            } else {
                request.read_only.push(path.clone());
            }
        }
        request.env.extend(policy.env_vars.clone());
        request.env.extend(policy.trusted_env.clone());
        if policy.max_memory_mb != 0 {
            request.max_memory_bytes = request.max_memory_bytes.min(
                policy
                    .max_memory_mb
                    .checked_mul(1024 * 1024)
                    .context("memory limit overflow")?,
            );
        }
        if policy.max_processes != 0 {
            request.max_processes = request.max_processes.min(policy.max_processes);
        }
    }
    // Host merges such as `/bin` -> `usr/bin` are real directories only after
    // resolution. The directory walk does not follow links, so an unresolved
    // parent fails as "not a directory".
    #[cfg(unix)]
    {
        request.executable =
            std::fs::canonicalize(&request.executable).context("resolve isolated executable")?;
    }
    let request = &request;
    if request.max_memory_bytes == 0 || request.max_processes == 0 {
        bail!("isolated execution requires explicit memory and process limits");
    }
    #[cfg(not(target_os = "linux"))]
    if request.linux_launcher.is_some() {
        bail!("a Linux launcher is unsupported on this platform");
    }
    #[cfg(target_os = "linux")]
    {
        let mut real = 0;
        let mut effective = 0;
        let mut saved = 0;
        if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error()).context("read Linux host UID");
        }
        if [real, effective, saved].contains(&0) {
            bail!("Linux isolated launch requires a non-root host UID");
        }
        let count = request
            .max_processes
            .checked_add(1)
            .context("task allowance plus PID1 overflows")?;
        let mut inherited: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut inherited) } != 0 {
            return Err(std::io::Error::last_os_error()).context("read inherited task allowance");
        }
        if libc::rlim_t::from(count) > inherited.rlim_cur
            || libc::rlim_t::from(count) > inherited.rlim_max
        {
            bail!("inherited task allowance is insufficient");
        }
        let launcher = request
            .linux_launcher
            .as_ref()
            .context("Linux requires a trusted agent-sandbox-launcher")?;
        if !launcher.is_absolute() {
            bail!("Linux launcher must be an absolute host path");
        }
        let parent =
            crate::snapshot_fs::Dir::open(launcher.parent().context("launcher has no parent")?)?;
        let mut file = parent.read(Path::new(
            launcher.file_name().context("launcher has no name")?,
        ))?;
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let mut magic = [0; 4];
        file.read_exact(&mut magic)
            .context("read Linux launcher ELF header")?;
        if magic != *b"\x7fELF" || file.metadata()?.permissions().mode() & 0o111 == 0 {
            bail!("Linux launcher must be an executable ELF file");
        }
        for path in request
            .read_only
            .iter()
            .chain(&request.deny_read)
            .chain(&request.deny_write)
            .map(PathBuf::as_path)
            .chain(std::iter::once(request.executable.as_path()))
            .chain(std::iter::once(scope.cwd(request)?))
        {
            for reserved in [Path::new("/proc"), Path::new("/.korei-launcher")] {
                if path.starts_with(reserved) || reserved.starts_with(path) {
                    bail!("a requested grant or deny overlaps the Linux launcher runtime");
                }
            }
        }
        let mut writable = scope.writable_roots()?;
        writable.push(scope.cwd(request)?.to_path_buf());
        for root in writable {
            let root = crate::snapshot_fs::Dir::open(&root)?;
            if launcher.starts_with(&root.path) || parent.lineage()?.contains(&root.identity()?) {
                bail!("Linux launcher overlaps a private execution directory");
            }
        }
    }
    if !request.executable.is_absolute() || !request.executable.is_file() {
        bail!("isolated executable must be an existing absolute file");
    }
    crate::snapshot_fs::Dir::open(
        request
            .executable
            .parent()
            .context("executable has no parent")?,
    )?
    .read(Path::new(
        request
            .executable
            .file_name()
            .context("executable has no filename")?,
    ))?;
    #[cfg(target_os = "macos")]
    if request.memory_enforcement != MemoryEnforcement::MonitoredRss {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS provides monitored RSS, not an OS-hard memory quota",
        )
        .into());
    }
    #[cfg(not(target_os = "macos"))]
    if request.memory_enforcement != MemoryEnforcement::OsHard {
        bail!("this platform requires OS-hard memory enforcement");
    }
    let source_roots: Vec<_> = match &scope {
        ExecutionScope::Snapshot(lease) => lease
            .roots()
            .map(|id| lease.source_root(id).map(Path::to_owned))
            .collect::<Result<_>>()?,
        ExecutionScope::Worker(_) => Vec::new(),
    };
    let source_handles = source_roots
        .iter()
        .map(|path| crate::snapshot_fs::Dir::open(path))
        .collect::<std::io::Result<Vec<_>>>()?;
    let executable_parent = crate::snapshot_fs::Dir::open(
        request
            .executable
            .parent()
            .context("executable has no parent")?,
    )?;
    for source in &source_handles {
        if executable_parent.lineage()?.contains(&source.identity()?) {
            bail!("isolated executable overlaps a source workspace identity");
        }
    }
    if source_roots
        .iter()
        .any(|root| request.executable.starts_with(root))
    {
        bail!("isolated executable must not read the source workspace");
    }
    #[cfg(target_os = "linux")]
    let mut runtime_bindings = Vec::new();
    #[cfg(target_os = "linux")]
    let runtime_forbidden = {
        let mut roots = source_roots.clone();
        roots.extend(scope.writable_roots()?);
        roots.push(scope.cwd(request)?.to_path_buf());
        roots
    };
    for (index, path) in request
        .read_only
        .iter()
        .chain(request.linux_launcher.iter())
        .enumerate()
    {
        #[cfg(not(target_os = "linux"))]
        let _ = index;
        #[cfg(target_os = "linux")]
        let resolved = runtime_alias_target(path, &runtime_forbidden)?;
        #[cfg(target_os = "linux")]
        if resolved.starts_with("/proc") || Path::new("/proc").starts_with(&resolved) {
            bail!("runtime read grant overlaps the Linux launcher procfs");
        }
        #[cfg(not(target_os = "linux"))]
        let resolved = path.clone();
        let directory = crate::snapshot_fs::Dir::open(if resolved.is_dir() {
            &resolved
        } else {
            resolved.parent().context("read grant has no parent")?
        })?;
        for source in &source_handles {
            if directory.lineage()?.contains(&source.identity()?)
                || (resolved.is_dir() && source.lineage()?.contains(&directory.identity()?))
            {
                bail!("runtime read grant overlaps a source workspace identity");
            }
        }
        if !resolved.is_dir() {
            crate::snapshot_fs::Dir::open(resolved.parent().context("read grant has no parent")?)?
                .read(Path::new(
                    resolved.file_name().context("read grant has no filename")?,
                ))?;
        }
        if source_roots.iter().any(|root| {
            resolved.starts_with(root)
                || root.starts_with(&resolved)
                || path.starts_with(root)
                || root.starts_with(path)
        }) {
            bail!("runtime read grant overlaps a source workspace");
        }
        #[cfg(target_os = "linux")]
        {
            let destination = if index < request.read_only.len() {
                path.as_path()
            } else {
                Path::new("/.korei-launcher")
            };
            validate_linux_runtime_binding(&scope, request, &resolved, destination)?;
            runtime_bindings.push((resolved, destination.to_path_buf()));
        }
    }
    if request
        .env
        .iter()
        .any(|(key, value)| crate::env_sanitize::is_denied(key, value))
    {
        bail!("isolated environment contains a denied key");
    }
    #[cfg(windows)]
    {
        let request = request.clone();
        return start_owner(scope, request.max_memory_bytes, move |owner| {
            crate::windows_isolated::spawn(
                owner.scope.as_ref().unwrap(),
                &request,
                &owner.effective_grants,
            )
        });
    }
    #[cfg(unix)]
    {
        let request = request.clone();
        let memory = request.max_memory_bytes;
        #[cfg(target_os = "linux")]
        let parent = request.linux_cgroup_parent.clone()
            .context("Linux isolated execution requires linux_cgroup_parent in a delegated cgroup v2 subtree")?;
        start_owner(scope, memory, move |owner| {
            let scope = owner.scope.as_ref().unwrap();
            #[cfg(target_os = "linux")]
            let mut command =
                unix_command(scope, &request, &runtime_bindings, &owner.effective_grants)?;
            #[cfg(not(target_os = "linux"))]
            let mut command = unix_command(scope, &request, &owner.effective_grants)?;
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_clear()
                .envs(request.env.iter().cloned())
                .process_group(0);
            unsafe {
                command.pre_exec(move || {
                    #[cfg(target_os = "linux")]
                    let memory = libc::rlimit {
                        rlim_cur: memory as libc::rlim_t,
                        rlim_max: memory as libc::rlim_t,
                    };
                    #[cfg(target_os = "linux")]
                    if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    #[cfg(target_os = "macos")]
                    let _ = memory;
                    Ok(())
                });
            }
            #[cfg(target_os = "linux")]
            {
                owner.cgroup = Some(crate::linux_cgroup::Cgroup::create(&parent)?);
                let join = owner.cgroup.as_ref().unwrap().join_file()?;
                crate::linux_cgroup::attach(&mut command, join);
            }
            owner.effective_grants.ready();
            command.spawn().context("start isolated process")
        })
    }
    #[cfg(not(any(unix, windows)))]
    bail!("isolated process launch is unsupported on this platform")
}

#[cfg(all(unix, any(target_os = "linux", test)))]
fn runtime_alias_target(path: &Path, forbidden: &[PathBuf]) -> Result<PathBuf> {
    use std::collections::VecDeque;
    use std::path::Component;

    if !path.is_absolute() {
        bail!("runtime grant must be absolute");
    }
    let roots = forbidden
        .iter()
        .map(|root| crate::snapshot_fs::Dir::open(root))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut pending: VecDeque<_> = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::from("/");
    let mut links = 0;
    while let Some(component) = pending.pop_front() {
        match Path::new(&component).components().next() {
            Some(Component::RootDir) => resolved = PathBuf::from("/"),
            Some(Component::CurDir) => {}
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::Normal(name)) => {
                let directory = crate::snapshot_fs::Dir::open(&resolved)?;
                for root in &roots {
                    if directory.lineage()?.contains(&root.identity()?) {
                        bail!("runtime alias traverses a workspace identity");
                    }
                }
                let candidate = resolved.join(name);
                if forbidden.iter().any(|root| candidate.starts_with(root)) {
                    bail!("runtime alias traverses a workspace");
                }
                if let Some(target) = directory.symlink_target(Path::new(name))? {
                    links += 1;
                    if links > 40 {
                        bail!("runtime alias chain exceeds its link limit");
                    }
                    for part in target.components().rev() {
                        pending.push_front(part.as_os_str().to_owned());
                    }
                } else {
                    resolved = candidate;
                }
            }
            _ => bail!("invalid runtime alias component"),
        }
    }
    let directory = crate::snapshot_fs::Dir::open(if resolved.is_dir() {
        &resolved
    } else {
        resolved.parent().context("runtime grant has no parent")?
    })?;
    for root in &roots {
        if directory.lineage()?.contains(&root.identity()?)
            || (resolved.is_dir() && root.lineage()?.contains(&directory.identity()?))
        {
            bail!("runtime grant overlaps a workspace identity");
        }
    }
    if !resolved.is_dir() {
        directory.read(Path::new(
            resolved
                .file_name()
                .context("runtime grant has no filename")?,
        ))?;
    }
    Ok(resolved)
}

#[cfg(all(test, unix))]
mod alias_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn runtime_alias_rejects_workspace_intermediate_hops() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let trusted = base.join("trusted");
        let workspace = base.join("workspace");
        let external = base.join("external");
        for path in [&trusted, &workspace, &external] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(external.join("lib"), b"library").unwrap();
        symlink(external.join("lib"), workspace.join("link")).unwrap();
        symlink(workspace.join("link"), trusted.join("alias")).unwrap();
        assert!(runtime_alias_target(&trusted.join("alias"), &[workspace.clone()]).is_err());
        symlink(&workspace, trusted.join("directory")).unwrap();
        assert!(
            runtime_alias_target(&trusted.join("directory/../external/lib"), &[workspace]).is_err()
        );
    }

    #[test]
    fn runtime_alias_accepts_trusted_loader_links() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let trusted = base.join("trusted");
        let workspace = base.join("workspace");
        std::fs::create_dir(&trusted).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(trusted.join("loader"), b"library").unwrap();
        symlink("loader", trusted.join("relative")).unwrap();
        symlink(trusted.join("relative"), trusted.join("absolute")).unwrap();
        for path in [trusted.join("loader"), trusted.join("absolute")] {
            assert_eq!(
                runtime_alias_target(&path, &[workspace.clone()]).unwrap(),
                trusted.join("loader")
            );
        }
        symlink(&trusted, base.join("directory")).unwrap();
        assert_eq!(
            runtime_alias_target(&base.join("directory/loader"), &[workspace]).unwrap(),
            trusted.join("loader")
        );
    }

    #[test]
    fn runtime_alias_refuses_direct_workspace_cycles_and_metadata_errors() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let workspace = base.join("workspace");
        let working = base.join("working");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&working).unwrap();
        let forbidden = [workspace.clone(), working.clone()];
        for (index, root) in forbidden.iter().enumerate() {
            std::fs::write(root.join("data"), b"private").unwrap();
            let alias = base.join(format!("direct-{index}"));
            symlink(root.join("data"), &alias).unwrap();
            assert!(runtime_alias_target(&alias, &forbidden).is_err());
            assert!(runtime_alias_target(&root.join("data"), &forbidden).is_err());
        }
        symlink("cycle-b", base.join("cycle-a")).unwrap();
        symlink("cycle-a", base.join("cycle-b")).unwrap();
        symlink("absent", base.join("dangling")).unwrap();
        std::fs::write(base.join("file"), b"file").unwrap();
        for name in ["cycle-a", "dangling", "absent", "file/child"] {
            assert!(runtime_alias_target(&base.join(name), &forbidden).is_err());
        }
        for index in 0..=40 {
            symlink(
                format!("link-{}", index + 1),
                base.join(format!("link-{index}")),
            )
            .unwrap();
        }
        std::fs::write(base.join("link-41"), b"end").unwrap();
        assert!(runtime_alias_target(&base.join("link-0"), &forbidden).is_err());
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_runtime_binding(
    scope: &ExecutionScope,
    request: &IsolatedSpawn,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    use crate::snapshot_fs::Dir;
    use std::os::unix::fs::MetadataExt;
    let overlaps = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
    if !destination.is_absolute()
        || destination
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("runtime destination requires an unambiguous absolute path");
    }
    let directory = Dir::open(if source.is_dir() {
        source
    } else {
        source.parent().context("runtime source has no parent")?
    })?;
    let mut private = scope.writable_roots()?;
    private.push(scope.cwd(request)?.to_path_buf());
    for root in private {
        let root = Dir::open(&root)?;
        if overlaps(destination, &root.path)
            || overlaps(source, &root.path)
            || directory.lineage()?.contains(&root.identity()?)
            || (source.is_dir() && root.lineage()?.contains(&directory.identity()?))
        {
            bail!("runtime binding overlaps a private execution directory");
        }
    }
    for denied in request.deny_read.iter().chain(&request.deny_write) {
        if !denied.is_absolute()
            || denied
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            bail!("runtime protection requires an unambiguous absolute path");
        }
        let mut existing = denied.as_path();
        let mut suffix = Vec::new();
        let mut protected = loop {
            match existing.canonicalize() {
                Ok(path) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    suffix.push(
                        existing
                            .file_name()
                            .context("cannot resolve protected runtime path")?,
                    );
                    existing = existing
                        .parent()
                        .context("protected runtime path has no ancestor")?;
                }
                Err(error) => return Err(error).context("resolve protected runtime path"),
            }
        };
        for name in suffix.into_iter().rev() {
            protected.push(name);
        }
        let textual = overlaps(source, &protected);
        let identity = if protected.is_dir() {
            let protected = Dir::open(&protected)?;
            directory.lineage()?.contains(&protected.identity()?)
                || (source.is_dir() && protected.lineage()?.contains(&directory.identity()?))
        } else if protected.is_file() && !source.is_dir() {
            let protected = std::fs::metadata(&protected)?;
            let source = std::fs::metadata(source)?;
            (source.dev(), source.ino()) == (protected.dev(), protected.ino())
        } else {
            false
        };
        if (textual || identity || overlaps(destination, denied))
            && !(source == destination && &protected == denied && overlaps(destination, denied))
        {
            bail!("runtime alias conflicts with a protected read/write path");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn unix_command(
    scope: &ExecutionScope,
    request: &IsolatedSpawn,
    grants: &crate::EffectiveOsGrants,
) -> Result<Command> {
    if !crate::mac_sandbox_exec::sandbox_exec_on_path() {
        bail!("sandbox-exec is required; no unconfined fallback");
    }
    // Seatbelt has no per-task process-count quota. A single-process profile
    // enforces the supported limit by denying fork entirely.
    if request.max_processes != 1 {
        bail!("macOS isolated launch supports exactly one process; fork is denied");
    }
    let quote = |path: &Path| -> Result<String> {
        let text = path
            .to_str()
            .context("Seatbelt cannot represent this non-UTF8 grant")?;
        if text.chars().any(|c| c.is_control()) {
            bail!("control character in Seatbelt grant");
        }
        Ok(format!(
            "\"{}\"",
            text.replace('\\', "\\\\").replace('"', "\\\"")
        ))
    };
    let mut profile = String::from("(version 1)(deny default)(allow process-exec)(deny process-fork)(allow signal (target self))(allow sysctl-read)(allow file-read-metadata)(allow file-read-data (literal \"/dev/urandom\") (literal \"/dev/random\"))(allow file-read* file-write-data (literal \"/dev/null\"))");
    // dyld inspects the root directory while locating its shared cache.
    profile.push_str("(allow file-read-data (literal \"/\"))");
    grants.seatbelt_implicit()?;
    profile.push_str(&format!(
        "(allow file-read* (literal {}))",
        quote(&request.executable)?
    ));
    grants.allow(&request.executable, None, "Seatbelt literal read")?;
    for path in &request.read_only {
        profile.push_str(&format!(
            "(allow file-read* ({} {}))",
            if path.is_dir() { "subpath" } else { "literal" },
            quote(path)?
        ));
        grants.allow(path, None, "Seatbelt runtime read")?;
    }
    let cwd = scope.cwd(request)?;
    if request.kind == ExecutionKind::Tool {
        for root in scope.writable_roots()? {
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath {}))",
                quote(&root)?
            ));
            grants.allow(&root, None, "Seatbelt private read/write")?;
        }
    }
    for path in &request.deny_read {
        profile.push_str(&format!("(deny file-read* (subpath {}))", quote(path)?));
        grants.deny(path, "Seatbelt read deny");
    }
    for path in &request.deny_write {
        profile.push_str(&format!("(deny file-write* (subpath {}))", quote(path)?));
        grants.deny(path, "Seatbelt write deny");
    }
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-p")
        .arg(profile)
        .arg(&request.executable)
        .args(&request.args)
        .current_dir(cwd);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn unix_command(
    scope: &ExecutionScope,
    request: &IsolatedSpawn,
    runtime: &[(PathBuf, PathBuf)],
    grants: &crate::EffectiveOsGrants,
) -> Result<Command> {
    let backend = crate::LinuxBwrap;
    use crate::SandboxBackend;
    if backend.id() != "bwrap" {
        bail!("bwrap is required");
    }
    let mut command = Command::new("bwrap");
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]);
    for (source, destination) in runtime {
        command.arg("--ro-bind").arg(source).arg(destination);
        grants.allow(source, Some(destination), "bwrap runtime ro-bind")?;
    }
    command
        .arg("--ro-bind")
        .arg(&request.executable)
        .arg(&request.executable);
    grants.allow(
        &request.executable,
        Some(&request.executable),
        "bwrap executable ro-bind",
    )?;
    let cwd = scope.cwd(request)?;
    if request.kind == ExecutionKind::Tool {
        for path in scope.writable_roots()? {
            command.arg("--bind").arg(&path).arg(&path);
            grants.allow(&path, Some(&path), "bwrap private read/write bind")?;
        }
    } else {
        command.arg("--dir").arg(cwd);
    }
    for path in &request.deny_read {
        if path.exists() {
            if path.is_dir() {
                command.arg("--tmpfs").arg(path);
            } else {
                command.arg("--ro-bind").arg("/dev/null").arg(path);
            }
            grants.deny(path, "bwrap masked read deny");
        }
    }
    for path in &request.deny_write {
        if path.exists() {
            command.arg("--ro-bind").arg(path).arg(path);
            grants.allow(path, Some(path), "bwrap write-deny ro-bind")?;
            grants.deny(path, "bwrap write deny");
        }
    }
    command
        .arg("--chdir")
        .arg(cwd)
        .arg("--")
        .arg("/.korei-launcher")
        .arg("--max-processes")
        .arg(request.max_processes.to_string())
        .arg("--")
        .arg(&request.executable)
        .args(&request.args);
    Ok(command)
}
