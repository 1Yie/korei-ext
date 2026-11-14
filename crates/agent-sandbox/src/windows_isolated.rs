use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::ptr::{null, null_mut};
#[cfg(test)]
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::{DENY_ACCESS, GRANT_ACCESS};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::*;

use crate::snapshot::WorkerScope;
use crate::spawn::{ExecutionKind, ExecutionScope, IsolatedSpawn};
use crate::windows_acl::AclGrant;

struct Handle(HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn checked(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: impl AsRef<OsStr>) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.as_ref().encode_wide().collect();
    if result.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    result.push(0);
    Ok(result)
}

fn nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("system random source failed: {status:#x}");
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

struct Profile {
    name: Vec<u16>,
    sid: PSID,
}
unsafe impl Send for Profile {}
impl Profile {
    fn create() -> Result<Self> {
        let name = wide(format!("korei-{}", nonce()?))?;
        let mut sid = null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        // Only a successfully created profile belongs to this execution.
        if result < 0 {
            bail!("create unique AppContainer profile: {result:#x}");
        }
        Ok(Self { name, sid })
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.sid);
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn new() -> io::Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size);
        }
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { storage })
    }
    fn set<T>(&mut self, attribute: usize, value: &mut T) -> io::Result<()> {
        checked(unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute,
                (value as *mut T).cast(),
                std::mem::size_of::<T>(),
                null_mut(),
                null(),
            )
        })
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

/// Overlapped parent endpoint; only the synchronous child endpoint is inherited.
fn pipe(input: bool) -> Result<(NamedPipeServer, Handle)> {
    let name = format!(r"\\.\pipe\korei-{}", nonce()?);
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .access_inbound(!input)
        .access_outbound(input)
        .reject_remote_clients(true)
        .create(&name)?;
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let child = unsafe {
        CreateFileW(
            wide(&name)?.as_ptr(),
            if input { GENERIC_READ } else { GENERIC_WRITE },
            0,
            &security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if child == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok((server, Handle(child)))
}

fn acl_file(path: &Path) -> io::Result<File> {
    if path.is_dir() {
        crate::snapshot_fs::Dir::open(path)?.acl_handle(None)
    } else {
        crate::snapshot_fs::Dir::open(
            path.parent()
                .ok_or_else(|| io::Error::other("ACL target has no parent"))?,
        )?
        .acl_handle(Some(Path::new(
            path.file_name()
                .ok_or_else(|| io::Error::other("ACL target has no name"))?,
        )))
    }
}

fn grant_tree(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
    grants: &mut Vec<AclGrant>,
) -> Result<()> {
    let directory = crate::snapshot_fs::Dir::open(path)?;
    grants.push(AclGrant::entry(acl_file(path)?, sid, access, mode, true)?);
    for name in directory.names()? {
        let is_dir = directory.is_dir(Path::new(&name))?;
        let child = path.join(&name);
        if is_dir {
            grant_tree(&child, sid, access, mode, grants)?;
        } else {
            let file = directory.read(child.file_name().context("missing filename")?.as_ref())?;
            crate::snapshot_fs::regular(&file)?;
            grants.push(AclGrant::entry(
                acl_file(&child)?,
                sid,
                access,
                mode,
                false,
            )?);
        }
    }
    Ok(())
}

fn quote(value: &OsStr) -> Vec<u16> {
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for c in value.encode_wide() {
        if c == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            b'\\' as u16,
            slashes * if c == b'"' as u16 { 2 } else { 1 },
        ));
        if c == b'"' as u16 {
            out.push(b'\\' as u16);
        }
        out.push(c);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    out
}

/// Native capabilities retained by the execution owner until the Job is empty.
pub(crate) struct WindowsIsolatedChild {
    pub stdin: Option<NamedPipeServer>,
    pub stdout: Option<NamedPipeServer>,
    pub stderr: Option<NamedPipeServer>,
    process: Handle,
    _thread: Handle,
    job: Handle,
    pid: u32,
    status: Option<std::process::ExitStatus>,
    grants: Vec<AclGrant>,
    _profile: Profile,
    _runtime: WorkerScope,
}
unsafe impl Send for WindowsIsolatedChild {}
impl WindowsIsolatedChild {
    pub fn id(&self) -> Option<u32> {
        if self.status.is_none() {
            Some(self.pid)
        } else {
            None
        }
    }
    pub fn start_kill(&mut self) -> io::Result<()> {
        checked(unsafe { TerminateJobObject(self.job.0, 1) })
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        if self.status.is_none() {
            match unsafe { WaitForSingleObject(self.process.0, 0) } {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    checked(unsafe { GetExitCodeProcess(self.process.0, &mut code) })?;
                    let status = std::process::ExitStatus::from_raw(code);
                    self.status = Some(status);
                    checked(unsafe { TerminateJobObject(self.job.0, 1) })?;
                }
                WAIT_TIMEOUT => return Ok(None),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        checked(unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                null_mut(),
            )
        })?;
        Ok(if accounting.ActiveProcesses == 0 {
            self.status
        } else {
            None
        })
    }
}
impl Drop for WindowsIsolatedChild {
    fn drop(&mut self) {
        unsafe {
            TerminateJobObject(self.job.0, 1);
            WaitForSingleObject(self.process.0, INFINITE);
        }
        // Restore children before parents to preserve their original ACLs.
        while self.grants.pop().is_some() {}
    }
}

/// Failure ownership starts immediately after CreateProcessW, before Job assignment.
struct Suspended {
    process: Handle,
    thread: Handle,
}
impl Drop for Suspended {
    fn drop(&mut self) {
        if !self.process.0.is_null() {
            unsafe {
                TerminateProcess(self.process.0, 1);
                WaitForSingleObject(self.process.0, INFINITE);
            }
        }
    }
}

pub(crate) fn spawn(
    scope: &ExecutionScope,
    request: &IsolatedSpawn,
) -> Result<WindowsIsolatedChild> {
    let writable = scope.writable_roots()?;
    if request
        .deny_read
        .iter()
        .any(|path| !writable.iter().any(|root| path.starts_with(root)))
    {
        bail!("Windows external read-deny policy requires an effective-access adapter; refusing before launch");
    }
    let cwd = scope.cwd(request)?.to_owned();
    let runtime = WorkerScope::prepare(cwd.parent().context("private cwd has no parent")?)
        .context("prepare Windows runtime directory")?;
    let directory = crate::snapshot_fs::Dir::open(runtime.directory()?)?;
    let executable = directory.path.join(
        request
            .executable
            .file_name()
            .context("executable has no filename")?,
    );
    let copy = |source: &Path, destination: &Path| -> Result<()> {
        let parent =
            crate::snapshot_fs::Dir::open(source.parent().context("resource has no parent")?)?;
        let mut input = parent.read(Path::new(
            source.file_name().context("resource has no name")?,
        ))?;
        let mut output = directory.create(destination)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        Ok(())
    };
    copy(
        &request.executable,
        Path::new(executable.file_name().unwrap()),
    )
    .context("copy isolated executable")?;
    for resource in &request.read_only {
        if resource.is_dir() {
            bail!("Windows runtime resources must be explicit files for private copying");
        }
        copy(
            resource,
            Path::new(resource.file_name().context("resource has no filename")?),
        )?;
    }
    let profile = Profile::create()?;
    let mut grants = Vec::new();
    // The private parent DACL does not include the AppContainer. Without
    // traverse there, CreateProcessW reports the working directory as an
    // invalid name. Traverse does not include write or create.
    if let Some(parent) = cwd.parent() {
        grants.push(AclGrant::entry(
            acl_file(parent)?,
            profile.sid,
            FILE_GENERIC_EXECUTE,
            GRANT_ACCESS,
            true,
        )?);
    }
    grants.push(AclGrant::entry(
        acl_file(&cwd)?,
        profile.sid,
        FILE_GENERIC_EXECUTE,
        GRANT_ACCESS,
        true,
    )?);
    grant_tree(
        &directory.path,
        profile.sid,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        GRANT_ACCESS,
        &mut grants,
    )?;
    if request.kind == ExecutionKind::Tool {
        for root in scope.writable_roots()? {
            grant_tree(
                &root,
                profile.sid,
                FILE_ALL_ACCESS,
                GRANT_ACCESS,
                &mut grants,
            )?;
        }
        for (paths, rights) in [
            (&request.deny_read, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
            (
                &request.deny_write,
                FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD,
            ),
        ] {
            for path in paths {
                // Only private objects can acquire temporary ACLs.
                if !scope
                    .writable_roots()?
                    .iter()
                    .any(|root| path.starts_with(root))
                {
                    continue;
                }
                if path.is_dir() {
                    grant_tree(path, profile.sid, rights, DENY_ACCESS, &mut grants)?;
                } else if path.exists() {
                    grants.push(AclGrant::entry(
                        acl_file(path)?,
                        profile.sid,
                        rights,
                        DENY_ACCESS,
                        false,
                    )?);
                } else {
                    bail!("Windows protected path must exist before launch");
                }
                for parent in path.ancestors().skip(1) {
                    if !scope
                        .writable_roots()?
                        .iter()
                        .any(|root| parent.starts_with(root))
                    {
                        break;
                    }
                    grants.push(AclGrant::entry(
                        acl_file(parent)?,
                        profile.sid,
                        FILE_DELETE_CHILD | DELETE,
                        DENY_ACCESS,
                        true,
                    )?);
                }
            }
        }
    }
    let job = Handle(unsafe { CreateJobObjectW(null(), null()) });
    if job.0.is_null() {
        return Err(io::Error::last_os_error()).context("create job");
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = request.max_processes;
    limits.ProcessMemoryLimit = usize::try_from(request.max_memory_bytes)?;
    limits.JobMemoryLimit = usize::try_from(request.max_memory_bytes)?;
    checked(unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    })
    .context("set job limits")?;
    let (stdin, input) = pipe(true).context("stdin pipe")?;
    let (stdout, output) = pipe(false).context("stdout pipe")?;
    let (stderr, error) = pipe(false).context("stderr pipe")?;
    let mut handles = [input.0, output.0, error.0];
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attributes = Attributes::new().context("process attribute list")?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &mut capabilities,
        )
        .context("security capabilities")?;
    attributes
        .set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, &mut handles)
        .context("inherited handles")?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.0;
    startup.StartupInfo.hStdOutput = output.0;
    startup.StartupInfo.hStdError = error.0;
    startup.lpAttributeList = attributes.pointer();
    let mut command = quote(executable.as_os_str());
    for arg in &request.args {
        command.push(b' ' as u16);
        command.extend(quote(arg));
    }
    if command.contains(&0) {
        bail!("NUL in command line");
    }
    command.push(0);
    let mut environment = Vec::new();
    let mut entries = request.env.clone();
    entries.sort_by_key(|(key, _)| key.to_uppercase());
    let mut previous: Option<String> = None;
    for (key, value) in entries {
        if key.is_empty()
            || key.contains('=')
            || previous
                .as_ref()
                .is_some_and(|p| p.eq_ignore_ascii_case(&key))
        {
            bail!("invalid or duplicate environment key");
        }
        previous = Some(key.clone());
        environment.extend(wide(format!("{key}={value}"))?);
    }
    if environment.is_empty() {
        environment.push(0);
    }
    environment.push(0);
    let mut information = PROCESS_INFORMATION::default();
    checked(unsafe {
        CreateProcessW(
            wide(&executable)?.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            wide(&cwd)?.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    })
    .context("CreateProcessW")?;
    let mut suspended = Suspended {
        process: Handle(information.hProcess),
        thread: Handle(information.hThread),
    };
    checked(unsafe { AssignProcessToJobObject(job.0, suspended.process.0) })?;
    if unsafe { ResumeThread(suspended.thread.0) } == u32::MAX {
        return Err(io::Error::last_os_error().into());
    }
    let process = Handle(std::mem::replace(&mut suspended.process.0, null_mut()));
    let thread = Handle(std::mem::replace(&mut suspended.thread.0, null_mut()));
    let child = WindowsIsolatedChild {
        stdin: Some(stdin),
        stdout: Some(stdout),
        stderr: Some(stderr),
        process,
        _thread: thread,
        job,
        pid: information.dwProcessId,
        status: None,
        grants,
        _profile: profile,
        _runtime: runtime,
    };
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawn::MemoryEnforcement;
    use std::io::{Read, Write};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn appcontainer_probe() {
        if std::env::var_os("KOREI_ISOLATED_PROBE").is_none() {
            return;
        }
        assert!(std::env::var_os("HOME").is_none());
        assert!(std::fs::read(std::env::var_os("KOREI_PROBE_FILE").unwrap()).is_err());
        assert!(std::fs::write(std::env::current_dir().unwrap().join("escape"), b"x").is_err());
        let port: u16 = std::env::var("KOREI_PROBE_PORT").unwrap().parse().unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .spawn()
            .is_err());
        let mut input = [0; 4];
        std::io::stdin().read_exact(&mut input).unwrap();
        assert_eq!(&input, b"ping");
        std::io::stdout().write_all(b"pong").unwrap();
        std::io::stdout().flush().unwrap();
        if std::env::var_os("KOREI_PROBE_WAIT").is_some() {
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }

    #[tokio::test]
    async fn native_appcontainer_stdio_job_and_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let storage = temp.path().join("private");
        crate::windows_acl::create_private_directory(&storage).unwrap();
        let host_file = temp.path().join("host-file");
        std::fs::write(&host_file, b"host").unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        for cancel in [false, true] {
            let scope = WorkerScope::prepare(&storage).unwrap();
            let mut request = IsolatedSpawn {
                linux_launcher: None,
                linux_cgroup_parent: None,
                executable: std::env::current_exe().unwrap(),
                args: vec![
                    "--exact".into(),
                    "windows_isolated::tests::appcontainer_probe".into(),
                    "--nocapture".into(),
                ],
                root: None,
                kind: ExecutionKind::Worker,
                read_only: vec![],
                deny_read: vec![],
                deny_write: vec![],
                env: vec![
                    ("KOREI_ISOLATED_PROBE".into(), "1".into()),
                    (
                        "KOREI_PROBE_FILE".into(),
                        host_file.to_str().unwrap().into(),
                    ),
                    (
                        "KOREI_PROBE_PORT".into(),
                        listener.local_addr().unwrap().port().to_string(),
                    ),
                ],
                max_memory_bytes: 256 * 1024 * 1024,
                max_processes: 1,
                memory_enforcement: MemoryEnforcement::OsHard,
                tool_policy: None,
            };
            if cancel {
                request.env.push(("KOREI_PROBE_WAIT".into(), "1".into()));
            }
            let mut process = crate::spawn::spawn_isolated(scope, &request).unwrap();
            process
                .stdin
                .take()
                .unwrap()
                .write_all(b"ping")
                .await
                .unwrap();
            let mut stdout = process.stdout.take().unwrap();
            let mut stderr = process.stderr.take().unwrap();
            let output = tokio::spawn(async move {
                let mut out = Vec::new();
                stdout.read_to_end(&mut out).await.unwrap();
                out
            });
            let errors = tokio::spawn(async move {
                let mut out = Vec::new();
                stderr.read_to_end(&mut out).await.unwrap();
                out
            });
            if cancel {
                tokio::time::sleep(Duration::from_millis(250)).await;
                process.start_kill().unwrap();
            }
            let status = tokio::time::timeout(Duration::from_secs(10), process.wait())
                .await
                .unwrap()
                .unwrap();
            let out = output.await.unwrap();
            let errors = errors.await.unwrap();
            if !cancel {
                assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
                assert!(out.windows(4).any(|bytes| bytes == b"pong"));
            } else {
                assert!(!status.success());
            }
            assert!(process.id().is_none());
        }
        assert_eq!(std::fs::read(&host_file).unwrap(), b"host");
        assert!(listener.accept().is_err());
        assert_eq!(std::fs::read_dir(&storage).unwrap().count(), 0);
    }
}
