//! Per-execution cgroup v2 capabilities. No controller or host migration changes.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

pub(crate) fn attach(command: &mut std::process::Command, join: File) {
    unsafe {
        command.pre_exec(move || loop {
            let result = libc::write(join.as_raw_fd(), b"0".as_ptr().cast(), 1);
            if result == 1 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if result < 0 && error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(if result < 0 {
                error
            } else {
                io::Error::from_raw_os_error(libc::EIO)
            });
        });
    }
}

struct Directory {
    parent: File,
    group: File,
    name: CString,
}

impl Directory {
    fn remove(&self) -> Result<()> {
        let current = open_at(&self.parent, &self.name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let expected = self.group.metadata()?;
        let actual = current.metadata()?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            bail!("execution cgroup identity changed; refusing removal");
        }
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error()).context("remove empty execution cgroup");
        }
        Ok(())
    }
}

pub(crate) struct Cgroup {
    directory: Directory,
    procs: File,
    kill: File,
    events: File,
    kill_attempted: bool,
    killed: bool,
}

fn check_v2(file: &File) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("inspect cgroup filesystem");
    }
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        bail!("linux_cgroup_parent must be on a cgroup v2 filesystem");
    }
    Ok(())
}

fn open_at(directory: &File, name: &CStr, flags: i32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open cgroup v2 interface");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    check_v2(&file)?;
    Ok(file)
}

fn domain(directory: &File) -> Result<()> {
    let mut kind = String::new();
    open_at(directory, c"cgroup.type", libc::O_RDONLY)?.read_to_string(&mut kind)?;
    if kind.trim() != "domain" {
        bail!("isolated execution requires a non-threaded domain cgroup");
    }
    Ok(())
}

impl Cgroup {
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let pinned = crate::snapshot_fs::Dir::open(path).context("open delegated cgroup parent")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = parent.metadata()?;
        if (metadata.dev(), metadata.ino()) != pinned.identity()? {
            bail!("delegated cgroup parent identity changed");
        }
        check_v2(&parent)?;
        domain(&parent)?;
        open_at(&parent, c"cgroup.controllers", libc::O_RDONLY)?;
        open_at(&parent, c"cgroup.procs", libc::O_WRONLY)
            .context("delegated cgroup parent requires migration permission")?;
        let mut nonce = [0u8; 16];
        let received = unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error()).context("mint execution cgroup nonce");
        }
        if received != nonce.len() as isize {
            bail!("execution cgroup nonce requires 16 bytes; received {received}");
        }
        let name = format!(".korei-execution-{:032x}", u128::from_ne_bytes(nonce));
        let created = pinned
            .mkdir(Path::new(&name))
            .context("create execution cgroup")?;
        let name = CString::new(name)?;
        let group = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let actual = group.metadata()?;
        if (actual.dev(), actual.ino()) != created.identity()? {
            bail!("execution cgroup identity changed during creation");
        }
        let directory = Directory {
            parent,
            group,
            name,
        };
        let interfaces = (|| -> Result<_> {
            domain(&directory.group)?;
            let procs = open_at(&directory.group, c"cgroup.procs", libc::O_WRONLY)?;
            let kill = open_at(&directory.group, c"cgroup.kill", libc::O_WRONLY)
                .context("execution requires writable cgroup.kill")?;
            let events = open_at(&directory.group, c"cgroup.events", libc::O_RDONLY)?;
            Ok((procs, kill, events))
        })();
        let (procs, kill, events) = match interfaces {
            Ok(interfaces) => interfaces,
            Err(error) => {
                directory
                    .remove()
                    .context(format!("{error:#}; clean unused cgroup"))?;
                return Err(error);
            }
        };
        Ok(Self {
            directory,
            procs,
            kill,
            events,
            kill_attempted: false,
            killed: false,
        })
    }

    pub(crate) fn join_file(&self) -> io::Result<File> {
        self.procs.try_clone()
    }

    pub(crate) fn kill(&mut self) -> Result<()> {
        if self.kill_attempted {
            if self.killed {
                return Ok(());
            }
            bail!("execution cgroup.kill previously failed; scope remains occupied");
        }
        self.kill_attempted = true;
        self.kill.write_all(b"1").context("kill execution cgroup")?;
        self.killed = true;
        Ok(())
    }

    pub(crate) fn populated(&mut self) -> Result<bool> {
        self.events.seek(SeekFrom::Start(0))?;
        let mut events = String::new();
        self.events.read_to_string(&mut events)?;
        for line in events.lines() {
            if line == "populated 0" {
                return Ok(false);
            }
            if line == "populated 1" {
                return Ok(true);
            }
        }
        bail!("cgroup.events has no valid populated state");
    }

    pub(crate) fn remove_empty(&mut self) -> Result<()> {
        if self.populated()? {
            bail!("execution cgroup is still populated; scope remains occupied");
        }
        self.directory.remove()
    }
}
