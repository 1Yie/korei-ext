//! Handle-relative filesystem operations used at the snapshot trust boundary.

use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};

pub(crate) fn relative(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a nonempty relative path without traversal",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if path.as_os_str().encode_wide().any(|c| c == b':' as u16)
            || path.components().any(|c| {
                let name = c.as_os_str().to_string_lossy();
                name.ends_with(['.', ' '])
                    || matches!(
                        name.split('.')
                            .next()
                            .unwrap_or("")
                            .to_ascii_uppercase()
                            .as_str(),
                        "CON"
                            | "PRN"
                            | "AUX"
                            | "NUL"
                            | "COM1"
                            | "COM2"
                            | "COM3"
                            | "COM4"
                            | "COM5"
                            | "COM6"
                            | "COM7"
                            | "COM8"
                            | "COM9"
                            | "LPT1"
                            | "LPT2"
                            | "LPT3"
                            | "LPT4"
                            | "LPT5"
                            | "LPT6"
                            | "LPT7"
                            | "LPT8"
                            | "LPT9"
                    )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ADS and Win32 alias paths are forbidden",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;

    #[derive(Debug)]
    pub(crate) struct Dir {
        file: File,
        pub path: PathBuf,
    }

    fn cstr(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }

    fn opened(fd: i32) -> io::Result<File> {
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    impl Dir {
        pub fn open(path: &Path) -> io::Result<Self> {
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root must be absolute",
                ));
            }
            let file = opened(unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            let mut dir = Self {
                file,
                path: PathBuf::from("/"),
            };
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => dir = dir.child(Path::new(name))?,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "root traversal forbidden",
                        ))
                    }
                }
            }
            Ok(dir)
        }
        pub fn metadata(&self) -> io::Result<Metadata> {
            self.file.metadata()
        }
        pub fn set_permissions(&self, permissions: std::fs::Permissions) -> io::Result<()> {
            self.file.set_permissions(permissions)
        }
        pub fn identity(&self) -> io::Result<(u64, u64)> {
            let m = self.metadata()?;
            Ok((m.dev(), m.ino()))
        }
        pub fn config_parent(&self) -> io::Result<Self> {
            let file = opened(unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    c"..".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let mut path = self.path.clone();
            path.pop();
            Ok(Self { file, path })
        }
        pub fn lineage(&self) -> io::Result<Vec<(u64, u64)>> {
            let mut file = self.file.try_clone()?;
            let mut identities = Vec::new();
            for _ in 0..4096 {
                let metadata = file.metadata()?;
                let identity = (metadata.dev(), metadata.ino());
                if identities.last() == Some(&identity) {
                    return Ok(identities);
                }
                identities.push(identity);
                file = opened(unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        c"..".as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory lineage exceeds limit",
            ))
        }
        pub fn child(&self, name: &Path) -> io::Result<Self> {
            let (parent, leaf) = self.parent(name)?;
            let name_c = cstr(Path::new(&leaf))?;
            let file = opened(unsafe {
                libc::openat(
                    parent.file.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            Ok(Self {
                file,
                path: self.path.join(name),
            })
        }
        pub fn symlink_target(&self, name: &Path) -> io::Result<Option<PathBuf>> {
            relative(name)?;
            if name.components().count() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected one link name",
                ));
            }
            let name = cstr(name)?;
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    &mut metadata,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if metadata.st_mode & libc::S_IFMT != libc::S_IFLNK {
                return Ok(None);
            }
            let mut target = vec![0u8; libc::PATH_MAX as usize + 1];
            let size = unsafe {
                libc::readlinkat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if size < 0 {
                return Err(io::Error::last_os_error());
            }
            if size as usize == target.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "runtime link too long",
                ));
            }
            target.truncate(size as usize);
            Ok(Some(PathBuf::from(OsString::from_vec(target))))
        }
        pub fn parent(&self, path: &Path) -> io::Result<(Self, OsString)> {
            relative(path)?;
            let mut dir = Self {
                file: self.file.try_clone()?,
                path: self.path.clone(),
            };
            let mut parts = path.components().peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    return Ok((dir, part.as_os_str().to_owned()));
                }
                dir = dir.child(Path::new(part.as_os_str()))?;
            }
            unreachable!()
        }
        pub fn read(&self, path: &Path) -> io::Result<File> {
            let (parent, name) = self.parent(path)?;
            let name = cstr(Path::new(&name))?;
            let f = opened(unsafe {
                libc::openat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            regular(&f)?;
            Ok(f)
        }
        pub fn create(&self, path: &Path) -> io::Result<File> {
            let (parent, name) = self.parent(path)?;
            let name = cstr(Path::new(&name))?;
            opened(unsafe {
                libc::openat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })
        }
        pub fn write(&self, path: &Path) -> io::Result<File> {
            let (parent, name) = self.parent(path)?;
            let name = cstr(Path::new(&name))?;
            let file = opened(unsafe {
                libc::openat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            })?;
            regular(&file)?;
            Ok(file)
        }
        pub fn mkdir(&self, path: &Path) -> io::Result<Self> {
            let (parent, name) = self.parent(path)?;
            let name = cstr(Path::new(&name))?;
            if unsafe { libc::mkdirat(parent.file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.child(path)
        }
        pub fn names(&self) -> io::Result<Vec<OsString>> {
            // openat(".") gives an independent directory offset, unlike dup.
            let fd = opened(unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    c".".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            use std::os::fd::IntoRawFd;
            let raw = fd.into_raw_fd();
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                unsafe { libc::close(raw) };
                return Err(io::Error::last_os_error());
            }
            let mut names = Vec::new();
            loop {
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = 0;
                }
                #[cfg(target_os = "linux")]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let error = io::Error::last_os_error();
                    unsafe { libc::closedir(stream) };
                    if error.raw_os_error() != Some(0) {
                        return Err(error);
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    names.push(OsString::from_vec(name.to_vec()));
                }
            }
            names.sort();
            Ok(names)
        }
        pub fn is_dir(&self, path: &Path) -> io::Result<bool> {
            let (parent, name) = self.parent(path)?;
            let name = cstr(Path::new(&name))?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            match st.st_mode & libc::S_IFMT {
                libc::S_IFDIR => Ok(true),
                libc::S_IFREG if st.st_nlink == 1 => Ok(false),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "links and special files are forbidden",
                )),
            }
        }
        pub fn unlink(&self, name: &Path, directory: bool) -> io::Result<()> {
            let (parent, name) = self.parent(name)?;
            let name = cstr(Path::new(&name))?;
            if unsafe {
                libc::unlinkat(
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    if directory { libc::AT_REMOVEDIR } else { 0 },
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            parent.sync()
        }
        pub fn rename_new(&self, from: &Path, to: &Self, name: &Path) -> io::Result<()> {
            let (src, from) = self.parent(from)?;
            let (dst, name) = to.parent(name)?;
            let from = cstr(Path::new(&from))?;
            let name = cstr(Path::new(&name))?;
            #[cfg(target_os = "macos")]
            let rc = unsafe {
                libc::renameatx_np(
                    src.file.as_raw_fd(),
                    from.as_ptr(),
                    dst.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    src.file.as_raw_fd(),
                    from.as_ptr(),
                    dst.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as i32
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn sync(&self) -> io::Result<()> {
            self.file.sync_all()
        }
    }

    pub(crate) fn regular(file: &File) -> io::Result<()> {
        let m = file.metadata()?;
        if !m.is_file() || m.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a single-link regular file",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn native_clone(source: &File, destination: &File) -> io::Result<bool> {
        #[cfg(target_os = "macos")]
        {
            // fclonefileat creates a new directory entry, so the caller uses
            // clonefile through /dev/fd only via the handle-relative helper.
            let _ = (source, destination);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "use clone_into on macOS",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe {
                libc::ioctl(
                    destination.as_raw_fd(),
                    0x40049409 as libc::c_ulong,
                    source.as_raw_fd(),
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::EXDEV | libc::ENOTTY)
            ) {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }

    pub(crate) fn clone_into(
        source: &File,
        target: &Dir,
        name: &Path,
        native: bool,
    ) -> io::Result<(File, bool)> {
        #[cfg(target_os = "macos")]
        if native {
            let (parent, name) = target.parent(name)?;
            let name = cstr(Path::new(&name))?;
            let rc = unsafe {
                libc::fclonefileat(
                    source.as_raw_fd(),
                    parent.file.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            };
            if rc == 0 {
                let file = parent.read(Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())))?;
                return Ok((file, true));
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::EXDEV | libc::ENOSYS)
            ) {
                return Err(error);
            }
        }
        let file = target.create(name)?;
        #[cfg(target_os = "linux")]
        if native && native_clone(source, &file)? {
            return Ok((file, true));
        }
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut input = source.try_clone()?;
        input.seek(SeekFrom::Start(0))?;
        let length = input.metadata()?.len();
        let mut input = input.take(length);
        let mut output = &file;
        let mut buffer = [0; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            output.write_all(&buffer[..n])?;
        }
        if file.metadata()?.len() != length || source.metadata()?.len() != length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source length changed during copy",
            ));
        }
        Ok((file, false))
    }
}

#[cfg(unix)]
pub(crate) use platform::*;
#[cfg(windows)]
#[path = "snapshot_fs_windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;
