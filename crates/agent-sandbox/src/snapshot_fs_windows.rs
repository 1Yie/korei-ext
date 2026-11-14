use super::*;
use std::fs::OpenOptions;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::Arc;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Ioctl::{DUPLICATE_EXTENTS_DATA, FSCTL_DUPLICATE_EXTENTS_TO_FILE};
use windows_sys::Win32::System::IO::DeviceIoControl;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: HANDLE,
    name: *mut UnicodeString,
    attributes: u32,
    descriptor: *mut core::ffi::c_void,
    qos: *mut core::ffi::c_void,
}

#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        sharing: u32,
        disposition: u32,
        options: u32,
        ea: *const core::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file: HANDLE,
        status: *mut IoStatus,
        information: *const core::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

fn nt_result(status: i32) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
    } else {
        Ok(())
    }
}

fn open_at(
    parent: &File,
    name: &Path,
    access: u32,
    disposition: u32,
    directory: bool,
    descriptor: *mut core::ffi::c_void,
    sharing: u32,
) -> io::Result<File> {
    open_at_inner(
        parent,
        name,
        access,
        disposition,
        directory,
        descriptor,
        sharing,
        false,
    )
}

fn open_at_inner(
    parent: &File,
    name: &Path,
    access: u32,
    disposition: u32,
    directory: bool,
    descriptor: *mut core::ffi::c_void,
    sharing: u32,
    config_link: bool,
) -> io::Result<File> {
    relative(name)?;
    if name.components().count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a single filename",
        ));
    }
    let mut text: Vec<_> = name.as_os_str().encode_wide().collect();
    if text.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in filename",
        ));
    }
    let length = u16::try_from(
        text.len()
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("filename overflow"))?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename too long"))?;
    let mut name = UnicodeString {
        length,
        maximum_length: length,
        buffer: text.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root: parent.as_raw_handle(),
        name: &mut name,
        attributes: 0x40 | if config_link { 0 } else { 0x1000 },
        descriptor,
        qos: std::ptr::null_mut(),
    };
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let mut handle = std::ptr::null_mut();
    nt_result(unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            sharing,
            disposition,
            0x20 | if directory && !config_link {
                1
            } else {
                0x200000
            },
            std::ptr::null(),
            0,
        )
    })?;
    let file = unsafe { File::from_raw_handle(handle) };
    if !config_link {
        info(&file)?;
    }
    Ok(file)
}

pub(crate) fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    wide.push(0);
    Ok(wide)
}

/// Root-relative opens reject reparses; ancestor handles also pin renames.
#[derive(Debug)]
pub(crate) struct Dir {
    pub(crate) file: Arc<File>,
    ancestors: Vec<Arc<File>>,
    pub path: PathBuf,
}

fn info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse points are forbidden",
        ));
    }
    Ok(info)
}

pub(crate) fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    let info = info(file)?;
    Ok((
        info.dwVolumeSerialNumber as u64,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    ))
}

fn open_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "expected directory",
        ));
    }
    Ok(file)
}

fn streams(file: &File) -> io::Result<()> {
    // Fail closed for an unbounded stream list instead of ignoring ADS.
    let mut buffer = vec![0u64; 8192];
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let pointer = buffer.as_ptr().cast::<FILE_STREAM_INFO>();
    let stream = unsafe { &*pointer };
    let length = stream.StreamNameLength as usize / 2;
    if length > 32 || stream.NextEntryOffset != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "alternate streams are forbidden",
        ));
    }
    let name = unsafe { std::slice::from_raw_parts(stream.StreamName.as_ptr(), length) };
    if name != "::$DATA".encode_utf16().collect::<Vec<_>>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected file stream",
        ));
    }
    Ok(())
}

pub(crate) fn regular(file: &File) -> io::Result<()> {
    let info = info(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || info.nNumberOfLinks != 1
        || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a single-link disk file",
        ));
    }
    streams(file)
}

impl Dir {
    pub fn config_parent(&self) -> io::Result<Self> {
        let mut ancestors = self.ancestors.clone();
        let mut path = self.path.clone();
        let file = match ancestors.pop() {
            Some(file) => {
                path.pop();
                file
            }
            None => self.file.clone(),
        };
        Ok(Self {
            file,
            ancestors,
            path,
        })
    }

    pub fn symlink_target(&self, name: &Path) -> io::Result<Option<PathBuf>> {
        use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

        let file = open_at_inner(
            &self.file,
            name,
            FILE_READ_ATTRIBUTES,
            1,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )?;
        let mut attributes = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            return Ok(None);
        }
        let mut buffer = vec![0u8; 16 * 1024];
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_GET_REPARSE_POINT,
                std::ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(returned as usize);
        let invalid =
            || io::Error::new(io::ErrorKind::InvalidData, "invalid configuration reparse");
        let tag = u32::from_le_bytes(buffer.get(..4).ok_or_else(invalid)?.try_into().unwrap());
        let start = match tag {
            0xA000000C => 20,
            0xA0000003 => 16,
            _ => return Err(invalid()),
        };
        let offset =
            u16::from_le_bytes(buffer.get(8..10).ok_or_else(invalid)?.try_into().unwrap()) as usize;
        let length = u16::from_le_bytes(buffer.get(10..12).ok_or_else(invalid)?.try_into().unwrap())
            as usize;
        if length % 2 != 0 || offset % 2 != 0 {
            return Err(invalid());
        }
        let bytes = buffer
            .get(start + offset..start + offset + length)
            .ok_or_else(invalid)?;
        let wide: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let target = PathBuf::from(OsString::from_wide(&wide));
        let text = target.as_os_str().to_string_lossy();
        Ok(Some(if let Some(rest) = text.strip_prefix(r"\??\") {
            PathBuf::from(format!(r"\\?\{rest}"))
        } else {
            target
        }))
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let mut parts = path.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected an absolute local drive path",
            ));
        };
        if !matches!(prefix.kind(), std::path::Prefix::Disk(_))
            || !matches!(parts.next(), Some(Component::RootDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UNC, device and relative roots are forbidden",
            ));
        }
        let root = PathBuf::from(prefix.as_os_str()).join("\\");
        let mut dir = Self {
            file: Arc::new(open_directory(&root)?),
            ancestors: Vec::new(),
            path: root,
        };
        for part in parts {
            if !matches!(part, Component::Normal(_)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root traversal forbidden",
                ));
            }
            dir = dir.child(Path::new(part.as_os_str()))?;
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
        file_identity(&self.file)
    }
    pub fn lineage(&self) -> io::Result<Vec<(u64, u64)>> {
        self.ancestors
            .iter()
            .chain(std::iter::once(&self.file))
            .map(|file| file_identity(file))
            .collect()
    }
    pub fn parent(&self, path: &Path) -> io::Result<(Self, OsString)> {
        relative(path)?;
        let mut dir = Self {
            file: Arc::clone(&self.file),
            ancestors: self.ancestors.clone(),
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
    pub fn child(&self, name: &Path) -> io::Result<Self> {
        let (parent, leaf) = self.parent(name)?;
        let path = parent.path.join(&leaf);
        let file = Arc::new(open_at(
            &parent.file,
            Path::new(&leaf),
            GENERIC_READ,
            1,
            true,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?);
        let mut ancestors = parent.ancestors.clone();
        ancestors.push(Arc::clone(&parent.file));
        Ok(Self {
            file,
            ancestors,
            path,
        })
    }
    pub fn read(&self, path: &Path) -> io::Result<File> {
        let (parent, name) = self.parent(path)?;
        let file = open_at(
            &parent.file,
            Path::new(&name),
            GENERIC_READ,
            1,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        regular(&file)?;
        Ok(file)
    }
    pub(crate) fn acl_handle(&self, path: Option<&Path>) -> io::Result<File> {
        match path {
            Some(path) => {
                let (parent, name) = self.parent(path)?;
                open_at(
                    &parent.file,
                    Path::new(&name),
                    READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                    1,
                    false,
                    std::ptr::null_mut(),
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                )
            }
            None => {
                // Ancestor handles pin this path against rename and replacement.
                let file = OpenOptions::new()
                    .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&self.path)?;
                if file_identity(&file)? != self.identity()? {
                    return Err(io::Error::other("ACL directory identity changed"));
                }
                Ok(file)
            }
        }
    }
    pub fn write(&self, path: &Path) -> io::Result<File> {
        let (parent, name) = self.parent(path)?;
        let file = open_at(
            &parent.file,
            Path::new(&name),
            GENERIC_READ | GENERIC_WRITE,
            1,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ,
        )?;
        regular(&file)?;
        Ok(file)
    }
    pub fn create(&self, path: &Path) -> io::Result<File> {
        let (parent, name) = self.parent(path)?;
        open_at(
            &parent.file,
            Path::new(&name),
            GENERIC_READ | GENERIC_WRITE,
            2,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ,
        )
    }
    pub fn mkdir(&self, path: &Path) -> io::Result<Self> {
        let (parent, name) = self.parent(path)?;
        let descriptor = crate::windows_acl::private_descriptor()?;
        let file = Arc::new(open_at(
            &parent.file,
            Path::new(&name),
            GENERIC_READ,
            2,
            true,
            descriptor.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?);
        let mut ancestors = parent.ancestors.clone();
        ancestors.push(Arc::clone(&parent.file));
        Ok(Self {
            file,
            ancestors,
            path: parent.path.join(name),
        })
    }
    pub fn names(&self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        let mut buffer = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            if unsafe {
                GetFileInformationByHandleEx(
                    self.file.as_raw_handle(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    break;
                }
                return Err(error);
            }
            class = FileIdBothDirectoryInfo;
            let mut offset = 0;
            loop {
                let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if offset + header > buffer.len() * 8 {
                    return Err(io::Error::other("invalid directory entry"));
                }
                let entry = unsafe {
                    &*buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFO>()
                };
                let length = entry.FileNameLength as usize;
                if length % 2 != 0 || offset + header + length > buffer.len() * 8 {
                    return Err(io::Error::other("invalid directory filename"));
                }
                let units =
                    unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), length / 2) };
                let name = OsString::from_wide(units);
                if name != "." && name != ".." {
                    names.push(name);
                }
                let next = entry.NextEntryOffset as usize;
                if next == 0 {
                    break;
                }
                if next < header || next % 8 != 0 {
                    return Err(io::Error::other("invalid directory offset"));
                }
                offset += next;
            }
        }
        names.sort();
        Ok(names)
    }
    pub fn is_dir(&self, path: &Path) -> io::Result<bool> {
        let (parent, name) = self.parent(path)?;
        let file = open_at(
            &parent.file,
            Path::new(&name),
            GENERIC_READ,
            1,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let directory = info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if !directory {
            regular(&file)?;
        }
        Ok(directory)
    }
    pub fn unlink(&self, path: &Path, directory: bool) -> io::Result<()> {
        let (parent, name) = self.parent(path)?;
        let file = open_at(
            &parent.file,
            Path::new(&name),
            DELETE | FILE_READ_ATTRIBUTES,
            1,
            directory,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let information = FILE_DISPOSITION_INFO { DeleteFile: true };
        let mut status = IoStatus {
            status: 0,
            information: 0,
        };
        nt_result(unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                (&information as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&information) as u32,
                13,
            )
        })
    }
    pub fn rename_new(&self, from: &Path, to: &Self, name: &Path) -> io::Result<()> {
        let (source, from) = self.parent(from)?;
        let (target, name) = to.parent(name)?;
        let file = open_at(
            &source.file,
            Path::new(&from),
            DELETE | FILE_READ_ATTRIBUTES,
            1,
            false,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let text: Vec<_> = name.encode_wide().collect();
        let size = std::mem::offset_of!(FILE_RENAME_INFO, FileName) + text.len() * 2;
        let mut bytes = vec![0u64; size.div_ceil(8)];
        let information = bytes.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*information).RootDirectory = target.file.as_raw_handle();
            (*information).FileNameLength = (text.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                text.as_ptr(),
                (*information).FileName.as_mut_ptr(),
                text.len(),
            );
        }
        let mut status = IoStatus {
            status: 0,
            information: 0,
        };
        nt_result(unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                information.cast(),
                size as u32,
                10,
            )
        })
    }
    // Regular-file data is flushed separately; directory durability is unverified.
    pub fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn check_private(dir: &Dir) -> io::Result<()> {
    crate::windows_acl::check_private(&dir.file)
}

pub(crate) fn clone_into(
    source: &File,
    target: &Dir,
    name: &Path,
    native: bool,
) -> io::Result<(File, bool)> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let output = target.create(name)?;
    let length = source.metadata()?.len();
    let mut cloned = 0;
    if native && length > 0 {
        let mut filesystem = [0u16; 32];
        if unsafe {
            GetVolumeInformationByHandleW(
                source.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = filesystem
            .iter()
            .position(|v| *v == 0)
            .unwrap_or(filesystem.len());
        if String::from_utf16_lossy(&filesystem[..end]).eq_ignore_ascii_case("ReFS")
            && file_identity(source)?.0 == file_identity(&output)?.0
        {
            let mut volume = [0u16; 32768];
            if unsafe {
                GetVolumePathNameW(
                    wide(&target.path)?.as_ptr(),
                    volume.as_mut_ptr(),
                    volume.len() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let (mut sectors, mut bytes, mut free, mut total) = (0, 0, 0, 0);
            if unsafe {
                GetDiskFreeSpaceW(
                    volume.as_ptr(),
                    &mut sectors,
                    &mut bytes,
                    &mut free,
                    &mut total,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let cluster = (sectors as u64)
                .checked_mul(bytes as u64)
                .filter(|n| *n != 0)
                .ok_or_else(|| io::Error::other("invalid ReFS cluster geometry"))?;
            let aligned = length / cluster * cluster;
            if aligned != 0 {
                output.set_len(length)?;
                let request = DUPLICATE_EXTENTS_DATA {
                    FileHandle: source.as_raw_handle(),
                    SourceFileOffset: 0,
                    TargetFileOffset: 0,
                    ByteCount: aligned as i64,
                };
                let mut returned = 0;
                if unsafe {
                    DeviceIoControl(
                        output.as_raw_handle(),
                        FSCTL_DUPLICATE_EXTENTS_TO_FILE,
                        (&request as *const DUPLICATE_EXTENTS_DATA).cast(),
                        std::mem::size_of_val(&request) as u32,
                        std::ptr::null_mut(),
                        0,
                        &mut returned,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    let error = io::Error::last_os_error();
                    if !matches!(error.raw_os_error(), Some(v) if v == ERROR_NOT_SUPPORTED as i32 || v == ERROR_INVALID_FUNCTION as i32)
                    {
                        return Err(error);
                    }
                } else {
                    cloned = aligned;
                }
            }
        }
    }
    let mut input = source.try_clone()?;
    input.seek(SeekFrom::Start(cloned))?;
    let mut input = input.take(length - cloned);
    let mut destination = &output;
    destination.seek(SeekFrom::Start(cloned))?;
    let mut buffer = [0; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        destination.write_all(&buffer[..n])?;
    }
    if source.metadata()?.len() != length || output.metadata()?.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source changed during clone",
        ));
    }
    Ok((output, cloned != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
    use std::io::Write;

    #[test]
    fn share_delete_is_not_a_reparse_mutation_barrier() {
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("private");
        let outside = temp.path().join("outside");
        crate::windows_acl::create_private_directory(&private).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("host-file"), b"host").unwrap();
        let root = Dir::open(&private).unwrap();
        let pinned = root.mkdir(Path::new("junction")).unwrap();
        let mutation = open_at_inner(
            &root.file,
            Path::new("junction"),
            GENERIC_WRITE,
            1,
            true,
            std::ptr::null_mut(),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            true,
        )
        .unwrap();
        let substitute: Vec<_> = format!(r"\??\{}", outside.display())
            .encode_utf16()
            .collect();
        let display: Vec<_> = outside.as_os_str().encode_wide().collect();
        let data_length = 8 + (substitute.len() + display.len() + 2) * 2;
        let mut data = Vec::with_capacity(data_length + 8);
        data.extend_from_slice(&0xa0000003u32.to_le_bytes());
        data.extend_from_slice(&(data_length as u16).to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        for value in [
            0,
            (substitute.len() * 2) as u16,
            ((substitute.len() + 1) * 2) as u16,
            (display.len() * 2) as u16,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        for unit in substitute
            .iter()
            .chain(std::iter::once(&0))
            .chain(display.iter())
            .chain(std::iter::once(&0))
        {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                mutation.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        assert!(root.child(Path::new("junction")).is_err());
        assert!(root.read(Path::new("junction/host-file")).is_err());
        let _ = pinned.create(Path::new("must-not-escape"));
        assert!(!outside.join("must-not-escape").exists());
        assert_eq!(std::fs::read(outside.join("host-file")).unwrap(), b"host");
    }

    #[test]
    fn directory_acl_handle_preserves_pinned_identity() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("private");
        crate::windows_acl::create_private_directory(&source).unwrap();
        let root = Dir::open(&source).unwrap();
        let child = root.mkdir(Path::new("child")).unwrap();
        for directory in [&root, &child] {
            let handle = directory.acl_handle(None).unwrap();
            assert_eq!(
                file_identity(&handle).unwrap(),
                directory.identity().unwrap()
            );
            crate::windows_acl::check_private(&handle).unwrap();
        }
    }

    #[test]
    fn windows_handle_relative_snapshot_publish_and_stream_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let storage = temp.path().join("storage");
        crate::windows_acl::create_private_directory(&source).unwrap();
        crate::windows_acl::create_private_directory(&storage).unwrap();
        let root = Dir::open(&source).unwrap();
        root.create(Path::new("file"))
            .unwrap()
            .write_all(b"original")
            .unwrap();
        let mut snapshot = WorkspaceSnapshot::prepare(
            &[source.clone()],
            &storage,
            SnapshotBudget {
                max_bytes: 1024 * 1024,
                max_entries: 32,
                max_depth: 4,
            },
            SnapshotPreference::PrivateCopy,
        )
        .unwrap();
        let lease = snapshot.lease().unwrap();
        let id = lease.roots().next().unwrap();
        lease.write_file(id, Path::new("file"), b"changed").unwrap();
        assert_eq!(std::fs::read(source.join("file")).unwrap(), b"original");
        drop(lease);
        snapshot.seal().unwrap();
        let report = snapshot.publish(|| false).unwrap();
        assert!(report.conflicts.is_empty());
        assert!(report.recovery_required.is_empty());
        assert_eq!(report.applied.len(), 1);
        assert_eq!(std::fs::read(source.join("file")).unwrap(), b"changed");
        assert_eq!(
            std::fs::read(report.recovery_material[0].join("original")).unwrap(),
            b"original"
        );
        assert!(root.read(Path::new("file:stream")).is_err());
        std::fs::write(source.join("file:stream"), b"hidden").unwrap();
        assert!(root.read(Path::new("file")).is_err());
        root.create(Path::new("single"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        std::fs::hard_link(source.join("single"), source.join("alias")).unwrap();
        assert!(root.read(Path::new("single")).is_err());
    }
}
