use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
#[cfg(test)]
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) struct Local(pub(crate) *mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn error(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn user() -> io::Result<Vec<usize>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
    }
    let mut bytes = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            bytes.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    let descriptor = private_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let ok = unsafe { CreateDirectoryW(crate::snapshot_fs::wide(path)?.as_ptr(), &attributes) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn private_descriptor() -> io::Result<Local> {
    let user = user()?;
    let sid = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) }.User.Sid;
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_text = Local(text.cast());
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(io::Error::other)?;
    let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{text})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(sid_text);
    Ok(Local(descriptor))
}

pub(crate) fn check_private(file: &File) -> io::Result<()> {
    let user = user()?;
    let sid = unsafe { &*(user.as_ptr().cast::<TOKEN_USER>()) }.User.Sid;
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    error(unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    })?;
    let _descriptor = Local(descriptor);
    if dacl.is_null() || unsafe { EqualSid(owner, sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private storage requires an owner-controlled DACL",
        ));
    }
    for index in 0..unsafe { (*dacl).AceCount } as u32 {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsupported private-storage ACL entry",
            ));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let trustee = (&allowed.SidStart as *const u32).cast_mut().cast();
        if unsafe { EqualSid(trustee, sid) } == 0
            && unsafe { IsWellKnownSid(trustee, WinLocalSystemSid) } == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private storage grants another principal",
            ));
        }
    }
    Ok(())
}

/// Restores the original DACL through the same pinned object handle.
pub(crate) struct AclGrant {
    file: File,
    descriptor: Local,
    original: *mut ACL,
}
unsafe impl Send for AclGrant {}

impl AclGrant {
    pub(crate) fn entry(
        file: File,
        sid: PSID,
        access: u32,
        mode: ACCESS_MODE,
        directory: bool,
    ) -> io::Result<Self> {
        let mut original = null_mut();
        let mut descriptor = null_mut();
        error(unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut original,
                null_mut(),
                &mut descriptor,
            )
        })?;
        let descriptor = Local(descriptor);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: mode,
            grfInheritance: if directory {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
            },
        };
        let mut updated = null_mut();
        error(unsafe { SetEntriesInAclW(1, &entry, original, &mut updated) })?;
        let updated = Local(updated.cast());
        error(unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated.0.cast(),
                null(),
            )
        })?;
        Ok(Self {
            file,
            descriptor,
            original,
        })
    }
}

impl Drop for AclGrant {
    fn drop(&mut self) {
        unsafe {
            SetSecurityInfo(
                self.file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.original,
                null_mut(),
            );
        }
        let _ = &self.descriptor;
    }
}
