//! Read-only proof that a previously observed process is gone.
//!
//! The query never signals or kills. A platform that cannot tie a pid to an
//! immutable start identity reports that the exit is unprovable.

use anyhow::{bail, Context, Result};

/// Identity captured from the live process table. It is not a permission to signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub start_sec: u64,
    pub start_usec: u64,
}

/// What a later read-only query can prove about a captured identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitObservation {
    /// The recorded process is not the process in that pid slot.
    Exited,
    /// The same boot session, pid and start time are still present.
    Alive,
    /// The platform cannot prove either result.
    Unprovable(&'static str),
}

/// Capture the stable identity of a live pid, if this platform has one.
pub fn identify(pid: u32) -> Result<ProcessIdentity> {
    #[cfg(target_os = "macos")]
    {
        let boot_id = boot_id()?;
        let info = bsd_info(pid).context("read process start identity")?;
        if info.pbi_pid != pid {
            bail!("process table returned a different pid");
        }
        return Ok(ProcessIdentity {
            boot_id,
            pid,
            start_sec: info.pbi_start_tvsec,
            start_usec: info.pbi_start_tvusec,
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        bail!("this platform has no stable process identity");
    }
}

/// Query the process table again. This does not signal the pid.
pub fn observe(identity: &ProcessIdentity) -> ExitObservation {
    #[cfg(target_os = "macos")]
    {
        let boot_id = match boot_id() {
            Ok(boot_id) => boot_id,
            Err(_) => return ExitObservation::Unprovable("boot session is unreadable"),
        };
        if boot_id != identity.boot_id {
            return ExitObservation::Unprovable("boot session changed");
        }
        match bsd_info(identity.pid) {
            Ok(info) => {
                if info.pbi_pid == identity.pid
                    && info.pbi_start_tvsec == identity.start_sec
                    && info.pbi_start_tvusec == identity.start_usec
                {
                    ExitObservation::Alive
                } else {
                    ExitObservation::Exited
                }
            }
            Err(error)
                if error.raw_os_error() == Some(libc::ESRCH)
                    || error.kind() == std::io::ErrorKind::NotFound =>
            {
                ExitObservation::Exited
            }
            Err(_) => ExitObservation::Unprovable("process start identity is unreadable"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = identity;
        ExitObservation::Unprovable("this platform has no stable process identity")
    }
}

#[cfg(target_os = "macos")]
fn boot_id() -> Result<String> {
    let mut bytes = [0u8; 64];
    let mut len = bytes.len();
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("read boot session");
    }
    let len = len.min(bytes.len());
    let end = bytes[..len].iter().position(|b| *b == 0).unwrap_or(len);
    let text = std::str::from_utf8(&bytes[..end]).context("boot session is not text")?;
    if text.is_empty() {
        bail!("boot session is empty");
    }
    Ok(text.to_owned())
}

#[cfg(target_os = "macos")]
fn bsd_info(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of_val(&info) as libc::c_int;
    let wrote = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if wrote == size {
        Ok(info)
    } else if wrote == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Err(std::io::Error::other(
            "process start identity has an unexpected size",
        ))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn the_current_process_is_alive_and_a_finished_child_has_exited() {
        let self_identity = identify(std::process::id()).unwrap();
        assert_eq!(observe(&self_identity), ExitObservation::Alive);
        assert!(matches!(
            observe(&ProcessIdentity {
                start_usec: self_identity.start_usec.wrapping_add(1),
                ..self_identity.clone()
            }),
            ExitObservation::Exited
        ));
        assert!(matches!(
            observe(&ProcessIdentity {
                boot_id: "not-this-boot".into(),
                ..self_identity
            }),
            ExitObservation::Unprovable(_)
        ));

        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let identity = identify(child.id()).unwrap();
        assert_eq!(observe(&identity), ExitObservation::Alive);
        assert!(child.wait().unwrap().success());
        assert_eq!(observe(&identity), ExitObservation::Exited);
    }
}
