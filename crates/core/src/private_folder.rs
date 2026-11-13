//! SS-08 (0.8.0 G4): a folder on this PC only this Windows user can open. "Edit on this PC" downloads a host's file into
//! one, so another user of the PC (or a service running as one) can't read a customer's config while it is edited.
//!
//! The folder gets a protected DACL with one entry: full control for the user Remotely runs as, inherited by everything
//! made in it (`D:P(A;OICI;FA;;;<the user's SID>)`). Nothing is inherited from the folder above, so the profile's
//! entries for SYSTEM and Administrators don't apply either. Elsewhere than Windows it is `0700`.

use std::path::Path;

use crate::error::{CoreError, Result};

/// Makes `path` (its parents as they are) and gives it this user's DACL alone. A folder already there is refused: the
/// caller names a new one each time.
pub fn make(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(path)?;
    if let Err(err) = restrict(path) {
        // A folder others could read holds nothing yet: it goes again.
        let _ = std::fs::remove_dir(path);
        return Err(err);
    }
    Ok(())
}

fn io_error(text: String) -> CoreError {
    CoreError::Io(std::io::Error::other(text))
}

/// The SID of the user Remotely runs as, as `S-1-5-21-...`.
#[cfg(windows)]
fn user_sid() -> Result<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let failed = |what: &str, err: String| io_error(format!("could not read this user's SID: {what}: {err}"));
    // SAFETY: the token buffer is sized as the API asks; the handle and the LocalAlloc'd string are freed here.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| failed("the process token", e.to_string()))?;
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        let read = GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), needed, &mut needed);
        let _ = CloseHandle(token);
        read.map_err(|e| failed("the user", e.to_string()))?;
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        let mut sid_text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid_text).map_err(|e| failed("the SID", e.to_string()))?;
        let sid = sid_text.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(sid_text.0.cast())));
        if !sid.starts_with("S-1-") {
            return Err(failed("the SID", "unreadable".into()));
        }
        Ok(sid)
    }
}

/// The DACL [`make`] gives a folder, as SDDL.
#[cfg(windows)]
fn private_sddl() -> Result<String> {
    Ok(format!("D:P(A;OICI;FA;;;{})", user_sid()?))
}

/// The one entry [`make`] gives, as Windows writes it back ([`describe`]): a well-known account is written by its alias
/// (the built-in Administrator's SID as `LA`), any other by its SID. For tests.
#[cfg(windows)]
pub fn user_entry() -> Result<String> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let sddl: Vec<u16> = private_sddl()?.encode_utf16().chain([0]).collect();
    // SAFETY: the descriptor and the string are LocalAlloc'd by the API and freed here.
    let written = unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| io_error(format!("could not read the access list: {e}")))?;
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        );
        let written = converted.map(|()| text.to_string().unwrap_or_default());
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        written.map_err(|e| io_error(format!("could not read the access list: {e}")))?
    };
    written
        .find("(A;")
        .map(|at| written[at..].to_owned())
        .ok_or_else(|| io_error(format!("the access list {written} has no entry")))
}

#[cfg(windows)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let failed =
        |what: &str, err: String| io_error(format!("could not make {} private: {what}: {err}", path.display()));
    let sddl: Vec<u16> = private_sddl()?.encode_utf16().chain([0]).collect();
    // SAFETY: the descriptor is LocalAlloc'd by the API and freed below; the DACL points into it.
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| failed("the access list", e.to_string()))?;
        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let got = GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted);
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let set = match got {
            Ok(()) => SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            ),
            Err(_) => WIN32_ERROR(1),
        };
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        if set != WIN32_ERROR(0) {
            return Err(failed("the access list", format!("Windows error {}", set.0)));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// The folder's DACL as SDDL (`D:PAI(A;OICI;FA;;;S-1-5-21-...)`), for tests and the log.
#[cfg(windows)]
pub fn describe(path: &Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: the descriptor and the string are LocalAlloc'd by the API and freed here.
    unsafe {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let got = GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        );
        if got != WIN32_ERROR(0) {
            return Err(io_error(format!(
                "could not read the access list: Windows error {}",
                got.0
            )));
        }
        let mut text = PWSTR::null();
        let converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        );
        let sddl = converted.map(|()| text.to_string().unwrap_or_default());
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        sddl.map_err(|e| io_error(format!("could not read the access list: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn only_this_user_gets_in_and_nothing_is_inherited() {
        let root = std::env::temp_dir().join(format!("remotely-private-{}", uuid::Uuid::new_v4().simple()));
        let folder = root.join("edit");
        make(&folder).unwrap();
        let sddl = describe(&folder).unwrap();
        // Protected (P: nothing from the folder above), one entry: this user's full control, inherited by files and
        // folders in it. (A CI runner's built-in Administrator is written `LA`, another user by their SID.)
        let entry = user_entry().unwrap();
        assert!(entry.starts_with("(A;OICI;FA;;;"), "{entry}");
        assert!(sddl.starts_with("D:P") && sddl.ends_with(&entry), "{sddl} vs {entry}");
        assert_eq!(sddl.matches("(A;").count(), 1, "{sddl}");
        // A file made in it inherits the one entry.
        let file = folder.join("hosts");
        std::fs::write(&file, "127.0.0.1 localhost\n").unwrap();
        let inherited = describe(&file).unwrap();
        assert_eq!(inherited.matches("(A;").count(), 1, "{inherited}");
        assert!(make(&folder).is_err(), "a folder there already is refused");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
