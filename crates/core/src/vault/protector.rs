//! Wraps the vault's data key with the Windows login (SS-04), through DPAPI.
//!
//! DPAPI ties the blob to the current Windows user: another account, or this account after an
//! administrator resets its password, cannot unwrap it. The master-password copy of the key is the
//! way back in then. A trait, so tests use a fake instead of the real user profile.

use zeroize::Zeroizing;

use crate::error::Result;

pub trait KeyProtector: Send + Sync {
    /// Whether this machine can protect keys this way.
    fn available(&self) -> bool;

    /// `entropy` must be passed again to unprotect; it ties the blob to one workspace's vault.
    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>>;

    fn unprotect(&self, blob: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// Windows DPAPI (`CryptProtectData`), scoped to the current user.
pub struct Dpapi;

impl KeyProtector for Dpapi {
    fn available(&self) -> bool {
        cfg!(windows)
    }

    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        win::protect(data, entropy).map(|blob| blob.to_vec())
    }

    fn unprotect(&self, blob: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        win::unprotect(blob, entropy)
    }
}

#[cfg(windows)]
mod win {
    use windows::core::w;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use zeroize::{Zeroize, Zeroizing};

    use crate::error::{CoreError, Result};

    fn os_error(call: &str, err: windows::core::Error) -> CoreError {
        CoreError::Vault(format!("{call}: {}", err.message()))
    }

    /// Borrows `data` as the API's input type. DPAPI only reads input blobs.
    fn blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).map_err(|_| CoreError::Vault("data too large for DPAPI".into()))?,
            pbData: data.as_ptr().cast_mut(),
        })
    }

    /// Copies an output blob, then zeroes and frees the buffer DPAPI allocated.
    fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        if out.pbData.is_null() {
            return Zeroizing::new(Vec::new());
        }
        // SAFETY: on success DPAPI sets pbData to a LocalAlloc'd buffer of cbData bytes that the caller
        // owns. It is read and zeroed here, then freed once, below.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
        let copy = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        // SAFETY: the buffer came from LocalAlloc inside DPAPI and is not used after this.
        unsafe { LocalFree(Some(HLOCAL(out.pbData.cast()))) };
        copy
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let input = blob(data)?;
        let entropy = blob(entropy)?;
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: both input blobs point at live slices that outlive the call; `out` is a live blob the
        // API fills with a buffer handed to `take`. UI_FORBIDDEN: never show a prompt.
        unsafe {
            CryptProtectData(
                &input,
                w!("Remotely vault key"),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| os_error("CryptProtectData", e))?;
        Ok(take(out))
    }

    pub fn unprotect(blob_in: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let input = blob(blob_in)?;
        let entropy = blob(entropy)?;
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as in `protect`; the description out-parameter is not asked for.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| os_error("CryptUnprotectData", e))?;
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod win {
    use zeroize::Zeroizing;

    use crate::error::{CoreError, Result};

    pub fn protect(_data: &[u8], _entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(CoreError::NotImplemented("DPAPI outside Windows"))
    }

    pub fn unprotect(_blob: &[u8], _entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(CoreError::NotImplemented("DPAPI outside Windows"))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    // Uses this Windows account's DPAPI key; stores nothing.
    #[test]
    fn dpapi_round_trips_for_this_user_and_needs_the_same_entropy() {
        let data = [0x5au8; 32];
        let blob = Dpapi.protect(&data, b"workspace-a").unwrap();
        assert!(!blob.windows(data.len()).any(|w| w == data));
        assert_eq!(&Dpapi.unprotect(&blob, b"workspace-a").unwrap()[..], &data);
        assert!(Dpapi.unprotect(&blob, b"workspace-b").is_err());

        let mut changed = blob.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(Dpapi.unprotect(&changed, b"workspace-a").is_err());
    }
}
