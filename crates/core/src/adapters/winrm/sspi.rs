//! SS-12: Windows' own sign-in for WinRM (SSPI), so Remotely holds no NTLM or Kerberos code of its own on the client
//! side and changes nothing on this PC:
//!
//! * **NTLM** (`NTLM` package) with the session's user and its vault password, given to `AcquireCredentialsHandleW`
//!   once per connection and zeroized as soon as it returns (Windows keeps its own copy in LSA for that handle).
//!   NTLMv2 with a MIC, sealing and signing as Windows does them.
//! * **My Windows sign-in** with the account signed in to this PC: **Kerberos only** (`Negotiate` with `!NTLM` in its
//!   package list, the SPN `HTTP/<host>`). NTLM never answers for this PC's account: a host that can't do Kerberos
//!   (outside the domain, or reached by an IP address) fails, saying to sign in with NTLM and a vault password. The
//!   caller also refuses any token that is NTLM, and requires the context complete with mutual authentication.
//!
//! Over HTTP every message after the sign-in is sealed with the context ([`Context::seal`], `EncryptMessage`) and
//! each answer unsealed ([`Context::unseal`], `DecryptMessage`): Windows keeps the sequence numbers and RC4 state, so
//! the messages of one connection must be sealed in order (the connection holds the context under a lock). Over HTTPS
//! the context is bound to the TLS channel (Extended Protection, RFC 5929's `tls-server-end-point`).
//!
//! No token, key or password from here reaches a log, an error or the UI: errors name only Windows' status code.

use crate::vault::SecretString;

/// Which SSPI package signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Package {
    /// `NTLM` with a user and password.
    Ntlm,
    /// `Negotiate` restricted to Kerberos (`!NTLM`), with this PC's own account.
    KerberosOnly,
}

/// A token holds NTLM (raw, or inside SPNEGO): its `NTLMSSP\0` signature.
pub fn is_ntlm(token: &[u8]) -> bool {
    token.windows(8).any(|w| w == b"NTLMSSP\0")
}

/// The `SEC_CHANNEL_BINDINGS` SSPI takes for `application` data: eight 32-bit fields (only the application data's length
/// and offset set), then the data.
pub fn channel_bindings(application: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let len = u32::try_from(application.len()).unwrap_or(0);
    out[24..28].copy_from_slice(&len.to_le_bytes());
    out[28..32].copy_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(application);
    out
}

/// A user and password for [`acquire`]. The user may be `DOMAIN\user`, `user@domain` or a local account's name.
pub struct Identity<'a> {
    pub user: &'a str,
    pub password: &'a SecretString,
}

/// `DOMAIN\user` split; `user@domain` and a plain name are kept whole with no domain (SSPI reads a UPN itself).
pub fn split_user(user: &str) -> (&str, &str) {
    match user.split_once('\\') {
        Some((domain, name)) => (name, domain),
        None => (user, ""),
    }
}

/// One step of the sign-in: the token to send, whether the context is complete, and whether the host proved itself
/// (mutual authentication: Kerberos does, NTLM never). No `Debug`: the token may be NTLM's AUTHENTICATE message.
pub struct Step {
    pub token: Vec<u8>,
    pub complete: bool,
    pub mutual: bool,
}

#[cfg(windows)]
mod imp {
    use std::sync::Arc;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY, SEC_E_NO_CREDENTIALS, SEC_E_OK, SEC_E_TARGET_UNKNOWN,
        SEC_E_WRONG_PRINCIPAL, SEC_I_CONTINUE_NEEDED,
    };
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, DecryptMessage, DeleteSecurityContext, EncryptMessage, FreeContextBuffer,
        FreeCredentialsHandle, InitializeSecurityContextW, QueryContextAttributesW, SecBuffer, SecBufferDesc,
        SecPkgContext_Sizes, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH,
        ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, ISC_RET_MUTUAL_AUTH, SECBUFFER_CHANNEL_BINDINGS,
        SECBUFFER_DATA, SECBUFFER_PADDING, SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_SIZES, SECPKG_CRED_OUTBOUND,
        SECURITY_NATIVE_DREP, SEC_CHANNEL_BINDINGS, SEC_WINNT_AUTH_IDENTITY_EXW, SEC_WINNT_AUTH_IDENTITY_VERSION,
    };
    use windows::Win32::Security::Credentials::SecHandle;
    use windows::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W};
    use zeroize::Zeroizing;

    use super::{channel_bindings, split_user, Identity, Package, Step};
    use crate::error::{CoreError, Result};

    // [`channel_bindings`] writes this structure by hand.
    const _: () = assert!(std::mem::size_of::<SEC_CHANNEL_BINDINGS>() == 32);

    fn wide(text: &str) -> Zeroizing<Vec<u16>> {
        let mut out: Vec<u16> = text.encode_utf16().collect();
        out.push(0);
        Zeroizing::new(out)
    }

    fn status_error(status: windows::core::HRESULT) -> CoreError {
        let code = status.0 as u32;
        if status == SEC_E_LOGON_DENIED {
            return CoreError::AuthFailed("the host refused the user name or password".into());
        }
        if status == SEC_E_NO_CREDENTIALS {
            return CoreError::AuthFailed("Windows has no sign-in to use for this host".into());
        }
        if status == SEC_E_TARGET_UNKNOWN || status == SEC_E_WRONG_PRINCIPAL {
            return CoreError::AuthFailed(format!(
                "Windows doesn't know this host's Kerberos name (HTTP/<host>; status 0x{code:08X}). Use the host's full domain name"
            ));
        }
        if status == SEC_E_NO_AUTHENTICATING_AUTHORITY {
            return CoreError::AuthFailed(
                "no domain controller answered for this sign-in, so Kerberos can't be used here".into(),
            );
        }
        CoreError::Winrm(format!("Windows' sign-in failed (status 0x{code:08X})"))
    }

    /// An SSPI credentials handle; freed when the last context using it is gone.
    pub struct Credentials {
        handle: SecHandle,
    }

    impl Drop for Credentials {
        fn drop(&mut self) {
            // SAFETY: the handle came from AcquireCredentialsHandleW and is freed once.
            let _ = unsafe { FreeCredentialsHandle(&self.handle) };
        }
    }

    /// Credentials for `package`: `identity`'s, or the signed-in Windows user's when `None`.
    pub fn acquire(package: Package, identity: Option<Identity<'_>>) -> Result<Arc<Credentials>> {
        let name = match package {
            Package::Ntlm => wide("NTLM"),
            Package::KerberosOnly => wide("Negotiate"),
        };
        let mut handle = SecHandle::default();
        let result = match (package, identity) {
            // The signed-in user's own credentials, with NTLM taken out of Negotiate's list: Kerberos or nothing, so this
            // PC's account never answers an NTLM challenge.
            (Package::KerberosOnly, _) => {
                let mut packages = wide("!NTLM");
                let auth = SEC_WINNT_AUTH_IDENTITY_EXW {
                    Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
                    Length: std::mem::size_of::<SEC_WINNT_AUTH_IDENTITY_EXW>() as u32,
                    User: std::ptr::null_mut(),
                    UserLength: 0,
                    Domain: std::ptr::null_mut(),
                    DomainLength: 0,
                    Password: std::ptr::null_mut(),
                    PasswordLength: 0,
                    Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE.0,
                    PackageList: packages.as_mut_ptr(),
                    PackageListLength: (packages.len() - 1) as u32,
                };
                // SAFETY: every pointer is valid for the call; with no user, domain or password the signed-in user's
                // own credentials are used, restricted to the package list.
                unsafe {
                    AcquireCredentialsHandleW(
                        PCWSTR::null(),
                        PCWSTR(name.as_ptr()),
                        SECPKG_CRED_OUTBOUND,
                        None,
                        Some(std::ptr::from_ref(&auth).cast()),
                        None,
                        None,
                        &mut handle,
                        None,
                    )
                }
            }
            (Package::Ntlm, Some(identity)) => {
                let (user, domain) = split_user(identity.user);
                let mut user = wide(user);
                let mut domain = wide(domain);
                let mut password = wide(identity.password.expose());
                let auth = SEC_WINNT_AUTH_IDENTITY_W {
                    User: user.as_mut_ptr(),
                    UserLength: (user.len() - 1) as u32,
                    Domain: domain.as_mut_ptr(),
                    DomainLength: (domain.len() - 1) as u32,
                    Password: password.as_mut_ptr(),
                    PasswordLength: (password.len() - 1) as u32,
                    Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
                };
                // SAFETY: every pointer is valid for the call; Windows copies what it keeps. The buffers are zeroized
                // when they drop at the end of this block.
                unsafe {
                    AcquireCredentialsHandleW(
                        PCWSTR::null(),
                        PCWSTR(name.as_ptr()),
                        SECPKG_CRED_OUTBOUND,
                        None,
                        Some(std::ptr::from_ref(&auth).cast()),
                        None,
                        None,
                        &mut handle,
                        None,
                    )
                }
            }
            // NTLM signs in only with a user and password: never with this PC's own account.
            (Package::Ntlm, None) => {
                return Err(CoreError::AuthFailed(
                    "NTLM signs in with the session's user and a password from the vault".into(),
                ))
            }
        };
        result.map_err(|err| status_error(err.code()))?;
        Ok(Arc::new(Credentials { handle }))
    }

    /// One sign-in's security context.
    pub struct Context {
        credentials: Arc<Credentials>,
        handle: Option<SecHandle>,
        target: Vec<u16>,
        flags: u32,
        sizes: Option<SecPkgContext_Sizes>,
        /// HTTPS: a SEC_CHANNEL_BINDINGS with `tls-server-end-point:` and the certificate's hash (RFC 5929), given with
        /// every step, so a host that requires Extended Protection takes the sign-in.
        bindings: Option<Vec<u8>>,
    }

    impl Drop for Context {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                // SAFETY: the handle came from InitializeSecurityContextW and is deleted once.
                let _ = unsafe { DeleteSecurityContext(&handle) };
            }
        }
    }

    impl Context {
        /// A context for the service `spn` (`HTTP/win01.example.com`).
        pub fn new(credentials: Arc<Credentials>, spn: &str, channel: Option<&[u8]>) -> Self {
            let flags = ISC_REQ_CONFIDENTIALITY.0
                | ISC_REQ_INTEGRITY.0
                | ISC_REQ_SEQUENCE_DETECT.0
                | ISC_REQ_REPLAY_DETECT.0
                | ISC_REQ_MUTUAL_AUTH.0
                | ISC_REQ_ALLOCATE_MEMORY.0;
            Self {
                credentials,
                handle: None,
                target: wide(spn).to_vec(),
                flags,
                sizes: None,
                bindings: channel.map(channel_bindings),
            }
        }

        /// The next token: the first without `input`, then each with the host's answer.
        pub fn step(&mut self, input: Option<&[u8]>) -> Result<Step> {
            let mut input_bytes = input.map(<[u8]>::to_vec).unwrap_or_default();
            let mut bindings = self.bindings.clone().unwrap_or_default();
            let mut in_buffers = Vec::with_capacity(2);
            if input.is_some() {
                in_buffers.push(SecBuffer {
                    cbBuffer: u32::try_from(input_bytes.len())
                        .map_err(|_| CoreError::Winrm("a sign-in token is too long".into()))?,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: input_bytes.as_mut_ptr().cast(),
                });
            }
            if !bindings.is_empty() {
                in_buffers.push(SecBuffer {
                    cbBuffer: bindings.len() as u32,
                    BufferType: SECBUFFER_CHANNEL_BINDINGS,
                    pvBuffer: bindings.as_mut_ptr().cast(),
                });
            }
            let in_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: in_buffers.len() as u32,
                pBuffers: in_buffers.as_mut_ptr(),
            };
            let has_input = !in_buffers.is_empty();
            let mut out_buffer = SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: std::ptr::null_mut(),
            };
            let mut out_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut out_buffer,
            };
            let mut attributes = 0u32;
            let mut handle = self.handle.unwrap_or_default();
            let existing = self.handle;
            // SAFETY: the buffers outlive the call; the output token is allocated by SSPI and freed below.
            let status = unsafe {
                InitializeSecurityContextW(
                    Some(&self.credentials.handle),
                    existing.as_ref().map(std::ptr::from_ref),
                    Some(self.target.as_ptr()),
                    windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS(self.flags),
                    0,
                    SECURITY_NATIVE_DREP,
                    has_input.then(|| std::ptr::from_ref(&in_desc)),
                    0,
                    Some(&mut handle),
                    Some(&mut out_desc),
                    &mut attributes,
                    None,
                )
            };
            if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED {
                self.handle = Some(handle);
            }
            let token = if out_buffer.pvBuffer.is_null() || out_buffer.cbBuffer == 0 {
                Vec::new()
            } else {
                // SAFETY: SSPI wrote `cbBuffer` bytes there.
                let bytes = unsafe {
                    std::slice::from_raw_parts(out_buffer.pvBuffer.cast::<u8>(), out_buffer.cbBuffer as usize).to_vec()
                };
                // SAFETY: allocated by SSPI for ISC_REQ_ALLOCATE_MEMORY.
                let _ = unsafe { FreeContextBuffer(out_buffer.pvBuffer) };
                bytes
            };
            let mutual = attributes & ISC_RET_MUTUAL_AUTH != 0;
            if status == SEC_E_OK {
                Ok(Step {
                    token,
                    complete: true,
                    mutual,
                })
            } else if status == SEC_I_CONTINUE_NEEDED {
                Ok(Step {
                    token,
                    complete: false,
                    mutual,
                })
            } else {
                Err(status_error(status))
            }
        }

        fn sizes(&mut self) -> Result<SecPkgContext_Sizes> {
            if let Some(sizes) = self.sizes {
                return Ok(sizes);
            }
            let handle = self
                .handle
                .ok_or_else(|| CoreError::Winrm("the sign-in has not finished".into()))?;
            let mut sizes = SecPkgContext_Sizes::default();
            // SAFETY: `sizes` is the structure SECPKG_ATTR_SIZES fills.
            unsafe { QueryContextAttributesW(&handle, SECPKG_ATTR_SIZES, std::ptr::from_mut(&mut sizes).cast()) }
                .map_err(|err| status_error(err.code()))?;
            self.sizes = Some(sizes);
            Ok(sizes)
        }

        /// Seals `data`: (the signature or header token, the sealed bytes with any padding).
        pub fn seal(&mut self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let sizes = self.sizes()?;
            let handle = self
                .handle
                .ok_or_else(|| CoreError::Winrm("the sign-in has not finished".into()))?;
            let mut token = vec![0u8; sizes.cbSecurityTrailer as usize];
            let mut sealed = data.to_vec();
            let mut padding = vec![0u8; sizes.cbBlockSize as usize];
            let length =
                |n: usize| u32::try_from(n).map_err(|_| CoreError::Winrm("a message is too long to seal".into()));
            let mut buffers = [
                SecBuffer {
                    cbBuffer: length(token.len())?,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: token.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: length(sealed.len())?,
                    BufferType: SECBUFFER_DATA,
                    pvBuffer: sealed.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: length(padding.len())?,
                    BufferType: SECBUFFER_PADDING,
                    pvBuffer: padding.as_mut_ptr().cast(),
                },
            ];
            let count = if padding.is_empty() { 2 } else { 3 };
            let desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: count,
                pBuffers: buffers.as_mut_ptr(),
            };
            // SAFETY: the buffers outlive the call and are sealed in place.
            let status = unsafe { EncryptMessage(&handle, 0, &desc, 0) };
            if status != SEC_E_OK {
                return Err(status_error(status));
            }
            token.truncate(buffers[0].cbBuffer as usize);
            sealed.truncate(buffers[1].cbBuffer as usize);
            if count == 3 {
                padding.truncate(buffers[2].cbBuffer as usize);
                sealed.extend_from_slice(&padding);
            }
            Ok((token, sealed))
        }

        /// Unseals an answer: its signature or header token and its sealed bytes.
        pub fn unseal(&mut self, signature: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
            let handle = self
                .handle
                .ok_or_else(|| CoreError::Winrm("the sign-in has not finished".into()))?;
            let mut signature = signature.to_vec();
            let mut data = sealed.to_vec();
            let length =
                |n: usize| u32::try_from(n).map_err(|_| CoreError::Winrm("an answer is too long to unseal".into()));
            let mut buffers = [
                SecBuffer {
                    cbBuffer: length(signature.len())?,
                    BufferType: SECBUFFER_TOKEN,
                    pvBuffer: signature.as_mut_ptr().cast(),
                },
                SecBuffer {
                    cbBuffer: length(data.len())?,
                    BufferType: SECBUFFER_DATA,
                    pvBuffer: data.as_mut_ptr().cast(),
                },
            ];
            let desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: buffers.as_mut_ptr(),
            };
            let mut qop = 0u32;
            // SAFETY: the buffers outlive the call and are unsealed in place.
            let status = unsafe { DecryptMessage(&handle, &desc, 0, Some(&mut qop)) };
            if status != SEC_E_OK {
                return Err(CoreError::Winrm(format!(
                    "an answer from the host failed its integrity check (status 0x{:08X}), so the connection was dropped",
                    status.0 as u32
                )));
            }
            let start = buffers[1].pvBuffer.cast::<u8>();
            let len = buffers[1].cbBuffer as usize;
            let base = data.as_ptr();
            // The plain bytes are inside `data` (SSPI unseals in place and may move the start for padding).
            let offset = (start as usize).saturating_sub(base as usize);
            data.get(offset..offset + len)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| CoreError::Winrm("an unsealed answer is not where Windows said".into()))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::sync::Arc;

    use super::{Identity, Package, Step};
    use crate::error::{CoreError, Result};

    fn needs_windows() -> CoreError {
        CoreError::Winrm("signing in to WinRM with NTLM or Kerberos needs Windows".into())
    }

    pub struct Credentials;

    pub fn acquire(_package: Package, _identity: Option<Identity<'_>>) -> Result<Arc<Credentials>> {
        Err(needs_windows())
    }

    pub struct Context;

    impl Context {
        pub fn new(_credentials: Arc<Credentials>, _spn: &str, _channel: Option<&[u8]>) -> Self {
            Self
        }
        pub fn step(&mut self, _input: Option<&[u8]>) -> Result<Step> {
            Err(needs_windows())
        }
        pub fn seal(&mut self, _data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(needs_windows())
        }
        pub fn unseal(&mut self, _signature: &[u8], _sealed: &[u8]) -> Result<Vec<u8>> {
            Err(needs_windows())
        }
    }
}

pub use imp::{acquire, Context, Credentials};

/// The SPN WinRM's HTTP listener answers to: `HTTP/<host>` (WinRM registers it for HTTPS too).
pub fn spn(host: &str) -> String {
    format!("HTTP/{}", host.trim_start_matches('[').trim_end_matches(']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_are_split_as_windows_reads_them() {
        assert_eq!(split_user(r"CORP\alice"), ("alice", "CORP"));
        assert_eq!(split_user("alice@corp.example.com"), ("alice@corp.example.com", ""));
        assert_eq!(split_user("alice"), ("alice", ""));
        assert_eq!(spn("[2001:db8::5]"), "HTTP/2001:db8::5");
        assert_eq!(spn("win01.example.com"), "HTTP/win01.example.com");
    }

    #[cfg(windows)]
    #[test]
    fn windows_starts_an_ntlm_sign_in_with_a_negotiate_message() {
        let password = SecretString::new("not-a-real-password");
        let credentials = acquire(
            Package::Ntlm,
            Some(Identity {
                user: "alice",
                password: &password,
            }),
        )
        .unwrap();
        let mut context = Context::new(credentials, &spn("win01.test"), None);
        let first = context.step(None).unwrap();
        assert!(!first.complete);
        assert!(
            first.token.starts_with(b"NTLMSSP\0\x01\0\0\0"),
            "an NTLM NEGOTIATE message"
        );
        assert!(is_ntlm(&first.token));
    }

    /// Review F4 #1: the Windows sign-in never offers NTLM for this PC's account, even where Kerberos can't work (an IP
    /// address has no Kerberos name).
    #[cfg(windows)]
    #[test]
    fn the_windows_sign_in_offers_no_ntlm() {
        let credentials = acquire(Package::KerberosOnly, None).unwrap();
        let mut context = Context::new(credentials, &spn("192.0.2.10"), None);
        // An error is Kerberos unable to start: refused before anything is sent.
        if let Ok(first) = context.step(None) {
            assert!(!is_ntlm(&first.token), "no NTLM token for this PC's account");
        }
    }

    #[test]
    fn channel_bindings_carry_only_the_application_data() {
        let bindings = channel_bindings(b"tls-server-end-point:abc");
        assert_eq!(bindings.len(), 32 + 24);
        assert!(bindings[..24].iter().all(|b| *b == 0));
        assert_eq!(&bindings[24..28], &24u32.to_le_bytes());
        assert_eq!(&bindings[28..32], &32u32.to_le_bytes());
        assert_eq!(&bindings[32..], b"tls-server-end-point:abc");
    }
}
