//! FD-07: the export file. A small JSON envelope that says what it is and how its key is derived,
//! around the encrypted payload:
//!
//! ```text
//! {
//!   "format": "remotely-export",
//!   "version": 1,
//!   "kdf": { "algorithm": "argon2id", "version": 19, "memoryKib": 65536, "iterations": 3, "parallelism": 1 },
//!   "salt": "<16 random bytes, base64>",
//!   "nonce": "<12 random bytes, base64>",
//!   "ciphertext": "<AES-256-GCM of the payload JSON, with its tag, base64>"
//! }
//! ```
//!
//! The key is Argon2id(passphrase, salt) with the parameters written in the file, so a file stays
//! readable when the defaults change. The header (format, version, parameters, salt) is the AES-GCM
//! associated data: changing any of it, or one bit of the ciphertext, makes the file fail to open,
//! exactly like a wrong passphrase. The payload JSON never touches the disk unencrypted.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::vault::crypto::{self, KdfParams, SALT_LEN};
use crate::vault::SecretString;

/// What the envelope's `format` says.
pub const FORMAT: &str = "remotely-export";
/// The payload layout this version writes and reads. A newer file is refused with a message.
pub const FORMAT_VERSION: u32 = 1;
/// Largest file opened: far more than any real session list with its secrets.
pub const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    format: String,
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Bounds for parameters read from a file, tighter than the vault's own: a file can come from
/// anywhere, and opening one must not take gigabytes or minutes.
fn check_import_kdf(kdf: &KdfParams) -> Result<()> {
    let ok = kdf.memory_kib <= 256 * 1024 && kdf.iterations <= 10 && kdf.parallelism <= 8;
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidInput(
            "The file asks for key derivation settings Remotely doesn't use. It was not made by Remotely, or it was changed."
                .into(),
        ))
    }
}

/// The associated data: everything in the header, so none of it can be swapped.
fn aad(version: u32, kdf: &KdfParams, salt: &[u8]) -> Result<Vec<u8>> {
    let kdf = serde_json::to_string(kdf)?;
    Ok(format!("{FORMAT}/v{version}/{kdf}/{}", BASE64.encode(salt)).into_bytes())
}

fn not_an_export() -> CoreError {
    CoreError::InvalidInput("That is not a Remotely export file.".into())
}

/// Encrypts `payload` (JSON) under a key from `passphrase`. Slow on purpose (Argon2id): run it off the
/// async threads.
pub fn seal(payload: &[u8], passphrase: &SecretString, kdf: &KdfParams) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    crypto::random(&mut salt)?;
    let key = crypto::derive(passphrase, &salt, kdf)?;
    let (nonce, ciphertext) = crypto::seal(&key, payload, &aad(FORMAT_VERSION, kdf, &salt)?)?;
    let envelope = Envelope {
        format: FORMAT.into(),
        version: FORMAT_VERSION,
        kdf: *kdf,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    };
    let mut text = serde_json::to_vec_pretty(&envelope)?;
    text.push(b'\n');
    Ok(text)
}

/// Decrypts a file `seal` wrote. [`CoreError::WrongPassphrase`] for a wrong passphrase or a changed
/// file; other errors say the file is not an export at all, or a newer one. Slow on purpose.
pub fn open(file: &[u8], passphrase: &SecretString) -> Result<Zeroizing<Vec<u8>>> {
    let envelope: Envelope = serde_json::from_slice(file).map_err(|_| not_an_export())?;
    if envelope.format != FORMAT {
        return Err(not_an_export());
    }
    if envelope.version > FORMAT_VERSION {
        return Err(CoreError::InvalidInput(format!(
            "This file was exported by a newer version of Remotely (file format {}). Update Remotely to import it.",
            envelope.version
        )));
    }
    if envelope.version == 0 {
        return Err(not_an_export());
    }
    check_import_kdf(&envelope.kdf)?;
    let decode = |field: &str| BASE64.decode(field).map_err(|_| not_an_export());
    let salt = decode(&envelope.salt)?;
    let nonce = decode(&envelope.nonce)?;
    let ciphertext = decode(&envelope.ciphertext)?;
    if salt.len() != SALT_LEN || nonce.len() != crypto::NONCE_LEN {
        return Err(not_an_export());
    }
    let key = crypto::derive(passphrase, &salt, &envelope.kdf)?;
    crypto::open(&key, &nonce, &ciphertext, &aad(envelope.version, &envelope.kdf, &salt)?)?
        .ok_or(CoreError::WrongPassphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::INSECURE_FAST;

    fn phrase(p: &str) -> SecretString {
        SecretString::new(p)
    }

    fn envelope(file: &[u8]) -> serde_json::Value {
        serde_json::from_slice(file).unwrap()
    }

    #[test]
    fn a_sealed_payload_opens_with_its_passphrase_and_is_not_readable_without_it() {
        let payload = br#"{"sessions":[{"host":"web01.example.com"}],"secret":"hunter2"}"#;
        let file = seal(payload, &phrase("tulip anvil orbit"), &FAST).unwrap();
        let text = String::from_utf8(file.clone()).unwrap();
        assert!(!text.contains("hunter2") && !text.contains("web01"), "{text}");
        let e = envelope(&file);
        assert_eq!(e["format"], FORMAT);
        assert_eq!(e["version"], FORMAT_VERSION);
        assert_eq!(e["kdf"]["algorithm"], "argon2id");

        let opened = open(&file, &phrase("tulip anvil orbit")).unwrap();
        assert_eq!(&opened[..], payload);
        let err = open(&file, &phrase("tulip anvil orbiT")).unwrap_err();
        assert!(matches!(err, CoreError::WrongPassphrase), "{err}");
    }

    #[test]
    fn every_seal_uses_a_new_salt_and_nonce() {
        let a = envelope(&seal(b"{}", &phrase("same passphrase"), &FAST).unwrap());
        let b = envelope(&seal(b"{}", &phrase("same passphrase"), &FAST).unwrap());
        assert_ne!(a["salt"], b["salt"]);
        assert_ne!(a["nonce"], b["nonce"]);
    }

    #[test]
    fn a_changed_file_does_not_open() {
        let file = seal(b"{\"sessions\":[]}", &phrase("tulip anvil orbit"), &FAST).unwrap();
        let tamper = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut e = envelope(&file);
            edit(&mut e);
            open(&serde_json::to_vec(&e).unwrap(), &phrase("tulip anvil orbit"))
        };
        // One bit of the ciphertext.
        let flipped = tamper(&|e| {
            let mut bytes = BASE64.decode(e["ciphertext"].as_str().unwrap()).unwrap();
            bytes[0] ^= 1;
            e["ciphertext"] = BASE64.encode(bytes).into();
        });
        assert!(matches!(flipped, Err(CoreError::WrongPassphrase)));
        // The header is authenticated too: another salt or other (still valid) parameters.
        let salt = tamper(&|e| e["salt"] = BASE64.encode([9u8; SALT_LEN]).into());
        assert!(matches!(salt, Err(CoreError::WrongPassphrase)));
        let params = tamper(&|e| e["kdf"]["iterations"] = 2.into());
        assert!(matches!(params, Err(CoreError::WrongPassphrase)));
        // Truncated: not JSON any more.
        assert_eq!(
            open(&file[..file.len() / 2], &phrase("tulip anvil orbit"))
                .unwrap_err()
                .code(),
            "invalid_input"
        );
    }

    #[test]
    fn other_files_and_newer_versions_are_refused_with_a_reason() {
        let file = seal(b"{}", &phrase("tulip anvil orbit"), &FAST).unwrap();
        let mut newer = envelope(&file);
        newer["version"] = (FORMAT_VERSION + 1).into();
        let err = open(&serde_json::to_vec(&newer).unwrap(), &phrase("tulip anvil orbit")).unwrap_err();
        assert!(err.to_string().contains("newer version"), "{err}");

        let mut other = envelope(&file);
        other["format"] = "something-else".into();
        let err = open(&serde_json::to_vec(&other).unwrap(), &phrase("tulip anvil orbit")).unwrap_err();
        assert!(err.to_string().contains("not a Remotely export"), "{err}");

        for junk in [&b"hostname,port\nweb01,22\n"[..], b"", b"{}"] {
            assert_eq!(open(junk, &phrase("x")).unwrap_err().code(), "invalid_input");
        }
    }

    #[test]
    fn costly_key_derivation_settings_in_a_file_are_refused_before_deriving() {
        let file = seal(b"{}", &phrase("tulip anvil orbit"), &FAST).unwrap();
        let mut e = envelope(&file);
        e["kdf"]["memoryKib"] = (1024 * 1024).into();
        let err = open(&serde_json::to_vec(&e).unwrap(), &phrase("tulip anvil orbit")).unwrap_err();
        assert!(err.to_string().contains("key derivation"), "{err}");
    }
}
