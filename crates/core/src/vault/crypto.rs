//! Vault crypto (SS-04, NFR Security): AES-256-GCM for items and for wrapping the data key, and
//! Argon2id to turn the master password into a key. Keys and plaintexts live in zeroizing buffers.
//!
//! Each AES-GCM call takes a fresh random 96-bit nonce. A vault holds at most thousands of items and
//! is re-encrypted on every change, far below the 2^32 random nonces NIST SP 800-38D allows per key.

use std::fmt;

use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::SecretString;
use crate::error::{CoreError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

/// A 256-bit AES key. Zeroized on drop; never printed.
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// A new random key from the operating system's CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        random(&mut *key)?;
        Ok(Self(key))
    }

    #[cfg(any(test, feature = "fakes"))]
    pub fn from_array(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        if bytes.len() != KEY_LEN {
            return Err(CoreError::Vault("the stored key has the wrong length".into()));
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        Aes256Gcm::new_from_slice(self.as_bytes()).map_err(|_| CoreError::Vault("bad key length".into()))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(***)")
    }
}

/// Fills `buf` from the operating system's CSPRNG.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|err| CoreError::Vault(format!("no random numbers from the system: {err}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// How the master key is derived. Saved with the vault, so a vault keeps working when the defaults
/// change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    /// Argon2 version (0x13 = 19).
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// RFC 9106's second recommended setting (64 MiB, 3 passes), on one lane: about half a second per
    /// unlock or Critical approval on a current PC.
    pub const DEFAULT: KdfParams = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        version: 0x13,
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// The cheapest Argon2id allows. Tests only: it resists no guessing at all.
    #[cfg(any(test, feature = "fakes"))]
    pub const INSECURE_FAST: KdfParams = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        version: 0x13,
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    /// Bounds for parameters read back from the database, so a damaged or edited row cannot make an
    /// unlock take gigabytes or minutes.
    fn check(&self) -> Result<()> {
        let ok = self.version == 0x13
            && (8..=1024 * 1024).contains(&self.memory_kib)
            && (1..=16).contains(&self.iterations)
            && (1..=16).contains(&self.parallelism);
        if ok {
            Ok(())
        } else {
            Err(CoreError::Vault(format!(
                "unsupported key derivation settings: {self:?}"
            )))
        }
    }
}

/// Argon2id(password, salt) -> a 256-bit key. Slow on purpose: run it off the async threads.
pub fn derive(password: &SecretString, salt: &[u8], params: &KdfParams) -> Result<Key> {
    params.check()?;
    let argon_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|err| CoreError::Vault(format!("key derivation settings: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.expose().as_bytes(), salt, &mut *out)
        .map_err(|err| CoreError::Vault(format!("key derivation failed: {err}")))?;
    Ok(Key(out))
}

/// Encrypts `plaintext` under `key` with a fresh random nonce. `aad` is authenticated, not stored:
/// decrypting needs the same one.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    random(&mut nonce)?;
    let ciphertext = key
        .cipher()?
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::Vault("encryption failed".into()))?;
    Ok((nonce, ciphertext))
}

/// Decrypts and authenticates. `None`: wrong key, wrong `aad`, or the data was changed.
pub fn open(key: &Key, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CoreError::Vault("a stored nonce has the wrong length".into()))?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    match key.cipher()?.decrypt_in_place(&Nonce::from(nonce), aad, &mut *buffer) {
        Ok(()) => Ok(Some(buffer)),
        Err(_) => Ok(None),
    }
}

/// The data key wrapped by `kek`: nonce followed by ciphertext and tag.
pub fn wrap(kek: &Key, key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = seal(kek, key.as_bytes(), aad)?;
    Ok([&nonce[..], &ciphertext].concat())
}

/// `None`: `kek` is not the key it was wrapped with (a wrong password), or the blob was changed.
pub fn unwrap(kek: &Key, wrapped: &[u8], aad: &[u8]) -> Result<Option<Key>> {
    if wrapped.len() <= NONCE_LEN {
        return Err(CoreError::Vault("the stored key is too short".into()));
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
    open(kek, nonce, ciphertext, aad)?
        .map(|bytes| Key::from_bytes(&bytes))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(p: &str) -> SecretString {
        SecretString::new(p)
    }

    #[test]
    fn items_round_trip_and_bind_to_their_aad() {
        let key = Key::generate().unwrap();
        let (nonce, ciphertext) = seal(&key, b"hunter2", b"item-1").unwrap();
        assert!(!ciphertext.windows(7).any(|w| w == b"hunter2"));
        let plain = open(&key, &nonce, &ciphertext, b"item-1").unwrap().unwrap();
        assert_eq!(&plain[..], b"hunter2");

        // Moved to another row (another AAD), under another key or changed by one bit: refused.
        assert!(open(&key, &nonce, &ciphertext, b"item-2").unwrap().is_none());
        assert!(open(&Key::generate().unwrap(), &nonce, &ciphertext, b"item-1")
            .unwrap()
            .is_none());
        let mut flipped = ciphertext.clone();
        flipped[0] ^= 1;
        assert!(open(&key, &nonce, &flipped, b"item-1").unwrap().is_none());
    }

    #[test]
    fn every_seal_uses_a_new_nonce() {
        let key = Key::generate().unwrap();
        let (n1, c1) = seal(&key, b"same", b"").unwrap();
        let (n2, c2) = seal(&key, b"same", b"").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn the_right_password_unwraps_the_key_and_a_wrong_one_does_not() {
        let salt = [7u8; SALT_LEN];
        let params = KdfParams::INSECURE_FAST;
        let data_key = Key::generate().unwrap();
        let kek = derive(&password("correct horse battery"), &salt, &params).unwrap();
        let wrapped = wrap(&kek, &data_key, b"ws").unwrap();

        let again = derive(&password("correct horse battery"), &salt, &params).unwrap();
        let unwrapped = unwrap(&again, &wrapped, b"ws").unwrap().unwrap();
        assert_eq!(unwrapped.as_bytes(), data_key.as_bytes());

        let wrong = derive(&password("correct horse batterY"), &salt, &params).unwrap();
        assert!(unwrap(&wrong, &wrapped, b"ws").unwrap().is_none());
        let other_salt = derive(&password("correct horse battery"), &[8u8; SALT_LEN], &params).unwrap();
        assert!(unwrap(&other_salt, &wrapped, b"ws").unwrap().is_none());
    }

    #[test]
    fn argon2id_gives_the_pinned_answers() {
        // Pinned outputs, so a change of algorithm, version or parameter handling cannot slip in
        // unnoticed: it would lock every existing vault. (The argon2 crate checks itself against the
        // RFC 9106 test vectors.)
        let key = derive(&password("password"), b"somesaltsomesalt", &KdfParams::INSECURE_FAST).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "05b6ca8f8038b683887ad4916533858b49cb52040126c134f4c6e9d8711b8c09"
        );
        let bigger = KdfParams {
            memory_kib: 64,
            iterations: 2,
            ..KdfParams::INSECURE_FAST
        };
        let key = derive(&password("password"), b"somesaltsomesalt", &bigger).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            "1a98fba8e6394425c9bdc333a9c750aaf811df070f5fb4a5788e1cf4db5793a1"
        );
    }

    #[test]
    fn stored_parameters_out_of_bounds_are_refused() {
        for bad in [
            KdfParams {
                memory_kib: 4 * 1024 * 1024,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                iterations: 0,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                version: 0x10,
                ..KdfParams::DEFAULT
            },
        ] {
            assert!(derive(&password("correct horse battery"), &[0u8; SALT_LEN], &bad).is_err());
        }
        assert!(KdfParams::DEFAULT.check().is_ok());
    }

    #[test]
    fn keys_do_not_print() {
        let key = Key::from_bytes(&[0x41; KEY_LEN]).unwrap();
        assert_eq!(format!("{key:?}"), "Key(***)");
    }
}
