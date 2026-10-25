//! Vault (SS-04, AP-06): passwords, private keys and passphrases, encrypted at rest.
//!
//! ```text
//!   master password ──Argon2id──► master key ──AES-256-GCM──┐
//!                                                           ├─► data key ──AES-256-GCM──► each item
//!   Windows login ─────────────────── DPAPI ────────────────┘   (random,     (own nonce; bound to
//!                                     (optional)                 in memory     its row by the AAD)
//!                                                                only while
//!                                                                unlocked)
//! ```
//!
//! * The data key is random and never stored in the clear. `vault_meta` keeps it wrapped by the
//!   master key, and, when the Windows login also unlocks the vault, wrapped by DPAPI too. New vaults
//!   leave that off unless the user turns it on: any program running as the Windows user can unwrap a
//!   DPAPI copy, from a copy of the database too, without the master password. Turning it off needs no
//!   password.
//! * Changing the master password makes a new data key and seals every item with it again, in one
//!   transaction, so an old copy of the wrapped key opens nothing written since.
//! * The master password is what Critical actions ask for again (AP-06), whichever way the vault is
//!   unlocked. It is checked by unwrapping the data key with it, so nothing that could be compared
//!   against is stored besides the wrapped key itself.
//! * The vault locks after 15 minutes without the user doing anything ([`IDLE_TIMEOUT`]) and on
//!   demand. Only the user's own input and the actions they start count ([`Vault::note_activity`]):
//!   background reads (the dashboard's logins, the Containers page's sudo) don't keep it open. Locking
//!   drops the data key, which zeroizes it, and the core closes what holds decrypted secrets.
//! * [`bindings`]: a vault password goes, without the master password being asked again, only where
//!   it already goes.
//! * Secrets never reach logs, the audit log, job output, error messages, exports or the UI. The UI
//!   holds secret IDs and labels only; values go one way, into the vault, and only adapters read them
//!   back ([`Vault::get`]).

pub mod bindings;
/// Also seals FD-07 export files (`crate::transfer`), with a key from the user's passphrase.
pub(crate) mod crypto;
mod local;
mod protector;
mod service;

use std::fmt;
use std::mem;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::domain::Context;
use crate::error::{CoreError, Result};

pub use bindings::{Destination, SecretBindings, REAUTH_GRACE};
pub use crypto::KdfParams;
pub use local::{LocalVault, VaultOptions, IDLE_TIMEOUT};
pub use protector::{Dpapi, KeyProtector};
pub use service::VaultService;

#[cfg(any(test, feature = "fakes"))]
pub(crate) use crypto::{open as decrypt, seal as encrypt, Key};

/// A secret that never prints and is zeroized when dropped.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Takes decrypted bytes; they are zeroized if they are not UTF-8.
    fn from_utf8(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        match String::from_utf8(mem::take(&mut *bytes)) {
            Ok(text) => Ok(Self(text)),
            Err(err) => {
                err.into_bytes().zeroize();
                Err(CoreError::Vault("a secret is not valid text".into()))
            }
        }
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(pub Uuid);

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultStatus {
    NotSetUp,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretKind {
    Password,
    PrivateKey,
    Passphrase,
}

impl SecretKind {
    /// The `vault_items.kind` value.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::PrivateKey => "private_key",
            SecretKind::Passphrase => "passphrase",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "password" => Some(SecretKind::Password),
            "private_key" => Some(SecretKind::PrivateKey),
            "passphrase" => Some(SecretKind::Passphrase),
            _ => None,
        }
    }

    /// For messages and the audit log.
    pub fn label(self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::PrivateKey => "private key",
            SecretKind::Passphrase => "passphrase",
        }
    }
}

#[derive(Debug)]
pub enum UnlockMethod {
    /// DPAPI, tied to the current Windows login.
    WindowsLogin,
    /// Argon2id-derived key; also what portable mode (FD-11) uses.
    MasterPassword(SecretString),
}

/// What the UI shows about the vault. Holds no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub status: VaultStatus,
    /// The Windows login unlocks the vault. The master password always does.
    pub windows_login: bool,
    /// This machine can wrap the key with DPAPI (Windows only).
    pub windows_login_available: bool,
    /// Minutes without use before the vault locks itself.
    pub idle_lock_minutes: u64,
}

/// A secret as the UI sees it: never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub id: SecretId,
    pub kind: SecretKind,
    pub label: String,
    /// Sessions that use it (SS-01). Deleting it leaves them without it.
    pub used_by: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Shortest master password the vault takes.
pub const MIN_PASSWORD_LEN: usize = 10;
/// Longest label, master password and secret the vault takes.
pub const MAX_LABEL_LEN: usize = 80;
pub const MAX_PASSWORD_LEN: usize = 1024;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

#[async_trait]
pub trait Vault: Send + Sync {
    fn info(&self) -> VaultInfo;

    fn status(&self) -> VaultStatus {
        self.info().status
    }

    /// Status changes, including the lock after 15 minutes idle, so the UI can follow them.
    fn watch(&self) -> watch::Receiver<VaultStatus>;

    /// SS-04: creates the vault, unlocked. The master password is always set; `windows_login` also
    /// lets the Windows login unlock it.
    async fn setup(&self, ctx: &Context, password: SecretString, windows_login: bool) -> Result<()>;

    async fn unlock(&self, method: UnlockMethod) -> Result<()>;

    fn lock(&self);

    /// AP-06: checks the master password before a Critical action. Works locked or unlocked and
    /// changes neither.
    async fn verify_password(&self, password: &SecretString) -> Result<bool>;

    /// Needs the current master password, whichever way the vault is unlocked: otherwise anyone at an
    /// unlocked Windows session could replace the password Critical actions ask for.
    async fn change_password(&self, current: &SecretString, new: SecretString) -> Result<()>;

    /// Lets the Windows login unlock the vault, or stops it. Needs the master password.
    async fn set_windows_login(&self, password: &SecretString, enabled: bool) -> Result<()>;

    /// SS-04: stops the Windows login from unlocking the vault: the DPAPI copy of the key is deleted
    /// (overwritten on disk). Needs no password, since it only removes a way in. True when there was one.
    async fn turn_off_windows_login(&self) -> Result<bool>;

    /// SS-04: the user did something (typed, clicked, started an action), so the idle lock starts again.
    /// Reading a secret ([`Vault::get`]) doesn't count: background reads must not keep the vault open.
    fn note_activity(&self) {}

    /// Labels and kinds only. Works while locked, so sessions can name their credentials.
    async fn list(&self, ctx: &Context) -> Result<Vec<SecretMeta>>;

    async fn put(&self, ctx: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretId>;

    /// A new value for an existing secret; its kind, label and the sessions using it stay.
    async fn replace(&self, ctx: &Context, id: SecretId, secret: SecretString) -> Result<()>;

    async fn rename(&self, ctx: &Context, id: SecretId, label: &str) -> Result<()>;

    async fn delete(&self, ctx: &Context, id: SecretId) -> Result<()>;

    /// For adapters only (SS-03, BX-07). Never reaches the UI.
    async fn get(&self, ctx: &Context, id: SecretId) -> Result<SecretString>;
}

/// Trims a label and checks it is 1 to [`MAX_LABEL_LEN`] characters with no control characters.
pub(crate) fn clean_label(label: &str) -> Result<String> {
    let label = label.trim();
    if label.is_empty() {
        return Err(CoreError::InvalidInput("Give the secret a label.".into()));
    }
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(CoreError::InvalidInput(format!(
            "A label can be at most {MAX_LABEL_LEN} characters."
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "A label can't hold line breaks or tabs.".into(),
        ));
    }
    Ok(label.to_owned())
}

/// SS-04: a master password long enough to resist guessing, since the wrapped key can be attacked
/// offline by anyone who copies the database.
pub(crate) fn check_master_password(password: &SecretString) -> Result<()> {
    let length = password.expose().chars().count();
    if password.expose().trim().is_empty() || length < MIN_PASSWORD_LEN {
        return Err(CoreError::InvalidInput(format!(
            "The vault password needs at least {MIN_PASSWORD_LEN} characters. A few unrelated words make a good one."
        )));
    }
    if length > MAX_PASSWORD_LEN {
        return Err(CoreError::InvalidInput(format!(
            "The vault password can be at most {MAX_PASSWORD_LEN} characters."
        )));
    }
    Ok(())
}

/// Checks a value before it is stored. Messages never quote the value.
pub(crate) fn check_secret(kind: SecretKind, secret: &SecretString) -> Result<()> {
    let value = secret.expose();
    if value.is_empty() {
        return Err(CoreError::InvalidInput(format!("The {} is empty.", kind.label())));
    }
    if value.len() > MAX_SECRET_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "The {} is larger than {} KB.",
            kind.label(),
            MAX_SECRET_BYTES / 1024
        )));
    }
    if kind == SecretKind::PrivateKey {
        let text = value.trim_start();
        if text.contains("PUBLIC KEY") || text.starts_with("ssh-") || text.starts_with("ecdsa-") {
            return Err(CoreError::InvalidInput(
                "That is a public key. Paste the private key (the file without .pub).".into(),
            ));
        }
        let private = (text.starts_with("-----BEGIN ") && text.contains("PRIVATE KEY-----"))
            || text.starts_with("PuTTY-User-Key-File-");
        if !private {
            return Err(CoreError::InvalidInput(
                "That doesn't look like a private key: expected an OpenSSH or PEM key (-----BEGIN ... PRIVATE KEY-----) or a PuTTY .ppk file.".into(),
            ));
        }
    } else if value.contains(['\n', '\r']) {
        return Err(CoreError::InvalidInput(format!(
            "A {} can't hold line breaks.",
            kind.label()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_do_not_print() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s:?}"), "SecretString(***)");
        assert_eq!(s.expose(), "hunter2");
        let unlock = UnlockMethod::MasterPassword(SecretString::new("hunter2"));
        assert!(!format!("{unlock:?}").contains("hunter2"));
    }

    #[test]
    fn secrets_deserialize_from_a_plain_string() {
        let s: SecretString = serde_json::from_str(r#""s3cret value""#).unwrap();
        assert_eq!(s.expose(), "s3cret value");
    }

    #[test]
    fn invalid_utf8_is_refused_without_quoting_it() {
        let err = SecretString::from_utf8(Zeroizing::new(vec![0xff, 0xfe, b'x'])).unwrap_err();
        assert_eq!(err.code(), "vault");
    }

    #[test]
    fn kinds_round_trip_through_their_column_value() {
        for kind in [SecretKind::Password, SecretKind::PrivateKey, SecretKind::Passphrase] {
            assert_eq!(SecretKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(SecretKind::parse("token"), None);
    }

    #[test]
    fn labels_are_trimmed_and_checked() {
        assert_eq!(clean_label("  web root  ").unwrap(), "web root");
        assert!(clean_label("   ").is_err());
        assert!(clean_label("a\tb").is_err());
        assert!(clean_label(&"x".repeat(MAX_LABEL_LEN + 1)).is_err());
        assert!(clean_label(&"x".repeat(MAX_LABEL_LEN)).is_ok());
    }

    #[test]
    fn master_passwords_must_be_long_enough() {
        assert!(check_master_password(&SecretString::new("short")).is_err());
        assert!(check_master_password(&SecretString::new("          ")).is_err());
        assert!(check_master_password(&SecretString::new("correct horse battery")).is_ok());
        let err = check_master_password(&SecretString::new("hunter2")).unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn private_keys_must_look_like_private_keys() {
        // Built at run time, so no key-shaped text is committed (gitleaks).
        let kind = "OPENSSH PRIVATE KEY";
        let openssh = format!("-----BEGIN {kind}-----\nAAAA\n-----END {kind}-----\n");
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
        for ok in [openssh.as_str(), ppk] {
            assert!(
                check_secret(SecretKind::PrivateKey, &SecretString::new(ok)).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "ssh-ed25519 AAAAC3Nza alice@example.com",
            "-----BEGIN PUBLIC KEY-----",
            "hunter2",
        ] {
            let err = check_secret(SecretKind::PrivateKey, &SecretString::new(bad)).unwrap_err();
            assert!(!err.to_string().contains(bad), "{err}");
        }
    }

    #[test]
    fn passwords_are_one_line_and_not_empty() {
        assert!(check_secret(SecretKind::Password, &SecretString::new("")).is_err());
        assert!(check_secret(SecretKind::Password, &SecretString::new("a\nb")).is_err());
        assert!(check_secret(SecretKind::Passphrase, &SecretString::new("pass phrase")).is_ok());
        let huge = SecretString::new("x".repeat(MAX_SECRET_BYTES + 1));
        assert!(check_secret(SecretKind::Password, &huge).is_err());
    }
}
