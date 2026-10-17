//! Vault (SS-04, AP-06): passwords, private keys and passphrases, encrypted at rest.
//!
//! Plan (NFR Security): AES-256-GCM per item, keyed by Windows DPAPI (unlocks with the Windows login)
//! or an Argon2id-derived master password; auto-lock after 15 minutes idle; ciphertext lives in the
//! `vault_items` table. Secrets never reach logs, history, the audit log or exports.
//!
//! This is a stub: [`UnimplementedVault`] is always locked, so Critical actions (which need the vault
//! password again) are refused until the real vault lands. That is the safe failure.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::Context;
use crate::error::{CoreError, Result};

/// A secret that never prints. The real vault should zeroize it on drop.
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
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultStatus {
    NotSetUp,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecretKind {
    Password,
    PrivateKey,
    Passphrase,
}

pub enum UnlockMethod {
    /// DPAPI, tied to the current Windows login.
    WindowsLogin,
    /// Argon2id-derived key; also what portable mode (FD-11) uses.
    MasterPassword(SecretString),
}

#[async_trait]
pub trait Vault: Send + Sync {
    fn status(&self) -> VaultStatus;
    async fn unlock(&self, method: UnlockMethod) -> Result<()>;
    fn lock(&self);
    /// AP-06: check the vault password again before a Critical action.
    async fn verify_password(&self, password: &SecretString) -> Result<bool>;
    async fn put(&self, ctx: &Context, kind: SecretKind, label: &str, secret: SecretString) -> Result<SecretId>;
    async fn get(&self, ctx: &Context, id: SecretId) -> Result<SecretString>;
}

/// Placeholder until SS-04 is built. Always locked.
pub struct UnimplementedVault;

#[async_trait]
impl Vault for UnimplementedVault {
    fn status(&self) -> VaultStatus {
        VaultStatus::NotSetUp
    }

    async fn unlock(&self, _method: UnlockMethod) -> Result<()> {
        Err(CoreError::NotImplemented("SS-04 vault"))
    }

    fn lock(&self) {}

    async fn verify_password(&self, _password: &SecretString) -> Result<bool> {
        Err(CoreError::NotImplemented(
            "SS-04 vault, needed for Critical actions (AP-06)",
        ))
    }

    async fn put(&self, _: &Context, _: SecretKind, _: &str, _: SecretString) -> Result<SecretId> {
        Err(CoreError::VaultLocked)
    }

    async fn get(&self, _: &Context, _: SecretId) -> Result<SecretString> {
        Err(CoreError::VaultLocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_do_not_print() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s:?}"), "SecretString(***)");
        assert_eq!(s.expose(), "hunter2");
    }
}
