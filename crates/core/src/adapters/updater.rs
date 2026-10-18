//! Updater adapter (FD-14): checks the GitHub Releases of the app's repository for a newer signed
//! version and installs it. The repository is private while the app is field-tested, so each call
//! gets the read-only GitHub update token from the vault ([`crate::updates`]).
//!
//! The real implementation lives in the Tauri shell: it finds the latest release through the GitHub
//! API ([`super::github`]) and has `tauri-plugin-updater` fetch latest.json and the installer from
//! their API asset URLs, verifying every update's signature. Checking is a read. Installing is a
//! state change: it is the [`Command::AppUpdate`](crate::command_bus::Command::AppUpdate) command,
//! Medium tier, and the job runner starts it only once no other job is open.

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::vault::SecretString;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub version: String,
    /// Release notes from the GitHub Release.
    pub notes: Option<String>,
    pub pub_date: Option<String>,
}

/// What one check found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReleaseCheck {
    /// `None` when this is the latest version (or nothing is published yet).
    pub update: Option<UpdateInfo>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` for a token with no expiry.
    pub token_expires_on: Option<String>,
}

/// What testing the token found. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenReport {
    /// `owner/name` of the repository whose releases the token can read.
    pub repository: String,
    /// The tag of the latest published release, if there is one.
    pub latest_release: Option<String>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` for a token with no expiry.
    pub expires_on: Option<String>,
}

#[async_trait]
pub trait UpdaterAdapter: Send + Sync {
    async fn check(&self, token: &SecretString) -> Result<ReleaseCheck>;
    /// Downloads, verifies and installs `version`. Only the job runner calls this.
    async fn install(&self, token: &SecretString, version: &str) -> Result<()>;
    /// Settings' "Test": can the token read the releases?
    async fn test_token(&self, token: &SecretString) -> Result<TokenReport>;
}

/// Used until the shell provides the real updater, and at air-gapped sites with checks turned off.
pub struct DisabledUpdater;

#[async_trait]
impl UpdaterAdapter for DisabledUpdater {
    async fn check(&self, _token: &SecretString) -> Result<ReleaseCheck> {
        Ok(ReleaseCheck::default())
    }

    async fn install(&self, _token: &SecretString, _version: &str) -> Result<()> {
        Err(CoreError::NotImplemented("FD-14 auto-update"))
    }

    async fn test_token(&self, _token: &SecretString) -> Result<TokenReport> {
        Err(CoreError::NotImplemented("FD-14 auto-update"))
    }
}
