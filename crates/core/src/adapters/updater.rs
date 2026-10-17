//! Updater adapter (FD-14): checks the public GitHub repo's Releases for a newer signed version and
//! installs it.
//!
//! The real implementation lives in the Tauri shell (it needs `tauri-plugin-updater`, which verifies
//! every update's signature). Checking is a read. Installing is a state change: it is the
//! [`Command::AppUpdate`](crate::command_bus::Command::AppUpdate) command, Medium tier, and the job
//! runner starts it only once no other job is open.

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub version: String,
    /// Release notes from the GitHub Release.
    pub notes: Option<String>,
    pub pub_date: Option<String>,
}

#[async_trait]
pub trait UpdaterAdapter: Send + Sync {
    /// `None` when this is the latest version.
    async fn check(&self) -> Result<Option<UpdateInfo>>;
    /// Downloads, verifies and installs `version`. Only the job runner calls this.
    async fn install(&self, version: &str) -> Result<()>;
}

/// Used until the shell provides the real updater, and at air-gapped sites with checks turned off.
pub struct DisabledUpdater;

#[async_trait]
impl UpdaterAdapter for DisabledUpdater {
    async fn check(&self) -> Result<Option<UpdateInfo>> {
        Ok(None)
    }

    async fn install(&self, _version: &str) -> Result<()> {
        Err(CoreError::NotImplemented("FD-14 auto-update"))
    }
}
