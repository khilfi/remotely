//! FD-14: the real updater adapter, on `tauri-plugin-updater`. It checks the public GitHub repo's
//! latest release (`plugins.updater.endpoints` in tauri.conf.json) and verifies every download
//! against the public key in the same file.
//!
//! The core calls `install` from an `AppUpdate` job, after the Medium-tier confirm and once no other
//! job is open. The download (and its signature check) happens inside the job; the installer starts
//! a moment after the job has been journaled and audited, because on Windows it exits the app.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use remotely_core::adapters::updater::{UpdateInfo, UpdaterAdapter};
use remotely_core::locks;
use remotely_core::{CoreError, Result};
use tauri::AppHandle;
use tauri_plugin_updater::{Update, UpdaterExt};

/// How long the installer waits after the job finishes, so its result and audit entry are written.
const INSTALL_DELAY: Duration = Duration::from_secs(2);

pub struct TauriUpdater {
    app: AppHandle,
    /// The update found by the last check, reused by `install`.
    offered: Mutex<Option<Update>>,
}

impl TauriUpdater {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            offered: Mutex::new(None),
        }
    }

    async fn fetch(&self) -> Result<Option<Update>> {
        let updater = self.app.updater().map_err(update_error)?;
        let update = updater.check().await.map_err(update_error)?;
        *locks::lock(&self.offered) = update.clone();
        Ok(update)
    }
}

#[async_trait]
impl UpdaterAdapter for TauriUpdater {
    async fn check(&self) -> Result<Option<UpdateInfo>> {
        Ok(self.fetch().await?.map(|u| UpdateInfo {
            current_version: u.current_version.clone(),
            version: u.version.clone(),
            notes: u.body.clone(),
            pub_date: u.date.map(|d| d.to_string()),
        }))
    }

    async fn install(&self, version: &str) -> Result<()> {
        let cached = locks::lock(&self.offered).clone();
        let update = match cached {
            Some(u) if u.version == version => u,
            _ => self
                .fetch()
                .await?
                .filter(|u| u.version == version)
                .ok_or_else(|| CoreError::Update(format!("version {version} is no longer offered")))?,
        };

        // Downloads and verifies the signature; a tampered or unsigned package fails here.
        let bytes = update.download(|_, _| {}, || {}).await.map_err(update_error)?;
        tracing::info!(version, "update downloaded and verified");

        let app = self.app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(INSTALL_DELAY).await;
            // On Windows this launches the installer and exits the app.
            match update.install(bytes) {
                Ok(()) => app.restart(),
                Err(err) => tracing::error!(error = %err, "update install failed"),
            }
        });
        Ok(())
    }
}

fn update_error(err: tauri_plugin_updater::Error) -> CoreError {
    CoreError::Update(err.to_string())
}
