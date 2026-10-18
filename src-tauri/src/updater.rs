//! FD-14: the real updater adapter, on `tauri-plugin-updater`. The app's repository is private while
//! it is field-tested, so every check and download carries the GitHub update token from the vault:
//!
//! 1. The latest release is found through the GitHub API ([`GithubReleases`], in the core).
//! 2. The plugin fetches that release's latest.json from its API asset URL, with the token and
//!    `Accept: application/octet-stream`. GitHub answers with a redirect to its storage, and the
//!    token is dropped on the way (reqwest removes `Authorization` when a redirect leaves the origin).
//! 3. The installer comes the same way. latest.json names it by its API asset URL (tauri-action
//!    writes those); any other URL is mapped to the release's file of the same name, or refused, so
//!    the token never goes anywhere but the API.
//! 4. The plugin verifies the download against `plugins.updater.pubkey` in tauri.conf.json, exactly
//!    as before: a tampered or unsigned package fails.
//!
//! The repository is the one `plugins.updater.endpoints` in tauri.conf.json names.
//!
//! The core calls `install` from an `AppUpdate` job, after the Medium-tier confirm and once no other
//! job is open. The download (and its signature check) happens inside the job; the installer starts
//! a moment after the job has been journaled and audited, because on Windows it exits the app.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use remotely_core::adapters::github::{scrub, GithubReleases, GithubRepo, Release, GITHUB_API};
use remotely_core::adapters::updater::{ReleaseCheck, TokenReport, UpdateInfo, UpdaterAdapter};
use remotely_core::locks;
use remotely_core::vault::SecretString;
use remotely_core::{CoreError, Result};
use tauri::{AppHandle, Runtime, Wry};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::Url;

/// How long the installer waits after the job finishes, so its result and audit entry are written.
const INSTALL_DELAY: Duration = Duration::from_secs(2);

/// The name tauri-action gives the update manifest in each release.
const MANIFEST: &str = "latest.json";

pub struct TauriUpdater<R: Runtime = Wry> {
    app: AppHandle<R>,
    github: GithubReleases,
    /// The update found by the last check, reused by `install`. Kept without its headers, so the
    /// token stays in memory no longer than a call that needs it (the vault's idle lock still counts).
    offered: Mutex<Option<Update>>,
}

impl<R: Runtime> TauriUpdater<R> {
    pub fn new(app: AppHandle<R>) -> Result<Self> {
        let api = Url::parse(GITHUB_API).map_err(|err| CoreError::Update(err.to_string()))?;
        Self::with_api(app, api)
    }

    /// `api` in place of `https://api.github.com`: tests point it at a local fake.
    pub fn with_api(app: AppHandle<R>, api: Url) -> Result<Self> {
        let repo = configured_repo(&app)?;
        Ok(Self {
            app,
            github: GithubReleases::new(api, repo)?,
            offered: Mutex::new(None),
        })
    }

    /// The latest release, and the update it offers this version, if any.
    async fn fetch(&self, token: &SecretString) -> Result<(Option<Update>, Option<String>)> {
        let lookup = self.github.latest_release(token).await?;
        let Some(release) = lookup.release else {
            *locks::lock(&self.offered) = None;
            return Ok((None, lookup.token_expires_on));
        };
        let update = self.check_release(&release, token).await?;
        *locks::lock(&self.offered) = update.clone().map(|mut u| {
            u.headers.clear();
            u
        });
        Ok((update, lookup.token_expires_on))
    }

    async fn check_release(&self, release: &Release, token: &SecretString) -> Result<Option<Update>> {
        let manifest = release.asset(MANIFEST).ok_or_else(|| {
            CoreError::Update(format!(
                "the release {} has no {MANIFEST}, so it can't be installed from the app",
                release.tag_name
            ))
        })?;
        let updater = self
            .app
            .updater_builder()
            .endpoints(vec![manifest.url.clone()])
            .map_err(|err| update_error(err, token))?
            .headers(self.github.download_headers(token)?)
            .build()
            .map_err(|err| update_error(err, token))?;
        let Some(mut update) = updater.check().await.map_err(|err| update_error(err, token))? else {
            return Ok(None);
        };
        // The token goes with the download, so only to an API asset URL of this release.
        update.download_url = self.github.asset_url(release, &update.download_url)?;
        Ok(Some(update))
    }

    /// Downloads `version` and verifies its signature. The bytes are what the installer runs.
    pub async fn download(&self, token: &SecretString, version: &str) -> Result<(Update, Vec<u8>)> {
        let cached = locks::lock(&self.offered).clone();
        let mut update = match cached {
            Some(u) if u.version == version => u,
            _ => self
                .fetch(token)
                .await?
                .0
                .filter(|u| u.version == version)
                .ok_or_else(|| CoreError::Update(format!("version {version} is no longer offered")))?,
        };
        update.headers = self.github.download_headers(token)?;
        // Downloads and verifies the signature; a tampered or unsigned package fails here.
        let bytes = update
            .download(|_, _| {}, || {})
            .await
            .map_err(|err| update_error(err, token))?;
        update.headers.clear();
        Ok((update, bytes))
    }
}

#[async_trait]
impl<R: Runtime> UpdaterAdapter for TauriUpdater<R> {
    async fn check(&self, token: &SecretString) -> Result<ReleaseCheck> {
        let (update, token_expires_on) = self.fetch(token).await?;
        Ok(ReleaseCheck {
            update: update.map(|u| UpdateInfo {
                current_version: u.current_version.clone(),
                version: u.version.clone(),
                notes: u.body.clone(),
                pub_date: u.date.map(|d| d.to_string()),
            }),
            token_expires_on,
        })
    }

    async fn install(&self, token: &SecretString, version: &str) -> Result<()> {
        let (update, bytes) = self.download(token, version).await?;
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

    async fn test_token(&self, token: &SecretString) -> Result<TokenReport> {
        let lookup = self.github.latest_release(token).await?;
        Ok(TokenReport {
            repository: self.github.repo().to_string(),
            latest_release: lookup.release.map(|r| r.tag_name),
            expires_on: lookup.token_expires_on,
        })
    }
}

/// From `plugins.updater.endpoints` in tauri.conf.json:
/// `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`.
fn configured_repo<R: Runtime>(app: &AppHandle<R>) -> Result<GithubRepo> {
    let endpoint = app
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|updater| updater.get("endpoints"))
        .and_then(|endpoints| endpoints.get(0))
        .and_then(|endpoint| endpoint.as_str())
        .ok_or_else(|| CoreError::Update("tauri.conf.json has no plugins.updater.endpoints".into()))?;
    let url = Url::parse(endpoint).map_err(|err| CoreError::Update(format!("{endpoint}: {err}")))?;
    GithubRepo::from_release_url(&url)
}

/// The plugin's errors name URLs and statuses, never headers; scrubbed all the same.
fn update_error(err: tauri_plugin_updater::Error, token: &SecretString) -> CoreError {
    CoreError::Update(scrub(&err.to_string(), token))
}
