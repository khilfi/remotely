//! FD-14: the real updater adapter, on `tauri-plugin-updater`. The app's repository is public, so a
//! check needs no token; the GitHub update token from the vault is optional, and used when it can be read:
//!
//! 1. The latest release is found through the GitHub API ([`GithubReleases`], in the core), with the
//!    token or without one.
//! 2. Without a token, the plugin fetches that release's latest.json and then the installer from their
//!    public download links on github.com, which redirect to GitHub's storage. No `Authorization`
//!    header is sent anywhere. latest.json names the installer by its API asset URL (the release
//!    workflow writes those); it is mapped to the same file's public link, or refused.
//! 3. With a token, they come from their API asset URLs instead, with the token and
//!    `Accept: application/octet-stream`. GitHub answers with a redirect to its storage, and the token
//!    is dropped on the way (reqwest removes `Authorization` when a redirect leaves the origin). Any
//!    other URL is mapped to the release's file of the same name, or refused, so the token never goes
//!    anywhere but the API.
//! 4. The plugin verifies the download against `plugins.updater.pubkey` in tauri.conf.json, exactly
//!    as before, with or without a token: a tampered or unsigned package fails.
//!
//! Before an update is offered, its signature must name the installer for the version latest.json
//! announces (`check_signed_release`, C3), so an old signed installer can't come back as a newer
//! version. `plugins.updater.requireSignedVersion` has the plugin check the signed version again
//! when it downloads.
//!
//! The repository is the one `plugins.updater.endpoints` in tauri.conf.json names.
//!
//! The core calls `install` from an `AppUpdate` job, after the Medium-tier confirm and once no other
//! job is open. The download (and its signature check) happens inside the job; the installer starts
//! a moment after the job has been journaled and audited, because on Windows it exits the app.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use remotely_core::adapters::github::{scrub_any, GithubReleases, GithubRepo, Release, GITHUB_API, GITHUB_WEB};
use remotely_core::adapters::updater::{check_signed_release, ReleaseCheck, TokenReport, UpdateInfo, UpdaterAdapter};
use remotely_core::locks;
use remotely_core::vault::SecretString;
use remotely_core::{CoreError, Result};
use tauri::{AppHandle, Manager, Runtime, Wry};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::Url;

/// How long the installer waits after the job finishes, so its result and audit entry are written.
const INSTALL_DELAY: Duration = Duration::from_secs(2);

/// QL-15: the longest a check (latest.json) may take, from connecting to its last byte.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// QL-15: the longest the installer's download may take in all. A slow link that keeps moving gets this long;
/// one that stalls fails after [`STALL_TIMEOUT`].
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// QL-15: no byte for this long ends a check or a download.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// QL-15: reaching GitHub at all.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The name tauri-action gives the update manifest in each release.
const MANIFEST: &str = "latest.json";

/// The update the last check found, with the release it came from, so `install` can fetch its installer
/// the way the install asks (with the token or without one) whichever way the check went.
#[derive(Clone)]
struct Offer {
    /// Kept without its headers, so the token stays in memory no longer than a call that needs it (the
    /// vault's idle lock still counts).
    update: Update,
    release: Release,
}

pub struct TauriUpdater<R: Runtime = Wry> {
    app: AppHandle<R>,
    github: GithubReleases,
    offered: Mutex<Option<Offer>>,
}

impl<R: Runtime> TauriUpdater<R> {
    pub fn new(app: AppHandle<R>) -> Result<Self> {
        let parse = |url: &str| Url::parse(url).map_err(|err| CoreError::Update(err.to_string()));
        Self::with_github(app, parse(GITHUB_API)?, parse(GITHUB_WEB)?)
    }

    /// `api` and `web` in place of `https://api.github.com` and `https://github.com`: tests point them at
    /// a local fake.
    pub fn with_github(app: AppHandle<R>, api: Url, web: Url) -> Result<Self> {
        let repo = configured_repo(&app)?;
        Ok(Self {
            app,
            github: GithubReleases::new(api, repo)?.with_web(web),
            offered: Mutex::new(None),
        })
    }

    /// The latest release, and the update it offers this version, if any.
    async fn fetch(&self, token: Option<&SecretString>) -> Result<(Option<Offer>, Option<String>)> {
        let lookup = self.github.latest_release(token).await?;
        let Some(release) = lookup.release else {
            *locks::lock(&self.offered) = None;
            return Ok((None, lookup.token_expires_on));
        };
        let offer = self
            .check_release(&release, token)
            .await?
            .map(|update| Offer { update, release });
        *locks::lock(&self.offered) = offer.clone().map(|mut o| {
            o.update.headers.clear();
            o
        });
        Ok((offer, lookup.token_expires_on))
    }

    async fn check_release(&self, release: &Release, token: Option<&SecretString>) -> Result<Option<Update>> {
        let manifest = release.asset(MANIFEST).ok_or_else(|| {
            CoreError::Update(format!(
                "the release {} has no {MANIFEST}, so it can't be installed from the app",
                release.tag_name
            ))
        })?;
        // Its API asset URL with a token, its public download link without one.
        let manifest_url = self.github.file_url(release, &manifest.url, token)?;
        let app = self.app.clone();
        let updater = self
            .app
            .updater_builder()
            .endpoints(vec![manifest_url])
            .map_err(|err| update_error(err, token))?
            .headers(self.github.download_headers(token)?)
            // QL-15: neither a check nor a download can hang; the download gets its own total below.
            .timeout(CHECK_TIMEOUT)
            .configure_client(|client| client.connect_timeout(CONNECT_TIMEOUT).read_timeout(STALL_TIMEOUT))
            // QL-15: the installer ends the app with `process::exit`, which skips the normal exit, so terminals
            // close here first, each audited, and their session logs are written out.
            .on_before_exit(move || before_installer_exits(&app))
            .build()
            .map_err(|err| update_error(err, token))?;
        let Some(mut update) = updater.check().await.map_err(|err| update_error(err, token))? else {
            return Ok(None);
        };
        // C3: refused unless the signature names this version's installer.
        check_signed_release(
            &updater_setting(&self.app, "pubkey")?,
            &update.signature,
            &product_name(&self.app)?,
            &update.version,
        )?;
        // A file of this release only: with the token, at an API asset URL of it.
        update.download_url = self.github.file_url(release, &update.download_url, token)?;
        Ok(Some(update))
    }

    /// Downloads `version` and verifies its signature. The bytes are what the installer runs.
    pub async fn download(&self, token: Option<&SecretString>, version: &str) -> Result<(Update, Vec<u8>)> {
        let cached = locks::lock(&self.offered).clone();
        let Offer { mut update, release } = match cached {
            Some(offer) if offer.update.version == version => offer,
            _ => self
                .fetch(token)
                .await?
                .0
                .filter(|offer| offer.update.version == version)
                .ok_or_else(|| CoreError::Update(format!("version {version} is no longer offered")))?,
        };
        // The check may have gone the other way (the vault was locked then, or is now), so the installer's
        // URL is mapped again: the token only ever goes to an API asset URL of this release.
        update.download_url = self.github.file_url(&release, &update.download_url, token)?;
        update.headers = self.github.download_headers(token)?;
        update.timeout = Some(DOWNLOAD_TIMEOUT);
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
    async fn check(&self, token: Option<&SecretString>) -> Result<ReleaseCheck> {
        let (offer, token_expires_on) = self.fetch(token).await?;
        Ok(ReleaseCheck {
            update: offer.map(|Offer { update: u, .. }| UpdateInfo {
                current_version: u.current_version.clone(),
                version: u.version.clone(),
                notes: u.body.clone(),
                pub_date: u.date.map(|d| d.to_string()),
            }),
            token_expires_on,
        })
    }

    async fn install(&self, token: Option<&SecretString>, version: &str) -> Result<()> {
        let (update, bytes) = self.download(token, version).await?;
        tracing::info!(version, "update downloaded and verified");

        let app = self.app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(INSTALL_DELAY).await;
            // On Windows this launches the installer and exits the app (after `before_installer_exits`). On a
            // blocking thread, so that hook can wait for the core to shut down.
            let installed = tauri::async_runtime::spawn_blocking(move || update.install(bytes)).await;
            match installed {
                Ok(Ok(())) => app.restart(),
                Ok(Err(err)) => tracing::error!(error = %err, "update install failed"),
                Err(err) => tracing::error!(error = %err, "update install stopped"),
            }
        });
        Ok(())
    }

    async fn test_token(&self, token: &SecretString) -> Result<TokenReport> {
        let lookup = self.github.latest_release(Some(token)).await?;
        Ok(TokenReport {
            repository: self.github.repo().to_string(),
            latest_release: lookup.release.map(|r| r.tag_name),
            expires_on: lookup.token_expires_on,
        })
    }
}

/// FD-14, QL-15: runs on the install's blocking thread, right before the installer starts and the app exits.
fn before_installer_exits<R: Runtime>(app: &AppHandle<R>) {
    tracing::info!("closing terminals before the update's installer starts");
    if let Some(state) = app.try_state::<crate::AppState>() {
        tauri::async_runtime::block_on(state.core.shutdown());
    }
    tracing::info!("Remotely stopped for the update");
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

/// A text setting of `plugins.updater` in tauri.conf.json, such as `pubkey`.
fn updater_setting<R: Runtime>(app: &AppHandle<R>, name: &str) -> Result<String> {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|updater| updater.get(name))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| CoreError::Update(format!("tauri.conf.json has no plugins.updater.{name}")))
}

/// `productName` in tauri.conf.json, which the installer's file name starts with.
fn product_name<R: Runtime>(app: &AppHandle<R>) -> Result<String> {
    app.config()
        .product_name
        .clone()
        .ok_or_else(|| CoreError::Update("tauri.conf.json has no productName".into()))
}

/// The plugin's errors name URLs and statuses, never headers; scrubbed all the same.
fn update_error(err: tauri_plugin_updater::Error, token: Option<&SecretString>) -> CoreError {
    CoreError::Update(scrub_any(&err.to_string(), token))
}
