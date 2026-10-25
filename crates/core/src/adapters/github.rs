//! FD-14: the GitHub Releases API of the repository Remotely updates from.
//!
//! * The repository is public, so its releases are read **without a token**: the latest release comes
//!   from the API with no `Authorization` header, and its files from their public download links
//!   (`browser_download_url` on github.com, which redirect to GitHub's storage). GitHub allows 60 such
//!   API calls an hour from one internet address. When the limit is used up (403 or 429), no call
//!   goes to GitHub until the time GitHub names ([`rate_limited_until`]).
//! * The read-only token from the vault is optional: it has a limit of its own (5,000 calls an hour),
//!   and it reads the releases if the repository goes private again, as it did from 0.2.0 to 0.4.0.
//!   With a token every API call carries it, and release files are fetched from their API asset URLs,
//!   which redirect to the storage on another host; reqwest drops the `Authorization` header when a
//!   redirect leaves the origin, so the storage never sees the token. The token only ever goes to the
//!   API ([`GithubReleases::api`]), never to github.com.
//! * The token is never part of a URL, an error, a log line or a `Debug` print. Errors that could
//!   carry outside text go through [`scrub`] first.

use std::error::Error as _;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::locks;
use crate::vault::SecretString;

/// The GitHub API that the app talks to. Tests point [`GithubReleases`] at a local fake instead.
pub const GITHUB_API: &str = "https://api.github.com";
/// Where GitHub serves a public repository's release files (`browser_download_url`).
pub const GITHUB_WEB: &str = "https://github.com";
/// The REST API version these calls were written against.
const API_VERSION: &str = "2022-11-28";
/// GitHub refuses API calls without a User-Agent.
const USER_AGENT: &str = concat!("Remotely/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(30);
/// Sent with every answer to a call made with a token that expires, e.g. `2026-12-31 00:00:00 UTC`.
const TOKEN_EXPIRATION: &str = "github-authentication-token-expiration";
/// The longest token Remotely takes; GitHub's are well under it.
pub const MAX_TOKEN_LEN: usize = 255;
/// GitHub asks for at least a minute's wait after a rate limit that names no time.
const MIN_BACKOFF: time::Duration = time::Duration::minutes(1);
/// A reset time further out than this is not believed: checks go on a day later at the latest.
const MAX_BACKOFF: time::Duration = time::Duration::hours(24);

/// `owner/name` of a GitHub repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubRepo {
    pub owner: String,
    pub name: String,
}

impl GithubRepo {
    pub fn new(owner: &str, name: &str) -> Self {
        Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        }
    }

    /// From a release URL on github.com, such as the updater endpoint in tauri.conf.json:
    /// `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`.
    pub fn from_release_url(url: &Url) -> Result<Self> {
        let parts: Vec<&str> = url.path_segments().map(Iterator::collect).unwrap_or_default();
        match (url.host_str(), parts.as_slice()) {
            (Some("github.com"), [owner, name, "releases", ..]) if !owner.is_empty() && !name.is_empty() => {
                Ok(Self::new(owner, name))
            }
            _ => Err(CoreError::Update(format!(
                "{url} is not a GitHub release URL (https://github.com/<owner>/<repo>/releases/...)"
            ))),
        }
    }
}

impl fmt::Display for GithubRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// A published release, as `GET /repos/{owner}/{repo}/releases/latest` returns it (the fields used).
#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

impl Release {
    pub fn asset(&self, name: &str) -> Option<&ReleaseAsset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    pub id: u64,
    pub name: String,
    /// The API asset URL. With `Accept: application/octet-stream` it redirects to the file; it is
    /// what the release workflow writes into latest.json, and what a token fetches.
    pub url: Url,
    /// The public download link, `https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`:
    /// what a check without a token fetches.
    #[serde(default)]
    pub browser_download_url: Option<Url>,
    #[serde(default)]
    pub size: u64,
}

/// What the latest-release lookup found.
#[derive(Debug, Clone)]
pub struct ReleaseLookup {
    /// `None` when the repository can be read but nothing is published there yet.
    pub release: Option<Release>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` without a token, and for
    /// a token with no expiry.
    pub token_expires_on: Option<String>,
}

/// Reads one repository's releases from the GitHub API, with the update token or without one.
pub struct GithubReleases {
    api: Url,
    web: Url,
    repo: GithubRepo,
    client: reqwest::Client,
    /// Until when GitHub asked for no more calls: `[0]` without a token, `[1]` with one. The two
    /// limits are GitHub's own, so one used up leaves the other free.
    backoff: Mutex<[Option<OffsetDateTime>; 2]>,
}

impl GithubReleases {
    /// `api` is [`GITHUB_API`] in the app; release files without a token come from [`GITHUB_WEB`].
    pub fn new(api: Url, repo: GithubRepo) -> Result<Self> {
        let web = Url::parse(GITHUB_WEB).map_err(|err| CoreError::Update(err.to_string()))?;
        Ok(Self {
            api,
            web,
            repo,
            client: client()?,
            backoff: Mutex::new([None, None]),
        })
    }

    /// `web` in place of `https://github.com`: tests point it at a local fake.
    pub fn with_web(mut self, web: Url) -> Self {
        self.web = web;
        self
    }

    pub fn repo(&self) -> &GithubRepo {
        &self.repo
    }

    pub fn api(&self) -> &Url {
        &self.api
    }

    /// The latest published release (GitHub leaves out drafts and pre-releases). `token` is the
    /// update token, or `None` to ask without one.
    pub async fn latest_release(&self, token: Option<&SecretString>) -> Result<ReleaseLookup> {
        self.check_backoff(token.is_some())?;
        let response = self.get(&["releases", "latest"], token).await?;
        let token_expires_on = expires_on(response.headers());
        match response.status() {
            status if status.is_success() => {
                let release = self.json::<Release>(response, token).await?;
                Ok(ReleaseLookup {
                    release: Some(release),
                    token_expires_on,
                })
            }
            // 404 means no published release, or a repository that can't be read (GitHub hides a
            // private repository, or its contents, behind 404). The release list needs the same
            // access, so it tells the two apart.
            StatusCode::NOT_FOUND => {
                let list = self.get_query(&["releases"], "per_page=1", token).await?;
                match list.status() {
                    status if status.is_success() => Ok(ReleaseLookup {
                        release: None,
                        token_expires_on: expires_on(list.headers()).or(token_expires_on),
                    }),
                    StatusCode::NOT_FOUND => Err(self.hidden(token)),
                    _ => Err(self.failure(list, token).await),
                }
            }
            _ => Err(self.failure(response, token).await),
        }
    }

    /// Headers for fetching a release file: `Accept: application/octet-stream`, so the API sends the
    /// file rather than its description, and with a token, the token for the API. The token's value
    /// is marked sensitive, so it never shows in a `Debug` print.
    pub fn download_headers(&self, token: Option<&SecretString>) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/octet-stream"));
        if let Some(token) = token {
            headers.insert(AUTHORIZATION, bearer(token)?);
            headers.insert(
                HeaderName::from_static("x-github-api-version"),
                HeaderValue::from_static(API_VERSION),
            );
        }
        Ok(headers)
    }

    /// The URL to fetch the release file `url` names: its API asset URL with a token
    /// ([`Self::asset_url`]), its public download link without one ([`Self::public_url`]).
    pub fn file_url(&self, release: &Release, url: &Url, token: Option<&SecretString>) -> Result<Url> {
        match token {
            Some(_) => self.asset_url(release, url),
            None => self.public_url(release, url),
        }
    }

    /// The URL to fetch a release file from, with the token: `url` when it is the API URL of one of
    /// this release's assets, else the API URL of the asset with the same file name (a download link,
    /// which a private repository does not serve to tokens). Anything else is refused, so the token
    /// never goes to another host.
    pub fn asset_url(&self, release: &Release, url: &Url) -> Result<Url> {
        if let Some(asset) = release
            .assets
            .iter()
            .find(|a| &a.url == url && self.is_api_asset(&a.url))
        {
            return Ok(asset.url.clone());
        }
        match release.asset(&file_name(url)) {
            Some(asset) if self.is_api_asset(&asset.url) => Ok(asset.url.clone()),
            _ => Err(not_in_release(release, url)),
        }
    }

    /// The URL to fetch a release file from without a token: the public download link of the asset
    /// `url` names, by its API asset URL, its download link or its file name. Only a link to this
    /// repository's release files on github.com is taken, so a file comes from this release or not at all.
    pub fn public_url(&self, release: &Release, url: &Url) -> Result<Url> {
        let asset = release
            .assets
            .iter()
            .find(|a| &a.url == url || a.browser_download_url.as_ref() == Some(url))
            .or_else(|| release.asset(&file_name(url)));
        match asset.and_then(|a| a.browser_download_url.as_ref()) {
            Some(link) if self.is_download_link(link) => Ok(link.clone()),
            _ => Err(not_in_release(release, url)),
        }
    }

    /// `{api}/repos/{owner}/{repo}/releases/assets/{id}`.
    fn is_api_asset(&self, url: &Url) -> bool {
        let prefix = self.endpoint(&["releases", "assets"]);
        url.origin() == self.api.origin()
            && url
                .path()
                .strip_prefix(prefix.path())
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
    }

    /// `{web}/{owner}/{repo}/releases/download/{tag}/{name}`.
    fn is_download_link(&self, url: &Url) -> bool {
        let mut prefix = self.web.clone();
        if let Ok(mut segments) = prefix.path_segments_mut() {
            segments.pop_if_empty().extend([
                self.repo.owner.as_str(),
                self.repo.name.as_str(),
                "releases",
                "download",
                "",
            ]);
        }
        let parts: Option<Vec<&str>> = url
            .path()
            .strip_prefix(prefix.path())
            .map(|rest| rest.split('/').collect());
        url.origin() == self.web.origin()
            && url.query().is_none()
            && matches!(parts.as_deref(), Some([tag, name]) if !tag.is_empty() && !name.is_empty())
    }

    /// `{api}/repos/{owner}/{repo}/<path...>`.
    fn endpoint(&self, path: &[&str]) -> Url {
        let mut url = self.api.clone();
        if let Ok(mut segments) = url.path_segments_mut() {
            segments
                .pop_if_empty()
                .extend(["repos", self.repo.owner.as_str(), self.repo.name.as_str()])
                .extend(path);
        }
        url
    }

    async fn get(&self, path: &[&str], token: Option<&SecretString>) -> Result<Response> {
        self.get_query(path, "", token).await
    }

    async fn get_query(&self, path: &[&str], query: &str, token: Option<&SecretString>) -> Result<Response> {
        let mut url = self.endpoint(path);
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert(AUTHORIZATION, bearer(token)?);
        }
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        headers.insert(
            HeaderName::from_static("x-github-api-version"),
            HeaderValue::from_static(API_VERSION),
        );
        self.client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|err| CoreError::Update(scrub_any(&format!("could not reach GitHub: {}", chain(&err)), token)))
    }

    async fn json<T: for<'de> Deserialize<'de>>(&self, response: Response, token: Option<&SecretString>) -> Result<T> {
        let bytes = response.bytes().await.map_err(|err| {
            CoreError::Update(scrub_any(&format!("GitHub's answer broke off: {}", chain(&err)), token))
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|err| CoreError::Update(format!("GitHub's answer was not what Remotely expected: {err}")))
    }

    /// GitHub answered 404 for the repository's releases: the token can't read them, or without a
    /// token the repository is private (again).
    fn hidden(&self, token: Option<&SecretString>) -> CoreError {
        let repo = self.repo.to_string();
        match token {
            Some(_) => CoreError::UpdateTokenNoAccess { repo },
            None => CoreError::UpdateTokenNeeded { repo },
        }
    }

    /// No call while GitHub's limit for this kind of call is used up.
    fn check_backoff(&self, with_token: bool) -> Result<()> {
        let until = locks::lock(&self.backoff)[usize::from(with_token)];
        match until {
            Some(until) if OffsetDateTime::now_utc() < until => Err(rate_limit_error(until, with_token)),
            _ => Ok(()),
        }
    }

    /// What a refused or failed call means for the user.
    async fn failure(&self, response: Response, token: Option<&SecretString>) -> CoreError {
        let status = response.status();
        let headers = response.headers().clone();
        let message = github_message(&response.bytes().await.unwrap_or_default(), token);
        let with_token = token.is_some();
        if let Some(until) = rate_limited_until(status, &headers, with_token, OffsetDateTime::now_utc()) {
            locks::lock(&self.backoff)[usize::from(with_token)] = Some(until);
            let anonymous = !with_token;
            tracing::warn!(%status, anonymous, %until, "GitHub's API limit is used up; update checks wait");
            return rate_limit_error(until, with_token);
        }
        match status {
            StatusCode::UNAUTHORIZED if with_token => CoreError::UpdateTokenRefused { expired_on: None },
            // A token that can see the repository but lacks Contents: Read-only.
            StatusCode::FORBIDDEN if with_token => self.hidden(token),
            status if status.is_server_error() => CoreError::Update(format!(
                "GitHub is not answering properly ({status}). Updates are checked again later"
            )),
            status => CoreError::Update(match message {
                Some(message) => format!("GitHub answered {status}: {message}"),
                None => format!("GitHub answered {status}"),
            }),
        }
    }
}

/// When GitHub's answer says its API limit is used up, until when to make no more calls of that kind.
/// 429 always says so. 403 says so with `retry-after` (the secondary limit) or `x-ratelimit-remaining: 0`
/// (the primary one), and, for a call without a token, always: only a token can lack permissions.
/// The wait is `retry-after` seconds, else until `x-ratelimit-reset` (Unix seconds), else a minute,
/// as GitHub's documentation asks; at least a minute, and at most a day.
pub fn rate_limited_until(
    status: StatusCode,
    headers: &HeaderMap,
    with_token: bool,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let number = |name: &str| headers.get(name)?.to_str().ok()?.trim().parse::<i64>().ok();
    let retry_after = number("retry-after");
    let used_up = number("x-ratelimit-remaining") == Some(0);
    let limited = status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN && (!with_token || retry_after.is_some() || used_up));
    if !limited {
        return None;
    }
    let latest = now + MAX_BACKOFF;
    let until = match (retry_after, used_up.then(|| number("x-ratelimit-reset")).flatten()) {
        (Some(secs), _) => now.checked_add(time::Duration::seconds(secs)).unwrap_or(latest),
        (None, Some(reset)) => OffsetDateTime::from_unix_timestamp(reset).unwrap_or(latest),
        (None, None) => now,
    };
    Some(until.clamp(now + MIN_BACKOFF, latest))
}

fn rate_limit_error(until: OffsetDateTime, with_token: bool) -> CoreError {
    let until = until
        .replace_nanosecond(0)
        .unwrap_or(until)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    CoreError::UpdateRateLimited { until, with_token }
}

/// Trims and checks a token before it goes into the vault. Messages never quote it.
pub fn clean_token(token: &SecretString) -> Result<SecretString> {
    let value = token.expose().trim();
    if value.is_empty() {
        return Err(CoreError::InvalidInput("Paste the token.".into()));
    }
    if value.len() > MAX_TOKEN_LEN {
        return Err(CoreError::InvalidInput(
            "That is longer than a GitHub token. Paste only the token.".into(),
        ));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CoreError::InvalidInput(
            "A GitHub token is a single word of letters, digits and underscores. Check for spaces or line breaks."
                .into(),
        ));
    }
    Ok(SecretString::new(value))
}

/// `Authorization: Bearer <token>`, marked sensitive.
fn bearer(token: &SecretString) -> Result<HeaderValue> {
    let text = Zeroizing::new(format!("Bearer {}", token.expose()));
    let mut value = HeaderValue::from_str(&text)
        .map_err(|_| CoreError::InvalidInput("The GitHub update token has characters a token can't have.".into()))?;
    value.set_sensitive(true);
    Ok(value)
}

fn client() -> Result<reqwest::Client> {
    // The provider tauri-plugin-updater installs as well; ring needs no CMake or NASM on Windows.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Fails only when another thread installed one first, which is just as good.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(TIMEOUT)
        .build()
        .map_err(|err| CoreError::Update(format!("could not set up HTTPS: {}", chain(&err))))
}

/// The date part of [`TOKEN_EXPIRATION`], when it is one.
fn expires_on(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(TOKEN_EXPIRATION)?.to_str().ok()?;
    let date = value.get(..10)?;
    let format = time::macros::format_description!("[year]-[month]-[day]");
    time::Date::parse(date, &format).ok().map(|_| date.to_owned())
}

/// GitHub's `{"message": "..."}`, scrubbed and cut short.
fn github_message(body: &[u8], token: Option<&SecretString>) -> Option<String> {
    #[derive(Deserialize)]
    struct Message {
        message: String,
    }
    let message = serde_json::from_slice::<Message>(body).ok()?.message;
    let message: String = scrub_any(&message, token).chars().take(200).collect();
    (!message.trim().is_empty()).then_some(message)
}

/// Replaces the token wherever it appears in `text`, in case an outside message ever echoes it.
pub fn scrub(text: &str, token: &SecretString) -> String {
    let token = token.expose();
    if token.is_empty() {
        text.to_owned()
    } else {
        text.replace(token, "[token]")
    }
}

/// [`scrub`] when there is a token.
pub fn scrub_any(text: &str, token: Option<&SecretString>) -> String {
    match token {
        Some(token) => scrub(text, token),
        None => text.to_owned(),
    }
}

fn not_in_release(release: &Release, url: &Url) -> CoreError {
    CoreError::Update(format!(
        "latest.json in {} points to {}, which is not a file of that release",
        release.tag_name,
        without_query(url)
    ))
}

/// The last path segment of `url`, decoded: a release file's name.
fn file_name(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next_back())
        .map(percent_decode)
        .unwrap_or_default()
}

/// An error and its causes, as one line.
fn chain(err: &reqwest::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// `url` without its query, which for GitHub's storage holds a signed access key.
fn without_query(url: &Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(byte) = bytes
                .get(i + 1..i + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn releases() -> GithubReleases {
        GithubReleases::new(Url::parse(GITHUB_API).unwrap(), GithubRepo::new("alice", "remotely")).unwrap()
    }

    fn release() -> Release {
        serde_json::from_value(serde_json::json!({
            "tag_name": "v0.9.0",
            "assets": [
                {"id": 11, "name": "latest.json", "url": "https://api.github.com/repos/alice/remotely/releases/assets/11",
                 "browser_download_url": "https://github.com/alice/remotely/releases/download/v0.9.0/latest.json"},
                {"id": 12, "name": "Remotely_0.9.0_x64-setup.exe", "url": "https://api.github.com/repos/alice/remotely/releases/assets/12",
                 "browser_download_url": "https://github.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe"},
            ],
        }))
        .unwrap()
    }

    #[test]
    fn the_repository_comes_from_the_updater_endpoint() {
        let url = Url::parse("https://github.com/alice/remotely/releases/latest/download/latest.json").unwrap();
        assert_eq!(
            GithubRepo::from_release_url(&url).unwrap(),
            GithubRepo::new("alice", "remotely")
        );
        for bad in [
            "https://example.com/alice/remotely/releases/latest/download/latest.json",
            "https://github.com/alice",
            "https://github.com/alice/remotely/archive/main.zip",
        ] {
            assert!(
                GithubRepo::from_release_url(&Url::parse(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_app_updates_from_the_repository_in_tauri_conf() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../../../src-tauri/tauri.conf.json")).unwrap();
        let endpoint = conf["plugins"]["updater"]["endpoints"][0].as_str().unwrap();
        let repo = GithubRepo::from_release_url(&Url::parse(endpoint).unwrap()).unwrap();
        assert_eq!(repo.to_string(), "khilfi/remotely");
    }

    #[test]
    fn endpoints_are_under_the_repository() {
        let r = releases();
        assert_eq!(
            r.endpoint(&["releases", "latest"]).as_str(),
            "https://api.github.com/repos/alice/remotely/releases/latest"
        );
        assert_eq!(r.endpoint(&[]).as_str(), "https://api.github.com/repos/alice/remotely");
        let local = GithubReleases::new(
            Url::parse("http://127.0.0.1:4000/").unwrap(),
            GithubRepo::new("alice", "remotely"),
        )
        .unwrap();
        assert_eq!(
            local.endpoint(&["releases", "latest"]).as_str(),
            "http://127.0.0.1:4000/repos/alice/remotely/releases/latest"
        );
    }

    #[test]
    fn api_asset_urls_are_kept_and_download_links_are_mapped_to_them() {
        let r = releases();
        let rel = release();
        let api = Url::parse("https://api.github.com/repos/alice/remotely/releases/assets/12").unwrap();
        assert_eq!(r.asset_url(&rel, &api).unwrap(), api);

        let link =
            Url::parse("https://github.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe")
                .unwrap();
        assert_eq!(r.asset_url(&rel, &link).unwrap(), api);
        let encoded =
            Url::parse("https://github.com/alice/remotely/releases/download/v0.9.0/Remotely%5F0.9.0_x64-setup.exe")
                .unwrap();
        assert_eq!(r.asset_url(&rel, &encoded).unwrap(), api);
        assert_eq!(r.file_url(&rel, &link, Some(&SecretString::new("t"))).unwrap(), api);
    }

    #[test]
    fn without_a_token_files_come_from_their_public_download_links() {
        let r = releases();
        let rel = release();
        let link =
            Url::parse("https://github.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe")
                .unwrap();
        // latest.json names the API asset URL: the same file's public link is fetched instead.
        let api = Url::parse("https://api.github.com/repos/alice/remotely/releases/assets/12").unwrap();
        assert_eq!(r.public_url(&rel, &api).unwrap(), link);
        assert_eq!(r.public_url(&rel, &link).unwrap(), link);
        assert_eq!(r.file_url(&rel, &api, None).unwrap(), link);
        // A foreign URL with a file name from the release is fetched from the release instead.
        let foreign = Url::parse("https://downloads.example.com/Remotely_0.9.0_x64-setup.exe").unwrap();
        assert_eq!(r.public_url(&rel, &foreign).unwrap(), link);
    }

    #[test]
    fn a_public_link_must_be_this_repositorys_release_file_on_github() {
        let r = releases();
        let unknown = Url::parse("https://downloads.example.com/other-setup.exe").unwrap();
        assert!(r.public_url(&release(), &unknown).is_err());
        for bad in [
            "https://downloads.example.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe",
            "https://github.com/mallory/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe",
            "https://github.com/alice/remotely/releases/download/Remotely_0.9.0_x64-setup.exe",
            "https://github.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe?x=1",
            "http://github.com/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe",
        ] {
            // The release lists the odd link for its installer.
            let mut odd = release();
            odd.assets[1].browser_download_url = Some(Url::parse(bad).unwrap());
            let api = odd.assets[1].url.clone();
            assert!(r.public_url(&odd, &api).is_err(), "{bad}");
        }
        // No public link at all.
        let mut none = release();
        none.assets[1].browser_download_url = None;
        let api = none.assets[1].url.clone();
        assert!(r.public_url(&none, &api).is_err());
    }

    #[test]
    fn the_token_never_goes_to_another_host_or_repository() {
        let r = releases();
        let rel = release();
        for bad in [
            "https://downloads.example.com/other.exe?X-Amz-Signature=abc",
            "https://api.github.com/repos/alice/remotely/releases/assets/99",
            "https://api.github.com/repos/mallory/remotely/releases/assets/12",
        ] {
            let err = r.asset_url(&rel, &Url::parse(bad).unwrap()).unwrap_err();
            assert!(!err.to_string().contains("X-Amz-Signature"), "{err}");
        }
        // A foreign URL with a file name from the release is fetched from the release instead.
        let foreign = Url::parse("https://downloads.example.com/Remotely_0.9.0_x64-setup.exe").unwrap();
        assert_eq!(
            r.asset_url(&rel, &foreign).unwrap().as_str(),
            "https://api.github.com/repos/alice/remotely/releases/assets/12"
        );
        // Not an API asset URL of this repository, even though the release lists it.
        let mut odd = rel.clone();
        odd.assets[1].url = Url::parse("https://downloads.example.com/Remotely_0.9.0_x64-setup.exe").unwrap();
        assert!(r.asset_url(&odd, &foreign).is_err());
    }

    #[test]
    fn tokens_are_trimmed_and_checked_without_quoting_them() {
        let token = format!("github_pat_{}", "A1b2".repeat(5));
        assert_eq!(
            clean_token(&SecretString::new(format!("  {token}\n")))
                .unwrap()
                .expose(),
            token
        );
        for bad in [String::new(), "   ".into(), format!("{token} {token}"), "x".repeat(300)] {
            let err = clean_token(&SecretString::new(bad.clone())).unwrap_err();
            assert!(bad.trim().is_empty() || !err.to_string().contains(bad.trim()), "{err}");
        }
    }

    #[test]
    fn the_authorization_header_never_prints() {
        let token = SecretString::new(format!("github_pat_{}", "Zz9".repeat(6)));
        let headers = releases().download_headers(Some(&token)).unwrap();
        assert!(!format!("{headers:?}").contains(token.expose()));
        assert_eq!(headers[ACCEPT], "application/octet-stream");
        assert!(headers[AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn downloads_without_a_token_send_no_authorization() {
        let headers = releases().download_headers(None).unwrap();
        assert_eq!(headers[ACCEPT], "application/octet-stream");
        assert!(!headers.contains_key(AUTHORIZATION));
    }

    #[test]
    fn expiry_dates_come_from_githubs_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(expires_on(&headers), None);
        headers.insert(TOKEN_EXPIRATION, HeaderValue::from_static("2026-12-31 00:00:00 UTC"));
        assert_eq!(expires_on(&headers).as_deref(), Some("2026-12-31"));
        headers.insert(TOKEN_EXPIRATION, HeaderValue::from_static("soon"));
        assert_eq!(expires_on(&headers), None);
    }

    #[test]
    fn outside_messages_are_scrubbed() {
        let token = SecretString::new("ghp_secretvalue123");
        assert_eq!(
            github_message(br#"{"message":"token ghp_secretvalue123 is bad"}"#, Some(&token)).as_deref(),
            Some("token [token] is bad")
        );
        assert_eq!(github_message(b"<html>", Some(&token)), None);
        assert_eq!(
            github_message(br#"{"message":"Not Found"}"#, None).as_deref(),
            Some("Not Found")
        );
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn rate_limits_wait_as_long_as_github_says() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let forbidden = StatusCode::FORBIDDEN;
        // The primary limit: until its reset.
        let primary = headers(&[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1800001800")]);
        for with_token in [false, true] {
            assert_eq!(
                rate_limited_until(forbidden, &primary, with_token, now),
                Some(now + time::Duration::minutes(30))
            );
        }
        // The secondary limit: retry-after seconds, on 403 or 429.
        let secondary = headers(&[("retry-after", "120")]);
        for status in [forbidden, StatusCode::TOO_MANY_REQUESTS] {
            assert_eq!(
                rate_limited_until(status, &secondary, true, now),
                Some(now + time::Duration::minutes(2))
            );
        }
        // 429 or an anonymous 403 that names no time: a minute.
        assert_eq!(
            rate_limited_until(StatusCode::TOO_MANY_REQUESTS, &HeaderMap::new(), true, now),
            Some(now + MIN_BACKOFF)
        );
        assert_eq!(
            rate_limited_until(forbidden, &HeaderMap::new(), false, now),
            Some(now + MIN_BACKOFF)
        );
    }

    #[test]
    fn rate_limit_times_are_kept_between_a_minute_and_a_day() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let past = headers(&[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1700000000")]);
        assert_eq!(
            rate_limited_until(StatusCode::FORBIDDEN, &past, false, now),
            Some(now + MIN_BACKOFF)
        );
        let far = headers(&[("retry-after", "99999999")]);
        assert_eq!(
            rate_limited_until(StatusCode::TOO_MANY_REQUESTS, &far, false, now),
            Some(now + MAX_BACKOFF)
        );
    }

    #[test]
    fn other_refusals_are_not_rate_limits() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        // A token without Contents gets a plain 403: that is a permission, not a limit.
        let plenty = headers(&[("x-ratelimit-remaining", "4999")]);
        assert_eq!(rate_limited_until(StatusCode::FORBIDDEN, &plenty, true, now), None);
        for status in [StatusCode::NOT_FOUND, StatusCode::UNAUTHORIZED, StatusCode::BAD_GATEWAY] {
            assert_eq!(rate_limited_until(status, &HeaderMap::new(), false, now), None);
        }
    }

    #[test]
    fn rate_limit_messages_name_the_time_and_the_limit() {
        let until = OffsetDateTime::from_unix_timestamp(1_800_001_800).unwrap();
        let err = rate_limit_error(until, false);
        assert_eq!(err.code(), "update_rate_limited");
        let CoreError::UpdateRateLimited { until: text, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(text, "2027-01-15T08:30:00Z");
        assert!(err.to_string().contains("until 08:30 UTC"), "{err}");
        assert!(err.to_string().contains("without a token"), "{err}");
        let err = rate_limit_error(until, true);
        assert!(err.to_string().contains("for the update token"), "{err}");
    }
}
