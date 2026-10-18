//! FD-14: the GitHub Releases API of the repository Remotely updates from. The repository is private
//! while the app is field-tested, so every call carries the read-only token from the vault.
//!
//! * The token only ever goes to the API ([`GithubReleases::api`]). Release files are fetched from
//!   their API asset URLs, which redirect to GitHub's storage on another host; reqwest drops the
//!   `Authorization` header when a redirect leaves the origin, so the storage never sees the token.
//! * The token is never part of a URL, an error, a log line or a `Debug` print. Errors that could
//!   carry outside text go through [`scrub`] first.

use std::error::Error as _;
use std::fmt;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::vault::SecretString;

/// The GitHub API that the app talks to. Tests point [`GithubReleases`] at a local fake instead.
pub const GITHUB_API: &str = "https://api.github.com";
/// The REST API version these calls were written against.
const API_VERSION: &str = "2022-11-28";
/// GitHub refuses API calls without a User-Agent.
const USER_AGENT: &str = concat!("Remotely/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(30);
/// Sent with every answer to a call made with a token that expires, e.g. `2026-12-31 00:00:00 UTC`.
const TOKEN_EXPIRATION: &str = "github-authentication-token-expiration";
/// The longest token Remotely takes; GitHub's are well under it.
pub const MAX_TOKEN_LEN: usize = 255;

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
    /// The API asset URL. With the token and `Accept: application/octet-stream` it redirects to the
    /// file; it is what tauri-action writes into latest.json.
    pub url: Url,
    #[serde(default)]
    pub size: u64,
}

/// What the latest-release lookup found.
#[derive(Debug, Clone)]
pub struct ReleaseLookup {
    /// `None` when the token can read the repository but nothing is published there yet.
    pub release: Option<Release>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` for a token with no expiry.
    pub token_expires_on: Option<String>,
}

/// Reads one repository's releases from the GitHub API.
pub struct GithubReleases {
    api: Url,
    repo: GithubRepo,
    client: reqwest::Client,
}

impl GithubReleases {
    /// `api` is [`GITHUB_API`] in the app.
    pub fn new(api: Url, repo: GithubRepo) -> Result<Self> {
        Ok(Self {
            api,
            repo,
            client: client()?,
        })
    }

    pub fn repo(&self) -> &GithubRepo {
        &self.repo
    }

    pub fn api(&self) -> &Url {
        &self.api
    }

    /// The latest published release (GitHub leaves out drafts and pre-releases).
    pub async fn latest_release(&self, token: &SecretString) -> Result<ReleaseLookup> {
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
            // 404 means no published release, or a repository the token can't read (GitHub hides a
            // private repository, or its contents, behind 404). The release list needs the same
            // access, so it tells the two apart.
            StatusCode::NOT_FOUND => {
                let list = self.get_query(&["releases"], "per_page=1", token).await?;
                match list.status() {
                    status if status.is_success() => Ok(ReleaseLookup {
                        release: None,
                        token_expires_on: expires_on(list.headers()).or(token_expires_on),
                    }),
                    StatusCode::NOT_FOUND => Err(self.no_access()),
                    _ => Err(self.failure(list, token).await),
                }
            }
            _ => Err(self.failure(response, token).await),
        }
    }

    /// Headers for fetching a release file from its API asset URL: the token, and
    /// `Accept: application/octet-stream` so GitHub sends the file rather than its description.
    /// The token's value is marked sensitive, so it never shows in a `Debug` print.
    pub fn download_headers(&self, token: &SecretString) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer(token)?);
        headers.insert(ACCEPT, HeaderValue::from_static("application/octet-stream"));
        headers.insert(
            HeaderName::from_static("x-github-api-version"),
            HeaderValue::from_static(API_VERSION),
        );
        Ok(headers)
    }

    /// The URL to fetch a release file from, with the token: `url` when it is the API URL of one of
    /// this release's assets, else the API URL of the asset with the same file name (a
    /// `https://github.com/.../releases/download/...` link, which a private repository does not serve
    /// to tokens). Anything else is refused, so the token never goes to another host.
    pub fn asset_url(&self, release: &Release, url: &Url) -> Result<Url> {
        if let Some(asset) = release
            .assets
            .iter()
            .find(|a| &a.url == url && self.is_api_asset(&a.url))
        {
            return Ok(asset.url.clone());
        }
        let name = url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .map(percent_decode)
            .unwrap_or_default();
        match release.asset(&name) {
            Some(asset) if self.is_api_asset(&asset.url) => Ok(asset.url.clone()),
            _ => Err(CoreError::Update(format!(
                "latest.json in {} points to {}, which is not a file of that release",
                release.tag_name,
                without_query(url)
            ))),
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

    async fn get(&self, path: &[&str], token: &SecretString) -> Result<Response> {
        self.get_query(path, "", token).await
    }

    async fn get_query(&self, path: &[&str], query: &str, token: &SecretString) -> Result<Response> {
        let mut url = self.endpoint(path);
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer(token)?);
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
            .map_err(|err| CoreError::Update(scrub(&format!("could not reach GitHub: {}", chain(&err)), token)))
    }

    async fn json<T: for<'de> Deserialize<'de>>(&self, response: Response, token: &SecretString) -> Result<T> {
        let bytes = response
            .bytes()
            .await
            .map_err(|err| CoreError::Update(scrub(&format!("GitHub's answer broke off: {}", chain(&err)), token)))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| CoreError::Update(format!("GitHub's answer was not what Remotely expected: {err}")))
    }

    fn no_access(&self) -> CoreError {
        CoreError::UpdateTokenNoAccess {
            repo: self.repo.to_string(),
        }
    }

    /// What a refused or failed call means for the user.
    async fn failure(&self, response: Response, token: &SecretString) -> CoreError {
        let status = response.status();
        let headers = response.headers().clone();
        let message = github_message(&response.bytes().await.unwrap_or_default(), token);
        // The primary limit sets `x-ratelimit-remaining: 0`; the secondary one sends `retry-after`.
        let rate_limited = status == StatusCode::TOO_MANY_REQUESTS
            || (status == StatusCode::FORBIDDEN
                && (headers.contains_key("retry-after")
                    || headers
                        .get("x-ratelimit-remaining")
                        .is_some_and(|v| v.as_bytes() == b"0")));
        if rate_limited {
            return CoreError::Update(
                "GitHub's API limit for this token is used up for now. Updates are checked again later".into(),
            );
        }
        match status {
            StatusCode::UNAUTHORIZED => CoreError::UpdateTokenRefused { expired_on: None },
            // A token that can see the repository but lacks Contents: Read-only.
            StatusCode::FORBIDDEN => self.no_access(),
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
fn github_message(body: &[u8], token: &SecretString) -> Option<String> {
    #[derive(Deserialize)]
    struct Message {
        message: String,
    }
    let message = serde_json::from_slice::<Message>(body).ok()?.message;
    let message: String = scrub(&message, token).chars().take(200).collect();
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
                {"id": 11, "name": "latest.json", "url": "https://api.github.com/repos/alice/remotely/releases/assets/11"},
                {"id": 12, "name": "Remotely_0.9.0_x64-setup.exe", "url": "https://api.github.com/repos/alice/remotely/releases/assets/12"},
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
        let headers = releases().download_headers(&token).unwrap();
        assert!(!format!("{headers:?}").contains(token.expose()));
        assert_eq!(headers[ACCEPT], "application/octet-stream");
        assert!(headers[AUTHORIZATION].is_sensitive());
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
            github_message(br#"{"message":"token ghp_secretvalue123 is bad"}"#, &token).as_deref(),
            Some("token [token] is bad")
        );
        assert_eq!(github_message(b"<html>", &token), None);
    }
}
