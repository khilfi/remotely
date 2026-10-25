//! FD-14 tests: a stand-in for the GitHub API and its release storage on 127.0.0.1, and a throwaway
//! update-signing key made at run time. No test talks to GitHub, and no token or key is committed.
//!
//! The fake behaves like GitHub does for a **private** repository, or a public one after
//! [`FakeGithub::set_public`]:
//!
//! * The API needs a User-Agent. A private repository needs `Authorization: Bearer <token>` with a
//!   token it was given ([`FakeGithub::add_token`]); without one it answers 404, as for a repository
//!   that doesn't exist. A public one answers calls without a token too. An unknown, revoked or
//!   expired token gets 401 "Bad credentials". A token that can't see the repository gets 404, one
//!   without Contents: Read-only gets 403. Answers to a token with an expiry carry
//!   `GitHub-Authentication-Token-Expiration`.
//! * A used-up limit gets 403 with `x-ratelimit-remaining: 0` and a reset an hour away, for calls
//!   with a token ([`FakeGithub::set_rate_limited`]) or without one
//!   ([`FakeGithub::set_anonymous_rate_limited`]). The secondary limit
//!   ([`FakeGithub::set_secondary_limit`]) gets 429 with `retry-after`.
//! * `GET /repos/{owner}/{repo}/releases/assets/{id}` with `Accept: application/octet-stream`
//!   redirects (302) to the "storage", another server on another port; any other Accept gets the
//!   asset's description as JSON.
//! * A third server stands in for github.com: `GET /{owner}/{repo}/releases/download/{tag}/{name}`
//!   (an asset's `browser_download_url`) redirects to the storage while the repository is public,
//!   and answers 404 while it is private.
//! * The storage serves a file only when the request carries no `Authorization` header (S3 refuses
//!   two kinds of authorization at once).
//!
//! Every server records every request, so tests can check where the token went.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use url::Url;

use crate::adapters::github::GithubRepo;
use crate::locks;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A minisign key pair for signing test updates, as `tauri signer generate` would make one.
pub struct UpdateSigner {
    key: SigningKey,
    key_id: [u8; 8],
}

impl UpdateSigner {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        let mut key_id = [0u8; 8];
        getrandom::fill(&mut seed).unwrap_or_else(|err| panic!("no random source: {err}"));
        getrandom::fill(&mut key_id).unwrap_or_else(|err| panic!("no random source: {err}"));
        Self {
            key: SigningKey::from_bytes(&seed),
            key_id,
        }
    }

    /// The `plugins.updater.pubkey` value: base64 of the minisign public key file.
    pub fn public_key(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(&self.key.verifying_key().to_bytes());
        let id: String = self.key_id.iter().rev().map(|b| format!("{b:02X}")).collect();
        BASE64.encode(format!(
            "untrusted comment: minisign public key: {id}\n{}\n",
            BASE64.encode(raw)
        ))
    }

    /// The signature as latest.json holds it: base64 of the `.sig` file, prehashed (BLAKE2b) like the
    /// Tauri CLI signs, with the trusted comment `tauri signer sign --app-version` writes.
    pub fn sign(&self, data: &[u8], file: &str, version: &str) -> String {
        self.sign_with_comment(data, &format!("timestamp:1700000000\tfile:{file}\tversion:{version}"))
    }

    /// Like [`Self::sign`], with any trusted comment (older Tauri CLIs wrote no version).
    pub fn sign_with_comment(&self, data: &[u8], trusted: &str) -> String {
        let signature = self.key.sign(&Blake2b512::digest(data)).to_bytes();
        let mut global = signature.to_vec();
        global.extend_from_slice(trusted.as_bytes());
        let global = self.key.sign(&global).to_bytes();
        let mut raw = b"ED".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(&signature);
        BASE64.encode(format!(
            "untrusted comment: signature from tauri secret key\n{}\ntrusted comment: {trusted}\n{}\n",
            BASE64.encode(raw),
            BASE64.encode(global)
        ))
    }
}

/// What a token may do on the fake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAccess {
    /// Contents: Read-only on the repository: what Remotely needs.
    Releases,
    /// A token for other repositories only: this one answers 404.
    OtherRepos,
    /// Sees the repository but has no Contents permission: 403.
    NoContents,
    /// No Contents permission, answered with 404 as if there were no releases.
    HiddenContents,
}

#[derive(Debug, Clone)]
struct Token {
    access: TokenAccess,
    /// `GitHub-Authentication-Token-Expiration`, e.g. `2026-12-31 00:00:00 UTC`.
    expires: Option<String>,
    revoked: bool,
}

#[derive(Debug, Clone)]
pub struct FakeAsset {
    pub id: u64,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// One request either server received.
#[derive(Debug, Clone)]
pub struct SeenRequest {
    /// `"api"` or `"storage"`.
    pub server: &'static str,
    pub path: String,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
}

impl SeenRequest {
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(String::as_str)
    }
}

#[derive(Default)]
struct State {
    owner: String,
    repo: String,
    /// Anyone may read the repository, without a token.
    public: bool,
    tokens: HashMap<String, Token>,
    /// The latest published release: tag, notes, files.
    release: Option<(String, String, Vec<FakeAsset>)>,
    next_asset: u64,
    /// The limit for calls with a token is used up.
    rate_limited: bool,
    /// The limit for calls without a token is used up.
    anonymous_rate_limited: bool,
    /// The secondary limit: every API call gets 429 with this `retry-after`.
    secondary_limit: Option<u64>,
    requests: Vec<SeenRequest>,
}

/// Where the fake's three servers listen.
#[derive(Clone)]
struct Urls {
    api: Url,
    web: Url,
    storage: Url,
}

/// The fake GitHub API, github.com and storage. All stop when it is dropped.
pub struct FakeGithub {
    urls: Urls,
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for FakeGithub {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl FakeGithub {
    /// Serves the private repository `owner/repo`, with no release and no token yet.
    pub async fn start(owner: &str, repo: &str) -> Self {
        let state = Arc::new(Mutex::new(State {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
            next_asset: 1000,
            ..Default::default()
        }));
        let mut listeners = Vec::new();
        for _ in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("bind: {e}"));
            listeners.push(listener);
        }
        let url = |l: &TcpListener| {
            let addr = l.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}"));
            Url::parse(&format!("http://{addr}/")).unwrap_or_else(|e| panic!("url: {e}"))
        };
        let urls = Urls {
            api: url(&listeners[0]),
            web: url(&listeners[1]),
            storage: url(&listeners[2]),
        };
        let tasks = listeners
            .into_iter()
            .zip(["api", "web", "storage"])
            .map(|(listener, server)| tokio::spawn(serve(listener, server, Arc::clone(&state), urls.clone())))
            .collect();
        Self { urls, state, tasks }
    }

    /// The API's base URL, in place of `https://api.github.com`.
    pub fn api_url(&self) -> Url {
        self.urls.api.clone()
    }

    /// The stand-in for `https://github.com`, where public download links point.
    pub fn web_url(&self) -> Url {
        self.urls.web.clone()
    }

    pub fn storage_url(&self) -> Url {
        self.urls.storage.clone()
    }

    /// Public: the API and the download links answer without a token. Private (as it starts): 404.
    pub fn set_public(&self, public: bool) {
        locks::lock(&self.state).public = public;
    }

    pub fn repo(&self) -> GithubRepo {
        let state = locks::lock(&self.state);
        GithubRepo::new(&state.owner, &state.repo)
    }

    /// A token GitHub knows. `expires` is the expiry header's value, e.g. `2026-12-31 00:00:00 UTC`.
    pub fn add_token(&self, token: &str, access: TokenAccess, expires: Option<&str>) {
        locks::lock(&self.state).tokens.insert(
            token.to_owned(),
            Token {
                access,
                expires: expires.map(str::to_owned),
                revoked: false,
            },
        );
    }

    /// Revoked or expired: GitHub answers both with 401 "Bad credentials".
    pub fn revoke(&self, token: &str) {
        if let Some(t) = locks::lock(&self.state).tokens.get_mut(token) {
            t.revoked = true;
        }
    }

    /// The limit for calls with a token (5,000 an hour) is used up.
    pub fn set_rate_limited(&self, limited: bool) {
        locks::lock(&self.state).rate_limited = limited;
    }

    /// The limit for calls without a token (60 an hour from one address) is used up.
    pub fn set_anonymous_rate_limited(&self, limited: bool) {
        locks::lock(&self.state).anonymous_rate_limited = limited;
    }

    /// The secondary limit: every API call gets 429 with `retry-after: <seconds>`, until `None`.
    pub fn set_secondary_limit(&self, retry_after: Option<u64>) {
        locks::lock(&self.state).secondary_limit = retry_after;
    }

    /// Publishes a release with these files (name, content), replacing the latest one. Returns the
    /// files with their asset ids.
    pub fn publish(&self, tag: &str, notes: &str, files: Vec<(&str, Vec<u8>)>) -> Vec<FakeAsset> {
        let mut state = locks::lock(&self.state);
        let mut assets = Vec::new();
        for (name, bytes) in files {
            state.next_asset += 1;
            assets.push(FakeAsset {
                id: state.next_asset,
                name: name.to_owned(),
                bytes,
            });
        }
        state.release = Some((tag.to_owned(), notes.to_owned(), assets.clone()));
        assets
    }

    /// Adds a file to the latest release (latest.json, once the installer's id is known).
    pub fn add_file(&self, name: &str, bytes: Vec<u8>) -> FakeAsset {
        let mut state = locks::lock(&self.state);
        state.next_asset += 1;
        let asset = FakeAsset {
            id: state.next_asset,
            name: name.to_owned(),
            bytes,
        };
        match &mut state.release {
            Some((_, _, assets)) => assets.push(asset.clone()),
            None => panic!("publish a release first"),
        }
        asset
    }

    /// Changes a published file's content (to tamper with it).
    pub fn replace_file(&self, name: &str, bytes: Vec<u8>) {
        let mut state = locks::lock(&self.state);
        if let Some((_, _, assets)) = &mut state.release {
            for asset in assets.iter_mut().filter(|a| a.name == name) {
                asset.bytes = bytes.clone();
            }
        }
    }

    /// `{api}/repos/{owner}/{repo}/releases/assets/{id}`, as tauri-action writes into latest.json.
    pub fn asset_api_url(&self, id: u64) -> Url {
        let state = locks::lock(&self.state);
        api_asset_url(&self.urls.api, &state.owner, &state.repo, id)
    }

    /// `{web}/{owner}/{repo}/releases/download/{tag}/{name}` (an asset's `browser_download_url`),
    /// which a public repository serves to anyone and a private one does not serve to tokens.
    pub fn download_link(&self, tag: &str, name: &str) -> Url {
        let state = locks::lock(&self.state);
        download_link(&self.urls.web, &state.owner, &state.repo, tag, name)
    }

    pub fn requests(&self) -> Vec<SeenRequest> {
        locks::lock(&self.state).requests.clone()
    }

    pub fn clear_requests(&self) {
        locks::lock(&self.state).requests.clear();
    }
}

/// latest.json as tauri-action writes it, for Windows x64.
pub fn latest_json(version: &str, notes: &str, url: &Url, signature: &str) -> Vec<u8> {
    let platform = json!({ "signature": signature, "url": url.as_str() });
    serde_json::to_vec_pretty(&json!({
        "version": version,
        "notes": notes,
        "pub_date": "2026-10-18T16:48:15.647Z",
        "platforms": { "windows-x86_64": platform, "windows-x86_64-nsis": platform },
    }))
    .unwrap_or_else(|e| panic!("json: {e}"))
}

fn api_asset_url(api: &Url, owner: &str, repo: &str, id: u64) -> Url {
    api.join(&format!("repos/{owner}/{repo}/releases/assets/{id}"))
        .unwrap_or_else(|e| panic!("url: {e}"))
}

fn download_link(web: &Url, owner: &str, repo: &str, tag: &str, name: &str) -> Url {
    web.join(&format!("{owner}/{repo}/releases/download/{tag}/{name}"))
        .unwrap_or_else(|e| panic!("url: {e}"))
}

/// Where the storage serves asset `id`, with a signed key in the query as S3 has.
fn storage_location(storage: &Url, id: u64) -> String {
    format!("{storage}assets/{id}?X-Amz-Signature=fake-signed-url")
}

async fn serve(listener: TcpListener, server: &'static str, state: Arc<Mutex<State>>, urls: Urls) {
    while let Ok((socket, _)) = listener.accept().await {
        let (state, urls) = (Arc::clone(&state), urls.clone());
        tokio::spawn(async move {
            let _ = handle(socket, server, &state, &urls).await;
        });
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json; charset=utf-8".into())],
            body: body.to_string().into_bytes(),
        }
    }

    fn message(status: u16, message: &str) -> Self {
        Self::json(
            status,
            json!({ "message": message, "documentation_url": "https://docs.github.com/rest", "status": status.to_string() }),
        )
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn redirect(location: String) -> Self {
        Self {
            status: 302,
            headers: vec![("Location".into(), location)],
            body: Vec::new(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// GitHub's answer once a primary limit is used up: it resets an hour from now.
    fn rate_limited(message: &str) -> Self {
        let reset = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 3600)
            .unwrap_or_default();
        Self::message(403, message)
            .header("x-ratelimit-limit", "60")
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", &reset.to_string())
    }
}

async fn handle(mut socket: TcpStream, server: &'static str, state: &Mutex<State>, urls: &Urls) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = socket.read(&mut buf).await?;
        if n == 0 || head.len() > 64 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let path = lines.next().and_then(|l| l.split(' ').nth(1)).unwrap_or("/").to_owned();
    let headers: HashMap<String, String> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let seen = SeenRequest {
        server,
        path: path.clone(),
        headers,
    };
    let reply = {
        let mut state = locks::lock(state);
        state.requests.push(seen.clone());
        match server {
            "api" => api_reply(&state, &seen, urls),
            "web" => web_reply(&state, &seen, urls),
            _ => storage_reply(&state, &seen),
        }
    };

    let mut out = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reason(reply.status),
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    socket.write_all(out.as_bytes()).await?;
    socket.write_all(&reply.body).await?;
    socket.shutdown().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        429 => "Too Many Requests",
        _ => "Not Found",
    }
}

fn api_reply(state: &State, req: &SeenRequest, urls: &Urls) -> Reply {
    if !req.headers.contains_key("user-agent") {
        return Reply::message(
            403,
            "Request forbidden by administrative rules. Please make sure your request has a User-Agent header",
        );
    }
    if let Some(retry_after) = state.secondary_limit {
        return Reply::message(429, "You have exceeded a secondary rate limit.")
            .header("retry-after", &retry_after.to_string());
    }
    let token = req
        .authorization()
        .and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("token ")));
    let Some(token) = token else {
        if state.anonymous_rate_limited {
            return Reply::rate_limited("API rate limit exceeded for 203.0.113.7.");
        }
        // A private repository: without a token it does not exist.
        return match state.public {
            true => route(state, req, TokenAccess::Releases, urls),
            false => Reply::message(404, "Not Found"),
        };
    };
    let Some(known) = state.tokens.get(token).filter(|t| !t.revoked) else {
        return Reply::message(401, "Bad credentials");
    };
    if state.rate_limited {
        return Reply::rate_limited("API rate limit exceeded for user ID 1.");
    }
    let reply = route(state, req, known.access, urls);
    match &known.expires {
        Some(expires) => reply.header("github-authentication-token-expiration", expires),
        None => reply,
    }
}

/// github.com: a public repository's download links redirect to the storage; a private one's are 404.
fn web_reply(state: &State, req: &SeenRequest, urls: &Urls) -> Reply {
    let Some((tag, _, assets)) = state.release.as_ref().filter(|_| state.public) else {
        return Reply::not_found();
    };
    let asset = assets
        .iter()
        .find(|a| req.path == download_link(&urls.web, &state.owner, &state.repo, tag, &a.name).path());
    match asset {
        Some(asset) => Reply::redirect(storage_location(&urls.storage, asset.id)),
        None => Reply::not_found(),
    }
}

fn route(state: &State, req: &SeenRequest, access: TokenAccess, urls: &Urls) -> Reply {
    let repo_path = format!("/repos/{}/{}", state.owner, state.repo);
    let path = req.path.split('?').next().unwrap_or_default();
    let Some(rest) = path.strip_prefix(&repo_path) else {
        return Reply::message(404, "Not Found");
    };
    if access == TokenAccess::OtherRepos {
        return Reply::message(404, "Not Found");
    }
    if rest.is_empty() {
        return Reply::json(
            200,
            json!({ "full_name": format!("{}/{}", state.owner, state.repo), "private": !state.public }),
        );
    }
    match access {
        TokenAccess::NoContents => return Reply::message(403, "Resource not accessible by personal access token"),
        // How GitHub answers some fine-grained tokens without Contents: as if nothing were there.
        TokenAccess::HiddenContents => return Reply::message(404, "Not Found"),
        _ => {}
    }
    if rest == "/releases" && state.release.is_none() {
        return Reply::json(200, json!([]));
    }
    let Some((tag, notes, assets)) = &state.release else {
        return Reply::message(404, "Not Found");
    };
    let describe = |a: &FakeAsset| {
        json!({
            "url": api_asset_url(&urls.api, &state.owner, &state.repo, a.id).as_str(),
            "id": a.id,
            "name": a.name,
            "browser_download_url": download_link(&urls.web, &state.owner, &state.repo, tag, &a.name).as_str(),
            "size": a.bytes.len(),
            "content_type": "application/octet-stream",
            "state": "uploaded",
        })
    };
    let release = json!({
        "tag_name": tag,
        "name": format!("Remotely {tag}"),
        "draft": false,
        "prerelease": false,
        "body": notes,
        "assets": assets.iter().map(describe).collect::<Vec<_>>(),
    });
    match rest {
        "/releases/latest" => return Reply::json(200, release),
        "/releases" => return Reply::json(200, json!([release])),
        _ => {}
    }
    let asset = rest
        .strip_prefix("/releases/assets/")
        .and_then(|id| id.parse::<u64>().ok())
        .and_then(|id| assets.iter().find(|a| a.id == id));
    match asset {
        Some(asset) if req.headers.get("accept").map(String::as_str) == Some("application/octet-stream") => {
            Reply::redirect(storage_location(&urls.storage, asset.id))
        }
        Some(asset) => Reply::json(200, describe(asset)),
        None => Reply::message(404, "Not Found"),
    }
}

fn storage_reply(state: &State, req: &SeenRequest) -> Reply {
    if req.authorization().is_some() {
        return Reply {
            status: 400,
            headers: vec![("Content-Type".into(), "application/xml".into())],
            body: b"<Error><Code>InvalidArgument</Code><Message>Only one auth mechanism allowed</Message></Error>"
                .to_vec(),
        };
    }
    let id = req
        .path
        .strip_prefix("/assets/")
        .and_then(|rest| rest.split('?').next())
        .and_then(|id| id.parse::<u64>().ok());
    let asset = state
        .release
        .as_ref()
        .and_then(|(_, _, assets)| assets.iter().find(|a| Some(a.id) == id));
    match asset {
        Some(asset) => Reply {
            status: 200,
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: asset.bytes.clone(),
        },
        None => Reply::not_found(),
    }
}
