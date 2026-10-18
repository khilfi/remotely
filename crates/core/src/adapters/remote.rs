//! Remote adapter: SSH to any reachable machine, via russh.
//!
//! Covers SS-03 (interactive terminal), SS-05 (the host key check, decided by a [`HostKeyVerifier`]
//! the core passes in), and later BX-02 (bulk exec), BX-07 (sudo from the vault, never echoed or
//! logged) and MO-02 (guest metrics from /proc). Jump hosts (SS-07, v2) will chain through russh's
//! direct-tcpip channels.
//!
//! The core reads secrets from the vault just before a connection and hands them over as
//! [`Credentials`]; this adapter never sees the vault, the UI never sees the secrets, and no secret
//! reaches a log or an error message. A login that needs something typed (a password that is not
//! saved, a key's passphrase, a one-time code) asks through the [`Prompter`], which the terminal
//! shows like PuTTY does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, MethodKind, MethodSet};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::domain::Environment;
use crate::error::{CoreError, Result};
use crate::known_hosts::{address, HostKey};
use crate::locks;
use crate::vault::{SecretId, SecretString};

/// A saved session, as the remote adapter needs it (SS-01).
#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Empty: the terminal asks for it ("login as").
    pub username: String,
    pub auth: AuthMethod,
    /// The jump host (SS-07, v2). Resolved one level, so the terminal can name it.
    pub jump: Option<Box<SessionSpec>>,
    pub environment: Environment,
    pub startup_command: Option<String>,
}

impl SessionSpec {
    /// `user@host:port`, for messages and the audit log.
    pub fn address(&self) -> String {
        let user = if self.username.is_empty() {
            String::new()
        } else {
            format!("{}@", self.username)
        };
        format!("{user}{}", address(&self.host, self.port))
    }
}

/// How a session logs in: vault IDs, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// `None`: no saved password, so the terminal asks for it.
    Password(Option<SecretId>),
    PrivateKey {
        key: SecretId,
        passphrase: Option<SecretId>,
    },
    Agent,
}

/// What a connection logs in with, read from the vault just before it. Zeroized when dropped.
pub enum Credentials {
    /// `None`: asked in the terminal.
    Password(Option<SecretString>),
    PrivateKey {
        key: SecretString,
        passphrase: Option<SecretString>,
        /// The key's vault label, for prompts ("passphrase for key 'web'").
        label: String,
    },
    Agent,
}

/// Where SSH agent logins find their agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSource {
    /// The Windows OpenSSH agent (the "OpenSSH Authentication Agent" service), then Pageant.
    System,
    /// A named pipe that speaks the agent protocol. Tests run their own agent on one.
    NamedPipe(String),
}

/// The Windows OpenSSH agent's pipe.
pub const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Reaching the host and agreeing on keys. Time spent waiting for the user to answer a prompt
    /// does not count.
    pub connect_timeout: Duration,
    /// SS-03 keep-alive: a message after this long without traffic. `None`: off.
    pub keepalive_interval: Option<Duration>,
    /// Keep-alives that may go unanswered before the connection counts as lost.
    pub keepalive_max: usize,
    pub agent: AgentSource,
    /// The terminal type the PTY announces.
    pub term: String,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            agent: AgentSource::System,
            term: "xterm-256color".into(),
        }
    }
}

/// SS-05: decides whether a presented host key is trusted. `Ok(())` lets the connection go on;
/// [`CoreError::HostKeyChanged`] or [`CoreError::HostKeyRejected`] stop it.
#[async_trait]
pub trait HostKeyVerifier: Send + Sync {
    async fn verify(&self, key: &HostKey) -> Result<()>;
}

/// Asks the user for what a login needs, in the terminal.
#[async_trait]
pub trait Prompter: Send {
    /// Shows `prompt` and reads one line. `echo: false` hides what is typed. [`CoreError::Cancelled`]
    /// when the user gave up (Ctrl+C, or closed the terminal).
    async fn ask(&mut self, prompt: &str, echo: bool) -> Result<SecretString>;

    /// Shows a message, e.g. the server's login banner.
    async fn show(&mut self, text: &str);

    /// A typed password worked. The terminal may keep it in memory to log in again after a dropped
    /// connection (SS-03 auto-reconnect); it is never stored.
    fn password_accepted(&mut self, _password: &SecretString) {}
}

/// PTY size in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

/// What an interactive shell needs.
pub struct ShellRequest<'a> {
    pub session: &'a SessionSpec,
    pub credentials: Credentials,
    pub size: PtySize,
    pub options: &'a ConnectOptions,
    pub verifier: Arc<dyn HostKeyVerifier>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Input to an interactive shell.
#[derive(Debug)]
pub enum ShellInput {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Output of an interactive shell: raw bytes (never decoded here, so a character split across two
/// reads arrives whole in xterm.js), then one `Closed`.
#[derive(Debug, PartialEq, Eq)]
pub enum ShellOutput {
    Data(Vec<u8>),
    Closed(ShellEnd),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEnd {
    /// The remote shell ended (`exit`, or the server closed the channel), or the user closed it.
    Exited { status: Option<u32> },
    /// The connection dropped: network, keep-alive timeout, server restart. Worth reconnecting.
    Lost { reason: String },
}

/// Both ends of an interactive shell: send keystrokes in, read terminal output.
pub struct ShellHandle {
    pub input: mpsc::Sender<ShellInput>,
    pub output: mpsc::Receiver<ShellOutput>,
}

#[async_trait]
pub trait RemoteAdapter: Send + Sync {
    /// Runs a command or script and collects its output (BX-02). `sudo_password` comes from the vault.
    async fn exec(
        &self,
        session: &SessionSpec,
        script: &str,
        sudo_password: Option<&SecretString>,
    ) -> Result<ExecResult>;

    /// Connects, checks the host key, logs in and opens a PTY shell (SS-03).
    async fn open_shell(&self, request: ShellRequest<'_>, prompter: &mut dyn Prompter) -> Result<ShellHandle>;
}

pub struct RusshAdapter;

impl RusshAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RusshAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RemoteAdapter for RusshAdapter {
    async fn exec(&self, _: &SessionSpec, _: &str, _: Option<&SecretString>) -> Result<ExecResult> {
        Err(CoreError::NotImplemented("BX-02 remote exec over SSH"))
    }

    async fn open_shell(&self, request: ShellRequest<'_>, prompter: &mut dyn Prompter) -> Result<ShellHandle> {
        let ShellRequest {
            session,
            credentials,
            size,
            options,
            verifier,
        } = request;
        let (mut handle, shared) = connect(session, options, verifier).await?;
        show_banners(&shared, prompter).await;
        let user = match session.username.as_str() {
            "" => {
                let typed = prompter.ask("login as: ", true).await?;
                typed.expose().trim().to_owned()
            }
            user => user.to_owned(),
        };
        if user.is_empty() {
            return Err(CoreError::AuthFailed("no user name was given".into()));
        }
        authenticate(&mut handle, &user, credentials, options, prompter, &shared).await?;
        open_pty(handle, shared, size, &options.term).await
    }
}

/// What the russh handler learns during the connection, for the code that waits on it.
#[derive(Default)]
struct Shared {
    /// The server presented its key; from here on the user may be deciding, so the connect timeout
    /// no longer applies.
    key_presented: bool,
    /// Why the verifier refused the key.
    verify_error: Option<CoreError>,
    banners: Vec<String>,
    /// Why the connection ended, once it has.
    disconnect: Option<String>,
}

struct Handler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier>,
    shared: Arc<Mutex<Shared>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key = server_key.public_key();
        let host_key = HostKey {
            host: self.host.clone(),
            port: self.port,
            key_type: key.algorithm().as_str().to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        };
        locks::lock(&self.shared).key_presented = true;
        match self.verifier.verify(&host_key).await {
            Ok(()) => Ok(true),
            Err(err) => {
                locks::lock(&self.shared).verify_error = Some(err);
                Ok(false)
            }
        }
    }

    async fn auth_banner(&mut self, banner: &str, _: &mut client::Session) -> std::result::Result<(), Self::Error> {
        locks::lock(&self.shared).banners.push(banner.to_owned());
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> std::result::Result<(), Self::Error> {
        let (text, result) = match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                let text = if info.message.trim().is_empty() {
                    "the server closed the connection".to_owned()
                } else {
                    format!("the server closed the connection: {}", info.message.trim())
                };
                (text, Ok(()))
            }
            client::DisconnectReason::Error(err) => (lost_reason(&err), Err(err)),
        };
        locks::lock(&self.shared).disconnect.get_or_insert(text);
        result
    }
}

/// Plain words for why a connection dropped.
fn lost_reason(err: &russh::Error) -> String {
    match err {
        russh::Error::KeepaliveTimeout => "the server stopped answering keep-alives".into(),
        russh::Error::InactivityTimeout => "the connection was idle for too long".into(),
        russh::Error::IO(io) => format!("the connection was lost ({io})"),
        russh::Error::Disconnect | russh::Error::HUP => "the connection was closed".into(),
        other => format!("the connection was lost ({other})"),
    }
}

/// The host as a socket address wants it: IPv6 without brackets.
fn dial_host(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

async fn connect(
    session: &SessionSpec,
    options: &ConnectOptions,
    verifier: Arc<dyn HostKeyVerifier>,
) -> Result<(client::Handle<Handler>, Arc<Mutex<Shared>>)> {
    let target = address(&session.host, session.port);
    let seconds = options.connect_timeout.as_secs().max(1);
    let stream = tokio::time::timeout(
        options.connect_timeout,
        TcpStream::connect((dial_host(&session.host), session.port)),
    )
    .await
    .map_err(|_| CoreError::Timeout {
        command: format!("connecting to {target}"),
        seconds,
    })?
    .map_err(|err| CoreError::Ssh(format!("can't connect to {target}: {err}")))?;
    // Keystrokes are small; send each at once.
    let _ = stream.set_nodelay(true);

    let config = Arc::new(client::Config {
        keepalive_interval: options.keepalive_interval,
        keepalive_max: options.keepalive_max,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    });
    let shared = Arc::new(Mutex::new(Shared::default()));
    let handler = Handler {
        host: session.host.clone(),
        port: session.port,
        verifier,
        shared: Arc::clone(&shared),
    };
    // The timeout covers agreeing on keys, not the user reading a host key prompt.
    let watchdog = {
        let shared = Arc::clone(&shared);
        let timeout = options.connect_timeout;
        async move {
            tokio::time::sleep(timeout).await;
            while locks::lock(&shared).key_presented {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    };
    let handle = tokio::select! {
        result = client::connect_stream(config, stream, handler) => result,
        () = watchdog => {
            return Err(CoreError::Timeout { command: format!("the SSH handshake with {target}"), seconds });
        }
    };
    match handle {
        Ok(handle) => Ok((handle, shared)),
        Err(err) => {
            if let Some(refused) = locks::lock(&shared).verify_error.take() {
                return Err(refused);
            }
            Err(CoreError::Ssh(format!("SSH handshake with {target} failed: {err}")))
        }
    }
}

async fn show_banners(shared: &Arc<Mutex<Shared>>, prompter: &mut dyn Prompter) {
    let banners = std::mem::take(&mut locks::lock(shared).banners);
    for banner in banners {
        prompter.show(&banner).await;
    }
}

fn has(methods: &MethodSet, kind: MethodKind) -> bool {
    methods.contains(&kind)
}

fn method_names(methods: &MethodSet) -> String {
    let names: Vec<&str> = methods.iter().map(<&str>::from).collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// Where a login step left things.
enum Step {
    Done,
    /// That worked, but the server wants another factor from these methods.
    More(MethodSet),
    Refused(MethodSet),
}

impl From<AuthResult> for Step {
    fn from(result: AuthResult) -> Self {
        match result {
            AuthResult::Success => Step::Done,
            AuthResult::Failure {
                remaining_methods,
                partial_success: true,
            } => Step::More(remaining_methods),
            AuthResult::Failure { remaining_methods, .. } => Step::Refused(remaining_methods),
        }
    }
}

fn ssh_err(err: russh::Error) -> CoreError {
    CoreError::Ssh(format!("login failed: {err}"))
}

/// Logs in. Errors name the method and user, never a secret.
async fn authenticate(
    handle: &mut client::Handle<Handler>,
    user: &str,
    credentials: Credentials,
    options: &ConnectOptions,
    prompter: &mut dyn Prompter,
    shared: &Arc<Mutex<Shared>>,
) -> Result<()> {
    let first = Step::from(handle.authenticate_none(user).await.map_err(ssh_err)?);
    show_banners(shared, prompter).await;
    let methods = match first {
        Step::Done => return Ok(()),
        Step::More(methods) | Step::Refused(methods) => methods,
    };
    let step = match credentials {
        Credentials::Password(saved) => password_login(handle, user, saved, &methods, prompter).await?,
        Credentials::PrivateKey { key, passphrase, label } => {
            key_login(handle, user, &key, passphrase, &label, &methods, prompter).await?
        }
        Credentials::Agent => agent_login(handle, user, &options.agent, &methods).await?,
    };
    let mut methods = match step {
        Step::Done => return Ok(()),
        Step::More(methods) => methods,
        Step::Refused(_) => {
            return Err(CoreError::AuthFailed(format!(
                "the server refused the login for {user}"
            )))
        }
    };
    // Further factors (say, a one-time code after the key): asked in the terminal.
    for _ in 0..4 {
        show_banners(shared, prompter).await;
        let step = if has(&methods, MethodKind::KeyboardInteractive) {
            keyboard_interactive(handle, user, None, prompter).await?
        } else if has(&methods, MethodKind::Password) {
            let typed = prompter.ask(&format!("{user}'s password: "), false).await?;
            Step::from(
                handle
                    .authenticate_password(user, typed.expose())
                    .await
                    .map_err(ssh_err)?,
            )
        } else {
            return Err(CoreError::AuthFailed(format!(
                "the server wants another login step ({}) that Remotely can't answer",
                method_names(&methods)
            )));
        };
        match step {
            Step::Done => return Ok(()),
            Step::More(next) => methods = next,
            Step::Refused(_) => {
                return Err(CoreError::AuthFailed(format!(
                    "the server refused the second login step for {user}"
                )))
            }
        }
    }
    Err(CoreError::AuthFailed(
        "the server asked for too many login steps".into(),
    ))
}

/// A saved password, or one typed in the terminal (up to three tries). Servers that only offer
/// keyboard-interactive get the password as the answer to their password prompt.
async fn password_login(
    handle: &mut client::Handle<Handler>,
    user: &str,
    saved: Option<SecretString>,
    methods: &MethodSet,
    prompter: &mut dyn Prompter,
) -> Result<Step> {
    let password = has(methods, MethodKind::Password);
    let interactive = has(methods, MethodKind::KeyboardInteractive);
    if !password && !interactive {
        return Err(CoreError::AuthFailed(format!(
            "the server doesn't take passwords for {user} (it offers: {})",
            method_names(methods)
        )));
    }
    if let Some(saved) = saved {
        let step = if password {
            Step::from(
                handle
                    .authenticate_password(user, saved.expose())
                    .await
                    .map_err(ssh_err)?,
            )
        } else {
            keyboard_interactive(handle, user, Some(&saved), prompter).await?
        };
        return match step {
            Step::Refused(_) => Err(CoreError::AuthFailed(format!(
                "the server refused the password for {user}"
            ))),
            other => Ok(other),
        };
    }
    for attempt in 0..3 {
        if attempt > 0 {
            prompter.show("Access denied\r\n").await;
        }
        let step = if password {
            let typed = prompter.ask(&format!("{user}'s password: "), false).await?;
            let step = Step::from(
                handle
                    .authenticate_password(user, typed.expose())
                    .await
                    .map_err(ssh_err)?,
            );
            if !matches!(step, Step::Refused(_)) {
                prompter.password_accepted(&typed);
            }
            step
        } else {
            keyboard_interactive(handle, user, None, prompter).await?
        };
        if !matches!(step, Step::Refused(_)) {
            return Ok(step);
        }
    }
    Err(CoreError::AuthFailed(format!(
        "the server refused the password for {user}"
    )))
}

/// Answers keyboard-interactive prompts: `password` (once) for the first hidden prompt that asks for
/// a password, the rest typed in the terminal.
async fn keyboard_interactive(
    handle: &mut client::Handle<Handler>,
    user: &str,
    mut password: Option<&SecretString>,
    prompter: &mut dyn Prompter,
) -> Result<Step> {
    let mut reply = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .map_err(ssh_err)?;
    for _ in 0..8 {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(Step::Done),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(if partial_success {
                    Step::More(remaining_methods)
                } else {
                    Step::Refused(remaining_methods)
                })
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                for text in [name, instructions] {
                    if !text.trim().is_empty() {
                        prompter.show(&format!("{}\r\n", text.trim_end())).await;
                    }
                }
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let saved = match password {
                        Some(p) if !prompt.echo && prompt.prompt.to_lowercase().contains("password") => {
                            password = None;
                            Some(p.expose().to_owned())
                        }
                        _ => None,
                    };
                    match saved {
                        Some(answer) => answers.push(answer),
                        None => answers.push(prompter.ask(&prompt.prompt, prompt.echo).await?.expose().to_owned()),
                    }
                }
                reply = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(ssh_err)?;
            }
        }
    }
    Err(CoreError::AuthFailed("the server asked too many questions".into()))
}

/// Opens the key with its saved passphrase, or one typed in the terminal when it has none.
fn decode_key(key: &SecretString, passphrase: Option<&str>) -> std::result::Result<PrivateKey, russh::keys::Error> {
    russh::keys::decode_secret_key(key.expose(), passphrase)
}

fn needs_passphrase(err: &russh::keys::Error) -> bool {
    match err {
        russh::keys::Error::KeyIsEncrypted => true,
        russh::keys::Error::SshKey(e) => matches!(e, russh::keys::ssh_key::Error::Encrypted),
        _ => false,
    }
}

async fn key_login(
    handle: &mut client::Handle<Handler>,
    user: &str,
    key: &SecretString,
    passphrase: Option<SecretString>,
    label: &str,
    methods: &MethodSet,
    prompter: &mut dyn Prompter,
) -> Result<Step> {
    if !has(methods, MethodKind::PublicKey) {
        return Err(CoreError::AuthFailed(format!(
            "the server doesn't take keys for {user} (it offers: {})",
            method_names(methods)
        )));
    }
    let private = match (
        decode_key(key, passphrase.as_ref().map(SecretString::expose)),
        passphrase,
    ) {
        (Ok(private), _) => private,
        (Err(_), Some(_)) => {
            return Err(CoreError::AuthFailed(format!(
                "the saved passphrase doesn't open the key '{label}'"
            )))
        }
        (Err(err), None) if needs_passphrase(&err) => {
            let mut opened = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    prompter.show("Wrong passphrase\r\n").await;
                }
                let typed = prompter.ask(&format!("Passphrase for key '{label}': "), false).await?;
                if let Ok(private) = decode_key(key, Some(typed.expose())) {
                    opened = Some(private);
                    break;
                }
            }
            opened.ok_or_else(|| CoreError::AuthFailed(format!("the passphrase doesn't open the key '{label}'")))?
        }
        (Err(err), None) => return Err(CoreError::AuthFailed(format!("the key '{label}' can't be read: {err}"))),
    };
    let hash = if matches!(private.algorithm(), Algorithm::Rsa { .. }) {
        handle.best_supported_rsa_hash().await.map_err(ssh_err)?.flatten()
    } else {
        None
    };
    let step = Step::from(
        handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(private), hash))
            .await
            .map_err(ssh_err)?,
    );
    match step {
        Step::Refused(_) => Err(CoreError::AuthFailed(format!(
            "the server refused the key '{label}' for {user}"
        ))),
        other => Ok(other),
    }
}

type DynAgent = AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin + 'static>>;

#[cfg(windows)]
async fn open_agent(source: &AgentSource) -> Result<DynAgent> {
    match source {
        AgentSource::NamedPipe(pipe) => AgentClient::connect_named_pipe(pipe)
            .await
            .map(AgentClient::dynamic)
            .map_err(|err| CoreError::AgentUnavailable(format!("the SSH agent at {pipe} can't be reached: {err}"))),
        AgentSource::System => {
            if let Ok(agent) = AgentClient::connect_named_pipe(OPENSSH_AGENT_PIPE).await {
                return Ok(agent.dynamic());
            }
            if let Ok(agent) = AgentClient::connect_pageant().await {
                return Ok(agent.dynamic());
            }
            Err(CoreError::AgentUnavailable(
                "no SSH agent is running. Start the \"OpenSSH Authentication Agent\" Windows service and add your key with ssh-add, or start Pageant".into(),
            ))
        }
    }
}

#[cfg(not(windows))]
async fn open_agent(source: &AgentSource) -> Result<DynAgent> {
    match source {
        AgentSource::NamedPipe(pipe) => Err(CoreError::AgentUnavailable(format!(
            "named pipe agents ({pipe}) need Windows"
        ))),
        AgentSource::System => AgentClient::connect_env()
            .await
            .map(AgentClient::dynamic)
            .map_err(|err| CoreError::AgentUnavailable(format!("no SSH agent is running: {err}"))),
    }
}

/// Tries each key the agent holds. Certificates are skipped (not in the MVP).
async fn agent_login(
    handle: &mut client::Handle<Handler>,
    user: &str,
    source: &AgentSource,
    methods: &MethodSet,
) -> Result<Step> {
    if !has(methods, MethodKind::PublicKey) {
        return Err(CoreError::AuthFailed(format!(
            "the server doesn't take keys for {user} (it offers: {})",
            method_names(methods)
        )));
    }
    let mut agent = open_agent(source).await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|err| CoreError::AgentUnavailable(format!("the SSH agent did not list its keys: {err}")))?;
    let keys: Vec<_> = identities
        .into_iter()
        .filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            AgentIdentity::Certificate { .. } => None,
        })
        .collect();
    if keys.is_empty() {
        return Err(CoreError::AgentUnavailable(
            "the SSH agent holds no keys. Add one with ssh-add".into(),
        ));
    }
    let count = keys.len();
    for key in keys {
        let hash = if matches!(key.algorithm(), Algorithm::Rsa { .. }) {
            handle.best_supported_rsa_hash().await.map_err(ssh_err)?.flatten()
        } else {
            None
        };
        let result = handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
            .map_err(|err| CoreError::AgentUnavailable(format!("the SSH agent could not sign: {err:?}")))?;
        match Step::from(result) {
            Step::Refused(_) => continue,
            other => return Ok(other),
        }
    }
    Err(CoreError::AuthFailed(format!(
        "the server refused all {count} keys in the SSH agent for {user}"
    )))
}

/// Opens a session channel with a PTY and a shell, then pumps it from a task of its own.
async fn open_pty(
    handle: client::Handle<Handler>,
    shared: Arc<Mutex<Shared>>,
    size: PtySize,
    term: &str,
) -> Result<ShellHandle> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|err| CoreError::Ssh(format!("the server did not open a session: {err}")))?;
    // Output that arrives before the replies (rare) is kept and sent first.
    let mut early: Vec<Vec<u8>> = Vec::new();
    for (what, request) in [("a terminal (PTY)", 0), ("a shell", 1)] {
        let sent = if request == 0 {
            channel
                .request_pty(true, term, u32::from(size.cols), u32::from(size.rows), 0, 0, &[])
                .await
        } else {
            channel.request_shell(true).await
        };
        sent.map_err(|err| CoreError::Ssh(format!("asking for {what} failed: {err}")))?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(CoreError::Ssh(format!("the server refused {what}")));
                }
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    early.push(data.to_vec())
                }
                Some(_) => {}
                None => {
                    let reason = locks::lock(&shared)
                        .disconnect
                        .clone()
                        .unwrap_or_else(|| "the connection closed".into());
                    return Err(CoreError::Ssh(format!("asking for {what} failed: {reason}")));
                }
            }
        }
    }

    let (input_tx, mut input_rx) = mpsc::channel::<ShellInput>(256);
    let (output_tx, output_rx) = mpsc::channel::<ShellOutput>(256);
    tokio::spawn(async move {
        for data in early {
            if output_tx.send(ShellOutput::Data(data)).await.is_err() {
                return;
            }
        }
        let mut exit_status: Option<u32> = None;
        let end = loop {
            tokio::select! {
                msg = input_rx.recv() => match msg {
                    Some(ShellInput::Data(bytes)) => {
                        // A failed write shows up as the channel closing below.
                        let _ = channel.data_bytes(bytes).await;
                    }
                    Some(ShellInput::Resize { cols, rows }) => {
                        let _ = channel.window_change(u32::from(cols), u32::from(rows), 0, 0).await;
                    }
                    Some(ShellInput::Close) | None => {
                        let _ = channel.close().await;
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                        break ShellEnd::Exited { status: exit_status };
                    }
                },
                msg = channel.wait() => match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if output_tx.send(ShellOutput::Data(data.to_vec())).await.is_err() {
                            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                            return;
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                    Some(ChannelMsg::Close) => {
                        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
                        break ShellEnd::Exited { status: exit_status };
                    }
                    Some(_) => {}
                    None => {
                        if exit_status.is_some() {
                            break ShellEnd::Exited { status: exit_status };
                        }
                        break ShellEnd::Lost { reason: disconnect_reason(&shared).await };
                    }
                },
            }
        };
        let _ = output_tx.send(ShellOutput::Closed(end)).await;
    });
    Ok(ShellHandle {
        input: input_tx,
        output: output_rx,
    })
}

/// The handler may record why the connection ended a moment after the channel closes.
async fn disconnect_reason(shared: &Arc<Mutex<Shared>>) -> String {
    for _ in 0..10 {
        if let Some(reason) = locks::lock(shared).disconnect.clone() {
            return reason;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    "the connection was lost".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_hosts_are_dialled_without_brackets() {
        assert_eq!(dial_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(dial_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(dial_host("web01.example.com"), "web01.example.com");
    }

    #[test]
    fn addresses_name_the_user_when_there_is_one() {
        let mut spec = SessionSpec {
            id: Uuid::new_v4(),
            name: "web01".into(),
            host: "web01.example.com".into(),
            port: 22,
            username: "alice".into(),
            auth: AuthMethod::Agent,
            jump: None,
            environment: Environment::None,
            startup_command: None,
        };
        assert_eq!(spec.address(), "alice@web01.example.com:22");
        spec.username.clear();
        spec.port = 2222;
        assert_eq!(spec.address(), "web01.example.com:2222");
    }

    #[test]
    fn dropped_connections_get_plain_reasons() {
        assert_eq!(
            lost_reason(&russh::Error::KeepaliveTimeout),
            "the server stopped answering keep-alives"
        );
        assert!(lost_reason(&russh::Error::Disconnect).contains("closed"));
    }
}
