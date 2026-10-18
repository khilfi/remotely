//! Terminal panes (SS-03): one SSH connection per pane, supervised so a dropped connection comes back
//! by itself, with its state visible to the UI at every step.
//!
//! ```text
//!   UI pane ──input (bytes, resize, reconnect, close)──► supervisor ──► remote adapter (russh)
//!           ◄──output (raw bytes)────────────────────────┘    │  ▲
//!           ◄──events (status, host key questions)───────────┘  └── vault (secrets, read per connection)
//! ```
//!
//! * Secrets are read from the vault just before each connection and go only to the adapter. A
//!   password that is not saved, a key's passphrase or a one-time code is typed in the terminal
//!   itself, PuTTY style; a typed password is kept in memory for this pane's reconnects only.
//! * SS-05: an unknown host key pauses the connection until the user answers
//!   [`Terminals::answer_host_key`]. A changed key blocks it; only [`Terminals::replace_host_key`],
//!   an explicit and audited step, trusts the new key.
//! * A dropped connection (network, keep-alive timeout, server restart) is retried with growing
//!   pauses. A shell that ended (`exit`) or a login that failed waits for the user instead.
//! * Opening and closing a terminal are audited: who, which session, when. Keystrokes and output are
//!   never logged. Interactive shells skip the approval flow; remote commands get it in BX-02.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, Credentials, HostKeyVerifier, Prompter, PtySize, RemoteAdapter,
    SessionSpec, ShellEnd, ShellHandle, ShellInput, ShellOutput, ShellRequest,
};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHost, KnownHosts};
use crate::locks;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretString, Vault};

/// The terminal settings (JSON) in the settings table.
pub const TERMINAL_SETTINGS_KEY: &str = "terminal.settings";
/// Longest keep-alive interval the settings take.
pub const MAX_KEEPALIVE_SECS: u64 = 3600;
/// Shortest keep-alive interval, so a typo can't flood a server.
pub const MIN_KEEPALIVE_SECS: u64 = 5;

/// SS-03 settings, edited on the Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TerminalSettings {
    /// Seconds without traffic before a keep-alive goes out; 0 turns them off.
    pub keepalive_secs: u64,
    /// Reconnect by itself after a dropped connection.
    pub auto_reconnect: bool,
    /// The UI copies a selection to the clipboard as soon as it is made.
    pub copy_on_select: bool,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            keepalive_secs: 30,
            auto_reconnect: true,
            copy_on_select: true,
        }
    }
}

impl TerminalSettings {
    pub fn validate(&self) -> Result<()> {
        if self.keepalive_secs != 0 && !(MIN_KEEPALIVE_SECS..=MAX_KEEPALIVE_SECS).contains(&self.keepalive_secs) {
            return Err(CoreError::InvalidSetting(format!(
                "the keep-alive interval must be 0 (off) or {MIN_KEEPALIVE_SECS} to {MAX_KEEPALIVE_SECS} seconds"
            )));
        }
        Ok(())
    }

    /// For the audit log.
    pub fn describe(&self) -> String {
        let keepalive = match self.keepalive_secs {
            0 => "keep-alive off".to_owned(),
            secs => format!("keep-alive every {secs} s"),
        };
        let on = |b: bool| if b { "on" } else { "off" };
        format!(
            "{keepalive}, auto-reconnect {}, copy on select {}",
            on(self.auto_reconnect),
            on(self.copy_on_select)
        )
    }
}

/// How connections and reconnects pace themselves. The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct TerminalTuning {
    pub connect_timeout: Duration,
    /// The pause before the first reconnect; it doubles with each try, up to `max_retry`.
    pub first_retry: Duration,
    pub max_retry: Duration,
    /// Reconnect tries before the pane gives up and waits for the user.
    pub max_attempts: u32,
    /// Overrides the keep-alive interval from the settings.
    pub keepalive_interval: Option<Duration>,
    pub keepalive_max: usize,
    pub agent: AgentSource,
    /// How long a host key question waits for an answer.
    pub host_key_wait: Duration,
}

impl Default for TerminalTuning {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            first_retry: Duration::from_secs(1),
            max_retry: Duration::from_secs(30),
            max_attempts: 10,
            keepalive_interval: None,
            keepalive_max: 3,
            agent: AgentSource::System,
            host_key_wait: Duration::from_secs(600),
        }
    }
}

impl TerminalTuning {
    fn retry_delay(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1).min(16));
        self.first_retry.saturating_mul(factor).min(self.max_retry)
    }
}

/// What a pane sends.
#[derive(Debug)]
pub enum TerminalInput {
    Data(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Connect again now (also drops a live connection first).
    Reconnect,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TerminalStatus {
    /// `attempt` 0 is a first or manual connection; 1 and up are automatic reconnects.
    Connecting {
        attempt: u32,
    },
    Connected,
    /// The connection dropped; the next try starts in `seconds`.
    Reconnecting {
        attempt: u32,
        max_attempts: u32,
        seconds: u64,
        reason: String,
    },
    /// The remote shell ended. Enter (or Reconnect) starts a new one.
    Ended {
        exit_status: Option<u32>,
    },
    /// Not connected and not trying. `code` is the error code (`host_key_changed`, `auth_failed`,
    /// `vault_locked`, ...), so the UI can offer the right next step.
    Disconnected {
        code: String,
        message: String,
    },
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TerminalEvent {
    Status {
        status: TerminalStatus,
    },
    /// SS-05: a host seen for the first time. The connection waits for [`Terminals::answer_host_key`].
    HostKeyUnknown {
        key: HostKey,
        other_key_types: Vec<String>,
    },
    /// SS-05: the host key changed and the connection was blocked. [`Terminals::replace_host_key`]
    /// trusts the new key and connects again.
    HostKeyChanged {
        key: HostKey,
        previous: KnownHost,
    },
}

/// A pane's connection, from [`Terminals::open`]. Input goes through [`Terminals`] by id.
pub struct TerminalHandle {
    pub id: Uuid,
    /// Raw bytes for xterm.js.
    pub output: mpsc::Receiver<Vec<u8>>,
    pub events: mpsc::Receiver<TerminalEvent>,
}

struct Control {
    input: mpsc::Sender<TerminalInput>,
    cancel: CancellationToken,
    target: Target,
    /// The open host key question, if any.
    answer: Mutex<Option<oneshot::Sender<bool>>>,
    /// The changed key that blocked the last connection.
    blocked: Mutex<Option<HostKey>>,
}

struct Inner {
    store: Store,
    vault: Arc<dyn Vault>,
    remote: Arc<dyn RemoteAdapter>,
    known_hosts: Arc<KnownHosts>,
    open: Mutex<HashMap<Uuid, Arc<Control>>>,
    tasks: Mutex<HashMap<Uuid, JoinHandle<()>>>,
    tuning: Mutex<TerminalTuning>,
}

/// The open terminal panes.
pub struct Terminals {
    inner: Arc<Inner>,
}

impl Terminals {
    pub fn new(
        store: Store,
        vault: Arc<dyn Vault>,
        remote: Arc<dyn RemoteAdapter>,
        known_hosts: Arc<KnownHosts>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                vault,
                remote,
                known_hosts,
                open: Mutex::default(),
                tasks: Mutex::default(),
                tuning: Mutex::new(TerminalTuning::default()),
            }),
        }
    }

    pub fn set_tuning(&self, tuning: TerminalTuning) {
        *locks::lock(&self.inner.tuning) = tuning;
    }

    pub async fn settings(&self, ctx: &Context) -> Result<TerminalSettings> {
        Ok(self
            .inner
            .store
            .get_setting::<TerminalSettings>(ctx, TERMINAL_SETTINGS_KEY)
            .await?
            .unwrap_or_default())
    }

    /// Opens a pane to a saved session and starts connecting. Fails at once, opening nothing, for a
    /// session with a jump host (SS-07, v2) or a key login with no key chosen.
    pub async fn open(&self, ctx: &Context, session_id: Uuid, size: PtySize) -> Result<TerminalHandle> {
        let spec = self
            .inner
            .store
            .session_spec(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        if let Some(jump) = &spec.jump {
            return Err(CoreError::JumpHostUnsupported {
                jump: jump.name.clone(),
            });
        }
        let target = Target {
            target: TargetRef::Session { session_id },
            name: spec.name.clone(),
            environment: spec.environment,
            protected: false,
        };
        let settings = self.settings(ctx).await?;
        let (input_tx, input_rx) = mpsc::channel(256);
        let (output_tx, output_rx) = mpsc::channel(256);
        let (events_tx, events_rx) = mpsc::channel(64);
        let id = Uuid::new_v4();
        let control = Arc::new(Control {
            input: input_tx,
            cancel: CancellationToken::new(),
            target: target.clone(),
            answer: Mutex::default(),
            blocked: Mutex::default(),
        });
        let detail = format!("{}, {}", spec.address(), describe_auth(&spec.auth));
        audit(
            &self.inner.store,
            ctx,
            "terminal_opened",
            &format!("Opened a terminal to '{}'", spec.name),
            &target,
            &detail,
        )
        .await?;
        locks::lock(&self.inner.open).insert(id, Arc::clone(&control));
        let pane = Pane {
            inner: Arc::clone(&self.inner),
            ctx: *ctx,
            id,
            session_id,
            control,
            input: input_rx,
            output: output_tx,
            events: events_tx,
            size,
            settings,
            remembered: None,
        };
        let task = tokio::spawn(pane.run());
        locks::lock(&self.inner.tasks).insert(id, task);
        Ok(TerminalHandle {
            id,
            output: output_rx,
            events: events_rx,
        })
    }

    fn control(&self, id: Uuid) -> Option<Arc<Control>> {
        locks::lock(&self.inner.open).get(&id).cloned()
    }

    async fn send(&self, id: Uuid, input: TerminalInput) {
        if let Some(control) = self.control(id) {
            let _ = control.input.send(input).await;
        }
    }

    /// Keystrokes and pastes, as raw bytes.
    pub async fn write(&self, id: Uuid, data: Vec<u8>) {
        self.send(id, TerminalInput::Data(data)).await;
    }

    pub async fn resize(&self, id: Uuid, cols: u16, rows: u16) {
        self.send(id, TerminalInput::Resize { cols, rows }).await;
    }

    pub async fn reconnect(&self, id: Uuid) {
        self.send(id, TerminalInput::Reconnect).await;
    }

    /// Ends the connection and the pane. Audited when the pane's task finishes.
    pub async fn close(&self, id: Uuid) {
        if let Some(control) = self.control(id) {
            control.cancel.cancel();
            let _ = control.input.send(TerminalInput::Close).await;
        }
    }

    /// Closes every pane and waits (briefly) for each to log its close, e.g. when the app exits.
    pub async fn close_all(&self) {
        let controls: Vec<Arc<Control>> = locks::lock(&self.inner.open).values().cloned().collect();
        for control in controls {
            control.cancel.cancel();
        }
        let tasks: Vec<JoinHandle<()>> = locks::lock(&self.inner.tasks).drain().map(|(_, t)| t).collect();
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }

    /// Panes open now.
    pub fn open_count(&self) -> usize {
        locks::lock(&self.inner.open).len()
    }

    /// SS-05: the user's answer to [`TerminalEvent::HostKeyUnknown`]. Trusting saves the key (audited).
    pub fn answer_host_key(&self, id: Uuid, trust: bool) -> Result<()> {
        let pending = self.control(id).and_then(|c| locks::lock(&c.answer).take());
        match pending {
            Some(answer) => {
                let _ = answer.send(trust);
                Ok(())
            }
            None => Err(CoreError::InvalidInput(
                "No host key question is waiting in that terminal.".into(),
            )),
        }
    }

    /// SS-05: trusts the changed key that blocked this pane's last connection (audited as a
    /// re-trust, with both fingerprints) and connects again.
    pub async fn replace_host_key(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id}")))?;
        let key = locks::lock(&control.blocked)
            .take()
            .ok_or_else(|| CoreError::InvalidInput("No changed host key is blocking that terminal.".into()))?;
        self.inner.known_hosts.trust(ctx, &key, Some(&control.target)).await?;
        let _ = control.input.send(TerminalInput::Reconnect).await;
        Ok(())
    }
}

/// For the audit log: how the session logs in, never a secret.
fn describe_auth(auth: &AuthMethod) -> &'static str {
    match auth {
        AuthMethod::Password(Some(_)) => "password from the vault",
        AuthMethod::Password(None) => "password typed in the terminal",
        AuthMethod::PrivateKey { .. } => "key from the vault",
        AuthMethod::Agent => "SSH agent",
    }
}

async fn audit(store: &Store, ctx: &Context, event: &str, action: &str, target: &Target, detail: &str) -> Result<()> {
    store
        .append_audit(
            ctx,
            NewAuditEntry {
                event,
                action,
                tier: None,
                job_id: None,
                targets: std::slice::from_ref(target),
                approval: None,
                result: None,
                detail: Some(detail),
            },
        )
        .await
        .map(drop)
}

/// Worth retrying by itself: the network or the server, not the login or a host key.
fn retryable(err: &CoreError) -> bool {
    matches!(err, CoreError::Ssh(_) | CoreError::Io(_) | CoreError::Timeout { .. })
}

/// "5 min", "1 h 20 min", for the close audit.
fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// Text for the terminal itself: CRLF line ends, in a colour.
fn notice(colour: &str, text: &str) -> Vec<u8> {
    format!("\r\n\x1b[{colour}m[{text}]\x1b[0m\r\n").into_bytes()
}

const DIM: &str = "2";
const YELLOW: &str = "33";
const RED: &str = "31";

/// What ended a live connection.
enum Pump {
    Closed,
    Reconnect,
    Ended(ShellEnd),
}

/// What the user chose while the pane waited.
#[derive(PartialEq, Eq)]
enum Wait {
    Connect,
    Close,
}

/// One pane's supervisor.
struct Pane {
    inner: Arc<Inner>,
    ctx: Context,
    id: Uuid,
    session_id: Uuid,
    control: Arc<Control>,
    input: mpsc::Receiver<TerminalInput>,
    output: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<TerminalEvent>,
    size: PtySize,
    settings: TerminalSettings,
    /// A password typed in this pane, for its reconnects. Zeroized when the pane closes.
    remembered: Option<SecretString>,
}

impl Pane {
    async fn status(&self, status: TerminalStatus) {
        let _ = self.events.send(TerminalEvent::Status { status }).await;
    }

    async fn say(&self, bytes: Vec<u8>) {
        let _ = self.output.send(bytes).await;
    }

    fn tuning(&self) -> TerminalTuning {
        locks::lock(&self.inner.tuning).clone()
    }

    async fn run(mut self) {
        let opened = Instant::now();
        let mut connections = 0u32;
        let mut last_error: Option<String> = None;
        let mut attempt = 0u32;
        loop {
            self.status(TerminalStatus::Connecting { attempt }).await;
            let cancel = self.control.cancel.clone();
            let connected = tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                result = self.connect() => Some(result),
            };
            let Some(connected) = connected else { break };
            let wait = match connected {
                Ok(shell) => {
                    connections += 1;
                    attempt = 0;
                    last_error = None;
                    self.status(TerminalStatus::Connected).await;
                    match self.pump(shell).await {
                        Pump::Closed => break,
                        Pump::Reconnect => continue,
                        Pump::Ended(ShellEnd::Exited { status }) => {
                            let text = match status {
                                Some(code) => format!("Session ended (exit status {code}). Press Enter to reconnect"),
                                None => "Session ended. Press Enter to reconnect".to_owned(),
                            };
                            self.say(notice(DIM, &text)).await;
                            self.status(TerminalStatus::Ended { exit_status: status }).await;
                            self.wait_for_user().await
                        }
                        Pump::Ended(ShellEnd::Lost { reason }) => {
                            last_error = Some(reason.clone());
                            if self.settings.auto_reconnect {
                                attempt = 1;
                                self.wait_to_retry(attempt, &reason).await
                            } else {
                                self.say(notice(
                                    YELLOW,
                                    &format!("Connection lost: {reason}. Press Enter to reconnect"),
                                ))
                                .await;
                                self.status(TerminalStatus::Disconnected {
                                    code: "connection_lost".into(),
                                    message: reason,
                                })
                                .await;
                                self.wait_for_user().await
                            }
                        }
                    }
                }
                Err(err) => {
                    let message = err.to_string();
                    last_error = Some(message.clone());
                    let tuning = self.tuning();
                    if attempt > 0 && retryable(&err) && attempt < tuning.max_attempts {
                        attempt += 1;
                        self.wait_to_retry(attempt, &message).await
                    } else {
                        attempt = 0;
                        if !matches!(err, CoreError::Cancelled) || !self.control.cancel.is_cancelled() {
                            self.say(notice(
                                RED,
                                &format!("Not connected: {message}. Press Enter to try again"),
                            ))
                            .await;
                        }
                        self.status(TerminalStatus::Disconnected {
                            code: err.code().to_owned(),
                            message,
                        })
                        .await;
                        self.wait_for_user().await
                    }
                }
            };
            if wait == Wait::Close {
                break;
            }
        }
        self.finish(opened, connections, last_error).await;
    }

    async fn finish(self, opened: Instant, connections: u32, last_error: Option<String>) {
        locks::lock(&self.inner.open).remove(&self.id);
        locks::lock(&self.inner.tasks).remove(&self.id);
        if let Some(answer) = locks::lock(&self.control.answer).take() {
            let _ = answer.send(false);
        }
        let open_for = human_duration(opened.elapsed());
        let detail = match (connections, last_error) {
            (0, Some(err)) => format!("open {open_for}; never connected: {err}"),
            (0, None) => format!("open {open_for}; never connected"),
            (1, _) => format!("open {open_for}; connected once"),
            (n, _) => format!("open {open_for}; connected {n} times (reconnects)"),
        };
        let action = format!("Closed the terminal to '{}'", self.control.target.name);
        if let Err(err) = audit(
            &self.inner.store,
            &self.ctx,
            "terminal_closed",
            &action,
            &self.control.target,
            &detail,
        )
        .await
        {
            tracing::error!(error = %err, "could not audit a terminal closing");
        }
        self.status(TerminalStatus::Closed).await;
    }

    /// One connection: the session as saved now, its secrets from the vault, then the adapter.
    async fn connect(&mut self) -> Result<ShellHandle> {
        let spec = self
            .inner
            .store
            .session_spec(&self.ctx, self.session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
        if let Some(jump) = &spec.jump {
            return Err(CoreError::JumpHostUnsupported {
                jump: jump.name.clone(),
            });
        }
        self.say(format!("\x1b[2mConnecting to {}…\x1b[0m\r\n", spec.address()).into_bytes())
            .await;
        let credentials = self.credentials(&spec).await?;
        let tuning = self.tuning();
        let keepalive = tuning.keepalive_interval.or(match self.settings.keepalive_secs {
            0 => None,
            secs => Some(Duration::from_secs(secs)),
        });
        let options = ConnectOptions {
            connect_timeout: tuning.connect_timeout,
            keepalive_interval: keepalive,
            keepalive_max: tuning.keepalive_max,
            agent: tuning.agent.clone(),
            ..ConnectOptions::default()
        };
        let verifier = Arc::new(PaneVerifier {
            known_hosts: Arc::clone(&self.inner.known_hosts),
            ctx: self.ctx,
            control: Arc::clone(&self.control),
            events: self.events.clone(),
            wait: tuning.host_key_wait,
        });
        let remote = Arc::clone(&self.inner.remote);
        let size = self.size;
        let mut prompter = PanePrompter {
            input: &mut self.input,
            output: &self.output,
            size: &mut self.size,
            remembered: &mut self.remembered,
        };
        let shell = remote
            .open_shell(
                ShellRequest {
                    session: &spec,
                    credentials,
                    size,
                    options: &options,
                    verifier,
                },
                &mut prompter,
            )
            .await?;
        if self.size != size {
            let _ = shell
                .input
                .send(ShellInput::Resize {
                    cols: self.size.cols,
                    rows: self.size.rows,
                })
                .await;
        }
        // SS-01: the session's startup command, typed into each new shell.
        if let Some(command) = &spec.startup_command {
            for line in command.lines() {
                let _ = shell
                    .input
                    .send(ShellInput::Data(format!("{line}\r").into_bytes()))
                    .await;
            }
        }
        Ok(shell)
    }

    async fn credentials(&self, spec: &SessionSpec) -> Result<Credentials> {
        crate::sessions::credentials(&*self.inner.vault, &self.ctx, spec, self.remembered.clone()).await
    }

    /// Moves bytes between the pane and the shell until one side ends.
    async fn pump(&mut self, mut shell: ShellHandle) -> Pump {
        let cancel = self.control.cancel.clone();
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    let _ = shell.input.send(ShellInput::Close).await;
                    return Pump::Closed;
                }
                msg = self.input.recv() => match msg {
                    None | Some(TerminalInput::Close) => {
                        let _ = shell.input.send(ShellInput::Close).await;
                        return Pump::Closed;
                    }
                    Some(TerminalInput::Data(bytes)) => {
                        let _ = shell.input.send(ShellInput::Data(bytes)).await;
                    }
                    Some(TerminalInput::Resize { cols, rows }) => {
                        self.size = PtySize { cols, rows };
                        let _ = shell.input.send(ShellInput::Resize { cols, rows }).await;
                    }
                    Some(TerminalInput::Reconnect) => {
                        let _ = shell.input.send(ShellInput::Close).await;
                        self.say(notice(DIM, "Reconnecting")).await;
                        return Pump::Reconnect;
                    }
                },
                out = shell.output.recv() => match out {
                    Some(ShellOutput::Data(bytes)) => {
                        if self.output.send(bytes).await.is_err() {
                            let _ = shell.input.send(ShellInput::Close).await;
                            return Pump::Closed;
                        }
                    }
                    Some(ShellOutput::Closed(end)) => return Pump::Ended(end),
                    None => return Pump::Ended(ShellEnd::Lost { reason: "the connection was lost".into() }),
                },
            }
        }
    }

    /// Shows the countdown to the next try; Enter or Reconnect tries at once.
    async fn wait_to_retry(&mut self, attempt: u32, reason: &str) -> Wait {
        let tuning = self.tuning();
        let delay = tuning.retry_delay(attempt);
        let seconds = delay.as_secs_f64().ceil() as u64;
        self.say(notice(
            YELLOW,
            &format!(
                "Connection lost: {reason}. Reconnecting in {seconds} s (try {attempt} of {}); press Enter to try now",
                tuning.max_attempts
            ),
        ))
        .await;
        self.status(TerminalStatus::Reconnecting {
            attempt,
            max_attempts: tuning.max_attempts,
            seconds,
            reason: reason.to_owned(),
        })
        .await;
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        let cancel = self.control.cancel.clone();
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Wait::Close,
                () = &mut sleep => return Wait::Connect,
                msg = self.input.recv() => match self.waiting_input(msg) {
                    Some(wait) => return wait,
                    None => continue,
                },
            }
        }
    }

    /// Waits until the user asks to connect again or closes the pane.
    async fn wait_for_user(&mut self) -> Wait {
        let cancel = self.control.cancel.clone();
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Wait::Close,
                msg = self.input.recv() => match self.waiting_input(msg) {
                    Some(wait) => return wait,
                    None => continue,
                },
            }
        }
    }

    /// Input while not connected: Enter or Reconnect connects, Close closes, the rest is dropped.
    fn waiting_input(&mut self, msg: Option<TerminalInput>) -> Option<Wait> {
        match msg {
            None | Some(TerminalInput::Close) => Some(Wait::Close),
            Some(TerminalInput::Reconnect) => Some(Wait::Connect),
            Some(TerminalInput::Data(bytes)) if bytes.contains(&b'\r') => Some(Wait::Connect),
            Some(TerminalInput::Resize { cols, rows }) => {
                self.size = PtySize { cols, rows };
                None
            }
            Some(TerminalInput::Data(_)) => None,
        }
    }
}

/// SS-05 for one pane: checks the key against the saved ones and asks the user about new ones.
struct PaneVerifier {
    known_hosts: Arc<KnownHosts>,
    ctx: Context,
    control: Arc<Control>,
    events: mpsc::Sender<TerminalEvent>,
    wait: Duration,
}

#[async_trait]
impl HostKeyVerifier for PaneVerifier {
    async fn verify(&self, key: &HostKey) -> Result<()> {
        match self.known_hosts.check(&self.ctx, key).await? {
            HostKeyCheck::Trusted => Ok(()),
            HostKeyCheck::Changed { previous } => {
                self.known_hosts
                    .record_blocked(&self.ctx, key, &previous, Some(&self.control.target))
                    .await?;
                *locks::lock(&self.control.blocked) = Some(key.clone());
                let _ = self
                    .events
                    .send(TerminalEvent::HostKeyChanged {
                        key: key.clone(),
                        previous,
                    })
                    .await;
                Err(CoreError::HostKeyChanged { address: key.address() })
            }
            HostKeyCheck::Unknown { other_key_types } => {
                let (answer, decision) = oneshot::channel();
                *locks::lock(&self.control.answer) = Some(answer);
                let _ = self
                    .events
                    .send(TerminalEvent::HostKeyUnknown {
                        key: key.clone(),
                        other_key_types,
                    })
                    .await;
                let trusted = tokio::time::timeout(self.wait, decision)
                    .await
                    .ok()
                    .and_then(|answer| answer.ok())
                    .unwrap_or(false);
                locks::lock(&self.control.answer).take();
                if !trusted {
                    return Err(CoreError::HostKeyRejected { address: key.address() });
                }
                self.known_hosts.trust(&self.ctx, key, Some(&self.control.target)).await
            }
        }
    }
}

/// Reads answers typed in the pane while a login needs them. Nothing typed here is logged.
struct PanePrompter<'a> {
    input: &'a mut mpsc::Receiver<TerminalInput>,
    output: &'a mpsc::Sender<Vec<u8>>,
    size: &'a mut PtySize,
    remembered: &'a mut Option<SecretString>,
}

/// Where the line reader is in an escape sequence (arrow keys and the like), which it skips.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Started,
    Sequence,
}

#[async_trait]
impl Prompter for PanePrompter<'_> {
    async fn ask(&mut self, prompt: &str, echo: bool) -> Result<SecretString> {
        let _ = self.output.send(prompt.replace('\n', "\r\n").into_bytes()).await;
        let mut line = Zeroizing::new(String::new());
        let mut escape = Escape::None;
        loop {
            let bytes = match self.input.recv().await {
                None | Some(TerminalInput::Close) => return Err(CoreError::Cancelled),
                Some(TerminalInput::Resize { cols, rows }) => {
                    *self.size = PtySize { cols, rows };
                    continue;
                }
                Some(TerminalInput::Reconnect) => continue,
                Some(TerminalInput::Data(bytes)) => Zeroizing::new(bytes),
            };
            let mut echoed = String::new();
            for ch in String::from_utf8_lossy(&bytes).chars() {
                match (escape, ch) {
                    (Escape::Started, '[' | 'O') => escape = Escape::Sequence,
                    (Escape::Started, _) => escape = Escape::None,
                    (Escape::Sequence, '@'..='~') => escape = Escape::None,
                    (Escape::Sequence, _) => {}
                    (Escape::None, '\x1b') => escape = Escape::Started,
                    (Escape::None, '\r' | '\n') => {
                        echoed.push_str("\r\n");
                        let _ = self.output.send(echoed.into_bytes()).await;
                        return Ok(SecretString::new(line.as_str()));
                    }
                    (Escape::None, '\x03') => {
                        let _ = self.output.send(format!("{echoed}^C\r\n").into_bytes()).await;
                        return Err(CoreError::Cancelled);
                    }
                    (Escape::None, '\x7f' | '\x08') => {
                        if line.pop().is_some() && echo {
                            echoed.push_str("\x08 \x08");
                        }
                    }
                    (Escape::None, '\x15') => {
                        if echo {
                            for _ in 0..line.chars().count() {
                                echoed.push_str("\x08 \x08");
                            }
                        }
                        line.clear();
                    }
                    (Escape::None, c) if c.is_control() => {}
                    (Escape::None, c) => {
                        line.push(c);
                        if echo {
                            echoed.push(c);
                        }
                    }
                }
            }
            if !echoed.is_empty() {
                let _ = self.output.send(echoed.into_bytes()).await;
            }
        }
    }

    async fn show(&mut self, text: &str) {
        let text = text.replace("\r\n", "\n").replace('\n', "\r\n");
        let _ = self.output.send(text.into_bytes()).await;
    }

    fn password_accepted(&mut self, password: &SecretString) {
        *self.remembered = Some(password.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_check_the_keepalive_interval() {
        assert!(TerminalSettings::default().validate().is_ok());
        for ok in [0, MIN_KEEPALIVE_SECS, 60, MAX_KEEPALIVE_SECS] {
            let s = TerminalSettings {
                keepalive_secs: ok,
                ..Default::default()
            };
            assert!(s.validate().is_ok(), "{ok}");
        }
        for bad in [1, MIN_KEEPALIVE_SECS - 1, MAX_KEEPALIVE_SECS + 1] {
            let s = TerminalSettings {
                keepalive_secs: bad,
                ..Default::default()
            };
            assert!(s.validate().is_err(), "{bad}");
        }
        assert_eq!(
            TerminalSettings::default().describe(),
            "keep-alive every 30 s, auto-reconnect on, copy on select on"
        );
    }

    #[test]
    fn reconnect_pauses_double_up_to_the_cap() {
        let tuning = TerminalTuning::default();
        let secs: Vec<u64> = (1..=8).map(|a| tuning.retry_delay(a).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(tuning.retry_delay(1000).as_secs(), 30);
    }

    #[test]
    fn only_network_failures_are_retried() {
        assert!(retryable(&CoreError::Ssh("reset".into())));
        assert!(retryable(&CoreError::Timeout {
            command: "connecting".into(),
            seconds: 15
        }));
        assert!(!retryable(&CoreError::AuthFailed("refused".into())));
        assert!(!retryable(&CoreError::HostKeyChanged {
            address: "web01.example.com:22".into()
        }));
        assert!(!retryable(&CoreError::VaultLocked));
        assert!(!retryable(&CoreError::Cancelled));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(Duration::from_secs(42)), "42 s");
        assert_eq!(human_duration(Duration::from_secs(300)), "5 min");
        assert_eq!(human_duration(Duration::from_secs(4800)), "1 h 20 min");
    }

    #[test]
    fn statuses_and_events_serialize_for_the_ui() {
        let event = TerminalEvent::Status {
            status: TerminalStatus::Reconnecting {
                attempt: 2,
                max_attempts: 10,
                seconds: 4,
                reason: "the server stopped answering keep-alives".into(),
            },
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event"], "status");
        assert_eq!(json["status"]["state"], "reconnecting");
        assert_eq!(json["status"]["maxAttempts"], 10);
    }
}
