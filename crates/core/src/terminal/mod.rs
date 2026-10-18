//! Terminal panes (SS-03): one SSH connection per pane, supervised so a dropped connection comes back
//! by itself, with its state visible to the UI at every step.
//!
//! ```text
//!   UI pane ──input (bytes, resize, reconnect, close)──► supervisor ──► remote adapter (russh)
//!           ◄──output (raw bytes)────────────────────────┘    │  ▲
//!           ◄──events (status, host, host key questions)─────┘  └── vault (secrets, read per connection)
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
//! * QL-02 ([`quick`]): a terminal to a host typed in the "New terminal" form, saved as a session or
//!   not. An unsaved one lives only as long as its terminal.
//! * QL-03: before connecting, DNS fills in the address or the name the session lacks; once
//!   connected, the address reached and the server's own `hostname` replace them
//!   ([`TerminalEvent::Host`]) and are kept on a saved session.
//! * SS-11: the UI's scrollback is saved, printed or copied with the pane's login secrets scrubbed
//!   ([`output`]); a pane can log its output to a file with timestamps ([`log`]). Saving and logging
//!   are audited with the file's path, never the output.

pub mod log;
pub mod output;
pub mod quick;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::log::{LogMessage, SessionLog};
use self::output::{SaveLayout, SavedOutput, TerminalText};
use self::quick::{QuickConnect, QuickOpened};
use crate::adapters::exec_output::Scrubber;
use crate::adapters::network::{ip_literal, NetworkAdapter};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, Credentials, HostKeyVerifier, Prompter, PtySize, RemoteAdapter,
    SessionSpec, ShellEnd, ShellHandle, ShellInput, ShellOutput, ShellRequest,
};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHost, KnownHosts};
use crate::locks;
use crate::sessions::SessionLibrary;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretString, Vault};

/// The terminal settings (JSON) in the settings table.
pub const TERMINAL_SETTINGS_KEY: &str = "terminal.settings";
/// Longest keep-alive interval the settings take.
pub const MAX_KEEPALIVE_SECS: u64 = 3600;
/// Shortest keep-alive interval, so a typo can't flood a server.
pub const MIN_KEEPALIVE_SECS: u64 = 5;
/// QL-05: terminal font sizes, in points.
pub const MIN_FONT_SIZE: u16 = 8;
pub const MAX_FONT_SIZE: u16 = 32;
/// QL-05: lines each terminal keeps to scroll back through.
pub const MIN_SCROLLBACK: u32 = 1_000;
pub const MAX_SCROLLBACK: u32 = 100_000;
/// QL-04: how often reachability is checked, in seconds.
pub const MIN_REACHABILITY_SECS: u64 = 15;
pub const MAX_REACHABILITY_SECS: u64 = 3600;

/// QL-04: whether the session tree checks each session's port in the background.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReachabilityMode {
    /// On, unless the library is large ([`crate::reachability::AUTO_MAX_SESSIONS`]).
    #[default]
    Auto,
    On,
    Off,
}

impl ReachabilityMode {
    fn describe(self) -> &'static str {
        match self {
            ReachabilityMode::Auto => "auto",
            ReachabilityMode::On => "on",
            ReachabilityMode::Off => "off",
        }
    }
}

/// SS-03 and QL-04/QL-05 settings, edited on the Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TerminalSettings {
    /// Seconds without traffic before a keep-alive goes out; 0 turns them off.
    pub keepalive_secs: u64,
    /// Reconnect by itself after a dropped connection.
    pub auto_reconnect: bool,
    /// The UI copies a selection to the clipboard as soon as it is made.
    pub copy_on_select: bool,
    /// QL-05: the font size, in points.
    pub font_size: u16,
    /// QL-05: lines each terminal keeps to scroll back through (and to copy or save, SS-11).
    pub scrollback: u32,
    /// QL-04: background TCP checks of each session's port (the dots in the session tree).
    pub reachability: ReachabilityMode,
    /// QL-04: seconds between two checks of the same session.
    pub reachability_secs: u64,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            keepalive_secs: 30,
            auto_reconnect: true,
            copy_on_select: true,
            font_size: 13,
            scrollback: 10_000,
            reachability: ReachabilityMode::Auto,
            reachability_secs: 60,
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
        if !(MIN_FONT_SIZE..=MAX_FONT_SIZE).contains(&self.font_size) {
            return Err(CoreError::InvalidSetting(format!(
                "the font size must be {MIN_FONT_SIZE} to {MAX_FONT_SIZE}"
            )));
        }
        if !(MIN_SCROLLBACK..=MAX_SCROLLBACK).contains(&self.scrollback) {
            return Err(CoreError::InvalidSetting(format!(
                "the scrollback must be {MIN_SCROLLBACK} to {MAX_SCROLLBACK} lines"
            )));
        }
        if !(MIN_REACHABILITY_SECS..=MAX_REACHABILITY_SECS).contains(&self.reachability_secs) {
            return Err(CoreError::InvalidSetting(format!(
                "reachability checks must be {MIN_REACHABILITY_SECS} to {MAX_REACHABILITY_SECS} seconds apart"
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
            "{keepalive}, auto-reconnect {}, copy on select {}, font {} pt, {} lines of scrollback, reachability checks {} (every {} s)",
            on(self.auto_reconnect),
            on(self.copy_on_select),
            self.font_size,
            self.scrollback,
            self.reachability.describe(),
            self.reachability_secs
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

/// QL-03: where a host fact came from. Later sources are more reliable and replace earlier ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FactSource {
    /// What the session says, filled in by DNS before connecting.
    Dns,
    /// The host itself: the address the connection reached, the name its `hostname` printed.
    Host,
}

/// QL-03: a terminal's host name and IP address, e.g. `web01 · 192.0.2.10`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostFacts {
    pub hostname: Option<String>,
    pub hostname_from: Option<FactSource>,
    pub ip: Option<String>,
    pub ip_from: Option<FactSource>,
}

impl HostFacts {
    /// Takes the name unless a more reliable one is known. True when that changed something.
    pub fn learn_hostname(&mut self, name: &str, from: FactSource) -> bool {
        learn(&mut self.hostname, &mut self.hostname_from, name.to_owned(), from)
    }

    /// Takes the address unless a more reliable one is known. True when that changed something.
    pub fn learn_ip(&mut self, ip: IpAddr, from: FactSource) -> bool {
        learn(&mut self.ip, &mut self.ip_from, ip.to_string(), from)
    }

    /// `web01 · 192.0.2.10`, or whichever of the two is known.
    pub fn title(&self) -> Option<String> {
        match (&self.hostname, &self.ip) {
            (Some(name), Some(ip)) if name != ip => Some(format!("{name} · {ip}")),
            (Some(name), _) => Some(name.clone()),
            (None, Some(ip)) => Some(ip.clone()),
            (None, None) => None,
        }
    }
}

/// One fact: a less reliable source never replaces a more reliable one; the same value from a more
/// reliable source confirms it.
fn learn(value: &mut Option<String>, known_from: &mut Option<FactSource>, new: String, from: FactSource) -> bool {
    if known_from.is_some_and(|known| known > from) {
        return false;
    }
    if value.as_deref() == Some(new.as_str()) && *known_from == Some(from) {
        return false;
    }
    *value = Some(new);
    *known_from = Some(from);
    true
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
    /// QL-03: what is known about the host so far.
    Host {
        facts: HostFacts,
    },
}

/// A pane's connection, from [`Terminals::open`]. Input goes through [`Terminals`] by id.
pub struct TerminalHandle {
    pub id: Uuid,
    /// Raw bytes for xterm.js.
    pub output: mpsc::Receiver<Vec<u8>>,
    pub events: mpsc::Receiver<TerminalEvent>,
}

/// Where a pane connects to.
#[derive(Clone)]
enum Source {
    /// A saved session, read again before each connection so edits apply.
    Saved(Uuid),
    /// QL-02: a quick connection that was not saved. It lives as long as the terminal.
    Unsaved(Arc<SessionSpec>),
}

struct Control {
    input: mpsc::Sender<TerminalInput>,
    cancel: CancellationToken,
    source: Source,
    /// The saved session as a command target; `None` for a quick connection that was not saved.
    target: Option<Target>,
    /// How audits and saved files name this terminal: the session's name, or `user@host:port`.
    name: String,
    /// The open host key question, if any.
    answer: Mutex<Option<oneshot::Sender<bool>>>,
    /// The changed key that blocked the last connection.
    blocked: Mutex<Option<HostKey>>,
    /// A password typed for this terminal (in the terminal itself or the quick-connect form): for its
    /// reconnects, and for another pane opened like it. Zeroized when the terminal closes.
    remembered: Mutex<Option<SecretString>>,
    /// SS-11: what the last connection logged in with, scrubbed from saved output and logs.
    secrets: Mutex<Vec<SecretString>>,
    /// QL-03.
    facts: Mutex<HostFacts>,
    /// QL-03: the current connection's `hostname` has answered (or failed), so what DNS finds after
    /// that is kept on the session as well.
    hostname_answered: std::sync::atomic::AtomicBool,
    /// SS-11: the session log, while one runs.
    log: Mutex<Option<SessionLog>>,
}

impl Control {
    fn targets(&self) -> &[Target] {
        self.target.as_slice()
    }

    /// Every secret this terminal knows, for scrubbing.
    fn known_secrets(&self) -> Vec<SecretString> {
        let mut secrets = locks::lock(&self.secrets).clone();
        secrets.extend(locks::lock(&self.remembered).clone());
        secrets
    }

    fn facts(&self) -> HostFacts {
        locks::lock(&self.facts).clone()
    }
}

struct Inner {
    store: Store,
    vault: Arc<dyn Vault>,
    remote: Arc<dyn RemoteAdapter>,
    network: Arc<dyn NetworkAdapter>,
    known_hosts: Arc<KnownHosts>,
    open: Mutex<HashMap<Uuid, Arc<Control>>>,
    tasks: Mutex<HashMap<Uuid, JoinHandle<()>>>,
    tuning: Mutex<TerminalTuning>,
}

/// A pane about to open.
struct NewPane {
    source: Source,
    target: Option<Target>,
    name: String,
    remembered: Option<SecretString>,
    /// The audit entry's action and detail.
    action: String,
    detail: String,
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
        network: Arc<dyn NetworkAdapter>,
        known_hosts: Arc<KnownHosts>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                vault,
                remote,
                network,
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
        self.open_saved(ctx, session_id, None, size, "Opened a terminal to", "")
            .await
    }

    async fn open_saved(
        &self,
        ctx: &Context,
        session_id: Uuid,
        remembered: Option<SecretString>,
        size: PtySize,
        verb: &str,
        // How the audit names a password typed before this terminal opened.
        typed_how: &str,
    ) -> Result<TerminalHandle> {
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
        let (_, environment, protected) = self.inner.store.find_session_target(ctx, session_id).await?.unwrap_or((
            spec.name.clone(),
            spec.environment,
            false,
        ));
        let target = Target {
            target: TargetRef::Session { session_id },
            name: spec.name.clone(),
            environment,
            protected,
        };
        let auth = match (&spec.auth, &remembered) {
            (AuthMethod::Password(None), Some(_)) => typed_how,
            (auth, _) => describe_auth(auth),
        };
        let pane = NewPane {
            source: Source::Saved(session_id),
            name: spec.name.clone(),
            action: format!("{verb} '{}'", spec.name),
            detail: format!("{}, {auth}", spec.address()),
            target: Some(target),
            remembered,
        };
        let handle = self.start(ctx, pane, size).await?;
        // QL-02: Recent sessions. Not worth failing the terminal over.
        if let Err(err) = self.inner.store.record_session_opened(ctx, session_id).await {
            tracing::warn!(error = %err, "could not note when a session was opened");
        }
        Ok(handle)
    }

    /// QL-02: opens a pane to a host typed in the "New terminal" form. With "Save as session" the
    /// session is created first (audited like any new session) and the pane opens to it; without,
    /// the connection lives only as long as the pane, and the history keeps where it went. A typed
    /// password is used for this pane's logins only.
    pub async fn quick_connect(&self, ctx: &Context, request: QuickConnect, size: PtySize) -> Result<QuickOpened> {
        let input = request.input()?;
        let typed = request.typed_password();
        let library = SessionLibrary::new(self.inner.store.clone());
        if request.save.is_some() {
            let session = library.create(ctx, input).await?;
            let handle = self
                .open_saved(
                    ctx,
                    session.id,
                    typed,
                    size,
                    "Opened a terminal to",
                    "password typed in the quick-connect form",
                )
                .await?;
            return Ok(QuickOpened {
                handle,
                session: Some(session),
            });
        }
        let input = library.check(ctx, None, input).await?;
        let spec = crate::store::unsaved_spec(&input)?;
        let auth = match (&spec.auth, &typed) {
            (AuthMethod::Password(None), Some(_)) => "password typed in the quick-connect form",
            (auth, _) => describe_auth(auth),
        };
        let address = spec.address();
        let pane = NewPane {
            source: Source::Unsaved(Arc::new(spec)),
            target: None,
            name: address.clone(),
            remembered: typed,
            action: format!("Opened a quick-connect terminal to {address}"),
            detail: format!("{address}, {auth}; not saved as a session"),
        };
        let handle = self.start(ctx, pane, size).await?;
        self.inner
            .store
            .remember_quick_connect(ctx, &input.host, input.port, input.username.as_deref(), &input.auth)
            .await?;
        Ok(QuickOpened { handle, session: None })
    }

    /// A second pane like an open one (a split): the same session or quick connection, and a password
    /// typed for the first one, so it is not asked again.
    pub async fn open_like(&self, ctx: &Context, id: Uuid, size: PtySize) -> Result<TerminalHandle> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id}")))?;
        let remembered = locks::lock(&control.remembered).clone();
        match &control.source {
            Source::Saved(session_id) => {
                self.open_saved(
                    ctx,
                    *session_id,
                    remembered,
                    size,
                    "Opened another terminal to",
                    "password typed earlier",
                )
                .await
            }
            Source::Unsaved(spec) => {
                let address = spec.address();
                let auth = match (&spec.auth, &remembered) {
                    (AuthMethod::Password(None), Some(_)) => "password typed earlier",
                    (auth, _) => describe_auth(auth),
                };
                let pane = NewPane {
                    source: Source::Unsaved(Arc::clone(spec)),
                    target: None,
                    name: address.clone(),
                    remembered,
                    action: format!("Opened another quick-connect terminal to {address}"),
                    detail: format!("{address}, {auth}; not saved as a session"),
                };
                self.start(ctx, pane, size).await
            }
        }
    }

    /// QL-02: quick connections not saved as sessions, newest first.
    pub async fn quick_connect_history(&self, ctx: &Context) -> Result<Vec<quick::QuickConnectEntry>> {
        self.inner.store.quick_connect_history(ctx).await
    }

    /// QL-02: forgets one history entry, or with `None` the whole history. Audited.
    pub async fn forget_quick_connects(&self, ctx: &Context, id: Option<Uuid>) -> Result<()> {
        let gone = self.inner.store.forget_quick_connects(ctx, id).await?;
        if gone == 0 {
            return Ok(());
        }
        let action = match id {
            Some(_) => "Removed a quick connection from the history",
            None => "Cleared the quick-connect history",
        };
        audit(
            &self.inner.store,
            ctx,
            "setting_changed",
            action,
            &[],
            &format!("{gone} removed"),
        )
        .await
    }

    async fn start(&self, ctx: &Context, pane: NewPane, size: PtySize) -> Result<TerminalHandle> {
        let settings = self.settings(ctx).await?;
        let (input_tx, input_rx) = mpsc::channel(256);
        let (output_tx, output_rx) = mpsc::channel(256);
        let (events_tx, events_rx) = mpsc::channel(64);
        let id = Uuid::new_v4();
        let control = Arc::new(Control {
            input: input_tx,
            cancel: CancellationToken::new(),
            source: pane.source,
            target: pane.target,
            name: pane.name,
            answer: Mutex::default(),
            blocked: Mutex::default(),
            remembered: Mutex::new(pane.remembered),
            secrets: Mutex::default(),
            facts: Mutex::default(),
            hostname_answered: std::sync::atomic::AtomicBool::new(false),
            log: Mutex::default(),
        });
        audit(
            &self.inner.store,
            ctx,
            "terminal_opened",
            &pane.action,
            control.targets(),
            &pane.detail,
        )
        .await?;
        locks::lock(&self.inner.open).insert(id, Arc::clone(&control));
        let pane = Pane {
            inner: Arc::clone(&self.inner),
            ctx: *ctx,
            id,
            control,
            input: input_rx,
            output: output_tx,
            events: events_tx,
            size,
            settings,
            asked_dns: false,
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

    /// QL-03: what is known about a pane's host so far.
    pub fn facts(&self, id: Uuid) -> Option<HostFacts> {
        self.control(id).map(|c| c.facts())
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
        self.inner.known_hosts.trust(ctx, &key, control.target.as_ref()).await?;
        let _ = control.input.send(TerminalInput::Reconnect).await;
        Ok(())
    }

    // ---- SS-11: output ----------------------------------------------------------------------------

    /// The terminals' text with each one's login secrets replaced by `[redacted]`, for copying,
    /// printing and saving. A pane that is gone has none left to scrub.
    pub fn scrub_output(&self, items: Vec<TerminalText>) -> Vec<TerminalText> {
        items
            .into_iter()
            .map(|mut item| {
                if let Some(control) = item.terminal_id.and_then(|id| self.control(id)) {
                    item.text = scrub(&item.text, &control.known_secrets());
                }
                item
            })
            .collect()
    }

    /// Saves the terminals' text: one file at `dest` (a header per terminal when there are several),
    /// or with [`SaveLayout::FilePerTerminal`] one file each in the folder `dest`. Audited with the
    /// sessions and the files, never the text.
    pub async fn save_output(
        &self,
        ctx: &Context,
        items: Vec<TerminalText>,
        layout: SaveLayout,
        dest: &Path,
    ) -> Result<SavedOutput> {
        output::check(&items)?;
        let items = self.scrub_output(items);
        let now = log::local_now();
        let mut files: Vec<PathBuf> = Vec::new();
        match layout {
            SaveLayout::OneFile => {
                let text = match items.as_slice() {
                    [one] => output::crlf(&one.text),
                    several => output::combined(several, now),
                };
                tokio::fs::write(dest, text).await?;
                files.push(dest.to_owned());
            }
            SaveLayout::FilePerTerminal => {
                if !dest.is_dir() {
                    return Err(CoreError::InvalidInput(format!("{} is not a folder.", dest.display())));
                }
                for item in &items {
                    let path = output::unique_path(dest, &output::file_name(&item.title, now, "txt"), &files);
                    tokio::fs::write(&path, output::crlf(&item.text)).await?;
                    files.push(path);
                }
            }
        }
        let (targets, names) = self.who(&items);
        let what = match items.len() {
            1 => format!("the output of {}", names[0]),
            n => format!("the output of {n} terminals"),
        };
        let action = match files.len() {
            1 => format!("Saved {what} to a file"),
            n => format!("Saved {what} to {n} files"),
        };
        let place = match (layout, files.as_slice()) {
            (SaveLayout::OneFile, [file]) => file.display().to_string(),
            _ => format!("{} files in {}", files.len(), dest.display()),
        };
        let detail = format!("{}; to {place}", list(&names));
        audit(
            &self.inner.store,
            ctx,
            "terminal_output_saved",
            &action,
            &targets,
            &detail,
        )
        .await?;
        Ok(SavedOutput {
            files: files.iter().map(|f| f.display().to_string()).collect(),
            terminals: items.len(),
        })
    }

    /// SS-11: the terminals' output went to the printer. Audited like a save, never the text.
    pub async fn record_printed(&self, ctx: &Context, items: &[TerminalText]) -> Result<()> {
        let (targets, names) = self.who(items);
        let action = match items.len() {
            1 => format!(
                "Printed the output of {}",
                names.first().map_or("a terminal", String::as_str)
            ),
            n => format!("Printed the output of {n} terminals"),
        };
        audit(
            &self.inner.store,
            ctx,
            "terminal_output_printed",
            &action,
            &targets,
            &list(&names),
        )
        .await
    }

    /// The saved sessions behind these terminals (once each) and how to name each terminal.
    fn who(&self, items: &[TerminalText]) -> (Vec<Target>, Vec<String>) {
        let mut targets: Vec<Target> = Vec::new();
        let mut names = Vec::new();
        for item in items {
            let control = item.terminal_id.and_then(|id| self.control(id));
            match control {
                Some(control) => {
                    if let Some(target) = &control.target {
                        if !targets.iter().any(|t| t.target == target.target) {
                            targets.push(target.clone());
                        }
                        names.push(format!("'{}'", control.name));
                    } else {
                        names.push(format!("{} (not saved)", control.name));
                    }
                }
                None => names.push(format!("'{}'", item.title.trim())),
            }
        }
        (targets, names)
    }

    /// SS-11: starts logging the pane's output to `path` (appended), each line with the time. Audited.
    pub async fn start_log(&self, ctx: &Context, id: Uuid, path: &Path) -> Result<()> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id}")))?;
        if locks::lock(&control.log).is_some() {
            return Err(CoreError::InvalidInput(
                "This terminal is already logging to a file.".into(),
            ));
        }
        let now = log::local_now();
        let about = match control.facts().title() {
            Some(title) => format!("{} ({title})", control.name),
            None => control.name.clone(),
        };
        let heading = format!(
            "Remotely session log of {about}, started {} {}",
            log::clock(now),
            log::offset_label(now)
        );
        let session_log = log::start(path, heading, control.known_secrets()).await?;
        *locks::lock(&control.log) = Some(session_log);
        audit(
            &self.inner.store,
            ctx,
            "terminal_log_started",
            &format!("Started logging the terminal to {} to a file", quoted_name(&control)),
            control.targets(),
            &path.display().to_string(),
        )
        .await
    }

    /// SS-11: stops the pane's log. False when it was not logging. Audited.
    pub async fn stop_log(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let Some(control) = self.control(id) else {
            return Ok(false);
        };
        stop_log(&self.inner.store, ctx, &control).await
    }

    /// SS-11: where the pane is logging to, if it is.
    pub fn log_path(&self, id: Uuid) -> Option<PathBuf> {
        self.control(id)
            .and_then(|c| locks::lock(&c.log).as_ref().map(|l| l.path.clone()))
    }
}

/// `'web01'`, or `alice@192.0.2.10:22 (not saved)`.
fn quoted_name(control: &Control) -> String {
    match control.target {
        Some(_) => format!("'{}'", control.name),
        None => format!("{} (not saved)", control.name),
    }
}

/// "a, b and 3 more".
fn list(names: &[String]) -> String {
    const SHOWN: usize = 8;
    if names.len() <= SHOWN {
        return names.join(", ");
    }
    format!("{} and {} more", names[..SHOWN].join(", "), names.len() - SHOWN)
}

fn scrub(text: &str, secrets: &[SecretString]) -> String {
    let refs: Vec<&SecretString> = secrets.iter().collect();
    let mut scrubber = Scrubber::new(&refs);
    let mut out = Vec::with_capacity(text.len());
    scrubber.push(text.as_bytes(), &mut out);
    scrubber.finish(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// QL-03: keeps what the connection saw on a saved session: the address it reached and the host's
/// name (its own, or DNS's when it did not say). An address DNS only guessed is not kept.
async fn keep_facts(store: &Store, ctx: &Context, control: &Control) {
    let Source::Saved(session_id) = &control.source else {
        return;
    };
    let facts = control.facts();
    let ip = facts.ip.as_deref().filter(|_| facts.ip_from == Some(FactSource::Host));
    if ip.is_none() && facts.hostname.is_none() {
        return;
    }
    if let Err(err) = store
        .record_host_facts(ctx, *session_id, ip, facts.hostname.as_deref())
        .await
    {
        tracing::warn!(error = %err, "could not keep what a connection saw");
    }
}

async fn stop_log(store: &Store, ctx: &Context, control: &Control) -> Result<bool> {
    let Some(session_log) = locks::lock(&control.log).take() else {
        return Ok(false);
    };
    let _ = session_log.sender.send(LogMessage::Stop).await;
    audit(
        store,
        ctx,
        "terminal_log_stopped",
        &format!("Stopped logging the terminal to {}", quoted_name(control)),
        control.targets(),
        &session_log.path.display().to_string(),
    )
    .await?;
    Ok(true)
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

async fn audit(
    store: &Store,
    ctx: &Context,
    event: &str,
    action: &str,
    targets: &[Target],
    detail: &str,
) -> Result<()> {
    store
        .append_audit(
            ctx,
            NewAuditEntry {
                event,
                action,
                tier: None,
                job_id: None,
                targets,
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

/// What a connection logs in with that may show up in its output: a password or a key's passphrase.
fn login_secrets(credentials: &Credentials) -> Vec<SecretString> {
    match credentials {
        Credentials::Password(Some(password)) => vec![password.clone()],
        Credentials::PrivateKey {
            passphrase: Some(passphrase),
            ..
        } => vec![passphrase.clone()],
        _ => Vec::new(),
    }
}

/// One pane's supervisor.
struct Pane {
    inner: Arc<Inner>,
    ctx: Context,
    id: Uuid,
    control: Arc<Control>,
    input: mpsc::Receiver<TerminalInput>,
    output: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<TerminalEvent>,
    size: PtySize,
    settings: TerminalSettings,
    /// QL-03: DNS is asked once, before the first connection.
    asked_dns: bool,
}

impl Pane {
    async fn status(&self, status: TerminalStatus) {
        let _ = self.events.send(TerminalEvent::Status { status }).await;
    }

    async fn say(&self, bytes: Vec<u8>) {
        self.tee(&bytes).await;
        let _ = self.output.send(bytes).await;
    }

    /// SS-11: a copy for the session log, while one runs. A full log queue holds the terminal up
    /// rather than lose lines.
    async fn tee(&self, bytes: &[u8]) {
        let sender = locks::lock(&self.control.log).as_ref().map(|l| l.sender.clone());
        if let Some(sender) = sender {
            let _ = sender.send(LogMessage::Output(bytes.to_vec())).await;
        }
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
                    if matches!(err, CoreError::AuthFailed(_)) {
                        // A typed password the server refused is no use for the next try: ask again.
                        locks::lock(&self.control.remembered).take();
                    }
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
        if let Err(err) = stop_log(&self.inner.store, &self.ctx, &self.control).await {
            tracing::error!(error = %err, "could not audit a session log stopping");
        }
        // Nothing typed outlives the terminal.
        locks::lock(&self.control.remembered).take();
        locks::lock(&self.control.secrets).clear();
        let open_for = human_duration(opened.elapsed());
        let detail = match (connections, last_error) {
            (0, Some(err)) => format!("open {open_for}; never connected: {err}"),
            (0, None) => format!("open {open_for}; never connected"),
            (1, _) => format!("open {open_for}; connected once"),
            (n, _) => format!("open {open_for}; connected {n} times (reconnects)"),
        };
        let action = format!("Closed the terminal to {}", quoted_name(&self.control));
        if let Err(err) = audit(
            &self.inner.store,
            &self.ctx,
            "terminal_closed",
            &action,
            self.control.targets(),
            &detail,
        )
        .await
        {
            tracing::error!(error = %err, "could not audit a terminal closing");
        }
        self.status(TerminalStatus::Closed).await;
    }

    /// The connection details: a saved session as it is saved now, or the quick connection.
    async fn spec(&self) -> Result<SessionSpec> {
        match &self.control.source {
            Source::Saved(session_id) => self
                .inner
                .store
                .session_spec(&self.ctx, *session_id)
                .await?
                .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into())),
            Source::Unsaved(spec) => Ok(SessionSpec::clone(spec)),
        }
    }

    /// One connection: the session as saved now, its secrets from the vault, then the adapter.
    async fn connect(&mut self) -> Result<ShellHandle> {
        let spec = self.spec().await?;
        if let Some(jump) = &spec.jump {
            return Err(CoreError::JumpHostUnsupported {
                jump: jump.name.clone(),
            });
        }
        self.say(format!("\x1b[2mConnecting to {}…\x1b[0m\r\n", spec.address()).into_bytes())
            .await;
        if !self.asked_dns {
            self.asked_dns = true;
            self.ask_dns(&spec.host);
        }
        let credentials = self.credentials(&spec).await?;
        *locks::lock(&self.control.secrets) = login_secrets(&credentials);
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
            remembered: &self.control.remembered,
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
        if let Some(ip) = shell.peer_ip {
            self.learn(|facts| facts.learn_ip(ip, FactSource::Host)).await;
        }
        Ok(shell)
    }

    /// QL-03: fills in what the session lacks, beside the connection so a slow DNS server never
    /// holds it up: the address of a host name, or the name of an IP address.
    fn ask_dns(&self, host: &str) {
        let network = Arc::clone(&self.inner.network);
        let control = Arc::clone(&self.control);
        let events = self.events.clone();
        let store = self.inner.store.clone();
        let ctx = self.ctx;
        let host = host.to_owned();
        tokio::spawn(async move {
            let changed = match ip_literal(&host) {
                Some(ip) => {
                    let name = network.reverse(ip).await;
                    let mut facts = locks::lock(&control.facts);
                    let ip_changed = facts.learn_ip(ip, FactSource::Dns);
                    let name_changed = name.is_some_and(|n| facts.learn_hostname(&n, FactSource::Dns));
                    ip_changed || name_changed
                }
                None => {
                    let ip = network.resolve(&host).await.ok().and_then(|ips| ips.first().copied());
                    let mut facts = locks::lock(&control.facts);
                    let name_changed = facts.learn_hostname(&host, FactSource::Dns);
                    let ip_changed = ip.is_some_and(|ip| facts.learn_ip(ip, FactSource::Dns));
                    name_changed || ip_changed
                }
            };
            if changed {
                let facts = control.facts();
                let _ = events.send(TerminalEvent::Host { facts }).await;
                // Late: the server already had its say, so this is what the session keeps.
                if control.hostname_answered.load(std::sync::atomic::Ordering::SeqCst) {
                    keep_facts(&store, &ctx, &control).await;
                }
            }
        });
    }

    /// Records a host fact; when it changed anything, tells the UI and keeps it on a saved session.
    async fn learn(&self, change: impl FnOnce(&mut HostFacts) -> bool) {
        let facts = {
            let mut facts = locks::lock(&self.control.facts);
            if !change(&mut facts) {
                return;
            }
            facts.clone()
        };
        let _ = self.events.send(TerminalEvent::Host { facts }).await;
    }

    async fn credentials(&self, spec: &SessionSpec) -> Result<Credentials> {
        let remembered = locks::lock(&self.control.remembered).clone();
        crate::sessions::credentials(&*self.inner.vault, &self.ctx, spec, remembered).await
    }

    /// Moves bytes between the pane and the shell until one side ends.
    async fn pump(&mut self, shell: ShellHandle) -> Pump {
        let ShellHandle {
            input: shell_input,
            output: mut shell_output,
            peer_ip: _,
            hostname: mut hostname_answer,
        } = shell;
        let mut hostname_pending = true;
        let cancel = self.control.cancel.clone();
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    let _ = shell_input.send(ShellInput::Close).await;
                    return Pump::Closed;
                }
                answer = &mut hostname_answer, if hostname_pending => {
                    hostname_pending = false;
                    if let Ok(Some(name)) = answer {
                        self.learn(|facts| facts.learn_hostname(&name, FactSource::Host)).await;
                    }
                    // Without an answer, what DNS found stands (now, or when it comes).
                    self.control.hostname_answered.store(true, std::sync::atomic::Ordering::SeqCst);
                    keep_facts(&self.inner.store, &self.ctx, &self.control).await;
                }
                msg = self.input.recv() => match msg {
                    None | Some(TerminalInput::Close) => {
                        let _ = shell_input.send(ShellInput::Close).await;
                        return Pump::Closed;
                    }
                    Some(TerminalInput::Data(bytes)) => {
                        let _ = shell_input.send(ShellInput::Data(bytes)).await;
                    }
                    Some(TerminalInput::Resize { cols, rows }) => {
                        self.size = PtySize { cols, rows };
                        let _ = shell_input.send(ShellInput::Resize { cols, rows }).await;
                    }
                    Some(TerminalInput::Reconnect) => {
                        let _ = shell_input.send(ShellInput::Close).await;
                        self.say(notice(DIM, "Reconnecting")).await;
                        return Pump::Reconnect;
                    }
                },
                out = shell_output.recv() => match out {
                    Some(ShellOutput::Data(bytes)) => {
                        self.tee(&bytes).await;
                        if self.output.send(bytes).await.is_err() {
                            let _ = shell_input.send(ShellInput::Close).await;
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
                    .record_blocked(&self.ctx, key, &previous, self.control.target.as_ref())
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
                self.known_hosts
                    .trust(&self.ctx, key, self.control.target.as_ref())
                    .await
            }
        }
    }
}

/// Reads answers typed in the pane while a login needs them. Nothing typed here is logged.
struct PanePrompter<'a> {
    input: &'a mut mpsc::Receiver<TerminalInput>,
    output: &'a mpsc::Sender<Vec<u8>>,
    size: &'a mut PtySize,
    remembered: &'a Mutex<Option<SecretString>>,
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
        *locks::lock(self.remembered) = Some(password.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_check_their_ranges() {
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
        let bad = [
            TerminalSettings {
                font_size: MIN_FONT_SIZE - 1,
                ..Default::default()
            },
            TerminalSettings {
                font_size: MAX_FONT_SIZE + 1,
                ..Default::default()
            },
            TerminalSettings {
                scrollback: MIN_SCROLLBACK - 1,
                ..Default::default()
            },
            TerminalSettings {
                scrollback: MAX_SCROLLBACK + 1,
                ..Default::default()
            },
            TerminalSettings {
                reachability_secs: MIN_REACHABILITY_SECS - 1,
                ..Default::default()
            },
        ];
        for settings in bad {
            assert!(settings.validate().is_err(), "{settings:?}");
        }
        assert_eq!(
            TerminalSettings::default().describe(),
            "keep-alive every 30 s, auto-reconnect on, copy on select on, font 13 pt, 10000 lines of scrollback, \
             reachability checks auto (every 60 s)"
        );
    }

    #[test]
    fn settings_saved_before_ql_05_still_load() {
        let old: TerminalSettings =
            serde_json::from_str(r#"{"keepaliveSecs":45,"autoReconnect":false,"copyOnSelect":true}"#).unwrap();
        assert_eq!(old.keepalive_secs, 45);
        assert_eq!(old.font_size, 13);
        assert_eq!(old.scrollback, 10_000);
        assert_eq!(old.reachability, ReachabilityMode::Auto);
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

        let mut facts = HostFacts::default();
        facts.learn_ip("192.0.2.10".parse().unwrap(), FactSource::Host);
        let json = serde_json::to_value(TerminalEvent::Host { facts }).unwrap();
        assert_eq!(json["event"], "host");
        assert_eq!(json["facts"]["ip"], "192.0.2.10");
        assert_eq!(json["facts"]["ipFrom"], "host");
        assert_eq!(json["facts"]["hostname"], serde_json::Value::Null);
    }

    #[test]
    fn what_the_host_says_outranks_dns() {
        let mut facts = HostFacts::default();
        assert!(facts.learn_hostname("web01.example.com", FactSource::Dns));
        assert!(facts.learn_ip("192.0.2.10".parse().unwrap(), FactSource::Dns));
        assert_eq!(facts.title().as_deref(), Some("web01.example.com · 192.0.2.10"));
        // The connection reached another address, and the server names itself.
        assert!(facts.learn_ip("192.0.2.11".parse().unwrap(), FactSource::Host));
        assert!(facts.learn_hostname("web01", FactSource::Host));
        assert_eq!(facts.title().as_deref(), Some("web01 · 192.0.2.11"));
        // A late DNS answer changes nothing; the same answer again neither.
        assert!(!facts.learn_hostname("old.example.com", FactSource::Dns));
        assert!(!facts.learn_ip("192.0.2.10".parse().unwrap(), FactSource::Dns));
        assert!(!facts.learn_hostname("web01", FactSource::Host));
        assert_eq!(facts.hostname_from, Some(FactSource::Host));
    }

    #[test]
    fn the_host_confirms_what_dns_said() {
        let mut facts = HostFacts::default();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(facts.learn_ip(ip, FactSource::Dns));
        assert!(facts.learn_ip(ip, FactSource::Host), "same address, now confirmed");
        assert_eq!(facts.ip_from, Some(FactSource::Host));
        assert!(!facts.learn_ip(ip, FactSource::Host));
    }

    #[test]
    fn titles_show_what_is_known() {
        let mut facts = HostFacts::default();
        assert_eq!(facts.title(), None);
        facts.learn_ip("192.0.2.10".parse().unwrap(), FactSource::Dns);
        assert_eq!(facts.title().as_deref(), Some("192.0.2.10"));
        facts.learn_hostname("192.0.2.10", FactSource::Dns);
        assert_eq!(facts.title().as_deref(), Some("192.0.2.10"));
    }

    #[test]
    fn scrubbing_replaces_every_secret() {
        let secret = SecretString::new(format!("pw-{}", Uuid::new_v4().simple()));
        let text = format!("echo {0}\n{0}\n", secret.expose());
        let clean = scrub(&text, std::slice::from_ref(&secret));
        assert_eq!(clean, "echo [redacted]\n[redacted]\n");
        assert_eq!(scrub("nothing here", &[]), "nothing here");
    }

    #[test]
    fn long_lists_are_cut_short() {
        let names: Vec<String> = (1..=10).map(|n| format!("web{n:02}")).collect();
        assert_eq!(list(&names[..2]), "web01, web02");
        assert!(list(&names).ends_with("web08 and 2 more"));
    }
}
