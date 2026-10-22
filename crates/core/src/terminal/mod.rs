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
//! * QL-06: [`Terminals::type_secret`] types a vault password into the terminal for a sudo or su
//!   prompt. The value goes from the vault to the shell only (never the UI or the clipboard), only
//!   while the terminal shows a password prompt unless the user insists, and is scrubbed from saved
//!   output and logs like the login's. Audited with the secret's label and the session, never the value.
//! * QL-07: each pane watches its shell ([`activity::RunWatch`]) and reports a command that ran long
//!   when its prompt comes back or its output stops ([`TerminalEvent::CommandFinished`]); the UI shows a
//!   Windows notification when that tab is in the background.
//! * SS-10 ([`multiexec`]): what is typed into one terminal goes to several at once. Each pane shares
//!   what its screen shows ([`PaneScreen`]: connected, the cursor's line, a full-screen program), and
//!   whether text was typed on its line outside MultiExec, so MultiExec knows what each shell holds.
//!   QL-12 ([`record`]): each pane records a MultiExec line's output from its Enter until the prompt
//!   comes back, for the Compare panel. A command MultiExec sent doesn't notify per terminal (QL-07):
//!   MultiExec notifies once per line.
//! * SS-08 ([`files`]): SFTP on each pane's own connection: the "Files here" drawer, downloads and
//!   uploads (a command on the bus). bash and zsh report their folder through a prompt hook typed
//!   invisibly on connect ([`folder`]), so the drawer and uploads follow the shell's folder. QL-09: the
//!   drawer says which user transfers run as (the login's), and which user the shell runs as when
//!   that differs or may differ ([`shell_user`]).
//! * SS-07: a session behind jump hosts connects through each of them in turn (the adapter's chain);
//!   each hop's host key is checked and asked about like the session's own, naming the jump host, and
//!   a password typed for a jump host is kept for reconnects like the session's. Port forwards
//!   ([`tunnels`]) open on the pane's connection through the command bus, and open again after a
//!   reconnect.

pub mod activity;
pub mod files;
pub mod folder;
pub mod log;
pub mod multiexec;
pub mod output;
pub mod quick;
pub mod record;
pub mod shell_user;
pub mod tunnels;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::activity::{is_password_prompt, FinishedHow, RunWatch, WatchConfig};
use self::files::{Transfers, UploadReport, UploadRun};
use self::folder::{FolderInfo, FolderTracking, FolderWatch, PromptHook};
use self::log::{LogMessage, SessionLog};
use self::output::{SaveLayout, SavedOutput, TerminalText};
use self::quick::{QuickConnect, QuickOpened};
use self::record::RecordSlot;
use self::shell_user::{UserInfo, UserWatch};
use self::tunnels::{TunnelInfo, TunnelRun, TunnelTable};
use crate::adapters::exec_output::Scrubber;
use crate::adapters::network::{ip_literal, NetworkAdapter};
use crate::adapters::remote::forward::RemoteForwards;
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, Credentials, ExecResult, ExecSession, HostKeyVerifier, PromptShell,
    Prompter, PtySize, RemoteAdapter, RemoteFiles, SessionSpec, ShellEnd, ShellHandle, ShellInput, ShellOutput,
    ShellRequest,
};
use crate::command_bus::CommandBus;
use crate::containers::ContainerShell;
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::host_details::SpecsCollector;
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHost, KnownHosts};
use crate::locks;
use crate::policy::Tier;
use crate::presentation::Change;
use crate::sessions::SessionLibrary;
use crate::store::{NewAuditEntry, Store};
use crate::vault::{SecretId, SecretKind, SecretString, Vault};
use crate::vm_links::VmLinks;

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
/// QL-04: how often reachability is checked, in seconds (each check shows in the host's sshd log).
pub const MIN_REACHABILITY_SECS: u64 = 15;
pub const MAX_REACHABILITY_SECS: u64 = 3600;
/// QL-04: 5 minutes since 0.4.1 (60 s before), to stay out of strict fail2ban rules' way.
pub const DEFAULT_REACHABILITY_SECS: u64 = 300;
/// QL-07: the shortest and longest run that counts as long, and quiet spell that ends one, in seconds.
pub const MIN_NOTIFY_SECS: u64 = 5;
pub const MAX_NOTIFY_SECS: u64 = 3600;
/// QL-06: how long typing a vault password waits for the terminal (it may be connecting).
pub const TYPE_SECRET_WAIT: Duration = Duration::from_secs(30);

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

/// QL-07: which finished commands notify (while the tab is not on screen or Remotely is not in front).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NotifyWhen {
    /// Commands that ran at least `notify_after_secs`.
    #[default]
    Long,
    /// Any command that finishes while the user is away, whatever its length.
    Any,
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
    /// QL-04: seconds between two checks of the same host and port while it is up (a host that is
    /// down waits longer: [`crate::reachability::next_check_after`]). 5 minutes by default since
    /// 0.4.1; a value saved before is kept.
    pub reachability_secs: u64,
    /// QL-07: a Windows notification when a command in a background tab finishes.
    pub notify_finished: bool,
    /// QL-07: long commands only, or any command that finishes while the user is away.
    pub notify_when: NotifyWhen,
    /// QL-07: seconds a command must run to count as long.
    pub notify_after_secs: u64,
    /// QL-07: seconds without output, after some came, that end a run whose prompt was not
    /// recognized; 0 waits for the prompt only.
    pub notify_quiet_secs: u64,
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
            reachability_secs: DEFAULT_REACHABILITY_SECS,
            notify_finished: true,
            notify_when: NotifyWhen::Long,
            notify_after_secs: 30,
            notify_quiet_secs: 30,
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
        if !(MIN_NOTIFY_SECS..=MAX_NOTIFY_SECS).contains(&self.notify_after_secs) {
            return Err(CoreError::InvalidSetting(format!(
                "a long command must run {MIN_NOTIFY_SECS} to {MAX_NOTIFY_SECS} seconds"
            )));
        }
        if self.notify_quiet_secs != 0 && !(MIN_NOTIFY_SECS..=MAX_NOTIFY_SECS).contains(&self.notify_quiet_secs) {
            return Err(CoreError::InvalidSetting(format!(
                "the quiet spell that ends a command must be 0 (wait for the prompt) or {MIN_NOTIFY_SECS} to {MAX_NOTIFY_SECS} seconds"
            )));
        }
        Ok(())
    }

    /// QL-07: how each pane watches for runs to report. "Any command" reports every run; the UI
    /// notifies only while the user is away.
    pub fn watch(&self) -> WatchConfig {
        WatchConfig {
            enabled: self.notify_finished,
            threshold: match self.notify_when {
                NotifyWhen::Long => Duration::from_secs(self.notify_after_secs),
                NotifyWhen::Any => Duration::ZERO,
            },
            quiet: (self.notify_quiet_secs > 0).then(|| Duration::from_secs(self.notify_quiet_secs)),
        }
    }

    /// For the audit log.
    pub fn describe(&self) -> String {
        let keepalive = match self.keepalive_secs {
            0 => "keep-alive off".to_owned(),
            secs => format!("keep-alive every {secs} s"),
        };
        let on = |b: bool| if b { "on" } else { "off" };
        let which = match self.notify_when {
            NotifyWhen::Long => format!("commands of {} s or more", self.notify_after_secs),
            NotifyWhen::Any => "any command that finishes while away".to_owned(),
        };
        let notify = match (self.notify_finished, self.notify_quiet_secs) {
            (false, _) => "notifications off".to_owned(),
            (true, 0) => format!("notify after {which}"),
            (true, quiet) => format!("notify after {which} (or {quiet} s quiet)"),
        };
        format!(
            "{keepalive}, auto-reconnect {}, copy on select {}, font {} pt, {} lines of scrollback, reachability checks {} (every {} s), {notify}",
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
    /// QL-07: the long-run threshold and the quiet spell instead of the settings' (whole seconds, at
    /// least 5), so tests can use milliseconds. Whether notifications are on still comes from the
    /// settings.
    pub notify_timing: Option<(Duration, Option<Duration>)>,
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
            notify_timing: None,
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
    /// SS-10: keys for the live shell only (MultiExec). Dropped while the pane is not connected, so
    /// Enter never means "reconnect", and never given to a login prompt.
    Keys(Vec<u8>),
    /// QL-12: record the MultiExec line whose Enter comes next in `Keys`, until the prompt is back.
    Record(Arc<RecordSlot>),
    /// QL-06: a vault secret to type, followed by Enter, if the terminal shows a password prompt (or
    /// `force`). The answer says whether a prompt was showing.
    TypeSecret {
        secret: SecretString,
        force: bool,
        reply: oneshot::Sender<Result<bool>>,
        /// Not typed after this: the caller stopped waiting.
        until: Instant,
    },
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
    /// SS-07: the jump hosts the connection goes through, by session name, in the order they are
    /// connected; empty for a direct connection.
    pub via: Vec<String>,
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
    /// `jump`: SS-07, the jump host on the way that presented it, if it is not the session's own host.
    HostKeyUnknown {
        key: HostKey,
        other_key_types: Vec<String>,
        jump: Option<String>,
    },
    /// SS-05: the host key changed and the connection was blocked. [`Terminals::replace_host_key`]
    /// trusts the new key and connects again. `jump`: as for `HostKeyUnknown`.
    HostKeyChanged {
        key: HostKey,
        previous: KnownHost,
        jump: Option<String>,
    },
    /// QL-03: what is known about the host so far.
    Host {
        facts: HostFacts,
    },
    /// QL-07: a command that ran at least the threshold ended: its prompt came back, or its output
    /// stopped. The UI notifies when the tab is in the background.
    CommandFinished {
        after_secs: u64,
        how: FinishedHow,
    },
    /// SS-08: the shell's folder, or how far it is known (each new connection starts over).
    Folder {
        folder: FolderInfo,
    },
    /// SS-07: the terminal's tunnels, after any of them changed.
    Tunnels {
        tunnels: Vec<TunnelInfo>,
    },
}

/// SS-10: what a pane's screen shows now, as far as its output tells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaneScreen {
    /// A shell is up (not connecting, logging in, or waiting to reconnect).
    pub connected: bool,
    /// The line the cursor is on. Never logged and never sent to the UI.
    pub line: String,
    /// A full-screen program (xterm's alternate screen buffer: vim, less, top) is open.
    pub alternate: bool,
}

impl PaneScreen {
    pub fn at_password_prompt(&self) -> bool {
        is_password_prompt(&self.line)
    }
}

/// SS-10: what MultiExec and the command bus need to know about an open pane.
#[derive(Debug, Clone)]
pub struct PaneInfo {
    /// The saved session; `None` for a quick connection that was not saved.
    pub session_id: Option<Uuid>,
    /// The session's name, or `user@host:port (not saved)`.
    pub name: String,
    pub screen: PaneScreen,
    /// Text was typed on the shell's line outside MultiExec since its last Enter.
    pub dirty: bool,
}

/// What the job runner does in open terminals: SS-10 sends a MultiExec line's held Enter, SS-08
/// uploads files over a terminal's SFTP channel, SS-07 opens a tunnel on a terminal's connection.
#[async_trait]
pub trait TerminalActions: Send + Sync {
    /// Sends keys to the terminal's live shell. Fails when it has closed or is not connected.
    async fn send(&self, terminal_id: Uuid, keys: &[u8]) -> Result<()>;
    /// Uploads the files of a [`crate::command_bus::Command::FileUpload`], each audited as it lands.
    async fn upload(&self, run: UploadRun<'_>, cancel: &CancellationToken) -> Result<UploadReport>;
    /// Opens the forward of a [`crate::command_bus::Command::OpenTunnel`]. Returns where it listens.
    async fn open_tunnel(&self, run: TunnelRun<'_>) -> Result<String>;
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
    /// SS-07: passwords typed for jump hosts on the way, by session, kept like `remembered`.
    jump_passwords: Mutex<HashMap<Uuid, SecretString>>,
    /// SS-11: what the last connection logged in with, scrubbed from saved output and logs.
    secrets: Mutex<Vec<SecretString>>,
    /// QL-03.
    facts: Mutex<HostFacts>,
    /// QL-03: the current connection's `hostname` has answered (or failed), so what DNS finds after
    /// that is kept on the session as well.
    hostname_answered: std::sync::atomic::AtomicBool,
    /// SS-11: the session log, while one runs.
    log: Mutex<Option<SessionLog>>,
    /// QL-06: vault secrets typed into this terminal, scrubbed from saved output and logs too.
    typed: Mutex<Vec<SecretString>>,
    /// SS-10: what the screen shows now.
    screen: Mutex<PaneScreen>,
    /// SS-10: text typed on the line outside MultiExec since the last Enter or Ctrl+C.
    dirty: AtomicBool,
    /// SS-08: the live connection's files (SFTP), while connected.
    files: Mutex<Option<Arc<dyn RemoteFiles>>>,
    /// SS-08: the shell's folder.
    folder: Mutex<FolderInfo>,
    /// SS-08: the login's home folder on this connection, once asked.
    home: Mutex<Option<String>>,
    /// QL-09: the folders the drawer opened, oldest first, for its Back button.
    opened: Mutex<Vec<String>>,
    /// SS-07: the live connection's port forwards, while connected.
    forwards: Mutex<Option<Arc<dyn RemoteForwards>>>,
    /// SS-07: the tunnels and their state.
    tunnels: Mutex<TunnelTable>,
    /// SS-07: one tunnel change at a time (starting, opening, stopping, reconnecting).
    tunnel_ops: tokio::sync::Mutex<()>,
    /// The pane's events, for changes made outside its task (SS-07 tunnels opened by the job runner).
    events: mpsc::Sender<TerminalEvent>,
    /// CT-01: a shell in a container: typed instead of the session's startup command at each connection.
    container: Option<ContainerShell>,
    /// MO-13, MO-14: exec channels on the live connection, while connected.
    commands: Mutex<Option<Arc<dyn ExecSession>>>,
}

impl Control {
    fn targets(&self) -> &[Target] {
        self.target.as_slice()
    }

    /// Every secret this terminal knows, for scrubbing.
    fn known_secrets(&self) -> Vec<SecretString> {
        let mut secrets = locks::lock(&self.secrets).clone();
        secrets.extend(locks::lock(&self.remembered).clone());
        secrets.extend(locks::lock(&self.jump_passwords).values().cloned());
        secrets.extend(locks::lock(&self.typed).iter().cloned());
        secrets
    }

    fn facts(&self) -> HostFacts {
        locks::lock(&self.facts).clone()
    }

    fn screen(&self) -> PaneScreen {
        locks::lock(&self.screen).clone()
    }

    fn session_id(&self) -> Option<Uuid> {
        match &self.source {
            Source::Saved(id) => Some(*id),
            Source::Unsaved(_) => None,
        }
    }
}

/// SS-10: whether keys typed straight into a terminal leave text on its line. Enter and Ctrl+C end the
/// line; anything else (a character, an arrow key, Tab) leaves something MultiExec did not see.
fn leaves_text(was_dirty: bool, bytes: &[u8]) -> bool {
    bytes.iter().fold(was_dirty, |_, b| !matches!(*b, b'\r' | b'\n' | 0x03))
}

struct Inner {
    store: Store,
    vault: Arc<dyn Vault>,
    remote: Arc<dyn RemoteAdapter>,
    network: Arc<dyn NetworkAdapter>,
    known_hosts: Arc<KnownHosts>,
    /// QL-01: a quick connection saved as a session is linked to its VM like any new session.
    links: Arc<VmLinks>,
    open: Mutex<HashMap<Uuid, Arc<Control>>>,
    tasks: Mutex<HashMap<Uuid, JoinHandle<()>>>,
    tuning: Mutex<TerminalTuning>,
    /// QL-07: from the settings; open panes follow a change at once.
    watch: Mutex<WatchConfig>,
    /// SS-08: every pane's file transfers.
    transfers: Transfers,
    /// SS-07: the command bus tunnels go through (set once the core is put together).
    bus: OnceLock<Weak<CommandBus>>,
    /// MO-13: reads a saved session's facts when one of its terminals connects.
    specs: OnceLock<SpecsCollector>,
}

/// A pane about to open.
struct NewPane {
    source: Source,
    target: Option<Target>,
    name: String,
    remembered: Option<SecretString>,
    /// SS-07: passwords typed for jump hosts (a pane opened like another).
    jump_passwords: HashMap<Uuid, SecretString>,
    /// The audit entry's action and detail.
    action: String,
    detail: String,
    /// CT-01: a shell in a container.
    container: Option<ContainerShell>,
}

/// The open terminal panes. Cloning gives another handle to the same panes.
#[derive(Clone)]
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
        links: Arc<VmLinks>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                vault,
                remote,
                network,
                known_hosts,
                links,
                open: Mutex::default(),
                tasks: Mutex::default(),
                tuning: Mutex::new(TerminalTuning::default()),
                watch: Mutex::new(TerminalSettings::default().watch()),
                transfers: Transfers::default(),
                bus: OnceLock::new(),
                specs: OnceLock::new(),
            }),
        }
    }

    /// MO-13: terminals to saved sessions read the host's facts when they connect.
    pub fn set_specs(&self, collector: SpecsCollector) {
        let _ = self.inner.specs.set(collector);
    }

    /// MO-13, MO-14: exec channels on an open terminal's live connection to the session, if any.
    pub fn commands_for(&self, session_id: Uuid) -> Option<Arc<dyn ExecSession>> {
        locks::lock(&self.inner.open)
            .values()
            .filter(|control| control.session_id() == Some(session_id))
            .find_map(|control| locks::lock(&control.commands).clone().filter(|c| !c.is_closed()))
    }

    /// Settings that open panes follow at once (QL-07's notifications).
    pub fn apply_settings(&self, settings: &TerminalSettings) {
        *locks::lock(&self.inner.watch) = settings.watch();
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

    /// Opens a pane to a saved session and starts connecting, through its jump hosts if it has any
    /// (SS-07). Fails at once, opening nothing, for a key login with no key chosen or jump hosts that
    /// go round in a loop.
    pub async fn open(&self, ctx: &Context, session_id: Uuid, size: PtySize) -> Result<TerminalHandle> {
        self.open_saved(
            ctx,
            session_id,
            None,
            HashMap::new(),
            size,
            "Opened a terminal to",
            "",
            None,
        )
        .await
    }

    /// CT-01 "Open a shell": a pane to the session that types `shell.command` (`docker exec -it` into a
    /// running container, from [`crate::containers::Containers::shell`]) once the login shell is ready,
    /// instead of the session's startup command. Audited like opening a terminal, naming the container.
    pub async fn open_container_shell(
        &self,
        ctx: &Context,
        session_id: Uuid,
        shell: ContainerShell,
        size: PtySize,
    ) -> Result<TerminalHandle> {
        self.open_saved(ctx, session_id, None, HashMap::new(), size, "", "", Some(shell))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_saved(
        &self,
        ctx: &Context,
        session_id: Uuid,
        remembered: Option<SecretString>,
        jump_passwords: HashMap<Uuid, SecretString>,
        size: PtySize,
        verb: &str,
        // How the audit names a password typed before this terminal opened.
        typed_how: &str,
        container: Option<ContainerShell>,
    ) -> Result<TerminalHandle> {
        let spec = self
            .inner
            .store
            .session_spec(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
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
        let via = spec.route().map(|route| format!("; via {route}")).unwrap_or_default();
        let (action, detail) = match &container {
            Some(shell) => (
                shell.action.clone(),
                format!("{}, {auth}{via}; {}", spec.address(), shell.detail),
            ),
            None => (
                format!("{verb} '{}'", spec.name),
                format!("{}, {auth}{via}", spec.address()),
            ),
        };
        let pane = NewPane {
            source: Source::Saved(session_id),
            name: spec.name.clone(),
            action,
            detail,
            target: Some(target),
            remembered,
            jump_passwords,
            container,
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
        let library = SessionLibrary::new(self.inner.store.clone(), Arc::clone(&self.inner.links));
        if request.save.is_some() {
            let session = library.create(ctx, input).await?;
            let handle = self
                .open_saved(
                    ctx,
                    session.id,
                    typed,
                    HashMap::new(),
                    size,
                    "Opened a terminal to",
                    "password typed in the quick-connect form",
                    None,
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
            jump_passwords: HashMap::new(),
            action: format!("Opened a quick-connect terminal to {address}"),
            detail: format!("{address}, {auth}; not saved as a session"),
            container: None,
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
        let jump_passwords = locks::lock(&control.jump_passwords).clone();
        match &control.source {
            Source::Saved(session_id) => {
                // CT-01: a split of a container's shell is another shell in that container.
                let container = control.container.clone().map(|mut shell| {
                    shell.action = shell.action.replacen("Opened a shell", "Opened another shell", 1);
                    shell
                });
                self.open_saved(
                    ctx,
                    *session_id,
                    remembered,
                    jump_passwords,
                    size,
                    "Opened another terminal to",
                    "password typed earlier",
                    container,
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
                    jump_passwords,
                    action: format!("Opened another quick-connect terminal to {address}"),
                    detail: format!("{address}, {auth}; not saved as a session"),
                    container: None,
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
        self.apply_settings(&settings);
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
            jump_passwords: Mutex::new(pane.jump_passwords),
            secrets: Mutex::default(),
            facts: Mutex::default(),
            hostname_answered: std::sync::atomic::AtomicBool::new(false),
            log: Mutex::default(),
            typed: Mutex::default(),
            screen: Mutex::default(),
            dirty: AtomicBool::new(false),
            files: Mutex::default(),
            folder: Mutex::default(),
            home: Mutex::default(),
            opened: Mutex::default(),
            forwards: Mutex::default(),
            tunnels: Mutex::default(),
            tunnel_ops: tokio::sync::Mutex::default(),
            events: events_tx.clone(),
            container: pane.container,
            commands: Mutex::default(),
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
        if let Some(control) = self.control(id) {
            // SS-10: MultiExec can't know what this put on the line.
            let dirty = leaves_text(control.dirty.load(Ordering::SeqCst), &data);
            control.dirty.store(dirty, Ordering::SeqCst);
            let _ = control.input.send(TerminalInput::Data(data)).await;
        }
    }

    // ---- SS-10: MultiExec -------------------------------------------------------------------------------

    /// What MultiExec and the command bus need to know about an open pane; `None` once it has closed.
    pub fn pane_info(&self, id: Uuid) -> Option<PaneInfo> {
        let control = self.control(id)?;
        Some(PaneInfo {
            session_id: control.session_id(),
            name: match control.target {
                Some(_) => control.name.clone(),
                None => format!("{} (not saved)", control.name),
            },
            screen: control.screen(),
            dirty: control.dirty.load(Ordering::SeqCst),
        })
    }

    /// SS-10: MultiExec left text on this terminal's line (or cleared it).
    pub(crate) fn set_dirty(&self, id: Uuid, dirty: bool) {
        if let Some(control) = self.control(id) {
            control.dirty.store(dirty, Ordering::SeqCst);
        }
    }

    /// SS-10: keys typed into several terminals at once go to each live shell here. Fails when the
    /// terminal has closed or is not connected.
    pub async fn send_keys(&self, id: Uuid, keys: &[u8]) -> Result<()> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        if !control.screen().connected {
            return Err(CoreError::InvalidInput(format!(
                "{} is not connected, so nothing was typed into it.",
                quoted_name(&control)
            )));
        }
        control
            .input
            .send(TerminalInput::Keys(keys.to_vec()))
            .await
            .map_err(|_| CoreError::UnknownTarget(format!("terminal {id} has closed")))
    }

    /// QL-12: the terminal records the MultiExec line whose Enter it gets next. Sent ahead of that
    /// Enter on the same input, so it is there first. A closed terminal never gets the line.
    pub(crate) async fn record(&self, slot: Arc<RecordSlot>) {
        let sent = match self.control(slot.terminal_id()) {
            Some(control) => control
                .input
                .send(TerminalInput::Record(Arc::clone(&slot)))
                .await
                .is_ok(),
            None => false,
        };
        if !sent {
            slot.not_sent("the terminal has closed");
        }
    }

    /// SS-10: a terminal as a command target, for the policy engine: its saved session's name, label
    /// and protection as they are now, or no label for a quick connection that was not saved.
    pub async fn target(&self, ctx: &Context, id: Uuid) -> Result<Target> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        let session_id = control.session_id();
        let found = match session_id {
            Some(session) => self.inner.store.find_session_target(ctx, session).await?,
            None => None,
        };
        let (name, environment, protected) = match found {
            Some(found) => found,
            None => match &control.target {
                Some(target) => (target.name.clone(), target.environment, target.protected),
                None => (format!("{} (not saved)", control.name), Default::default(), false),
            },
        };
        Ok(Target {
            target: TargetRef::Terminal {
                terminal_id: id,
                session_id,
            },
            name,
            environment,
            protected,
        })
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

    /// QL-04: the saved sessions with a terminal whose shell is up now (not connecting, or waiting to
    /// reconnect). The reachability checks leave their hosts alone.
    pub fn connected_sessions(&self) -> HashSet<Uuid> {
        locks::lock(&self.inner.open)
            .values()
            .filter(|control| control.screen().connected)
            .filter_map(|control| control.session_id())
            .collect()
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
        self.inner.store.read_only().check(Change::KnownHosts)?;
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

    // ---- QL-06: a vault password typed at a prompt -----------------------------------------------------

    /// QL-06: types a vault password or passphrase into the terminal, then Enter, for a sudo, su or
    /// key prompt. Only while the terminal shows a password prompt, unless `force`: at a shell prompt
    /// it would run as a command and stay in the shell's history. The value goes from the vault to the
    /// shell only, and from now on is scrubbed from this terminal's saved output and log. Audited with
    /// the secret's label and the session, never the value.
    pub async fn type_secret(&self, ctx: &Context, id: Uuid, secret_id: SecretId, force: bool) -> Result<()> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id}")))?;
        let meta = self
            .inner
            .vault
            .list(ctx)
            .await?
            .into_iter()
            .find(|m| m.id == secret_id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("secret {secret_id}")))?;
        if !matches!(meta.kind, SecretKind::Password | SecretKind::Passphrase) {
            return Err(CoreError::InvalidInput(
                "Only passwords and passphrases can be typed into a terminal, not private keys.".into(),
            ));
        }
        let secret = self.inner.vault.get(ctx, secret_id).await?;
        if secret.expose().contains(['\r', '\n']) {
            return Err(CoreError::InvalidInput(format!(
                "The {} '{}' holds a line break, so it can't be typed at a prompt.",
                meta.kind.label(),
                meta.label
            )));
        }
        // Scrubbed before it can show up in the output.
        let added = remember_typed(&control, &secret).await;
        let (reply, answer) = oneshot::channel();
        let input = TerminalInput::TypeSecret {
            secret,
            force,
            reply,
            until: Instant::now() + TYPE_SECRET_WAIT,
        };
        let closed = || CoreError::InvalidInput("That terminal has closed.".into());
        let outcome = match control.input.send(input).await {
            Err(_) => Err(closed()),
            Ok(()) => match tokio::time::timeout(TYPE_SECRET_WAIT, answer).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(closed()),
                Err(_) => Err(CoreError::Timeout {
                    command: "typing the password".into(),
                    seconds: TYPE_SECRET_WAIT.as_secs(),
                }),
            },
        };
        let prompt = match outcome {
            Ok(prompt) => prompt,
            Err(err) => {
                if added {
                    locks::lock(&control.typed).pop();
                }
                return Err(err);
            }
        };
        let detail = if prompt {
            "at a password prompt"
        } else {
            "no password prompt was showing; typed at the user's request"
        };
        audit(
            &self.inner.store,
            ctx,
            "vault_secret_typed",
            &format!(
                "Typed the {} '{}' into the terminal to {}",
                meta.kind.label(),
                meta.label,
                quoted_name(&control)
            ),
            control.targets(),
            detail,
        )
        .await
    }
}

/// QL-06: a secret about to be typed joins the ones scrubbed from this terminal's saved output and
/// its running log. True when it was new.
async fn remember_typed(control: &Control, secret: &SecretString) -> bool {
    let added = {
        let mut typed = locks::lock(&control.typed);
        if typed.iter().any(|s| s.expose() == secret.expose()) {
            false
        } else {
            typed.push(secret.clone());
            true
        }
    };
    let log = locks::lock(&control.log).as_ref().map(|l| l.sender.clone());
    if let Some(log) = log {
        let _ = log.send(LogMessage::Secret(secret.clone())).await;
    }
    added
}

#[async_trait]
impl TerminalActions for Terminals {
    async fn send(&self, terminal_id: Uuid, keys: &[u8]) -> Result<()> {
        self.send_keys(terminal_id, keys).await
    }

    async fn upload(&self, run: UploadRun<'_>, cancel: &CancellationToken) -> Result<UploadReport> {
        self.run_upload(run, cancel).await
    }

    async fn open_tunnel(&self, run: TunnelRun<'_>) -> Result<String> {
        Terminals::open_tunnel(self, run).await
    }
}

/// Where a `select!` timer waits when there is nothing to wait for.
fn sleep_until(deadline: Option<Instant>) -> tokio::time::Sleep {
    let far = Instant::now() + Duration::from_secs(86_400 * 365);
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.unwrap_or(far)))
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

/// MO-13, MO-14: a terminal's exec channels, with what the terminal knows of its secrets scrubbed from
/// what they print.
struct ScrubbedCommands {
    inner: Arc<dyn ExecSession>,
    control: Arc<Control>,
}

#[async_trait]
impl ExecSession for ScrubbedCommands {
    async fn run(&self, script: &str, max_output: usize) -> Result<ExecResult> {
        let mut result = self.inner.run(script, max_output).await?;
        let secrets = self.control.known_secrets();
        if !secrets.is_empty() {
            result.output.stdout = scrub(&result.output.stdout, &secrets);
            result.output.stderr = scrub(&result.output.stderr, &secrets);
        }
        Ok(result)
    }

    async fn run_sudo(&self, script: &str, password: &SecretString, max_output: usize) -> Result<ExecResult> {
        self.inner.run_sudo(script, password, max_output).await
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    async fn close(&self) {}
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
    audit_entry(store, ctx, event, action, None, None, targets, detail).await
}

/// An audit entry that may name the tier and job it belongs to (SS-07: a tunnel opened by a job).
#[allow(clippy::too_many_arguments)]
async fn audit_entry(
    store: &Store,
    ctx: &Context,
    event: &str,
    action: &str,
    tier: Option<Tier>,
    job_id: Option<Uuid>,
    targets: &[Target],
    detail: &str,
) -> Result<()> {
    store
        .append_audit(
            ctx,
            NewAuditEntry {
                event,
                action,
                tier,
                job_id,
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

/// SS-01: how long a session's startup command waits for the SS-08 prompt hook at most.
const STARTUP_WAIT: Duration = Duration::from_secs(3);

/// A live shell, as the pump keeps it.
struct Live {
    input: mpsc::Sender<ShellInput>,
    /// QL-06, QL-07, SS-10: what the shell shows and whether a command runs.
    watch: RunWatch,
    /// SS-08: the prompt hook, and the folders the shell reports.
    hook: PromptHook,
    folders: FolderWatch,
    /// QL-09: who the shell runs as.
    users: UserWatch,
    /// SS-01: the startup command's lines, until typed.
    startup: Vec<String>,
    startup_until: Instant,
    /// QL-12: the MultiExec line whose Enter comes next, and the one being recorded now.
    armed: Option<Arc<RecordSlot>>,
    recording: Option<Arc<RecordSlot>>,
    /// QL-07: the command running now was sent by MultiExec, which notifies once per line instead.
    multiexec_run: bool,
}

impl Live {
    /// QL-12: MultiExec keys reached the shell. Enter starts recording the line they were armed for
    /// (ending one still running: the next line came first); Ctrl+C before it drops the arm.
    fn record_keys(&mut self, bytes: &[u8], secrets: impl FnOnce() -> Vec<SecretString>, quiet: Option<Duration>) {
        let enter = bytes.iter().position(|b| matches!(*b, b'\r' | b'\n'));
        let interrupt = bytes.iter().position(|b| *b == 0x03);
        let now = Instant::now();
        match (enter, interrupt) {
            (Some(enter), interrupt) if interrupt.is_none_or(|i| enter < i) => {
                let Some(slot) = self.armed.take() else {
                    return;
                };
                if let Some(running) = self.recording.take() {
                    running.next_line(now);
                }
                if slot.start(self.watch.line(), secrets(), quiet, now) {
                    self.recording = Some(slot);
                }
            }
            (_, Some(_)) => {
                if let Some(slot) = self.armed.take() {
                    slot.not_sent("Ctrl+C came before Enter");
                }
            }
            _ => {}
        }
    }

    /// QL-12: the recording, while it still records.
    fn recording(&mut self) -> Option<&Arc<RecordSlot>> {
        if self.recording.as_ref().is_some_and(|s| !s.recording()) {
            self.recording = None;
        }
        self.recording.as_ref()
    }
}

impl Drop for Live {
    /// QL-12: the shell is gone; so is what it was recording.
    fn drop(&mut self) {
        if let Some(slot) = self.recording.take() {
            slot.lost("the connection ended before the prompt came back");
        }
        if let Some(slot) = self.armed.take() {
            slot.lost("the connection ended before Enter was sent");
        }
    }
}

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
                Ok((shell, startup)) => {
                    connections += 1;
                    attempt = 0;
                    last_error = None;
                    self.status(TerminalStatus::Connected).await;
                    match self.pump(shell, startup).await {
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
                        locks::lock(&self.control.jump_passwords).clear();
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
        // SS-07: every tunnel closes with the terminal.
        let terminals = Terminals {
            inner: Arc::clone(&self.inner),
        };
        tunnels::closed(&terminals, &self.ctx, &self.control).await;
        // Nothing typed outlives the terminal.
        locks::lock(&self.control.remembered).take();
        locks::lock(&self.control.jump_passwords).clear();
        locks::lock(&self.control.secrets).clear();
        locks::lock(&self.control.typed).clear();
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

    /// One connection: the session as saved now, its secrets from the vault, then the adapter. Also
    /// returns the session's startup command (SS-01), which the pump types once the SS-08 prompt hook
    /// is out of the way.
    async fn connect(&mut self) -> Result<(ShellHandle, Vec<String>)> {
        let spec = self.spec().await?;
        // SS-07: the chain, as the tab and the session details show it.
        let via: Vec<String> = spec.jumps().iter().map(|j| j.name.clone()).collect();
        let route = match spec.route() {
            Some(route) => format!(" via {route}"),
            None => String::new(),
        };
        self.learn(|facts| {
            let changed = facts.via != via;
            facts.via.clone_from(&via);
            changed
        })
        .await;
        self.say(format!("\x1b[2mConnecting to {}{route}…\x1b[0m\r\n", spec.address()).into_bytes())
            .await;
        if !self.asked_dns {
            self.asked_dns = true;
            if via.is_empty() {
                self.ask_dns(&spec.host);
            } else if let Some(ip) = ip_literal(&spec.host) {
                // Behind a jump host a name means what it means there, not here: no DNS from this PC.
                self.learn(|facts| facts.learn_ip(ip, FactSource::Dns)).await;
            }
        }
        let credentials = self.credentials(&spec).await?;
        let typed = locks::lock(&self.control.jump_passwords).clone();
        let jump_credentials = crate::sessions::jump_credentials(&*self.inner.vault, &self.ctx, &spec, &typed).await?;
        let mut secrets = login_secrets(&credentials);
        secrets.extend(jump_credentials.iter().flat_map(login_secrets));
        *locks::lock(&self.control.secrets) = secrets;
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
            jump_passwords: &self.control.jump_passwords,
            jump: None,
        };
        let shell = remote
            .open_shell(
                ShellRequest {
                    session: &spec,
                    credentials,
                    jump_credentials,
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
        // SS-01: the session's startup command, typed into each new shell by the pump. CT-01: a container's
        // shell instead, in a pane opened for one.
        let startup = match &self.control.container {
            Some(shell) => vec![shell.command.clone()],
            None => spec
                .startup_command
                .as_deref()
                .map(|command| command.lines().map(str::to_owned).collect())
                .unwrap_or_default(),
        };
        if let Some(ip) = shell.peer_ip {
            self.learn(|facts| facts.learn_ip(ip, FactSource::Host)).await;
        }
        Ok((shell, startup))
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

    /// QL-07: the current notification settings.
    fn watch_config(&self) -> WatchConfig {
        let mut config = *locks::lock(&self.inner.watch);
        if let Some((threshold, quiet)) = locks::lock(&self.inner.tuning).notify_timing {
            // "Any command" (no threshold) stays that way.
            if !config.threshold.is_zero() {
                config.threshold = threshold;
            }
            config.quiet = quiet;
        }
        config
    }

    /// SS-10: shares what the live shell's screen shows now.
    fn show_screen(&self, watch: &RunWatch) {
        let mut screen = locks::lock(&self.control.screen);
        screen.connected = true;
        watch.line().clone_into(&mut screen.line);
        screen.alternate = watch.alternate();
    }

    /// QL-07: tells the UI a long command ended, unless MultiExec sent it (it notifies per line).
    async fn finished(&self, done: activity::Finished, live: &Live) {
        if live.multiexec_run {
            return;
        }
        let _ = self
            .events
            .send(TerminalEvent::CommandFinished {
                after_secs: done.after.as_secs(),
                how: done.how,
            })
            .await;
    }

    /// SS-08: changes the shell's folder as the UI knows it, and tells it when that changed.
    async fn update_folder(&self, change: impl FnOnce(&mut FolderInfo)) {
        let folder = {
            let mut folder = locks::lock(&self.control.folder);
            let before = folder.clone();
            change(&mut folder);
            if *folder == before {
                return;
            }
            folder.clone()
        };
        let _ = self.events.send(TerminalEvent::Folder { folder }).await;
    }

    /// SS-08: how far the folder is known, from the hook, unless the shell reported one already.
    async fn sync_folder(&self, hook: &PromptHook) {
        let tracking = hook.tracking();
        self.update_folder(|folder| {
            if folder.path.is_none() {
                folder.tracking = tracking;
            }
        })
        .await;
    }

    /// QL-09: who the shell runs as, as the drawer shows it.
    async fn sync_user(&self, users: &UserWatch) {
        let user = users.info().clone();
        self.update_folder(|folder| folder.user = user).await;
    }

    /// Output the user sees: the session log, QL-07's watch, MultiExec's screen, the folder the shell
    /// reports (SS-08), then the pane. False when the pane has gone away.
    async fn pass(&self, bytes: Vec<u8>, live: &mut Live) -> bool {
        if bytes.is_empty() {
            return true;
        }
        self.tee(&bytes).await;
        let now = Instant::now();
        let done = live.watch.output(&bytes, now);
        self.show_screen(&live.watch);
        // QL-12: after the screen line, which says whether the prompt is back.
        let (line, alternate) = (live.watch.line().to_owned(), live.watch.alternate());
        if let Some(slot) = live.recording() {
            slot.output(&bytes, &line, alternate, now);
        }
        live.users.output(now);
        let reports = live.folders.feed(&bytes);
        if let Some(path) = reports.folder {
            self.update_folder(|folder| {
                folder.path = Some(path);
                folder.tracking = FolderTracking::Following;
            })
            .await;
        }
        if let Some(user) = reports.user {
            if live.users.report(&user) {
                self.sync_user(&live.users).await;
            }
        }
        if self.output.send(bytes).await.is_err() {
            return false;
        }
        if let Some(done) = done {
            self.finished(done, live).await;
        }
        true
    }

    /// Moves bytes between the pane and the shell until one side ends.
    async fn pump(&mut self, shell: ShellHandle, startup: Vec<String>) -> Pump {
        let ShellHandle {
            input: shell_input,
            output: mut shell_output,
            peer_ip: _,
            hostname: mut hostname_answer,
            shell: shell_answer,
            files,
            forwards,
            commands,
        } = shell;
        // SS-08: this connection's files; the folder is learnt again. QL-09: transfers run as its login.
        let login = files.user();
        *locks::lock(&self.control.files) = Some(files);
        // SS-07: tunnels approved for this terminal open again on the new connection, and its first
        // connection asks for the session's that start with it (through the bus, so beside the shell).
        *locks::lock(&self.control.forwards) = Some(forwards);
        let terminals = Terminals {
            inner: Arc::clone(&self.inner),
        };
        tokio::spawn(tunnels::connected(
            terminals,
            self.ctx,
            self.id,
            Arc::clone(&self.control),
        ));
        // MO-13: the host's facts on an exec channel of this connection, beside the shell (never in it).
        let commands = commands.map(|inner| -> Arc<dyn ExecSession> {
            Arc::new(ScrubbedCommands {
                inner,
                control: Arc::clone(&self.control),
            })
        });
        if let (Some(exec), Some(session_id), Some(collector)) =
            (&commands, self.control.session_id(), self.inner.specs.get())
        {
            collector.on_terminal(self.ctx, session_id, Arc::clone(exec));
        }
        *locks::lock(&self.control.commands) = commands;
        locks::lock(&self.control.home).take();
        self.update_folder(|folder| {
            *folder = FolderInfo {
                user: UserInfo::connected(&login),
                ..FolderInfo::default()
            }
        })
        .await;
        let now = Instant::now();
        let live = Live {
            input: shell_input,
            // QL-06, QL-07: a new shell, watched from its first output.
            watch: RunWatch::new(self.watch_config()),
            hook: PromptHook::new(&Uuid::new_v4().simple().to_string(), now),
            folders: FolderWatch::new(),
            users: UserWatch::new(&login),
            startup,
            startup_until: now + STARTUP_WAIT,
            armed: None,
            recording: None,
            multiexec_run: false,
        };
        // SS-10: a new shell has nothing typed on its line yet.
        self.control.dirty.store(false, Ordering::SeqCst);
        self.show_screen(&live.watch);
        let end = self
            .pump_shell(live, &mut shell_output, &mut hostname_answer, shell_answer)
            .await;
        *locks::lock(&self.control.screen) = PaneScreen::default();
        locks::lock(&self.control.files).take();
        locks::lock(&self.control.forwards).take();
        locks::lock(&self.control.commands).take();
        // SS-07: open tunnels close with the connection and wait for the next one; closing the
        // terminal closes them for good (see `finish`).
        let reason = match &end {
            Pump::Closed => None,
            Pump::Reconnect => Some("the terminal reconnected".to_owned()),
            Pump::Ended(ShellEnd::Exited { .. }) => Some("the shell ended".to_owned()),
            Pump::Ended(ShellEnd::Lost { reason }) => Some(reason.clone()),
        };
        if let Some(reason) = reason {
            tunnels::disconnected(&self.inner.store, &self.ctx, &self.control, &reason).await;
        }
        end
    }

    /// SS-01: types the session's startup command once the SS-08 hook is set up or given up (or after
    /// [`STARTUP_WAIT`]), never while the hook is out and unanswered.
    async fn type_startup(&self, live: &mut Live) -> bool {
        if live.startup.is_empty() || live.hook.typing() {
            return true;
        }
        if !live.hook.settled() && Instant::now() < live.startup_until {
            return true;
        }
        // Like typing: the hook gives up or shows the prompt it held.
        let shown = live.hook.input();
        if !self.pass(shown, live).await {
            return false;
        }
        for line in std::mem::take(&mut live.startup) {
            live.users.input(b"\r");
            let _ = live
                .input
                .send(ShellInput::Data(format!("{line}\r").into_bytes()))
                .await;
        }
        self.sync_folder(&live.hook).await;
        true
    }

    /// The loop of [`Pane::pump`].
    async fn pump_shell(
        &mut self,
        mut live: Live,
        shell_output: &mut mpsc::Receiver<ShellOutput>,
        hostname_answer: &mut oneshot::Receiver<Option<String>>,
        mut shell_answer: oneshot::Receiver<Option<PromptShell>>,
    ) -> Pump {
        let mut hostname_pending = true;
        let mut shell_pending = true;
        let cancel = self.control.cancel.clone();
        loop {
            if !self.type_startup(&mut live).await {
                let _ = live.input.send(ShellInput::Close).await;
                return Pump::Closed;
            }
            live.watch.set_config(self.watch_config());
            let startup_due = (!live.startup.is_empty()).then_some(live.startup_until);
            // QL-12: the screen line decides whether quiet counts (never at a password prompt).
            let line = match live.recording() {
                Some(_) => live.watch.line().to_owned(),
                None => String::new(),
            };
            let recording_due = live.recording().and_then(|slot| slot.deadline(&line));
            let deadline = [
                live.watch.deadline(),
                live.hook.deadline(),
                live.users.deadline(),
                startup_due,
                recording_due,
            ]
            .into_iter()
            .flatten()
            .min();
            tokio::select! {
                () = cancel.cancelled() => {
                    let _ = live.input.send(ShellInput::Close).await;
                    return Pump::Closed;
                }
                () = sleep_until(deadline), if deadline.is_some() => {
                    let now = Instant::now();
                    if let Some(done) = live.watch.tick(now) {
                        self.finished(done, &live).await;
                    }
                    // QL-12: a recording that went quiet or reached its time limit ends.
                    if let Some(slot) = live.recording() {
                        slot.tick(now, &line);
                    }
                    // SS-08: the hook goes out at the first quiet prompt; what it held is shown.
                    let tick = live.hook.tick(now, live.watch.line(), live.watch.alternate());
                    if let Some(hook) = tick.type_now {
                        let _ = live.input.send(ShellInput::Data(hook)).await;
                    }
                    if !self.pass(tick.show, &mut live).await {
                        let _ = live.input.send(ShellInput::Close).await;
                        return Pump::Closed;
                    }
                    self.sync_folder(&live.hook).await;
                    // QL-09: a prompt without the hook's report after Enter: the shell switched.
                    if live.users.tick(now, live.watch.line(), live.watch.alternate()) {
                        self.sync_user(&live.users).await;
                    }
                }
                answer = &mut *hostname_answer, if hostname_pending => {
                    hostname_pending = false;
                    if let Ok(Some(name)) = answer {
                        self.learn(|facts| facts.learn_hostname(&name, FactSource::Host)).await;
                    }
                    // Without an answer, what DNS found stands (now, or when it comes).
                    self.control.hostname_answered.store(true, std::sync::atomic::Ordering::SeqCst);
                    keep_facts(&self.inner.store, &self.ctx, &self.control).await;
                }
                answer = &mut shell_answer, if shell_pending => {
                    shell_pending = false;
                    live.hook.probe(answer.ok().flatten());
                    self.sync_folder(&live.hook).await;
                }
                msg = self.input.recv() => {
                    // SS-08: the user's keys never mix with the hook: before it went out it is given up,
                    // and a prompt it held is shown first.
                    if matches!(msg, Some(TerminalInput::Data(_) | TerminalInput::Keys(_) | TerminalInput::TypeSecret { .. })) {
                        let shown = live.hook.input();
                        if !self.pass(shown, &mut live).await {
                            let _ = live.input.send(ShellInput::Close).await;
                            return Pump::Closed;
                        }
                        self.sync_folder(&live.hook).await;
                    }
                    match msg {
                        None | Some(TerminalInput::Close) => {
                            let _ = live.input.send(ShellInput::Close).await;
                            return Pump::Closed;
                        }
                        Some(TerminalInput::Data(bytes)) => {
                            // A settings change while waiting applies to this Enter already.
                            live.watch.set_config(self.watch_config());
                            let was_running = live.watch.is_running();
                            live.watch.input(&bytes, Instant::now());
                            if !was_running && live.watch.is_running() {
                                live.multiexec_run = false;
                            }
                            live.users.input(&bytes);
                            let _ = live.input.send(ShellInput::Data(bytes)).await;
                        }
                        Some(TerminalInput::Keys(bytes)) => {
                            live.watch.set_config(self.watch_config());
                            let was_running = live.watch.is_running();
                            live.watch.input(&bytes, Instant::now());
                            // QL-07: MultiExec notifies once for the line, not per terminal.
                            if !was_running && live.watch.is_running() {
                                live.multiexec_run = true;
                            }
                            live.users.input(&bytes);
                            let control = &self.control;
                            let quiet = self.watch_config().quiet;
                            live.record_keys(&bytes, || control.known_secrets(), quiet);
                            let _ = live.input.send(ShellInput::Data(bytes)).await;
                        }
                        Some(TerminalInput::Record(slot)) => {
                            if let Some(old) = live.armed.replace(slot) {
                                old.not_sent("another line came before its Enter");
                            }
                        }
                        Some(TerminalInput::TypeSecret { secret, force, reply, until }) => {
                            if Instant::now() > until {
                                continue;
                            }
                            // Checked here, where the output arrives, so the prompt can't change in between.
                            let prompt = is_password_prompt(live.watch.line());
                            if !prompt && !force {
                                let _ = reply.send(Err(CoreError::NoPasswordPrompt));
                                continue;
                            }
                            // QL-12: a line being recorded never keeps it either.
                            if let Some(slot) = live.recording() {
                                slot.add_secret(&secret);
                            }
                            let mut bytes = Zeroizing::new(secret.expose().as_bytes().to_vec());
                            bytes.push(b'\r');
                            let _ = live.input.send(ShellInput::Data(bytes.to_vec())).await;
                            live.watch.input(b"\r", Instant::now());
                            live.users.input(b"\r");
                            let _ = reply.send(Ok(prompt));
                        }
                        Some(TerminalInput::Resize { cols, rows }) => {
                            self.size = PtySize { cols, rows };
                            let _ = live.input.send(ShellInput::Resize { cols, rows }).await;
                        }
                        Some(TerminalInput::Reconnect) => {
                            let _ = live.input.send(ShellInput::Close).await;
                            self.say(notice(DIM, "Reconnecting")).await;
                            return Pump::Reconnect;
                        }
                    }
                }
                out = shell_output.recv() => match out {
                    Some(ShellOutput::Data(bytes)) => {
                        // SS-08: the hook's own echo stays hidden.
                        let shown = live.hook.output(&bytes, Instant::now());
                        if !self.pass(shown, &mut live).await {
                            let _ = live.input.send(ShellInput::Close).await;
                            return Pump::Closed;
                        }
                        self.sync_folder(&live.hook).await;
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
            Some(TerminalInput::Data(_) | TerminalInput::Keys(_)) => None,
            Some(TerminalInput::Record(slot)) => {
                slot.not_sent("not connected");
                None
            }
            Some(TerminalInput::TypeSecret { reply, .. }) => {
                let _ = reply.send(Err(CoreError::InvalidInput(
                    "This terminal is not connected, so nothing was typed. Reconnect it first.".into(),
                )));
                None
            }
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
    async fn verify(&self, key: &HostKey, jump: Option<&str>) -> Result<()> {
        let jump = jump.map(str::to_owned);
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
                        jump: jump.clone(),
                    })
                    .await;
                Err(CoreError::HostKeyChanged {
                    address: key.address(),
                    jump,
                })
            }
            HostKeyCheck::Unknown { other_key_types } => {
                let (answer, decision) = oneshot::channel();
                *locks::lock(&self.control.answer) = Some(answer);
                let _ = self
                    .events
                    .send(TerminalEvent::HostKeyUnknown {
                        key: key.clone(),
                        other_key_types,
                        jump: jump.clone(),
                    })
                    .await;
                let trusted = tokio::time::timeout(self.wait, decision)
                    .await
                    .ok()
                    .and_then(|answer| answer.ok())
                    .unwrap_or(false);
                locks::lock(&self.control.answer).take();
                if !trusted {
                    return Err(CoreError::HostKeyRejected {
                        address: key.address(),
                        jump,
                    });
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
    jump_passwords: &'a Mutex<HashMap<Uuid, SecretString>>,
    /// SS-07: the jump host logging in now, or `None` for the session itself.
    jump: Option<Uuid>,
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
                // SS-10: keys typed into several terminals are not answers to this login.
                Some(TerminalInput::Reconnect | TerminalInput::Keys(_)) => continue,
                Some(TerminalInput::Record(slot)) => {
                    slot.not_sent("still logging in");
                    continue;
                }
                Some(TerminalInput::Data(bytes)) => Zeroizing::new(bytes),
                // QL-06 at a login prompt: the vault's password answers it.
                Some(TerminalInput::TypeSecret {
                    secret,
                    force,
                    reply,
                    until,
                }) => {
                    if Instant::now() > until {
                        continue;
                    }
                    let shown = is_password_prompt(prompt);
                    if !shown && !force {
                        let _ = reply.send(Err(CoreError::NoPasswordPrompt));
                        continue;
                    }
                    let _ = reply.send(Ok(shown));
                    let _ = self.output.send(b"\r\n".to_vec()).await;
                    return Ok(secret);
                }
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

    fn hop(&mut self, session: &SessionSpec, jump: bool) {
        self.jump = jump.then_some(session.id);
    }

    fn password_accepted(&mut self, password: &SecretString) {
        match self.jump {
            Some(id) => {
                locks::lock(self.jump_passwords).insert(id, password.clone());
            }
            None => *locks::lock(self.remembered) = Some(password.clone()),
        }
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
            TerminalSettings {
                notify_after_secs: MIN_NOTIFY_SECS - 1,
                ..Default::default()
            },
            TerminalSettings {
                notify_after_secs: MAX_NOTIFY_SECS + 1,
                ..Default::default()
            },
            TerminalSettings {
                notify_quiet_secs: 1,
                ..Default::default()
            },
        ];
        for settings in bad {
            assert!(settings.validate().is_err(), "{settings:?}");
        }
        assert_eq!(
            TerminalSettings::default().describe(),
            "keep-alive every 30 s, auto-reconnect on, copy on select on, font 13 pt, 10000 lines of scrollback, \
             reachability checks auto (every 300 s), notify after commands of 30 s or more (or 30 s quiet)"
        );
        let quiet_off = TerminalSettings {
            notify_quiet_secs: 0,
            ..Default::default()
        };
        assert!(quiet_off.validate().is_ok());
        assert!(quiet_off.describe().ends_with("notify after commands of 30 s or more"));
        let off = TerminalSettings {
            notify_finished: false,
            ..Default::default()
        };
        assert!(off.describe().ends_with("notifications off"));
        assert!(!off.watch().enabled);
        assert_eq!(quiet_off.watch().quiet, None);
    }

    #[test]
    fn settings_saved_before_ql_05_still_load() {
        let old: TerminalSettings =
            serde_json::from_str(r#"{"keepaliveSecs":45,"autoReconnect":false,"copyOnSelect":true}"#).unwrap();
        assert_eq!(old.keepalive_secs, 45);
        assert_eq!(old.font_size, 13);
        assert_eq!(old.scrollback, 10_000);
        assert_eq!(old.reachability, ReachabilityMode::Auto);
        assert_eq!(old.reachability_secs, 300, "QL-04: every 5 minutes unless chosen");
        assert!(old.notify_finished, "QL-07 is on for settings saved before it");
        assert_eq!(old.notify_after_secs, 30);
        assert_eq!(
            old.notify_when,
            NotifyWhen::Long,
            "QL-07's choice: long commands, as before"
        );
    }

    #[test]
    fn a_reachability_interval_saved_before_0_4_1_is_kept() {
        let saved: TerminalSettings = serde_json::from_str(r#"{"reachability":"on","reachabilitySecs":60}"#).unwrap();
        assert_eq!(saved.reachability_secs, 60);
        assert!(saved.validate().is_ok());
        assert_eq!(TerminalSettings::default().reachability_secs, DEFAULT_REACHABILITY_SECS);
    }

    #[test]
    fn any_command_while_away_reports_every_run_and_keeps_the_threshold_for_later() {
        let any = TerminalSettings {
            notify_when: NotifyWhen::Any,
            notify_after_secs: 120,
            ..Default::default()
        };
        assert!(any.validate().is_ok());
        assert_eq!(any.watch().threshold, Duration::ZERO);
        assert_eq!(any.watch().quiet, Some(Duration::from_secs(30)));
        assert!(any
            .describe()
            .ends_with("notify after any command that finishes while away (or 30 s quiet)"));
        // The threshold stays as it was, for switching back.
        let json = serde_json::to_string(&any).unwrap();
        assert!(
            json.contains(r#""notifyWhen":"any""#) && json.contains(r#""notifyAfterSecs":120"#),
            "{json}"
        );
        let back: TerminalSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, any);
        let long = TerminalSettings {
            notify_when: NotifyWhen::Long,
            ..any
        };
        assert_eq!(long.watch().threshold, Duration::from_secs(120));

        // A run of any length then reports when its prompt comes back.
        let mut watch = RunWatch::new(any.watch());
        let t0 = Instant::now();
        watch.output(b"$ uptime", t0);
        watch.input(b"\r", t0);
        let done = watch.output(b"\r\n 10:00 up 3 days\r\n$ ", t0).unwrap();
        assert_eq!(done.how, FinishedHow::Prompt);
        assert_eq!(done.after, Duration::ZERO);
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
            address: "web01.example.com:22".into(),
            jump: Some("bastion".into()),
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
