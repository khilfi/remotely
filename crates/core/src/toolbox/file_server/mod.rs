//! FD-09: the quick file server, TFTP and HTTP from one chosen file or folder of this PC, for a switch's firmware or a
//! host's config at a customer site (docs/plan-0.7.md, "Quick file server").
//!
//! * **A job on the bus.** Running it is [`crate::command_bus::Command::FileServer`]: Medium while it only serves,
//!   High with "Accept uploads" on. Never built by the UI: [`FileServers::submit`] checks the paths, the folder and
//!   the address first. The job runs as long as the server: its start and end are audited, and its output lists the
//!   requests ([`log`]: every transfer, refusals folded per client).
//! * **No path from the window.** The served file or folder and the upload folder come from the shell's dialogs,
//!   kept here and named by a token ([`FileServers::remember_pick`]), or from this workspace's last choices, checked
//!   again. Never Remotely's own data folder, anything holding it, a drive's root or the user profile's own folder
//!   ([`Runner::protect`]).
//! * **One address.** It listens on one address of this PC the user chose (an adapter's, or loopback), never on all
//!   of them. Windows Firewall may ask the first time; Remotely changes no firewall rule.
//! * **Stops.** At its time limit (30 minutes by default, 8 hours at most), Stop, the job's Cancel, a workspace
//!   switch, the vault locking, a reload of the window and Remotely closing; every socket closes with it.
//! * **One at a time.** A second server is refused while one runs.
//! * **Hostile requests.** Paths are checked as text and then on the file system ([`paths`], [`served`]); uploads go
//!   only into the chosen empty folder, capped, never replacing a file, marked as from the internet ([`uploads`]);
//!   every protocol limit is in [`tftp`] and [`http`], and [`FileServerTuning`] holds the timeouts and caps.

pub mod http;
pub mod log;
pub mod paths;
pub mod served;
pub mod tftp;
pub mod uploads;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::net_tools::NetworkTools;
use crate::command_bus::{Command, CommandBus, SubmitOutcome};
use crate::domain::{Context, TargetRef, WorkspaceId};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::save_guard::{self, Saved};
use crate::store::Store;
use crate::untrusted::path_refusal;

use log::{plural, RequestLog, STATUS_ROWS};
pub use log::{Counts, LogRow, Outcome, Protocol, RequestEntry, MAX_JOB_OUTPUT};
use served::{display_path, Served};
pub use uploads::UploadLimits;
use uploads::{size_text, Uploads, MB};

/// The time limit unless chosen.
pub const DEFAULT_MINUTES: u32 = 30;
/// The longest time limit.
pub const MAX_MINUTES: u32 = 8 * 60;
pub const DEFAULT_TFTP_PORT: u16 = 69;
pub const DEFAULT_HTTP_PORT: u16 = 8080;
/// Upload caps unless chosen, in MB.
pub const DEFAULT_MAX_FILE_MB: u64 = 2048;
pub const DEFAULT_MAX_TOTAL_MB: u64 = 4096;
/// The largest cap an upload may be given, in MB (64 GB).
pub const MAX_UPLOAD_MB: u64 = 64 * 1024;
/// FD-02: the File server tab's last choices, per workspace.
pub const LAST_KEY: &str = "fileServer.last";

/// What a [`Command::FileServer`] serves, where and for how long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileServerSpec {
    /// The file or folder served (chosen in a dialog).
    pub root: String,
    /// The address of this PC it listens on.
    pub address: IpAddr,
    /// TFTP's UDP port, or `None` for no TFTP. 0 takes any free port (tests).
    pub tftp_port: Option<u16>,
    /// HTTP's TCP port, or `None` for no HTTP.
    pub http_port: Option<u16>,
    /// The time limit.
    pub minutes: u32,
    /// "Accept uploads": where they go and how much they may take.
    #[serde(default)]
    pub uploads: Option<UploadSpec>,
}

/// Uploads into one empty folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadSpec {
    pub folder: String,
    /// The most one file may take, in MB.
    pub max_file_mb: u64,
    /// The most all of them may take, in MB.
    pub max_total_mb: u64,
}

impl FileServerSpec {
    /// Checks what was chosen, before the file system is asked anything.
    pub fn validate(&self) -> Result<()> {
        let invalid = |m: &str| Err(CoreError::InvalidInput(m.into()));
        if self.root.trim().is_empty() {
            return invalid("Choose a file or a folder to serve.");
        }
        if let Some(why) = path_refusal(&self.root) {
            return Err(CoreError::InvalidInput(format!(
                "{} {}: choose a file or folder on this PC.",
                self.root,
                why.describe()
            )));
        }
        if self.tftp_port.is_none() && self.http_port.is_none() {
            return invalid("Turn on TFTP, HTTP or both.");
        }
        if self.minutes == 0 || self.minutes > MAX_MINUTES {
            return invalid("Choose a time limit from 1 minute to 8 hours.");
        }
        if !is_listen_address(self.address) {
            return Err(CoreError::InvalidInput(format!(
                "{} isn't one address of this PC: choose the adapter to serve on.",
                self.address
            )));
        }
        if let Some(uploads) = &self.uploads {
            if uploads.folder.trim().is_empty() {
                return invalid("Choose the folder uploads go into.");
            }
            if let Some(why) = path_refusal(&uploads.folder) {
                return Err(CoreError::InvalidInput(format!(
                    "{} {}: choose a folder on this PC.",
                    uploads.folder,
                    why.describe()
                )));
            }
            if uploads.max_file_mb == 0 || uploads.max_total_mb == 0 {
                return invalid("Upload limits are at least 1 MB.");
            }
            if uploads.max_file_mb > MAX_UPLOAD_MB || uploads.max_total_mb > MAX_UPLOAD_MB {
                return invalid("Upload limits are at most 65,536 MB (64 GB).");
            }
            if uploads.max_file_mb > uploads.max_total_mb {
                return invalid("One file can't be allowed more than all uploads together.");
            }
        }
        Ok(())
    }

    /// The one target: this PC.
    pub fn targets(&self) -> Vec<TargetRef> {
        vec![TargetRef::App]
    }

    /// "TFTP (port 69) and HTTP (port 8080)".
    pub fn protocols(&self) -> String {
        let port = |p: u16| {
            if p == 0 {
                "any free port".to_owned()
            } else {
                format!("port {p}")
            }
        };
        match (self.tftp_port, self.http_port) {
            (Some(t), Some(h)) => format!("TFTP ({}) and HTTP ({})", port(t), port(h)),
            (Some(t), None) => format!("TFTP ({})", port(t)),
            (None, Some(h)) => format!("HTTP ({})", port(h)),
            (None, None) => "nothing".into(),
        }
    }

    /// "Serve C:\Images over TFTP (port 69) on 192.0.2.10 for 30 minutes, accepting uploads into C:\Uploads".
    pub fn summary(&self) -> String {
        let uploads = self
            .uploads
            .as_ref()
            .map(|u| format!(", accepting uploads into {}", u.folder))
            .unwrap_or_default();
        format!(
            "Serve {} over {} on {} for {}{uploads}",
            self.root,
            self.protocols(),
            self.address,
            minutes_text(self.minutes)
        )
    }
}

/// "30 minutes", "1 hour", "2 hours 30 minutes".
pub fn minutes_text(minutes: u32) -> String {
    let (hours, rest) = (minutes / 60, minutes % 60);
    match (hours, rest) {
        (0, m) => plural(u64::from(m), "minute", "minutes"),
        (h, 0) => plural(u64::from(h), "hour", "hours"),
        (h, m) => format!(
            "{} {}",
            plural(u64::from(h), "hour", "hours"),
            plural(u64::from(m), "minute", "minutes")
        ),
    }
}

/// An address a server may take: one address, not "all of them", a multicast group or the broadcast.
fn is_listen_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    }
}

/// Timeouts and caps (tests shorten them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileServerTuning {
    /// How long a minute of the time limit lasts.
    pub minute: Duration,
    /// How long a TFTP block waits for its answer before it is sent again.
    pub tftp_timeout: Duration,
    /// How many times a TFTP block is sent again.
    pub tftp_retries: u32,
    pub max_tftp: usize,
    pub max_tftp_per_client: usize,
    /// How long an HTTP request's head may take to arrive.
    pub http_head: Duration,
    /// How long an upload's body or a response may make no progress.
    pub http_idle: Duration,
    pub max_http: usize,
    pub max_http_per_client: usize,
    /// How often the window hears that the request list changed.
    pub change_every: Duration,
    /// Uploads per client, and the minimum rate each must keep.
    pub uploads: UploadLimits,
}

impl Default for FileServerTuning {
    fn default() -> Self {
        Self {
            minute: Duration::from_secs(60),
            tftp_timeout: Duration::from_secs(2),
            tftp_retries: 5,
            max_tftp: 8,
            max_tftp_per_client: 4,
            http_head: Duration::from_secs(10),
            http_idle: Duration::from_secs(30),
            max_http: 32,
            max_http_per_client: 8,
            change_every: Duration::from_millis(500),
            uploads: UploadLimits::default(),
        }
    }
}

/// Why a server stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StopReason {
    /// Stop, on the File server tab.
    User,
    TimeLimit,
    /// The job's Cancel (Activity).
    Cancelled,
    WorkspaceSwitched,
    VaultLocked,
    /// The window reloaded, so nobody could see the server.
    PageReloaded,
    AppClosing,
}

impl StopReason {
    pub fn describe(self, minutes: u32) -> String {
        match self {
            StopReason::User => "stopped by you".into(),
            StopReason::TimeLimit => format!("its time limit of {} ran out", minutes_text(minutes)),
            StopReason::Cancelled => "cancelled".into(),
            StopReason::WorkspaceSwitched => "stopped: another workspace was opened".into(),
            StopReason::VaultLocked => "stopped: the vault locked".into(),
            StopReason::PageReloaded => "stopped: the window reloaded".into(),
            StopReason::AppClosing => "stopped: Remotely closed".into(),
        }
    }
}

/// What the window shows of a server, running or just stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub job_id: Uuid,
    pub running: bool,
    /// What is served, as a path.
    pub served: String,
    pub folder: bool,
    /// The address it listens on (FD-03 masks it).
    pub address: String,
    /// The ports it listens on (the real ones when 0 was asked).
    pub tftp_port: Option<u16>,
    pub http_port: Option<u16>,
    /// Where clients fetch from: `http://192.0.2.10:8080/`, `tftp://192.0.2.10/fw.bin`.
    pub urls: Vec<String>,
    pub uploads: Option<UploadStatus>,
    pub started_at: String,
    /// When the time limit ends it (RFC 3339).
    pub ends_at: String,
    /// Why it stopped, once it has.
    pub stopped: Option<String>,
    pub counts: Counts,
    /// Transfers (files and listings sent, uploads received, or cut off on the way), repeats summed, the last
    /// changed first; at most 200 (`transfer_rows` says how many the job keeps).
    pub transfers: Vec<LogRow>,
    pub transfer_rows: usize,
    /// Refused requests, folded per client, the last changed first; at most 200.
    pub refusals: Vec<LogRow>,
    pub refusal_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadStatus {
    pub folder: String,
    pub max_file_mb: u64,
    pub max_total_mb: u64,
    /// Bytes taken so far (uploads under way included).
    pub used: u64,
    /// Files that arrived whole.
    pub files: usize,
}

/// An address of this PC a server can listen on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServeAddress {
    pub address: String,
    /// "Ethernet", "This PC only".
    pub name: String,
    pub loopback: bool,
}

/// What the File server tab needs to draw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileServerOptions {
    pub addresses: Vec<ServeAddress>,
    /// The last choices in this workspace.
    pub last: Option<FileServerSpec>,
    pub status: Option<ServerStatus>,
}

/// For the window (the shell forwards only the shown workspace's): read [`FileServers::status`] again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum FileServerEvent {
    Started {
        job_id: Uuid,
    },
    /// Requests came in (at most every [`FileServerTuning::change_every`]).
    Changed {
        job_id: Uuid,
    },
    Stopped {
        job_id: Uuid,
    },
}

impl FileServerEvent {
    pub fn job_id(&self) -> Uuid {
        match self {
            FileServerEvent::Started { job_id }
            | FileServerEvent::Changed { job_id }
            | FileServerEvent::Stopped { job_id } => *job_id,
        }
    }
}

/// What the server's TFTP and HTTP sides share.
pub(crate) struct Shared {
    served: Served,
    uploads: Option<Arc<Uploads>>,
    log: Mutex<RequestLog>,
    tuning: FileServerTuning,
    /// The address transfers are sent from (TFTP's transfer sockets).
    ip: IpAddr,
    /// Where HTTP listens: a request's `Host` must name it (no DNS rebinding).
    http_at: Option<SocketAddr>,
    /// A request was logged since the window last heard.
    dirty: AtomicBool,
}

impl Shared {
    fn record(&self, entry: RequestEntry) {
        locks::lock(&self.log).push(entry);
        self.dirty.store(true, Ordering::Relaxed);
    }
}

/// Transfers or connections open at once, in all and per client.
pub(crate) struct Slots {
    max: usize,
    per_client: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
}

/// One taken slot, given back when dropped.
pub(crate) struct Slot {
    slots: Arc<Slots>,
    ip: IpAddr,
}

impl Slots {
    pub(crate) fn new(max: usize, per_client: usize) -> Self {
        Self {
            max: max.max(1),
            per_client: per_client.max(1),
            open: Mutex::default(),
        }
    }

    pub(crate) fn take(self: &Arc<Self>, ip: IpAddr) -> Option<Slot> {
        let mut open = locks::lock(&self.open);
        let total: usize = open.values().sum();
        let mine = open.get(&ip).copied().unwrap_or(0);
        if total >= self.max || mine >= self.per_client {
            return None;
        }
        open.insert(ip, mine + 1);
        Some(Slot {
            slots: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = locks::lock(&self.slots.open);
        if let Some(n) = open.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&self.ip);
            }
        }
    }
}

/// A request's log entry until it is done; one cut off (the server stopped) is logged as that.
pub(crate) struct Pending {
    shared: Arc<Shared>,
    entry: Option<RequestEntry>,
}

impl Pending {
    pub(crate) fn new(shared: &Arc<Shared>, entry: RequestEntry) -> Self {
        Self {
            shared: Arc::clone(shared),
            entry: Some(entry),
        }
    }

    pub(crate) fn bytes(&mut self, bytes: u64) {
        if let Some(entry) = self.entry.as_mut() {
            entry.bytes = bytes;
        }
    }

    /// The request reached a file, a listing or an upload: it is a transfer, kept whatever comes after.
    pub(crate) fn transfer(&mut self) {
        if let Some(entry) = self.entry.as_mut() {
            entry.transfer = true;
        }
    }

    pub(crate) fn done(&mut self, outcome: Outcome, detail: &str) {
        if let Some(mut entry) = self.entry.take() {
            entry.outcome = outcome;
            entry.detail = log::clean_path(detail);
            self.shared.record(entry);
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.done(Outcome::Failed, "cut off: the server stopped");
    }
}

/// What the job keeps when the server stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    /// For the end of the job's audit entry: why it stopped, the requests, the uploads.
    pub note: String,
    /// The job's output: the request log.
    pub log: String,
}

/// The job runner's side of the file server.
#[async_trait]
pub trait FileServerActions: Send + Sync {
    /// Runs the server until it stops (Stop, its time limit, `token`, a workspace switch...).
    async fn serve(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &FileServerSpec,
        token: &CancellationToken,
    ) -> Result<ServeReport>;
}

/// The running server's fixed facts.
#[derive(Debug, Clone)]
struct Facts {
    served: String,
    folder: bool,
    address: IpAddr,
    tftp_port: Option<u16>,
    http_port: Option<u16>,
    file_name: Option<String>,
    started_at: String,
    ends_at: String,
}

struct Live {
    job_id: Uuid,
    workspace: WorkspaceId,
    stop: CancellationToken,
    reason: Arc<Mutex<Option<StopReason>>>,
    shared: Arc<Shared>,
    facts: Facts,
}

#[derive(Default)]
struct RunnerState {
    live: Option<Live>,
    /// The server that stopped last, for its workspace's tab.
    last: Option<(WorkspaceId, ServerStatus)>,
}

/// Runs servers for the job runner, and stops them.
pub struct Runner {
    state: Mutex<RunnerState>,
    events: broadcast::Sender<FileServerEvent>,
    tuning: RwLock<FileServerTuning>,
    /// Folders never served, written into or held by what is: Remotely's data folder ([`Runner::protect`]).
    protected: RwLock<Vec<PathBuf>>,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            state: Mutex::default(),
            events,
            tuning: RwLock::new(FileServerTuning::default()),
            protected: RwLock::new(Vec::new()),
        }
    }

    /// From the next server on.
    pub fn set_tuning(&self, tuning: FileServerTuning) {
        *locks::write(&self.tuning) = tuning;
    }

    /// Never serves `folder`, anything in it or anything holding it, nor writes uploads there: Remotely's data folder
    /// (the core protects its database's folder; the shell adds the logs folder).
    pub fn protect(&self, folder: &std::path::Path) {
        let real = std::fs::canonicalize(folder).unwrap_or_else(|_| std::path::absolute(folder).unwrap_or_default());
        if real.as_os_str().is_empty() {
            return;
        }
        let mut protected = locks::write(&self.protected);
        if !protected.contains(&real) {
            protected.push(real);
        }
    }

    fn protected(&self) -> Vec<PathBuf> {
        locks::read(&self.protected).clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FileServerEvent> {
        self.events.subscribe()
    }

    /// The running server's job, if one runs.
    pub fn running(&self) -> Option<Uuid> {
        locks::lock(&self.state).live.as_ref().map(|l| l.job_id)
    }

    /// Stops the server of `job_id` (only from its workspace). False when it isn't running.
    pub fn stop(&self, workspace: WorkspaceId, job_id: Uuid, reason: StopReason) -> bool {
        let state = locks::lock(&self.state);
        match &state.live {
            Some(live) if live.job_id == job_id && live.workspace == workspace => {
                locks::lock(&live.reason).get_or_insert(reason);
                live.stop.cancel();
                true
            }
            _ => false,
        }
    }

    /// Stops whatever runs; returns the jobs, to wait for.
    pub fn stop_all(&self, reason: StopReason) -> Vec<Uuid> {
        self.stop_where(reason, |_| true)
    }

    /// Stops the server if its job is one of `jobs` (what a window had open); returns the jobs stopped.
    pub fn stop_these(&self, jobs: &[Uuid], reason: StopReason) -> Vec<Uuid> {
        self.stop_where(reason, |id| jobs.contains(&id))
    }

    fn stop_where(&self, reason: StopReason, which: impl Fn(Uuid) -> bool) -> Vec<Uuid> {
        let state = locks::lock(&self.state);
        state
            .live
            .iter()
            .filter(|live| which(live.job_id))
            .map(|live| {
                locks::lock(&live.reason).get_or_insert(reason);
                live.stop.cancel();
                live.job_id
            })
            .collect()
    }

    /// The running server of `workspace`, or the one that stopped last there.
    pub fn status(&self, workspace: WorkspaceId) -> Option<ServerStatus> {
        let state = locks::lock(&self.state);
        if let Some(live) = state.live.as_ref().filter(|l| l.workspace == workspace) {
            return Some(status_of(live.job_id, &live.facts, &live.shared, None));
        }
        state
            .last
            .as_ref()
            .filter(|(w, _)| *w == workspace)
            .map(|(_, status)| status.clone())
    }

    fn emit(&self, event: FileServerEvent) {
        let _ = self.events.send(event);
    }
}

fn status_of(job_id: Uuid, facts: &Facts, shared: &Shared, stopped: Option<String>) -> ServerStatus {
    let log = locks::lock(&shared.log);
    let host = match facts.address {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    let name = facts
        .file_name
        .as_deref()
        .map(paths::percent_encode)
        .unwrap_or_default();
    let mut urls = Vec::new();
    if let Some(port) = facts.http_port {
        urls.push(format!("http://{host}:{port}/{name}"));
    }
    if let Some(port) = facts.tftp_port {
        let port = if port == DEFAULT_TFTP_PORT {
            String::new()
        } else {
            format!(":{port}")
        };
        urls.push(format!("tftp://{host}{port}/{name}"));
    }
    ServerStatus {
        job_id,
        running: stopped.is_none(),
        served: facts.served.clone(),
        folder: facts.folder,
        address: facts.address.to_string(),
        tftp_port: facts.tftp_port,
        http_port: facts.http_port,
        urls,
        uploads: shared.uploads.as_ref().map(|u| UploadStatus {
            folder: display_path(u.folder()),
            max_file_mb: u.max_file() / MB,
            max_total_mb: u.max_total() / MB,
            used: u.used(),
            files: u.done().len(),
        }),
        started_at: facts.started_at.clone(),
        ends_at: facts.ends_at.clone(),
        stopped,
        counts: log.counts(),
        transfers: log.recent_transfers(STATUS_ROWS),
        transfer_rows: log.transfer_rows(),
        refusals: log.recent_refusals(STATUS_ROWS),
        refusal_rows: log.refusal_rows(),
    }
}

fn rfc3339(at: time::OffsetDateTime) -> String {
    at.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Opens the upload folder for a server: there, a folder, empty, outside any Git working tree and outside what is
/// never served or written ([`check_place`]).
fn open_upload_folder(spec: &UploadSpec, limits: UploadLimits, protected: &[PathBuf]) -> Result<Uploads> {
    let folder = PathBuf::from(&spec.folder);
    let meta = std::fs::metadata(&folder)
        .map_err(|err| CoreError::InvalidInput(format!("{} can't take uploads: {err}", spec.folder)))?;
    if !meta.is_dir() {
        return Err(CoreError::InvalidInput(format!("{} is not a folder.", spec.folder)));
    }
    let real = std::fs::canonicalize(&folder)?;
    check_place(&real, protected, "Uploads can't go into")?;
    save_guard::refuse_repository_folder(&real, Saved::Upload)?;
    if std::fs::read_dir(&real)?.next().is_some() {
        return Err(CoreError::InvalidInput(format!(
            "{} isn't empty. Uploads go into an empty folder, so nothing in it can be replaced or mixed up: choose \
             or make an empty one.",
            spec.folder
        )));
    }
    Ok(Uploads::new(
        real,
        spec.max_file_mb * MB,
        spec.max_total_mb * MB,
        limits,
    ))
}

/// Opens what a server serves, refusing what is never served ([`check_place`]).
fn open_served(root: &str, protected: &[PathBuf]) -> Result<Served> {
    let served = Served::open(std::path::Path::new(root))?;
    let real = match &served {
        Served::Folder { root } => root.clone(),
        Served::File { path, .. } => path.clone(),
    };
    check_place(&real, protected, "Remotely doesn't serve")?;
    Ok(served)
}

/// Refuses a place (its final path) that a file server must never serve or write into: a drive's or share's root,
/// the Windows user profile's own folder, Remotely's data folder (the database, the vault, logs, WebView2's profile)
/// or anything inside it, and any folder holding it.
fn check_place(real: &std::path::Path, protected: &[PathBuf], verb: &str) -> Result<()> {
    let shown = display_path(real);
    let refused = |why: &str| Err(CoreError::InvalidInput(format!("{verb} {shown}: {why}.")));
    if real.parent().is_none() {
        return refused("it is a whole drive or share; choose a folder or a file in it");
    }
    let same = |a: &std::path::Path, b: &std::path::Path| {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    };
    let profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .and_then(|p| std::fs::canonicalize(p).ok());
    if profile.as_deref().is_some_and(|p| same(p, real)) {
        return refused("it is your whole user folder; choose a folder in it, such as Downloads");
    }
    for folder in protected {
        if paths::is_under(folder, real) {
            return refused("it is Remotely's own data (its database, vault and logs)");
        }
        if paths::is_under(real, folder) {
            return refused("it holds Remotely's own data (its database, vault and logs); choose a folder beside it");
        }
    }
    Ok(())
}

fn bind_error(what: &str, address: IpAddr, port: u16, err: &std::io::Error) -> CoreError {
    let advice = match err.kind() {
        std::io::ErrorKind::AddrInUse => " Another program uses that port: choose another, or close it.",
        std::io::ErrorKind::AddrNotAvailable => " This PC no longer has that address: choose the adapter again.",
        std::io::ErrorKind::PermissionDenied => " Windows refused it: choose another port.",
        _ => "",
    };
    CoreError::Network(format!(
        "could not listen for {what} on {}: {err}.{advice}",
        SocketAddr::new(address, port)
    ))
}

#[async_trait]
impl FileServerActions for Runner {
    async fn serve(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &FileServerSpec,
        token: &CancellationToken,
    ) -> Result<ServeReport> {
        spec.validate()?;
        if self.running().is_some() {
            return Err(CoreError::InvalidInput(
                "A file server is running already: stop it before starting another.".into(),
            ));
        }
        let tuning = *locks::read(&self.tuning);
        let root = spec.root.clone();
        let upload_spec = spec.uploads.clone();
        let protected = self.protected();
        // Checked again here: the folders may have changed since the submit (and its approval).
        let (served, uploads) = tokio::task::spawn_blocking(move || {
            let served = open_served(&root, &protected)?;
            let uploads = upload_spec
                .as_ref()
                .map(|u| open_upload_folder(u, tuning.uploads, &protected))
                .transpose()?;
            Ok::<_, CoreError>((served, uploads))
        })
        .await
        .map_err(|err| CoreError::Network(format!("could not open what to serve: {err}")))??;

        let tftp = match spec.tftp_port {
            Some(port) => Some(
                UdpSocket::bind(SocketAddr::new(spec.address, port))
                    .await
                    .map_err(|err| bind_error("TFTP", spec.address, port, &err))?,
            ),
            None => None,
        };
        let http = match spec.http_port {
            Some(port) => Some(
                TcpListener::bind(SocketAddr::new(spec.address, port))
                    .await
                    .map_err(|err| bind_error("HTTP", spec.address, port, &err))?,
            ),
            None => None,
        };
        let tftp_port = tftp.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port());
        let http_at = http.as_ref().and_then(|l| l.local_addr().ok());
        let http_port = http_at.map(|a| a.port());

        let file_name = match &served {
            Served::File { name, .. } => Some(name.clone()),
            Served::Folder { .. } => None,
        };
        let started = time::OffsetDateTime::now_utc();
        let limit = tuning.minute.saturating_mul(spec.minutes);
        let facts = Facts {
            served: served.label(),
            folder: served.is_folder(),
            address: spec.address,
            tftp_port,
            http_port,
            file_name,
            started_at: rfc3339(started),
            ends_at: rfc3339(started + time::Duration::minutes(i64::from(spec.minutes))),
        };
        let shared = Arc::new(Shared {
            served,
            uploads: uploads.map(Arc::new),
            log: Mutex::default(),
            tuning,
            ip: spec.address,
            http_at,
            dirty: AtomicBool::new(false),
        });
        let stop = CancellationToken::new();
        let reason = Arc::new(Mutex::new(None));
        {
            let mut state = locks::lock(&self.state);
            if state.live.is_some() {
                return Err(CoreError::InvalidInput(
                    "A file server is running already: stop it before starting another.".into(),
                ));
            }
            state.last = None;
            state.live = Some(Live {
                job_id,
                workspace: ctx.workspace_id,
                stop: stop.clone(),
                reason: Arc::clone(&reason),
                shared: Arc::clone(&shared),
                facts: facts.clone(),
            });
        }
        tracing::info!(%job_id, ?tftp_port, ?http_port, "the file server started");
        self.emit(FileServerEvent::Started { job_id });

        let mut loops = JoinSet::new();
        if let Some(socket) = tftp {
            loops.spawn(tftp::serve(socket, Arc::clone(&shared), stop.clone()));
        }
        if let Some(listener) = http {
            loops.spawn(http::serve(listener, Arc::clone(&shared), stop.clone()));
        }
        let deadline = tokio::time::sleep(limit);
        tokio::pin!(deadline);
        let mut tick = tokio::time::interval(tuning.change_every.max(Duration::from_millis(10)));
        let why = loop {
            tokio::select! {
                () = token.cancelled() => break StopReason::Cancelled,
                () = stop.cancelled() => break locks::lock(&reason).unwrap_or(StopReason::User),
                () = &mut deadline => break StopReason::TimeLimit,
                _ = tick.tick() => {
                    if shared.dirty.swap(false, Ordering::Relaxed) {
                        self.emit(FileServerEvent::Changed { job_id });
                    }
                }
            }
        };
        // Every loop ends its transfers and connections, then drops its socket.
        stop.cancel();
        while loops.join_next().await.is_some() {}
        tracing::info!(%job_id, reason = ?why, "the file server stopped");

        let why_text = why.describe(spec.minutes);
        let status = status_of(job_id, &facts, &shared, Some(why_text.clone()));
        let (summary, mut text) = {
            let log = locks::lock(&shared.log);
            (log.summary(), log.text())
        };
        let mut note = format!("{why_text}; {summary}");
        if let Some(uploads) = &shared.uploads {
            let done = uploads.done();
            if !done.is_empty() {
                let mut names: Vec<String> = done
                    .iter()
                    .take(10)
                    .map(|u| format!("{} ({}) from {}", u.name, size_text(u.bytes), u.ip))
                    .collect();
                if done.len() > 10 {
                    names.push(format!("and {} more", done.len() - 10));
                }
                note.push_str(&format!(
                    "; uploaded into {}: {}",
                    display_path(uploads.folder()),
                    names.join(", ")
                ));
                text.push_str(&format!("uploaded into {}:\n", display_path(uploads.folder())));
                for u in &done {
                    let mark = u.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
                    text.push_str(&format!("{} ({}) from {}{mark}\n", u.name, size_text(u.bytes), u.ip));
                }
            }
        }
        let header = format!(
            "{} on {}: {}; {}\n",
            facts.served,
            spec.address,
            [
                facts.tftp_port.map(|p| format!("TFTP port {p}")),
                facts.http_port.map(|p| format!("HTTP port {p}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", "),
            why_text
        );
        {
            let mut state = locks::lock(&self.state);
            state.live = None;
            state.last = Some((ctx.workspace_id, status));
        }
        self.emit(FileServerEvent::Stopped { job_id });
        Ok(ServeReport {
            note,
            log: format!("{header}{text}"),
        })
    }
}

/// The File server tab's service: its options and last choices, the start (a command on the bus), Stop and the
/// status.
#[derive(Clone)]
pub struct FileServers {
    runner: Arc<Runner>,
    store: Store,
    tools: Arc<dyn NetworkTools>,
    bus: Arc<CommandBus>,
    /// What the shell's dialogs chose, by token.
    picks: Arc<Mutex<Vec<Pick>>>,
}

impl FileServers {
    pub fn new(store: Store, tools: Arc<dyn NetworkTools>, bus: Arc<CommandBus>, runner: Arc<Runner>) -> Self {
        Self {
            runner,
            store,
            tools,
            bus,
            picks: Arc::default(),
        }
    }

    /// What runs the servers (the job runner's side, and the stop paths).
    pub fn runner(&self) -> &Arc<Runner> {
        &self.runner
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FileServerEvent> {
        self.runner.subscribe()
    }

    /// This PC's addresses a server may listen on: each up adapter's (not link-local), then loopback.
    pub async fn addresses(&self) -> Vec<ServeAddress> {
        let mut out = Vec::new();
        for adapter in self.tools.adapters().await.unwrap_or_default() {
            if !adapter.up || adapter.loopback {
                continue;
            }
            for address in &adapter.addresses {
                let usable = match address.address {
                    IpAddr::V4(v4) => !(v4.is_link_local() || v4.is_loopback() || v4.is_unspecified()),
                    // fe80:: needs a scope this list doesn't carry.
                    IpAddr::V6(v6) => {
                        !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80)
                    }
                };
                if usable
                    && !out
                        .iter()
                        .any(|a: &ServeAddress| a.address == address.address.to_string())
                {
                    out.push(ServeAddress {
                        address: address.address.to_string(),
                        name: adapter.name.clone(),
                        loopback: false,
                    });
                }
            }
        }
        out.push(ServeAddress {
            address: Ipv4Addr::LOCALHOST.to_string(),
            name: "This PC only".into(),
            loopback: true,
        });
        out
    }

    /// What the tab draws: the addresses, the last choices here, and the server running here (or the last one).
    pub async fn options(&self, ctx: &Context) -> Result<FileServerOptions> {
        let last = self
            .store
            .get_setting::<FileServerSpec>(ctx, LAST_KEY)
            .await
            .ok()
            .flatten();
        Ok(FileServerOptions {
            addresses: self.addresses().await,
            last,
            status: self.runner.status(ctx.workspace_id),
        })
    }

    /// The running server here, or the one that stopped last.
    pub fn status(&self, ctx: &Context) -> Option<ServerStatus> {
        self.runner.status(ctx.workspace_id)
    }

    /// Stop on the tab.
    pub fn stop(&self, ctx: &Context, job_id: Uuid) -> bool {
        self.runner.stop(ctx.workspace_id, job_id, StopReason::User)
    }

    /// A file or folder the shell's dialog chose: kept here, and named by a token the window sends back to start the
    /// server, so no path ever comes from the window. Refused at once when it is something a server never serves or
    /// writes into.
    pub async fn remember_pick(&self, ctx: &Context, purpose: PickFor, path: PathBuf) -> Result<PickedPath> {
        let protected = self.runner.protected();
        let real = tokio::task::spawn_blocking(move || {
            let meta = std::fs::metadata(&path)
                .map_err(|err| CoreError::InvalidInput(format!("{} can't be used: {err}", path.display())))?;
            let fits = match purpose {
                PickFor::File => meta.is_file(),
                PickFor::Folder | PickFor::Uploads => meta.is_dir(),
            };
            if !fits {
                return Err(CoreError::InvalidInput(format!(
                    "{} is not a {}.",
                    path.display(),
                    if purpose == PickFor::File { "file" } else { "folder" }
                )));
            }
            let real = std::fs::canonicalize(&path)?;
            let verb = if purpose == PickFor::Uploads {
                "Uploads can't go into"
            } else {
                "Remotely doesn't serve"
            };
            check_place(&real, &protected, verb)?;
            Ok::<_, CoreError>(real)
        })
        .await
        .map_err(|err| CoreError::InvalidInput(format!("could not check that: {err}")))??;
        let picked = PickedPath {
            token: Uuid::new_v4(),
            path: display_path(&real),
        };
        let mut picks = locks::lock(&self.picks);
        if picks.len() >= MAX_PICKS {
            picks.remove(0);
        }
        picks.push(Pick {
            token: picked.token,
            workspace: ctx.workspace_id,
            purpose,
            path: picked.path.clone(),
        });
        Ok(picked)
    }

    /// The path a choice stands for: a pick of this workspace for that purpose, or the last choice kept here.
    fn resolve(
        &self,
        ctx: &Context,
        choice: &PathChoice,
        uploads: bool,
        last: Option<&FileServerSpec>,
    ) -> Result<String> {
        match choice {
            PathChoice::Picked { token } => locks::lock(&self.picks)
                .iter()
                .find(|p| {
                    p.token == *token && p.workspace == ctx.workspace_id && (p.purpose == PickFor::Uploads) == uploads
                })
                .map(|p| p.path.clone())
                .ok_or_else(|| {
                    CoreError::InvalidInput("Choose the file or folder again: that choice is no longer known.".into())
                }),
            PathChoice::Last => {
                let path = last.and_then(|l| {
                    if uploads {
                        l.uploads.as_ref().map(|u| u.folder.clone())
                    } else {
                        Some(l.root.clone())
                    }
                });
                path.ok_or_else(|| CoreError::InvalidInput("There is no last choice here: choose one.".into()))
            }
        }
    }

    /// Checks the choices against this PC, then submits [`Command::FileServer`] to the bus. The paths come from the
    /// dialogs' picks or this workspace's last choices, which are checked again like new ones. The choices are kept for
    /// next time in this workspace.
    pub async fn submit(&self, ctx: &Context, request: FileServerRequest) -> Result<SubmitOutcome> {
        let last = self
            .store
            .get_setting::<FileServerSpec>(ctx, LAST_KEY)
            .await
            .ok()
            .flatten();
        let root = self.resolve(ctx, &request.root, false, last.as_ref())?;
        let uploads = match &request.uploads {
            Some(u) => Some(UploadSpec {
                folder: self.resolve(ctx, &u.folder, true, last.as_ref())?,
                max_file_mb: u.max_file_mb,
                max_total_mb: u.max_total_mb,
            }),
            None => None,
        };
        let spec = FileServerSpec {
            root,
            address: request.address,
            tftp_port: request.tftp_port,
            http_port: request.http_port,
            minutes: request.minutes,
            uploads,
        };
        spec.validate()?;
        if self.runner.running().is_some() {
            return Err(CoreError::InvalidInput(
                "A file server is running already: stop it before starting another.".into(),
            ));
        }
        let known = self.addresses().await;
        let ours = spec.address.is_loopback() || known.iter().any(|a| a.address == spec.address.to_string());
        if !ours {
            return Err(CoreError::InvalidInput(format!(
                "This PC has no adapter with the address {} now: choose one from the list.",
                spec.address
            )));
        }
        let check = spec.clone();
        let protected = self.runner.protected();
        let limits = locks::read(&self.runner.tuning).uploads;
        tokio::task::spawn_blocking(move || {
            open_served(&check.root, &protected)?;
            if let Some(uploads) = &check.uploads {
                open_upload_folder(uploads, limits, &protected)?;
            }
            Ok::<_, CoreError>(())
        })
        .await
        .map_err(|err| CoreError::InvalidInput(format!("could not check the folders: {err}")))??;
        let outcome = self
            .bus
            .submit(
                ctx,
                Command::FileServer {
                    targets: spec.targets(),
                    spec: Box::new(spec.clone()),
                },
            )
            .await?;
        if let Err(err) = self.store.put_setting(ctx, LAST_KEY, &spec).await {
            tracing::warn!(error = %err, "could not keep the file server's choices");
        }
        Ok(outcome)
    }
}

/// What a dialog chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PickFor {
    /// A folder to serve.
    Folder,
    /// One file to serve.
    File,
    /// The empty folder uploads go into.
    Uploads,
}

/// A dialog's choice, as the window gets it: a token to send back, and the path to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedPath {
    pub token: Uuid,
    pub path: String,
}

/// Picks kept at once; the oldest goes first.
const MAX_PICKS: usize = 32;

#[derive(Debug, Clone)]
struct Pick {
    token: Uuid,
    workspace: WorkspaceId,
    purpose: PickFor,
    path: String,
}

/// Where a path comes from: never the window itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PathChoice {
    /// What the shell's dialog chose ([`FileServers::remember_pick`]).
    Picked { token: Uuid },
    /// This workspace's last choice for it, checked again.
    Last,
}

/// What the File server tab sends to start a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileServerRequest {
    pub root: PathChoice,
    pub address: IpAddr,
    pub tftp_port: Option<u16>,
    pub http_port: Option<u16>,
    pub minutes: u32,
    #[serde(default)]
    pub uploads: Option<UploadRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadRequest {
    pub folder: PathChoice,
    pub max_file_mb: u64,
    pub max_total_mb: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn spec() -> FileServerSpec {
        FileServerSpec {
            root: r"C:\Images".into(),
            address: "192.0.2.10".parse().unwrap(),
            tftp_port: Some(69),
            http_port: Some(8080),
            minutes: 30,
            uploads: None,
        }
    }

    #[test]
    fn a_spec_is_checked_before_anything_is_opened() {
        assert!(spec().validate().is_ok());
        for bad in [
            FileServerSpec {
                root: " ".into(),
                ..spec()
            },
            FileServerSpec {
                root: r"\\server\share\fw".into(),
                ..spec()
            },
            FileServerSpec {
                root: r"\\?\C:\Images".into(),
                ..spec()
            },
            FileServerSpec {
                root: r"C:\Images\NUL".into(),
                ..spec()
            },
            FileServerSpec {
                tftp_port: None,
                http_port: None,
                ..spec()
            },
            FileServerSpec { minutes: 0, ..spec() },
            FileServerSpec {
                minutes: MAX_MINUTES + 1,
                ..spec()
            },
            FileServerSpec {
                address: "0.0.0.0".parse().unwrap(),
                ..spec()
            },
            FileServerSpec {
                address: "::".parse().unwrap(),
                ..spec()
            },
            FileServerSpec {
                address: "255.255.255.255".parse().unwrap(),
                ..spec()
            },
            FileServerSpec {
                address: "224.0.0.1".parse().unwrap(),
                ..spec()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let uploads = |folder: &str, file: u64, total: u64| FileServerSpec {
            uploads: Some(UploadSpec {
                folder: folder.into(),
                max_file_mb: file,
                max_total_mb: total,
            }),
            ..spec()
        };
        assert!(uploads(r"C:\Uploads", 10, 100).validate().is_ok());
        assert!(uploads("", 10, 100).validate().is_err());
        assert!(uploads(r"\\server\share", 10, 100).validate().is_err());
        assert!(uploads(r"C:\Uploads", 0, 100).validate().is_err());
        assert!(uploads(r"C:\Uploads", 200, 100).validate().is_err());
        assert!(uploads(r"C:\Uploads", 10, MAX_UPLOAD_MB + 1).validate().is_err());
    }

    #[test]
    fn the_summary_says_what_where_and_how_long() {
        assert_eq!(
            spec().summary(),
            r"Serve C:\Images over TFTP (port 69) and HTTP (port 8080) on 192.0.2.10 for 30 minutes"
        );
        let with = FileServerSpec {
            http_port: None,
            minutes: 90,
            uploads: Some(UploadSpec {
                folder: r"C:\Uploads".into(),
                max_file_mb: 10,
                max_total_mb: 100,
            }),
            ..spec()
        };
        assert_eq!(
            with.summary(),
            r"Serve C:\Images over TFTP (port 69) on 192.0.2.10 for 1 hour 30 minutes, accepting uploads into C:\Uploads"
        );
        assert_eq!(minutes_text(120), "2 hours");
        assert_eq!(StopReason::TimeLimit.describe(1), "its time limit of 1 minute ran out");
    }

    #[test]
    fn slots_cap_all_and_each_client() {
        let slots = Arc::new(Slots::new(3, 2));
        let a: IpAddr = "192.0.2.7".parse().unwrap();
        let b: IpAddr = "192.0.2.8".parse().unwrap();
        let a1 = slots.take(a).unwrap();
        let _a2 = slots.take(a).unwrap();
        assert!(slots.take(a).is_none(), "two per client");
        let _b1 = slots.take(b).unwrap();
        assert!(slots.take(b).is_none(), "three in all");
        drop(a1);
        assert!(slots.take(b).is_some(), "a slot given back is free again");
    }
}
