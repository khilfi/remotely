//! MO-02: Linux guest metrics over SSH, for the sessions the user chose to watch on the dashboard
//! (a VM's guest metrics come from a session linked to it).
//!
//! Each watched host gets one connection, logged in once and kept between rounds; every poll runs
//! [`procfs::GUEST_SCRIPT_WITHOUT_DF`] on a new channel of it (one `grep`), and once a minute
//! [`procfs::GUEST_SCRIPT`] (with `df`). A host is polled every 5 s by default, or every 15, 30 or 60 s
//! ([`POLL_KEY`], Settings): each poll is a few process starts on the host that a SIEM may log. A
//! read, so it skips the command bus and the approval flow (CLAUDE.md, architecture rule 3), and it
//! changes nothing on the host.
//!
//! A host that can't be reached or presents an untrusted key is retried after a wait that doubles
//! each time (5 s up to 5 minutes), and its state says why. A login the host refused, a changed host
//! key or a password that isn't saved parks the host instead ([`crate::login_guard`]): no new login
//! until the session or its credentials change or the user presses Retry, so a rotated password never
//! locks the account. Every login counts against the hourly cap per host. A login that needs a secret
//! waits while the vault is locked, without trying. Host keys are checked like a bulk run checks them:
//! trusted passes, unknown fails (trust it in a terminal first), changed blocks and is audited once
//! per park. Secrets come from the vault for each new login and go only to the adapter.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::procfs::{self, GuestReading};
use super::{GuestState, GuestStatus, MetricSample, MetricSource, MetricsSource, SourceRound};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, ConnectRequest, ExecSession, HostKeyVerifier, RemoteAdapter, SessionSpec,
};
use crate::adapters::winrm::{WinrmAdapter, WinrmConnect, WinrmSession, WinrmSpec, WinrmTuning};
use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::host_details::{CollectedBy, SpecsCollector};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHosts};
use crate::locks;
use crate::login_guard::{self, LoginGuard, ParkReason, ParkScope, Parked};
use crate::sessions;
use crate::store::Store;
use crate::vault::{Vault, VaultStatus};
use crate::workspaces::Current;

/// Settings key: the sessions watched for guest metrics (a list of session ids).
pub const WATCHED_KEY: &str = "metrics.guestSessions";

/// Settings key: seconds between two polls of a watched host (MO-02, P8): one of [`POLL_CHOICES`].
pub const POLL_KEY: &str = "metrics.guestPollSecs";
/// The polling intervals offered, in seconds; the first is the default.
pub const POLL_CHOICES: [u64; 4] = [5, 15, 30, 60];
/// A host is polled in the collector's round that comes this close to its interval, so a 15 s
/// interval on 5 s rounds polls every third round rather than every fourth.
const POLL_SLACK: Duration = Duration::from_secs(1);

/// How guest polling connects and backs off. The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct GuestTuning {
    pub connect_timeout: Duration,
    /// One round's command.
    pub command_timeout: Duration,
    /// How long a round waits for its hosts. A slower host's reading arrives with a later round.
    pub round_budget: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// Hosts polled at once.
    pub parallel: usize,
    pub agent: AgentSource,
}

impl Default for GuestTuning {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            command_timeout: Duration::from_secs(10),
            round_budget: Duration::from_secs(3),
            backoff_min: Duration::from_secs(5),
            backoff_max: Duration::from_secs(300),
            parallel: 16,
            agent: AgentSource::System,
        }
    }
}

/// The wait before try number `failures + 1`: doubling from `min`, at most `max`.
pub fn backoff(failures: u32, min: Duration, max: Duration) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    min.saturating_mul(1 << doublings).min(max)
}

/// One watched host's connection and counters. Locked for the whole of a poll, so a host is never
/// polled twice at once.
struct Host {
    /// What the connection was made with: a session edited since then reconnects.
    spec_key: String,
    conn: Option<Arc<dyn ExecSession>>,
    /// F4: the same connection as a WinRM session (its kept PowerShell), for a Windows host.
    winrm: Option<Arc<dyn WinrmSession>>,
    previous: Option<(GuestReading, Instant)>,
    failures: u32,
    next_try: Option<Instant>,
    /// MO-13: when this connection last looked at the age of the host's stored facts.
    specs_checked: Option<Instant>,
    /// P8: when it was last polled (the polling interval counts from there) and last ran `df`.
    polled_at: Option<Instant>,
    df_at: Option<Instant>,
}

impl Host {
    fn new() -> Self {
        Self {
            spec_key: String::new(),
            conn: None,
            winrm: None,
            previous: None,
            failures: 0,
            next_try: None,
            specs_checked: None,
            polled_at: None,
            df_at: None,
        }
    }

    async fn disconnect(&mut self) {
        self.winrm = None;
        if let Some(conn) = self.conn.take() {
            conn.close().await;
        }
    }
}

struct StatusEntry {
    status: GuestStatus,
    retry_at: Option<Instant>,
}

/// What the polls share.
struct Shared {
    store: Store,
    /// FD-02: the workspace shown, whose watched hosts are polled.
    current: Current,
    remote: Arc<dyn RemoteAdapter>,
    vault: Arc<dyn Vault>,
    known_hosts: Arc<KnownHosts>,
    /// Parks refused logins and caps logins per host (shared with the Containers page).
    guard: LoginGuard,
    tuning: RwLock<GuestTuning>,
    statuses: Mutex<HashMap<Uuid, StatusEntry>>,
    /// Good readings not yet handed to a round.
    fresh: Mutex<HashMap<Uuid, MetricSample>>,
    /// MO-13: reads a watched host's facts on its kept connection when they are old.
    specs: OnceLock<SpecsCollector>,
    /// P8: the time between two polls of a host ([`POLL_KEY`]).
    interval: RwLock<Duration>,
    /// F4: the WinRM client Windows hosts are read with.
    winrm: RwLock<Arc<dyn WinrmAdapter>>,
}

impl Shared {
    fn ctx(&self) -> Context {
        self.current.get()
    }
}

pub struct GuestSource {
    shared: Arc<Shared>,
    hosts: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<Host>>>>,
}

/// Why a poll did not give a reading.
struct Failure {
    state: GuestState,
    message: String,
    /// Retry next round without waiting (nothing was sent over the network).
    retry_now: bool,
    /// Parked: no new login until something changes or the user presses Retry.
    parked: bool,
    /// The hourly cap on logins was reached: the next try waits this long.
    wait: Option<Duration>,
}

impl Failure {
    fn new(state: GuestState, message: impl Into<String>) -> Self {
        Self {
            state,
            message: message.into(),
            retry_now: false,
            parked: false,
            wait: None,
        }
    }

    fn parked(parked: &Parked) -> Self {
        let state = match parked.reason {
            ParkReason::HostKeyChanged => GuestState::HostKey,
            ParkReason::LoginRefused | ParkReason::SecretMissing | ParkReason::SudoRefused => GuestState::LoginFailed,
        };
        Self {
            parked: true,
            ..Self::new(state, parked.message.clone())
        }
    }

    fn from_error(err: &CoreError) -> Self {
        let state = match err {
            CoreError::VaultLocked | CoreError::VaultNotSetUp => GuestState::VaultLocked,
            CoreError::AuthFailed(_) | CoreError::AgentUnavailable(_) => GuestState::LoginFailed,
            CoreError::HostKeyChanged { .. }
            | CoreError::HostKeyRejected { .. }
            | CoreError::HostKeyUnknown { .. }
            | CoreError::CertificateChanged { .. }
            | CoreError::CertificateRejected { .. }
            | CoreError::CertificateUnknown { .. }
            | CoreError::CertificateNotTrusted { .. } => GuestState::HostKey,
            CoreError::Ssh(_) | CoreError::Timeout { .. } | CoreError::Io(_) => GuestState::Unreachable,
            _ => GuestState::Error,
        };
        let message = match err {
            // The bulk-run wording offers a checkbox the dashboard doesn't have.
            CoreError::HostKeyUnknown { address, jump } => {
                let place = match jump {
                    Some(name) => format!("the jump host '{name}' ({address})"),
                    None => address.clone(),
                };
                format!(
                    "the host key of {place} is not trusted yet. Connect to it once in a terminal to check and trust it"
                )
            }
            other => other.to_string(),
        };
        Self {
            retry_now: state == GuestState::VaultLocked,
            ..Self::new(state, message)
        }
    }
}

/// SS-05 for guest polling: trusted keys pass, unknown keys fail (no one is there to ask), and a
/// changed key blocks the connection and is audited.
pub(crate) struct GuestVerifier {
    pub(crate) known_hosts: Arc<KnownHosts>,
    pub(crate) ctx: Context,
    pub(crate) target: Target,
    pub(crate) record_blocked: bool,
}

#[async_trait]
impl HostKeyVerifier for GuestVerifier {
    async fn verify(&self, key: &HostKey, jump: Option<&str>) -> Result<()> {
        let jump = jump.map(str::to_owned);
        match self.known_hosts.check(&self.ctx, key).await? {
            HostKeyCheck::Trusted => Ok(()),
            HostKeyCheck::Changed { previous } => {
                if self.record_blocked {
                    self.known_hosts
                        .record_blocked(&self.ctx, key, &previous, Some(&self.target))
                        .await?;
                }
                Err(CoreError::HostKeyChanged {
                    address: key.address(),
                    jump,
                })
            }
            HostKeyCheck::Unknown { .. } => Err(CoreError::HostKeyUnknown {
                address: key.address(),
                jump,
            }),
        }
    }

    async fn known_key_types(&self, host: &str, port: u16) -> Vec<String> {
        self.known_hosts
            .key_types(&self.ctx, host, port)
            .await
            .unwrap_or_default()
    }
}

/// What a connection depends on: host, port, user, login method and its vault ids, for the session
/// and each jump host on the way (SS-07).
pub(crate) fn spec_key(spec: &SessionSpec) -> String {
    login_guard::login_key(spec)
}

fn needs_vault(auth: &AuthMethod) -> bool {
    matches!(auth, AuthMethod::Password(Some(_)) | AuthMethod::PrivateKey { .. })
}

impl GuestSource {
    pub fn new(
        store: Store,
        current: Current,
        remote: Arc<dyn RemoteAdapter>,
        vault: Arc<dyn Vault>,
        known_hosts: Arc<KnownHosts>,
        guard: LoginGuard,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                store,
                current,
                remote,
                vault,
                known_hosts,
                guard,
                tuning: RwLock::new(GuestTuning::default()),
                statuses: Mutex::new(HashMap::new()),
                fresh: Mutex::new(HashMap::new()),
                specs: OnceLock::new(),
                interval: RwLock::new(Duration::from_secs(POLL_CHOICES[0])),
                winrm: RwLock::new(Arc::new(crate::adapters::winrm::NoWinrm)),
            }),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// MO-13: the kept connections also read each host's facts when they are older than
    /// [`crate::host_details::SpecsTuning::dashboard_max_age`].
    pub fn set_specs(&self, collector: SpecsCollector) {
        let _ = self.shared.specs.set(collector);
    }

    /// F4: the WinRM client Windows guests are read with (MO-05).
    pub fn set_winrm(&self, adapter: Arc<dyn WinrmAdapter>) {
        *locks::write(&self.shared.winrm) = adapter;
    }

    /// MO-13, MO-14: the watched session's kept connection, when it is open and not in the middle of
    /// connecting (waited for briefly). Commands on it run on channels of their own beside the polls.
    pub async fn kept_connection(&self, session_id: Uuid) -> Option<Arc<dyn ExecSession>> {
        let host = locks::lock(&self.hosts).get(&session_id).cloned()?;
        let host = tokio::time::timeout(Duration::from_secs(2), host.lock()).await.ok()?;
        host.conn.clone().filter(|c| !c.is_closed())
    }

    pub fn tuning(&self) -> GuestTuning {
        locks::read(&self.shared.tuning).clone()
    }

    /// Tests shorten the timeouts and waits.
    pub fn set_tuning(&self, tuning: GuestTuning) {
        *locks::write(&self.shared.tuning) = tuning;
    }

    /// P8: how long a watched host waits between two polls.
    pub fn interval(&self) -> Duration {
        *locks::read(&self.shared.interval)
    }

    /// P8: polls each host this often from now on (the next poll counts from the last one).
    pub fn set_interval(&self, every: Duration) {
        *locks::write(&self.shared.interval) = every;
    }

    /// The user pressed Retry: a parked host logs in again next round, and a waiting one stops waiting.
    pub fn retry(&self, session_id: Uuid) {
        self.shared.guard.retry(session_id);
        let host = locks::lock(&self.hosts).get(&session_id).cloned();
        if let Some(host) = host {
            if let Ok(mut host) = host.try_lock() {
                host.failures = 0;
                host.next_try = None;
                host.polled_at = None;
            }
        }
        if let Some(entry) = locks::lock(&self.shared.statuses).get_mut(&session_id) {
            let last_ok = entry.status.last_ok.take();
            entry.status = GuestStatus::new(session_id, GuestState::Connecting, None);
            entry.status.last_ok = last_ok;
            entry.retry_at = None;
        }
    }

    /// The sessions watched for guest metrics.
    pub async fn watched(&self) -> Result<Vec<Uuid>> {
        Ok(self
            .shared
            .store
            .get_setting::<Vec<Uuid>>(&self.shared.ctx(), WATCHED_KEY)
            .await?
            .unwrap_or_default())
    }

    /// Every watched host's state, with the wait before its next try counted from now.
    pub fn statuses(&self) -> HashMap<Uuid, GuestStatus> {
        let now = Instant::now();
        locks::lock(&self.shared.statuses)
            .iter()
            .map(|(id, entry)| {
                let mut status = entry.status.clone();
                status.retry_in_secs = entry
                    .retry_at
                    .map(|at| at.saturating_duration_since(now).as_secs_f64().ceil() as u64);
                (*id, status)
            })
            .collect()
    }

    /// SS-04: the vault locked: every kept connection closes, since it logged in with vault secrets and
    /// keeps the login password to scrub output. A host that needs the vault then waits for it to be
    /// unlocked; one that logs in with the SSH agent connects again next round.
    pub async fn close_all(&self) {
        let hosts: Vec<Arc<tokio::sync::Mutex<Host>>> = locks::lock(&self.hosts).values().cloned().collect();
        for host in hosts {
            // Waits for a poll in the middle of its round, then closes what it used.
            let mut host = host.lock().await;
            host.disconnect().await;
            host.spec_key.clear();
        }
    }

    /// FD-02: another workspace is shown: every kept connection closes and the hosts' states are forgotten, so
    /// nothing of the old workspace's hosts is polled or shown. The new workspace's watched hosts connect next round.
    pub async fn leave_workspace(&self) {
        self.close_all().await;
        self.forget_unwatched(&[]).await;
    }

    /// Drops what is kept for hosts no longer watched and closes their connections.
    async fn forget_unwatched(&self, watched: &[Uuid]) {
        let gone: Vec<Arc<tokio::sync::Mutex<Host>>> = {
            let mut hosts = locks::lock(&self.hosts);
            let ids: Vec<Uuid> = hosts.keys().filter(|id| !watched.contains(id)).copied().collect();
            ids.into_iter().filter_map(|id| hosts.remove(&id)).collect()
        };
        locks::lock(&self.shared.statuses).retain(|id, _| watched.contains(id));
        locks::lock(&self.shared.fresh).retain(|id, _| watched.contains(id));
        for host in gone {
            // A poll still running ends on its own; its connection closes when it is dropped.
            if let Ok(mut host) = host.try_lock() {
                host.disconnect().await;
            }
        }
    }
}

#[async_trait]
impl MetricsSource for GuestSource {
    fn name(&self) -> &'static str {
        "ssh-guest"
    }

    async fn collect(&self) -> Result<SourceRound> {
        let watched = self.watched().await?;
        self.forget_unwatched(&watched).await;
        let tuning = self.tuning();
        let now = Instant::now();
        let every = self.interval().saturating_sub(POLL_SLACK);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(tuning.parallel.max(1)));
        let (done_tx, mut done_rx) = mpsc::channel::<()>(watched.len().max(1));
        let mut started = 0usize;
        for id in &watched {
            let host = Arc::clone(
                locks::lock(&self.hosts)
                    .entry(*id)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(Host::new()))),
            );
            // Still polling from an earlier round: its reading arrives when it is done.
            let Ok(guard) = host.try_lock_owned() else {
                continue;
            };
            if guard.next_try.is_some_and(|at| at > now) {
                continue;
            }
            // P8: polled less than an interval ago (a failed poll waits for `next_try` instead).
            if guard.next_try.is_none()
                && guard
                    .polled_at
                    .is_some_and(|at| now.saturating_duration_since(at) < every)
            {
                continue;
            }
            locks::lock(&self.shared.statuses)
                .entry(*id)
                .or_insert_with(|| StatusEntry {
                    status: GuestStatus::new(*id, GuestState::Connecting, None),
                    retry_at: None,
                });
            let shared = Arc::clone(&self.shared);
            let semaphore = Arc::clone(&semaphore);
            let done = done_tx.clone();
            let id = *id;
            started += 1;
            // Spawned, not awaited here: a slow host keeps polling past this round's budget.
            tokio::spawn(async move {
                let mut host = guard;
                if let Ok(_permit) = semaphore.acquire().await {
                    poll(&shared, id, &mut host).await;
                }
                let _ = done.send(()).await;
            });
        }
        drop(done_tx);
        let _ = tokio::time::timeout(tuning.round_budget, async {
            for _ in 0..started {
                if done_rx.recv().await.is_none() {
                    break;
                }
            }
        })
        .await;

        let samples: Vec<MetricSample> = locks::lock(&self.shared.fresh).drain().map(|(_, s)| s).collect();
        let statuses = self.statuses();
        Ok(SourceRound {
            samples,
            statuses: watched.iter().filter_map(|id| statuses.get(id).cloned()).collect(),
            running: None,
            elsewhere: Vec::new(),
        })
    }
}

/// One poll of one host: connect if needed, run the script, keep the reading.
async fn poll(shared: &Shared, id: Uuid, host: &mut Host) {
    let tuning = locks::read(&shared.tuning).clone();
    host.polled_at = Some(Instant::now());
    match read_once(shared, &tuning, id, host).await {
        Ok(sample) => {
            host.failures = 0;
            host.next_try = None;
            let mut status = GuestStatus::new(id, GuestState::Ok, None);
            status.last_ok = Some(sample.ts.clone());
            locks::lock(&shared.statuses).insert(id, StatusEntry { status, retry_at: None });
            locks::lock(&shared.fresh).insert(id, sample);
            read_specs_when_old(shared, id, host).await;
        }
        Err(failure) => {
            // Nothing went over the network (the vault is locked): next round, whatever the interval.
            if failure.retry_now {
                host.polled_at = None;
            }
            // Parked: the guard keeps it from logging in, at no cost each round. Retry clears it.
            let retry_at = if failure.retry_now || failure.parked {
                None
            } else if let Some(wait) = failure.wait {
                Some(Instant::now() + wait)
            } else {
                host.failures = host.failures.saturating_add(1);
                Some(Instant::now() + backoff(host.failures, tuning.backoff_min, tuning.backoff_max))
            };
            host.next_try = retry_at;
            let mut statuses = locks::lock(&shared.statuses);
            let last_ok = statuses.get(&id).and_then(|e| e.status.last_ok.clone());
            let mut status = GuestStatus::new(id, failure.state, Some(failure.message));
            status.last_ok = last_ok;
            status.parked = failure.parked;
            statuses.insert(id, StatusEntry { status, retry_at });
        }
    }
}

async fn read_once(
    shared: &Shared,
    tuning: &GuestTuning,
    id: Uuid,
    host: &mut Host,
) -> std::result::Result<MetricSample, Failure> {
    let ctx = shared.ctx();
    let spec = match shared.store.session_spec(&ctx, id).await {
        Ok(Some(spec)) => spec,
        Ok(None) => return Err(Failure::new(GuestState::Error, "the session was deleted")),
        // MO-05: a Windows host over WinRM.
        Err(CoreError::WrongSessionKind { .. }) => match shared.store.winrm_spec(&ctx, id).await {
            Ok(Some(spec)) => return read_windows(shared, tuning, id, host, &spec).await,
            Ok(None) => return Err(Failure::new(GuestState::Error, "the session was deleted")),
            Err(err) => return Err(Failure::from_error(&err)),
        },
        Err(err) => return Err(Failure::from_error(&err)),
    };
    let key = spec_key(&spec);
    if host.spec_key != key {
        host.disconnect().await;
        host.previous = None;
        host.spec_key = key;
    }
    if host.conn.as_ref().is_some_and(|c| c.is_closed()) {
        host.conn = None;
    }
    if host.conn.is_none() {
        host.conn = Some(connect(shared, tuning, &spec).await?);
    }
    let Some(conn) = host.conn.as_ref() else {
        return Err(Failure::new(GuestState::Error, "no connection"));
    };
    // P8: `df` once a minute (and on the first poll of a connection); the rounds between keep its mounts.
    let with_df = host.previous.is_none() || host.df_at.is_none_or(|at| at.elapsed() >= procfs::DF_EVERY);
    let script = if with_df {
        procfs::GUEST_SCRIPT
    } else {
        procfs::GUEST_SCRIPT_WITHOUT_DF
    };
    let ran = tokio::time::timeout(tuning.command_timeout, conn.run(script, procfs::MAX_OUTPUT)).await;
    let result = match ran {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            host.disconnect().await;
            return Err(Failure::from_error(&err));
        }
        Err(_) => {
            host.disconnect().await;
            return Err(Failure::new(
                GuestState::Unreachable,
                format!(
                    "{} stopped answering (no reply in {} s)",
                    spec.name,
                    tuning.command_timeout.as_secs()
                ),
            ));
        }
    };
    let at = Instant::now();
    let mut reading = procfs::parse(&result.output.stdout);
    if with_df {
        host.df_at = Some(at);
    } else if let Some((previous, _)) = &host.previous {
        reading.mounts = previous.mounts.clone();
    }
    if reading.is_empty() {
        return Err(Failure::new(
            GuestState::NoData,
            "the host answered, but has no /proc: guest metrics need a Linux host",
        ));
    }
    let rates = procfs::rates(host.previous.as_ref().map(|(r, t)| (r, *t)), &reading, at);
    let load = reading.load;
    let sample = MetricSample {
        source: MetricSource::Guest,
        target: TargetRef::Session { session_id: id },
        ts: now_rfc3339(),
        cpu_pct: rates.cpu_pct,
        host_cpu_pct: None,
        host_mem_pct: None,
        mem_bytes: reading.mem_used_bytes(),
        mem_total_bytes: reading.mem_total_bytes,
        swap_used_bytes: reading.swap_used_bytes(),
        swap_total_bytes: reading.swap_total_bytes,
        disk_read_bps: rates.disk_read_bps,
        disk_write_bps: rates.disk_write_bps,
        net_rx_bps: rates.net_rx_bps,
        net_tx_bps: rates.net_tx_bps,
        load1: load.map(|l| l[0]),
        load5: load.map(|l| l[1]),
        load15: load.map(|l| l[2]),
        uptime_secs: reading.uptime_secs.map(|u| u as u64),
        mounts: reading.mounts.clone(),
    };
    host.previous = Some((reading, at));
    Ok(sample)
}

/// MO-05: one read of a Windows host: its WinRM connection kept between rounds (signed in once, the certificate
/// checked like a bulk run checks a host key), the CIM script in the PowerShell it keeps open, and the reading made
/// rates like a Linux guest's.
async fn read_windows(
    shared: &Shared,
    tuning: &GuestTuning,
    id: Uuid,
    host: &mut Host,
    spec: &WinrmSpec,
) -> std::result::Result<MetricSample, Failure> {
    let key = spec.login_key();
    if host.spec_key != key {
        host.disconnect().await;
        host.previous = None;
        host.spec_key = key;
    }
    if host.conn.as_ref().is_some_and(|c| c.is_closed()) {
        host.disconnect().await;
    }
    if host.winrm.is_none() {
        let session = connect_windows(shared, tuning, spec).await?;
        host.conn = Some(Arc::clone(&session).exec());
        host.winrm = Some(session);
    }
    let Some(session) = host.winrm.clone() else {
        return Err(Failure::new(GuestState::Error, "no connection"));
    };
    let read = tokio::time::timeout(
        tuning.command_timeout.saturating_mul(2),
        session.read(
            super::windows::METRICS_SCRIPT,
            super::windows::MAX_OUTPUT,
            tuning.command_timeout,
        ),
    )
    .await;
    let text = match read {
        Ok(Ok(text)) => text,
        Ok(Err(err)) => {
            host.disconnect().await;
            return Err(Failure::from_error(&err));
        }
        Err(_) => {
            host.disconnect().await;
            return Err(Failure::new(
                GuestState::Unreachable,
                format!(
                    "{} stopped answering (no reply in {} s)",
                    spec.name,
                    tuning.command_timeout.as_secs()
                ),
            ));
        }
    };
    let at = Instant::now();
    let reading = super::windows::parse(&text);
    if reading.is_empty() {
        return Err(Failure::new(
            GuestState::NoData,
            "the host answered, but its CIM classes gave nothing: guest metrics need Windows with PowerShell 5.1",
        ));
    }
    let rates = procfs::rates(host.previous.as_ref().map(|(r, t)| (r, *t)), &reading, at);
    let sample = MetricSample {
        source: MetricSource::Guest,
        target: TargetRef::Session { session_id: id },
        ts: now_rfc3339(),
        cpu_pct: rates.cpu_pct,
        host_cpu_pct: None,
        host_mem_pct: None,
        mem_bytes: reading.mem_used_bytes(),
        mem_total_bytes: reading.mem_total_bytes,
        swap_used_bytes: reading.swap_used_bytes(),
        swap_total_bytes: reading.swap_total_bytes,
        disk_read_bps: rates.disk_read_bps,
        disk_write_bps: rates.disk_write_bps,
        net_rx_bps: rates.net_rx_bps,
        net_tx_bps: rates.net_tx_bps,
        load1: None,
        load5: None,
        load15: None,
        uptime_secs: reading.uptime_secs.map(|u| u as u64),
        mounts: reading.mounts.clone(),
    };
    host.previous = Some((reading, at));
    Ok(sample)
}

/// MO-05: signs in to a Windows host with the session's saved login, through the same parks and caps as an SSH login
/// ([`crate::login_guard`]). Nothing is asked: a certificate not trusted yet fails (open the console once).
async fn connect_windows(
    shared: &Shared,
    tuning: &GuestTuning,
    spec: &WinrmSpec,
) -> std::result::Result<Arc<dyn WinrmSession>, Failure> {
    let key = spec.login_key();
    let park = |reason: ParkReason, what: &str| {
        let parked = Parked {
            reason,
            message: login_guard::parked_message(what),
        };
        shared.guard.park(spec.id, ParkScope::Login, &key, parked.clone());
        Failure::parked(&parked)
    };
    if let Some(parked) = shared.guard.parked(spec.id, ParkScope::Login, &key) {
        return Err(Failure::parked(&parked));
    }
    if spec.missing_password() {
        return Err(park(
            ParkReason::SecretMissing,
            &format!(
                "no password is saved for '{}'. Save it in the vault and choose it in that session, so the dashboard can sign in",
                spec.name
            ),
        ));
    }
    let password = match spec.password_id {
        Some(secret) => {
            if shared.vault.status() != VaultStatus::Unlocked {
                return Err(Failure {
                    retry_now: true,
                    ..Failure::new(
                        GuestState::VaultLocked,
                        format!(
                            "the vault is locked, and signing in to '{}' needs a secret from it",
                            spec.name
                        ),
                    )
                });
            }
            match shared.vault.get(&shared.ctx(), secret).await {
                Ok(password) => Some(password),
                Err(CoreError::UnknownTarget(_)) => {
                    return Err(park(
                        ParkReason::SecretMissing,
                        "a secret this login needs is no longer in the vault. Choose another one in the session",
                    ))
                }
                Err(err) => return Err(Failure::from_error(&err)),
            }
        }
        None => None,
    };
    if let Err(wait) = shared.guard.admit(spec.id, &[spec.login_host()]) {
        return Err(Failure {
            wait: Some(wait),
            ..Failure::new(
                GuestState::Paused,
                login_guard::capped_message(&spec.login_host(), shared.guard.per_hour(), wait),
            )
        });
    }
    let verifier = Arc::new(GuestVerifier {
        known_hosts: Arc::clone(&shared.known_hosts),
        ctx: shared.ctx(),
        target: Target {
            target: TargetRef::Session { session_id: spec.id },
            name: spec.name.clone(),
            environment: spec.environment,
            protected: false,
        },
        record_blocked: true,
    });
    let adapter = Arc::clone(&*locks::read(&shared.winrm));
    let limit = tuning.connect_timeout.saturating_mul(2);
    let connected = tokio::time::timeout(
        limit,
        adapter.connect(WinrmConnect {
            spec,
            password,
            verifier,
            tuning: WinrmTuning {
                connect_timeout: tuning.connect_timeout,
                request_timeout: tuning.command_timeout,
                ..WinrmTuning::default()
            },
        }),
    )
    .await;
    match connected {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(err)) => match ParkReason::of(&err) {
            Some(reason) => Err(park(reason, &Failure::from_error(&err).message)),
            None => Err(Failure::from_error(&err)),
        },
        Err(_) => Err(Failure::new(
            GuestState::Unreachable,
            format!("signing in to '{}' took longer than {} s", spec.name, limit.as_secs()),
        )),
    }
}

/// MO-13: after a good reading, the host's facts on the same connection when they are older than
/// the dashboard's limit. Their age is looked at every half hour at most, not every round.
async fn read_specs_when_old(shared: &Shared, id: Uuid, host: &mut Host) {
    let Some(collector) = shared.specs.get() else {
        return;
    };
    let tuning = collector.tuning();
    if host
        .specs_checked
        .is_some_and(|at| at.elapsed() < tuning.dashboard_check)
    {
        return;
    }
    host.specs_checked = Some(Instant::now());
    let Some(conn) = host.conn.as_ref() else {
        return;
    };
    if let Err(err) = collector
        .collect_if_older(
            &shared.ctx(),
            id,
            conn.as_ref(),
            tuning.dashboard_max_age,
            CollectedBy::Dashboard,
        )
        .await
    {
        tracing::debug!(session_id = %id, error = %err, "host details: reading on the dashboard's connection failed");
    }
}

/// Logs in with the session's saved login. Nothing is asked: a login that needs something typed
/// fails, saying what to save.
async fn connect(
    shared: &Shared,
    tuning: &GuestTuning,
    spec: &SessionSpec,
) -> std::result::Result<Arc<dyn ExecSession>, Failure> {
    let key = login_guard::login_key(spec);
    let park = |reason: ParkReason, what: &str| {
        let parked = Parked {
            reason,
            message: login_guard::parked_message(what),
        };
        shared.guard.park(spec.id, ParkScope::Login, &key, parked.clone());
        Failure::parked(&parked)
    };
    if let Some(parked) = shared.guard.parked(spec.id, ParkScope::Login, &key) {
        return Err(Failure::parked(&parked));
    }
    if let Some(what) = login_guard::missing_password(spec) {
        return Err(park(
            ParkReason::SecretMissing,
            &format!(
                "no password is saved for {what}. Save it in the vault and choose it in that session, so the dashboard can log in"
            ),
        ));
    }
    // SS-07: every jump host on the way logs in too, with its own saved login.
    let mut hops = spec.jumps();
    hops.push(spec);
    for hop in &hops {
        let what = if hop.id == spec.id {
            format!("'{}'", hop.name)
        } else {
            format!("the jump host '{}'", hop.name)
        };
        if needs_vault(&hop.auth) && shared.vault.status() != VaultStatus::Unlocked {
            return Err(Failure {
                retry_now: true,
                ..Failure::new(
                    GuestState::VaultLocked,
                    format!("the vault is locked, and logging in to {what} needs a secret from it"),
                )
            });
        }
    }
    // A secret that was deleted from the vault can't come back on its own.
    let missing = |err: CoreError| match err {
        CoreError::UnknownTarget(_) => park(
            ParkReason::SecretMissing,
            "a secret this login needs is no longer in the vault. Choose another one in the session",
        ),
        other => Failure::from_error(&other),
    };
    let credentials = sessions::credentials(shared.vault.as_ref(), &shared.ctx(), spec, None)
        .await
        .map_err(missing)?;
    let jump_credentials = sessions::jump_credentials(shared.vault.as_ref(), &shared.ctx(), spec, &HashMap::new())
        .await
        .map_err(missing)?;
    if let Err(wait) = shared.guard.admit(spec.id, &login_guard::login_hosts(spec)) {
        let host = crate::known_hosts::address(&spec.host, spec.port);
        return Err(Failure {
            wait: Some(wait),
            ..Failure::new(
                GuestState::Paused,
                login_guard::capped_message(&host, shared.guard.per_hour(), wait),
            )
        });
    }
    let options = ConnectOptions {
        connect_timeout: tuning.connect_timeout,
        agent: tuning.agent.clone(),
        ..ConnectOptions::default()
    };
    let verifier = Arc::new(GuestVerifier {
        known_hosts: Arc::clone(&shared.known_hosts),
        ctx: shared.ctx(),
        target: Target {
            target: TargetRef::Session { session_id: spec.id },
            name: spec.name.clone(),
            environment: spec.environment,
            protected: false,
        },
        // Once per park: a blocked key parks the host, so the next try comes after a change or Retry.
        record_blocked: true,
    });
    // The handshake has its own timeout; this one also covers a login that hangs.
    let limit = tuning.connect_timeout.saturating_mul(2);
    let connected = tokio::time::timeout(
        limit,
        shared.remote.connect(ConnectRequest {
            session: spec,
            credentials,
            jump_credentials,
            options: &options,
            verifier,
            who: "the dashboard",
        }),
    )
    .await;
    match connected {
        Ok(Ok(conn)) => Ok(Arc::from(conn)),
        Ok(Err(err)) => match ParkReason::of(&err) {
            Some(reason) => Err(park(reason, &Failure::from_error(&err).message)),
            None => Err(Failure::from_error(&err)),
        },
        Err(_) => Err(Failure::new(
            GuestState::Unreachable,
            format!("logging in to '{}' took longer than {} s", spec.name, limit.as_secs()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_wait_longer_each_time_up_to_the_cap() {
        let (min, max) = (Duration::from_secs(5), Duration::from_secs(300));
        let waits: Vec<u64> = (1..=9).map(|n| backoff(n, min, max).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(backoff(u32::MAX, min, max), max);
    }

    #[test]
    fn errors_map_to_states_the_dashboard_can_show() {
        let state = |err: CoreError| Failure::from_error(&err).state;
        assert_eq!(state(CoreError::VaultLocked), GuestState::VaultLocked);
        assert_eq!(state(CoreError::AuthFailed("x".into())), GuestState::LoginFailed);
        assert_eq!(state(CoreError::Ssh("refused".into())), GuestState::Unreachable);
        assert_eq!(
            state(CoreError::HostKeyChanged {
                address: "web01.example.com:22".into(),
                jump: None,
            }),
            GuestState::HostKey
        );
        let unknown = Failure::from_error(&CoreError::HostKeyUnknown {
            address: "web01.example.com:22".into(),
            jump: None,
        });
        assert!(unknown.message.contains("in a terminal"), "{}", unknown.message);
        assert!(
            !unknown.message.contains("tick"),
            "no bulk-run advice: {}",
            unknown.message
        );
        let at_jump = Failure::from_error(&CoreError::HostKeyUnknown {
            address: "bastion.example.com:22".into(),
            jump: Some("bastion".into()),
        });
        assert!(at_jump.message.contains("jump host 'bastion'"), "{}", at_jump.message);
        assert!(Failure::from_error(&CoreError::VaultLocked).retry_now);
        assert!(!Failure::from_error(&CoreError::Ssh("x".into())).retry_now);
    }
}
