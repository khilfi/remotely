//! MO-02: Linux guest metrics over SSH, for the sessions the user chose to watch on the dashboard
//! (a VM's guest metrics come from a session linked to it).
//!
//! Each watched host gets one connection, logged in once and kept between rounds; every round runs
//! [`procfs::GUEST_SCRIPT`] on a new channel of it. A read, so it skips the command bus and the
//! approval flow (CLAUDE.md, architecture rule 3), and it changes nothing on the host.
//!
//! A host that can't be reached, refuses the login, or presents an untrusted key is retried after a
//! wait that doubles each time (5 s up to 5 minutes), and its state says why. A login that needs a
//! secret waits while the vault is locked, without trying. Host keys are checked like a bulk run
//! checks them: trusted passes, unknown fails (trust it in a terminal first), changed blocks and is
//! audited. Secrets come from the vault for each new login and go only to the adapter.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::procfs::{self, GuestReading};
use super::{GuestState, GuestStatus, MetricSample, MetricSource, MetricsSource, SourceRound};
use crate::adapters::remote::{
    AgentSource, AuthMethod, ConnectOptions, ConnectRequest, ExecSession, HostKeyVerifier, RemoteAdapter, SessionSpec,
};
use crate::domain::{now_rfc3339, Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, HostKeyCheck, KnownHosts};
use crate::locks;
use crate::sessions;
use crate::store::Store;
use crate::vault::{Vault, VaultStatus};

/// Settings key: the sessions watched for guest metrics (a list of session ids).
pub const WATCHED_KEY: &str = "metrics.guestSessions";

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
    conn: Option<Box<dyn ExecSession>>,
    previous: Option<(GuestReading, Instant)>,
    failures: u32,
    next_try: Option<Instant>,
    /// A changed host key was audited for this host already; not again every retry.
    blocked_recorded: bool,
}

impl Host {
    fn new() -> Self {
        Self {
            spec_key: String::new(),
            conn: None,
            previous: None,
            failures: 0,
            next_try: None,
            blocked_recorded: false,
        }
    }

    async fn disconnect(&mut self) {
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
    ctx: Context,
    remote: Arc<dyn RemoteAdapter>,
    vault: Arc<dyn Vault>,
    known_hosts: Arc<KnownHosts>,
    tuning: RwLock<GuestTuning>,
    statuses: Mutex<HashMap<Uuid, StatusEntry>>,
    /// Good readings not yet handed to a round.
    fresh: Mutex<HashMap<Uuid, MetricSample>>,
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
    /// The host key changed: the block is audited once, not at every retry.
    key_changed: bool,
}

impl Failure {
    fn new(state: GuestState, message: impl Into<String>) -> Self {
        Self {
            state,
            message: message.into(),
            retry_now: false,
            key_changed: false,
        }
    }

    fn from_error(err: &CoreError) -> Self {
        let state = match err {
            CoreError::VaultLocked | CoreError::VaultNotSetUp => GuestState::VaultLocked,
            CoreError::AuthFailed(_) | CoreError::AgentUnavailable(_) => GuestState::LoginFailed,
            CoreError::HostKeyChanged { .. } | CoreError::HostKeyRejected { .. } | CoreError::HostKeyUnknown { .. } => {
                GuestState::HostKey
            }
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
            key_changed: matches!(err, CoreError::HostKeyChanged { .. }),
            ..Self::new(state, message)
        }
    }
}

/// SS-05 for guest polling: trusted keys pass, unknown keys fail (no one is there to ask), and a
/// changed key blocks the connection and is audited.
struct GuestVerifier {
    known_hosts: Arc<KnownHosts>,
    ctx: Context,
    target: Target,
    record_blocked: bool,
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
}

/// What a connection depends on: host, port, user, login method and its vault ids, for the session
/// and each jump host on the way (SS-07).
fn spec_key(spec: &SessionSpec) -> String {
    let hop = |s: &SessionSpec| format!("{}|{}|{}|{:?}", s.host, s.port, s.username, s.auth);
    let mut key: Vec<String> = spec.jumps().into_iter().map(hop).collect();
    key.push(hop(spec));
    key.join(" > ")
}

fn needs_vault(auth: &AuthMethod) -> bool {
    matches!(auth, AuthMethod::Password(Some(_)) | AuthMethod::PrivateKey { .. })
}

impl GuestSource {
    pub fn new(
        store: Store,
        ctx: Context,
        remote: Arc<dyn RemoteAdapter>,
        vault: Arc<dyn Vault>,
        known_hosts: Arc<KnownHosts>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                store,
                ctx,
                remote,
                vault,
                known_hosts,
                tuning: RwLock::new(GuestTuning::default()),
                statuses: Mutex::new(HashMap::new()),
                fresh: Mutex::new(HashMap::new()),
            }),
            hosts: Mutex::new(HashMap::new()),
        }
    }

    pub fn tuning(&self) -> GuestTuning {
        locks::read(&self.shared.tuning).clone()
    }

    /// Tests shorten the timeouts and waits.
    pub fn set_tuning(&self, tuning: GuestTuning) {
        *locks::write(&self.shared.tuning) = tuning;
    }

    /// The sessions watched for guest metrics.
    pub async fn watched(&self) -> Result<Vec<Uuid>> {
        Ok(self
            .shared
            .store
            .get_setting::<Vec<Uuid>>(&self.shared.ctx, WATCHED_KEY)
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
        })
    }
}

/// One poll of one host: connect if needed, run the script, keep the reading.
async fn poll(shared: &Shared, id: Uuid, host: &mut Host) {
    let tuning = locks::read(&shared.tuning).clone();
    match read_once(shared, &tuning, id, host).await {
        Ok(sample) => {
            host.failures = 0;
            host.next_try = None;
            let mut status = GuestStatus::new(id, GuestState::Ok, None);
            status.last_ok = Some(sample.ts.clone());
            locks::lock(&shared.statuses).insert(id, StatusEntry { status, retry_at: None });
            locks::lock(&shared.fresh).insert(id, sample);
        }
        Err(failure) => {
            let retry_at = if failure.retry_now {
                None
            } else {
                host.failures = host.failures.saturating_add(1);
                Some(Instant::now() + backoff(host.failures, tuning.backoff_min, tuning.backoff_max))
            };
            host.next_try = retry_at;
            let mut statuses = locks::lock(&shared.statuses);
            let last_ok = statuses.get(&id).and_then(|e| e.status.last_ok.clone());
            let mut status = GuestStatus::new(id, failure.state, Some(failure.message));
            status.last_ok = last_ok;
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
    let ctx = shared.ctx;
    let spec = match shared.store.session_spec(&ctx, id).await {
        Ok(Some(spec)) => spec,
        Ok(None) => return Err(Failure::new(GuestState::Error, "the session was deleted")),
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
        match connect(shared, tuning, &spec, host.blocked_recorded).await {
            Ok(conn) => {
                host.conn = Some(conn);
                host.blocked_recorded = false;
            }
            Err(failure) => {
                host.blocked_recorded |= failure.key_changed;
                return Err(failure);
            }
        }
    }
    let Some(conn) = host.conn.as_ref() else {
        return Err(Failure::new(GuestState::Error, "no connection"));
    };
    let ran = tokio::time::timeout(
        tuning.command_timeout,
        conn.run(procfs::GUEST_SCRIPT, procfs::MAX_OUTPUT),
    )
    .await;
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
    let reading = procfs::parse(&result.output.stdout);
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

/// Logs in with the session's saved login. Nothing is asked: a login that needs something typed
/// fails, saying what to save.
async fn connect(
    shared: &Shared,
    tuning: &GuestTuning,
    spec: &SessionSpec,
    blocked_recorded: bool,
) -> std::result::Result<Box<dyn ExecSession>, Failure> {
    // SS-07: every jump host on the way logs in too, with its own saved login.
    let mut hops = spec.jumps();
    hops.push(spec);
    for hop in &hops {
        let what = if hop.id == spec.id {
            format!("'{}'", hop.name)
        } else {
            format!("the jump host '{}'", hop.name)
        };
        if hop.auth == AuthMethod::Password(None) {
            return Err(Failure::new(
                GuestState::LoginFailed,
                format!(
                    "no password is saved for {what}. Save it in the vault and choose it in that session, so the dashboard can log in"
                ),
            ));
        }
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
    let credentials = sessions::credentials(shared.vault.as_ref(), &shared.ctx, spec, None)
        .await
        .map_err(|err| Failure::from_error(&err))?;
    let jump_credentials = sessions::jump_credentials(shared.vault.as_ref(), &shared.ctx, spec, &HashMap::new())
        .await
        .map_err(|err| Failure::from_error(&err))?;
    let options = ConnectOptions {
        connect_timeout: tuning.connect_timeout,
        agent: tuning.agent.clone(),
        ..ConnectOptions::default()
    };
    let verifier = Arc::new(GuestVerifier {
        known_hosts: Arc::clone(&shared.known_hosts),
        ctx: shared.ctx,
        target: Target {
            target: TargetRef::Session { session_id: spec.id },
            name: spec.name.clone(),
            environment: spec.environment,
            protected: false,
        },
        record_blocked: !blocked_recorded,
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
        }),
    )
    .await;
    match connected {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(err)) => Err(Failure::from_error(&err)),
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
