//! QL-04 reachability dots (MO-08 lite): a cheap background check of each saved session's SSH port,
//! for the Terminal page's session tree.
//!
//! A check opens a TCP connection and closes it at once (no SSH handshake, no login), through the
//! network adapter. It is a read, so it skips the command bus and the audit log. The host's sshd still
//! logs each one (a connection that closed before it logged in), and strict fail2ban rules may count
//! them, so the checks stay light:
//!
//! * only the sessions the tree shows are checked ([`ReachabilityChecker::set_watched`]), each host and
//!   port once however many sessions share it, a few at a time;
//! * each host and port no more often than the interval in the terminal settings (5 minutes by
//!   default; the settings can turn checks off, and by default they are off for libraries of more than
//!   [`AUTO_MAX_SESSIONS`] sessions);
//! * a host found down waits longer before the next check: the interval doubles with each Down in a
//!   row, up to [`MAX_DOWN_WAIT`] ([`next_check_after`]), and is back to the interval once it is up;
//! * a host this PC already holds an SSH connection to (an open terminal, the dashboard's or the
//!   Containers page's kept connection: [`OpenConnections`]) is not checked at all. Its dot says
//!   "connected" ([`Reachability::connected`]), and the next check comes one interval after that
//!   connection closed.
//!
//! SS-07: a session behind jump hosts is not checked from this PC (its name may only resolve over
//! there, and its port is only open to the jump host). Its dot shows the first jump host's check,
//! the one this PC dials, and says so ([`Reachability::via`]); it is never red because the session
//! itself can't be reached from here. A connection through that jump host counts as one to it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::network::NetworkAdapter;
use crate::adapters::remote::{
    ConnectRequest, ExecRequest, ExecResult, ExecSession, Prompter, RemoteAdapter, ShellHandle, ShellRequest,
};
use crate::domain::now_rfc3339;
use crate::error::Result;
use crate::locks;
use crate::sessions::{SessionRecord, MAX_JUMP_DEPTH};
use crate::store::Store;
use crate::terminal::{ReachabilityMode, TerminalSettings, Terminals, TERMINAL_SETTINGS_KEY};
use crate::vault::SecretString;
use crate::workspaces::Current;

/// With the setting on "auto", libraries larger than this are not checked.
pub const AUTO_MAX_SESSIONS: usize = 200;

/// The longest a host that stays down waits between two checks (unless the interval is longer).
pub const MAX_DOWN_WAIT: Duration = Duration::from_secs(30 * 60);

/// How long after a check the same host and port is checked again: the interval while it is up, and
/// after `downs` Downs in a row the interval doubled that many times, up to [`MAX_DOWN_WAIT`] (or the
/// interval itself, when that is longer).
pub fn next_check_after(interval: Duration, downs: u32) -> Duration {
    let longest = MAX_DOWN_WAIT.max(interval);
    interval.saturating_mul(1u32 << downs.min(16)).min(longest)
}

/// How the checker paces itself. Tests shorten it.
#[derive(Debug, Clone)]
pub struct ReachabilityTuning {
    /// How long a probe waits for the port to answer.
    pub probe_timeout: Duration,
    /// Probes at once.
    pub parallel: usize,
    /// How often the checker looks for sessions that are due (and for connections opened or closed).
    pub tick: Duration,
    /// "auto" checks libraries up to this size.
    pub auto_max_sessions: usize,
    /// Overrides the interval from the terminal settings.
    pub interval: Option<Duration>,
}

impl Default for ReachabilityTuning {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(3),
            parallel: 8,
            tick: Duration::from_secs(5),
            auto_max_sessions: AUTO_MAX_SESSIONS,
            interval: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReachState {
    /// The port took a connection.
    Up,
    /// Refused, no answer in time, or the name did not resolve.
    Down,
}

/// One session's last check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reachability {
    pub session_id: Uuid,
    pub state: ReachState,
    /// How long connecting took, when a probe worked.
    pub latency_ms: Option<u64>,
    /// Why it is down.
    pub reason: Option<String>,
    /// When it was checked, or (connected) last seen with a connection open.
    pub checked_at: String,
    /// SS-07: the session is behind jump hosts, and this is the first one's state (by name): the one
    /// this PC reaches. The session itself was not checked.
    pub via: Option<String>,
    /// Not probed: this PC holds an SSH connection to the host (or, `via`, to the first jump host)
    /// now, from a terminal, the dashboard or the Containers page.
    pub connected: bool,
}

/// What the UI gets after each round that changed something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityUpdate {
    /// False when the settings (or the size of the library) turned checks off.
    pub enabled: bool,
    pub states: Vec<Reachability>,
}

/// SSH connections this PC holds open now, by saved session. A host with one is not probed: the open
/// connection already says it answers, and a probe would only add a line to its sshd log.
pub trait OpenConnections: Send + Sync {
    /// The saved sessions with a live connection now.
    fn open_sessions(&self) -> HashSet<Uuid>;
}

/// SS-03: saved sessions with a terminal connected now.
impl OpenConnections for Terminals {
    fn open_sessions(&self) -> HashSet<Uuid> {
        self.connected_sessions()
    }
}

/// One host and port, however many sessions share it.
type Endpoint = (String, u16);

fn endpoint(session: &SessionRecord) -> Endpoint {
    (session.host.to_lowercase(), session.port)
}

/// The last word on one host and port: a probe, or a connection seen open.
#[derive(Debug, Clone)]
struct Probed {
    at: Instant,
    /// Downs in a row; 0 once it is up.
    downs: u32,
    state: ReachState,
    latency_ms: Option<u64>,
    reason: Option<String>,
    checked_at: String,
}

impl Probed {
    /// What a probe found, counting Downs in a row from the last word on the same host and port.
    fn from_probe(previous: Option<&Probed>, result: &Result<Duration>, at: Instant) -> Self {
        match result {
            Ok(took) => Self {
                at,
                downs: 0,
                state: ReachState::Up,
                latency_ms: Some(u64::try_from(took.as_millis()).unwrap_or(u64::MAX)),
                reason: None,
                checked_at: now_rfc3339(),
            },
            Err(err) => Self {
                at,
                downs: previous.map_or(0, |p| p.downs).saturating_add(1),
                state: ReachState::Down,
                latency_ms: None,
                reason: Some(err.to_string()),
                checked_at: now_rfc3339(),
            },
        }
    }

    /// An open connection to the host: as good as a probe that found it up.
    fn connected(at: Instant) -> Self {
        Self {
            at,
            downs: 0,
            state: ReachState::Up,
            latency_ms: None,
            reason: None,
            checked_at: now_rfc3339(),
        }
    }

    /// Still fresh at `now`: the wait after it ([`next_check_after`]) is not over.
    fn fresh(&self, now: Instant, interval: Duration) -> bool {
        now.saturating_duration_since(self.at) < next_check_after(interval, self.downs)
    }

    fn state_for(&self, session_id: Uuid, via: Option<String>) -> Reachability {
        Reachability {
            session_id,
            state: self.state,
            latency_ms: self.latency_ms,
            reason: self.reason.clone(),
            checked_at: self.checked_at.clone(),
            via,
            connected: false,
        }
    }
}

pub struct ReachabilityChecker {
    store: Store,
    /// FD-02: the workspace shown, whose sessions are checked.
    current: Current,
    network: Arc<dyn NetworkAdapter>,
    tuning: Mutex<ReachabilityTuning>,
    watched: Mutex<HashSet<Uuid>>,
    results: Mutex<HashMap<Uuid, Reachability>>,
    last_probe: Mutex<HashMap<Endpoint, Probed>>,
    enabled: Mutex<Option<bool>>,
    connections: Mutex<Vec<Arc<dyn OpenConnections>>>,
    updates: broadcast::Sender<ReachabilityUpdate>,
    wake: Notify,
}

impl ReachabilityChecker {
    pub fn new(store: Store, current: Current, network: Arc<dyn NetworkAdapter>) -> Self {
        let (updates, _) = broadcast::channel(16);
        Self {
            store,
            current,
            network,
            tuning: Mutex::new(ReachabilityTuning::default()),
            watched: Mutex::default(),
            results: Mutex::default(),
            last_probe: Mutex::default(),
            enabled: Mutex::default(),
            connections: Mutex::default(),
            updates,
            wake: Notify::new(),
        }
    }

    pub fn set_tuning(&self, tuning: ReachabilityTuning) {
        *locks::lock(&self.tuning) = tuning;
    }

    /// Where open connections are found: the core adds its terminals and its kept connections.
    pub fn add_connections(&self, source: Arc<dyn OpenConnections>) {
        locks::lock(&self.connections).push(source);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ReachabilityUpdate> {
        self.updates.subscribe()
    }

    /// The sessions the tree shows now; only these are checked. New ones are checked at once.
    pub fn set_watched(&self, ids: impl IntoIterator<Item = Uuid>) {
        let ids: HashSet<Uuid> = ids.into_iter().collect();
        let grew = {
            let mut watched = locks::lock(&self.watched);
            let grew = ids.iter().any(|id| !watched.contains(id));
            *watched = ids;
            grew
        };
        if grew {
            self.wake.notify_one();
        }
    }

    /// The last check of every session checked so far, and whether checks are on.
    pub fn snapshot(&self) -> ReachabilityUpdate {
        let mut states: Vec<Reachability> = locks::lock(&self.results).values().cloned().collect();
        states.sort_by_key(|s| s.session_id);
        ReachabilityUpdate {
            enabled: locks::lock(&self.enabled).unwrap_or(false),
            states,
        }
    }

    /// Checks again at once, e.g. after the settings changed (a host down waits no longer either).
    pub fn poke(&self) {
        locks::lock(&self.last_probe).clear();
        self.wake.notify_one();
    }

    /// The hosts and ports this PC holds an SSH connection to now: each open session's first hop.
    fn held(&self, by_id: &HashMap<Uuid, &SessionRecord>) -> HashSet<Endpoint> {
        let sources: Vec<Arc<dyn OpenConnections>> = locks::lock(&self.connections).clone();
        sources
            .iter()
            .flat_map(|source| source.open_sessions())
            .filter_map(|id| by_id.get(&id).copied())
            .filter_map(|session| first_hop(session, by_id))
            .map(|(hop, _)| endpoint(hop))
            .collect()
    }

    /// One round: probes each watched host and port that is due, a few at a time, and returns the
    /// sessions whose state changed (or that were checked for the first time). Hosts with an open
    /// connection are not probed.
    pub async fn check_once(&self) -> Result<Vec<Reachability>> {
        let tuning = locks::lock(&self.tuning).clone();
        let settings = self
            .store
            .get_setting::<TerminalSettings>(&self.current.get(), TERMINAL_SETTINGS_KEY)
            .await?
            .unwrap_or_default();
        let watched = locks::lock(&self.watched).clone();
        // P8: with checks off, or no session on screen to check, the session list isn't read at all.
        if settings.reachability != ReachabilityMode::Off && watched.is_empty() {
            return Ok(Vec::new());
        }
        let sessions = if settings.reachability == ReachabilityMode::Off {
            Vec::new()
        } else {
            self.store.list_sessions(&self.current.get()).await?
        };
        let enabled = match settings.reachability {
            ReachabilityMode::Off => false,
            ReachabilityMode::On => true,
            ReachabilityMode::Auto => sessions.len() <= tuning.auto_max_sessions,
        };
        let was = locks::lock(&self.enabled).replace(enabled);
        if !enabled {
            locks::lock(&self.results).clear();
            if was != Some(false) {
                let _ = self.updates.send(self.snapshot());
            }
            return Ok(Vec::new());
        }

        let interval = tuning
            .interval
            .unwrap_or(Duration::from_secs(settings.reachability_secs));
        let by_id: HashMap<Uuid, &SessionRecord> = sessions.iter().map(|s| (s.id, s)).collect();
        let held = self.held(&by_id);
        let now = Instant::now();
        let mut changed = Vec::new();
        let mut due: HashMap<Endpoint, Vec<(Uuid, Option<String>)>> = HashMap::new();
        {
            let mut last = locks::lock(&self.last_probe);
            let mut results = locks::lock(&self.results);
            for session in sessions.iter().filter(|s| watched.contains(&s.id)) {
                // SS-07: behind jump hosts, the first one stands in; a chain that loops is not checked.
                let Some((checked, via)) = first_hop(session, &by_id) else {
                    continue;
                };
                let endpoint = endpoint(checked);
                let state = if held.contains(&endpoint) {
                    // An open connection answers for it, and counts as a check that found it up.
                    let probed = Probed::connected(now);
                    let state = Reachability {
                        connected: true,
                        ..probed.state_for(session.id, via)
                    };
                    last.insert(endpoint, probed);
                    state
                } else {
                    match last.get(&endpoint) {
                        // Checked lately (maybe for another session, or seen connected until a moment ago).
                        Some(probed) if probed.fresh(now, interval) => probed.state_for(session.id, via),
                        _ => {
                            due.entry(endpoint).or_default().push((session.id, via));
                            continue;
                        }
                    }
                };
                if differs(results.get(&session.id), &state) {
                    changed.push(state.clone());
                }
                results.insert(session.id, state);
            }
        }

        let limit = Arc::new(Semaphore::new(tuning.parallel.max(1)));
        let mut probes = JoinSet::new();
        for (endpoint, ids) in due {
            let network = Arc::clone(&self.network);
            let limit = Arc::clone(&limit);
            let timeout = tuning.probe_timeout;
            probes.spawn(async move {
                let _permit = limit.acquire_owned().await;
                let result = network.probe(&endpoint.0, endpoint.1, timeout).await;
                (endpoint, ids, result)
            });
        }
        while let Some(done) = probes.join_next().await {
            let Ok((endpoint, ids, result)) = done else { continue };
            let probed = {
                let mut last = locks::lock(&self.last_probe);
                let probed = Probed::from_probe(last.get(&endpoint), &result, Instant::now());
                last.insert(endpoint, probed.clone());
                probed
            };
            for (session_id, via) in ids {
                let state = probed.state_for(session_id, via);
                let previous = locks::lock(&self.results).insert(session_id, state.clone());
                if differs(previous.as_ref(), &state) {
                    changed.push(state);
                }
            }
        }
        // Sessions deleted since: forget them.
        let alive: HashSet<Uuid> = sessions.iter().map(|s| s.id).collect();
        locks::lock(&self.results).retain(|id, _| alive.contains(id));
        if !changed.is_empty() || was != Some(true) {
            let _ = self.updates.send(self.snapshot());
        }
        Ok(changed)
    }

    /// Checks until `token` is cancelled. The shell spawns it on Tauri's runtime.
    pub async fn run(self: Arc<Self>, token: CancellationToken) {
        loop {
            if let Err(err) = self.check_once().await {
                tracing::warn!(error = %err, "reachability round failed");
            }
            let tick = locks::lock(&self.tuning).tick;
            tokio::select! {
                () = token.cancelled() => break,
                () = tokio::time::sleep(tick) => {}
                () = self.wake.notified() => {}
            }
        }
    }
}

/// Whether the UI needs to hear about `now`: a new session, or another state, reason, route or
/// connection. A later time or latency alone is not news.
fn differs(previous: Option<&Reachability>, now: &Reachability) -> bool {
    previous.is_none_or(|p| {
        p.state != now.state || p.reason != now.reason || p.via != now.via || p.connected != now.connected
    })
}

/// SS-07: what this PC checks for a session: the session itself, or behind jump hosts the first one
/// (the one this PC dials) and its name. `None` for jump hosts that go round in a loop.
fn first_hop<'a>(
    session: &'a SessionRecord,
    by_id: &HashMap<Uuid, &'a SessionRecord>,
) -> Option<(&'a SessionRecord, Option<String>)> {
    let mut hop = session;
    for _ in 0..=MAX_JUMP_DEPTH {
        match hop.jump_session_id.and_then(|id| by_id.get(&id)) {
            Some(jump) => hop = jump,
            None if hop.id == session.id => return Some((session, None)),
            None => return Some((hop, Some(hop.name.clone()))),
        }
    }
    None
}

/// The remote adapter as the services that keep connections use it (MO-02 the dashboard, CT-01 the
/// Containers page, MO-13 host details), noting which saved session each kept connection is to for as
/// long as it stays open. Everything else passes straight through.
pub struct TrackedRemote {
    inner: Arc<dyn RemoteAdapter>,
    open: Mutex<Vec<(Uuid, Weak<dyn ExecSession>)>>,
}

impl TrackedRemote {
    pub fn new(inner: Arc<dyn RemoteAdapter>) -> Self {
        Self {
            inner,
            open: Mutex::default(),
        }
    }
}

#[async_trait]
impl RemoteAdapter for TrackedRemote {
    async fn exec(&self, request: ExecRequest<'_>) -> Result<ExecResult> {
        self.inner.exec(request).await
    }

    async fn open_shell(&self, request: ShellRequest<'_>, prompter: &mut dyn Prompter) -> Result<ShellHandle> {
        self.inner.open_shell(request, prompter).await
    }

    async fn connect(&self, request: ConnectRequest<'_>) -> Result<Box<dyn ExecSession>> {
        let session_id = request.session.id;
        let connection: Arc<dyn ExecSession> = Arc::from(self.inner.connect(request).await?);
        {
            let mut open = locks::lock(&self.open);
            open.retain(|(_, kept)| kept.strong_count() > 0);
            open.push((session_id, Arc::downgrade(&connection)));
        }
        Ok(Box::new(Tracked(connection)))
    }
}

/// While open and not dropped by whoever keeps it.
impl OpenConnections for TrackedRemote {
    fn open_sessions(&self) -> HashSet<Uuid> {
        let mut open = locks::lock(&self.open);
        open.retain(|(_, kept)| kept.upgrade().is_some_and(|c| !c.is_closed()));
        open.iter().map(|(id, _)| *id).collect()
    }
}

/// A kept connection from [`TrackedRemote::connect`]: the only strong hold on it, so it counts as open
/// until this is dropped (or the connection closes).
struct Tracked(Arc<dyn ExecSession>);

#[async_trait]
impl ExecSession for Tracked {
    async fn run(&self, script: &str, max_output: usize) -> Result<ExecResult> {
        self.0.run(script, max_output).await
    }

    async fn run_sudo(&self, script: &str, password: &SecretString, max_output: usize) -> Result<ExecResult> {
        self.0.run_sudo(script, password, max_output).await
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    async fn close(&self) {
        self.0.close().await;
    }

    async fn open_direct(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<crate::adapters::net_tools::BoxedStream, crate::adapters::net_tools::ConnectFailure> {
        self.0.open_direct(host, port).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn an_up_host_waits_the_interval() {
        assert_eq!(next_check_after(5 * MINUTE, 0), 5 * MINUTE);
        assert_eq!(next_check_after(Duration::from_secs(15), 0), Duration::from_secs(15));
        assert_eq!(next_check_after(60 * MINUTE, 0), 60 * MINUTE);
    }

    #[test]
    fn a_down_host_waits_twice_as_long_each_time_up_to_half_an_hour() {
        let waits: Vec<Duration> = (0..6).map(|downs| next_check_after(5 * MINUTE, downs)).collect();
        assert_eq!(
            waits,
            [
                5 * MINUTE,
                10 * MINUTE,
                20 * MINUTE,
                30 * MINUTE,
                30 * MINUTE,
                30 * MINUTE
            ]
        );
        let short: Vec<u64> = (0..9)
            .map(|downs| next_check_after(Duration::from_secs(15), downs).as_secs())
            .collect();
        assert_eq!(short, [15, 30, 60, 120, 240, 480, 960, 1800, 1800]);
    }

    #[test]
    fn an_interval_longer_than_the_cap_is_kept_and_nothing_overflows() {
        assert_eq!(next_check_after(60 * MINUTE, 1), 60 * MINUTE);
        assert_eq!(next_check_after(60 * MINUTE, 3), 60 * MINUTE);
        assert_eq!(next_check_after(Duration::from_secs(15), u32::MAX), MAX_DOWN_WAIT);
        assert_eq!(next_check_after(Duration::MAX, u32::MAX), Duration::MAX);
    }

    fn refused() -> Result<Duration> {
        Err(crate::error::CoreError::Network("connection refused".into()))
    }

    #[test]
    fn downs_in_a_row_are_counted_and_an_up_starts_again() {
        let t0 = Instant::now();
        let first = Probed::from_probe(None, &refused(), t0);
        assert_eq!((first.state, first.downs), (ReachState::Down, 1));
        assert_eq!(first.reason.as_deref(), Some("connection refused"));
        let second = Probed::from_probe(Some(&first), &refused(), t0);
        let third = Probed::from_probe(Some(&second), &refused(), t0);
        assert_eq!(third.downs, 3);
        let up = Probed::from_probe(Some(&third), &Ok(Duration::from_millis(12)), t0);
        assert_eq!((up.state, up.downs, up.latency_ms), (ReachState::Up, 0, Some(12)));
        assert_eq!(Probed::connected(t0).downs, 0);
    }

    #[test]
    fn a_host_down_is_due_later_each_time_and_on_time_again_once_up() {
        let interval = 5 * MINUTE;
        let t0 = Instant::now();
        let up = Probed::from_probe(None, &Ok(Duration::from_millis(3)), t0);
        assert!(up.fresh(t0 + interval - Duration::from_secs(1), interval));
        assert!(!up.fresh(t0 + interval, interval));

        let down = Probed::from_probe(Some(&up), &refused(), t0);
        assert!(down.fresh(t0 + interval, interval), "a Down waits twice the interval");
        assert!(!down.fresh(t0 + 2 * interval, interval));
        let mut probed = down;
        for _ in 0..10 {
            probed = Probed::from_probe(Some(&probed), &refused(), t0);
        }
        assert!(probed.fresh(t0 + MAX_DOWN_WAIT - Duration::from_secs(1), interval));
        assert!(
            !probed.fresh(t0 + MAX_DOWN_WAIT, interval),
            "never more than half an hour"
        );

        let back = Probed::from_probe(Some(&probed), &Ok(Duration::from_millis(3)), t0);
        assert!(!back.fresh(t0 + interval, interval), "up again: the interval again");
    }

    #[test]
    fn only_a_change_of_state_reason_route_or_connection_is_news() {
        let state = Reachability {
            session_id: Uuid::new_v4(),
            state: ReachState::Up,
            latency_ms: Some(3),
            reason: None,
            checked_at: "2026-10-22T10:00:00Z".into(),
            via: None,
            connected: false,
        };
        assert!(differs(None, &state));
        let later = Reachability {
            latency_ms: Some(9),
            checked_at: "2026-10-22T10:05:00Z".into(),
            ..state.clone()
        };
        assert!(!differs(Some(&state), &later));
        let connected = Reachability {
            connected: true,
            latency_ms: None,
            ..state.clone()
        };
        assert!(differs(Some(&state), &connected));
        let down = Reachability {
            state: ReachState::Down,
            reason: Some("connection refused".into()),
            ..state.clone()
        };
        assert!(differs(Some(&state), &down));
    }
}
