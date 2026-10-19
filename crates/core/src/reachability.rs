//! QL-04 reachability dots (MO-08 lite): a cheap background check of each saved session's SSH port,
//! for the Terminal page's session tree.
//!
//! A check opens a TCP connection and closes it at once (no SSH handshake, no login), through the
//! network adapter. It is a read, so it skips the command bus and the audit log. To stay light on
//! large libraries it only checks the sessions the tree shows ([`ReachabilityChecker::set_watched`]),
//! each host and port once however many sessions share it, a few at a time, and each no more often
//! than the interval in the terminal settings. The settings can turn it off; by default it is off for
//! libraries of more than [`AUTO_MAX_SESSIONS`] sessions.
//!
//! SS-07: a session behind jump hosts is not checked from this PC (its name may only resolve over
//! there, and its port is only open to the jump host). Its dot shows the first jump host's check,
//! the one this PC dials, and says so ([`Reachability::via`]); it is never red because the session
//! itself can't be reached from here.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::network::NetworkAdapter;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::locks;
use crate::sessions::{SessionRecord, MAX_JUMP_DEPTH};
use crate::store::Store;
use crate::terminal::{ReachabilityMode, TerminalSettings, TERMINAL_SETTINGS_KEY};

/// With the setting on "auto", libraries larger than this are not checked.
pub const AUTO_MAX_SESSIONS: usize = 200;

/// How the checker paces itself. Tests shorten it.
#[derive(Debug, Clone)]
pub struct ReachabilityTuning {
    /// How long a probe waits for the port to answer.
    pub probe_timeout: Duration,
    /// Probes at once.
    pub parallel: usize,
    /// How often the checker looks for sessions that are due.
    pub tick: Duration,
    /// "auto" checks libraries up to this size.
    pub auto_max_sessions: usize,
}

impl Default for ReachabilityTuning {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(3),
            parallel: 8,
            tick: Duration::from_secs(5),
            auto_max_sessions: AUTO_MAX_SESSIONS,
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
    /// How long connecting took, when it worked.
    pub latency_ms: Option<u64>,
    /// Why it is down.
    pub reason: Option<String>,
    pub checked_at: String,
    /// SS-07: the session is behind jump hosts, and this is the first one's state (by name): the one
    /// this PC reaches. The session itself was not checked.
    pub via: Option<String>,
}

/// What the UI gets after each round that changed something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachabilityUpdate {
    /// False when the settings (or the size of the library) turned checks off.
    pub enabled: bool,
    pub states: Vec<Reachability>,
}

/// One host and port, however many sessions share it.
type Endpoint = (String, u16);

pub struct ReachabilityChecker {
    store: Store,
    ctx: Context,
    network: Arc<dyn NetworkAdapter>,
    tuning: Mutex<ReachabilityTuning>,
    watched: Mutex<HashSet<Uuid>>,
    results: Mutex<HashMap<Uuid, Reachability>>,
    last_probe: Mutex<HashMap<Endpoint, Instant>>,
    enabled: Mutex<Option<bool>>,
    updates: broadcast::Sender<ReachabilityUpdate>,
    wake: Notify,
}

impl ReachabilityChecker {
    pub fn new(store: Store, ctx: Context, network: Arc<dyn NetworkAdapter>) -> Self {
        let (updates, _) = broadcast::channel(16);
        Self {
            store,
            ctx,
            network,
            tuning: Mutex::new(ReachabilityTuning::default()),
            watched: Mutex::default(),
            results: Mutex::default(),
            last_probe: Mutex::default(),
            enabled: Mutex::default(),
            updates,
            wake: Notify::new(),
        }
    }

    pub fn set_tuning(&self, tuning: ReachabilityTuning) {
        *locks::lock(&self.tuning) = tuning;
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

    /// Checks again at once, e.g. after the settings changed.
    pub fn poke(&self) {
        locks::lock(&self.last_probe).clear();
        self.wake.notify_one();
    }

    /// One round: probes each watched host and port that is due, a few at a time, and returns the
    /// sessions whose state changed (or that were checked for the first time).
    pub async fn check_once(&self) -> Result<Vec<Reachability>> {
        let tuning = locks::lock(&self.tuning).clone();
        let settings = self
            .store
            .get_setting::<TerminalSettings>(&self.ctx, TERMINAL_SETTINGS_KEY)
            .await?
            .unwrap_or_default();
        let sessions = self.store.list_sessions(&self.ctx).await?;
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

        let watched = locks::lock(&self.watched).clone();
        let interval = Duration::from_secs(settings.reachability_secs);
        let now = Instant::now();
        let known: HashSet<Uuid> = locks::lock(&self.results).keys().copied().collect();
        let mut due: HashMap<Endpoint, Vec<(Uuid, Option<String>)>> = HashMap::new();
        {
            let last = locks::lock(&self.last_probe);
            let by_id: HashMap<Uuid, &SessionRecord> = sessions.iter().map(|s| (s.id, s)).collect();
            for session in sessions.iter().filter(|s| watched.contains(&s.id)) {
                // SS-07: behind jump hosts, the first one stands in; a chain that loops is not checked.
                let Some((checked, via)) = first_hop(session, &by_id) else {
                    continue;
                };
                let endpoint = (checked.host.to_lowercase(), checked.port);
                let fresh = last.get(&endpoint).is_some_and(|at| now.duration_since(*at) < interval);
                if !fresh || !known.contains(&session.id) {
                    due.entry(endpoint).or_default().push((session.id, via));
                }
            }
        }
        if due.is_empty() {
            return Ok(Vec::new());
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
        let mut changed = Vec::new();
        while let Some(done) = probes.join_next().await {
            let Ok((endpoint, ids, result)) = done else { continue };
            locks::lock(&self.last_probe).insert(endpoint, Instant::now());
            let checked_at = now_rfc3339();
            for (session_id, via) in ids {
                let state = match &result {
                    Ok(took) => Reachability {
                        session_id,
                        state: ReachState::Up,
                        latency_ms: Some(u64::try_from(took.as_millis()).unwrap_or(u64::MAX)),
                        reason: None,
                        checked_at: checked_at.clone(),
                        via,
                    },
                    Err(err) => Reachability {
                        session_id,
                        state: ReachState::Down,
                        latency_ms: None,
                        reason: Some(err.to_string()),
                        checked_at: checked_at.clone(),
                        via,
                    },
                };
                let previous = locks::lock(&self.results).insert(session_id, state.clone());
                let same =
                    previous.is_some_and(|p| p.state == state.state && p.reason == state.reason && p.via == state.via);
                if !same {
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
