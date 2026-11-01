//! FD-09, SS-07: the connections port and certificate checks of a session behind a jump host go through. An open
//! terminal to the jump host lends its connection; otherwise the toolbox keeps one of its own, logged in with the
//! saved login only (nothing is asked), through [`crate::login_guard`]: a refused login, a changed host key or a
//! missing secret parks the jump host, and every login counts against the hourly cap. A kept connection closes once
//! it was idle for [`KEPT_IDLE`] (a sweep looks every [`SWEEP_EVERY`], so QL-04 checks the jump host again soon after),
//! when the vault locks and when the workspace switches; one a check is still using stays.
//!
//! MO-08: a health check that runs every few minutes would log in on each run once the idle time passed, and use up
//! the hourly cap. So a check's use may **hold** the connection past the idle time, until its next run is due
//! ([`JumpConnections::connection_held`]); the checks service lets go of every hold no active check needs any more
//! ([`JumpConnections::release_holds`]: a check paused, deleted or edited, or the workspace switched), and the idle
//! time applies again from there. The same goes for a session's own connection that a service check reads on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use uuid::Uuid;

use crate::adapters::remote::{AuthMethod, ConnectOptions, ConnectRequest, ExecSession, RemoteAdapter, SessionSpec};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::KnownHosts;
use crate::locks;
use crate::login_guard::{self, LoginGuard, ParkReason, ParkScope, Parked};
use crate::metrics::guest::{spec_key, GuestVerifier};
use crate::store::Store;
use crate::terminal::Terminals;
use crate::vault::{Vault, VaultStatus};

/// A kept connection unused this long is closed.
pub(super) const KEPT_IDLE: Duration = Duration::from_secs(120);

/// How often the sweep looks for idle kept connections (or sooner, with a shorter idle time).
pub(super) const SWEEP_EVERY: Duration = Duration::from_secs(15);

/// How long connecting and logging in to a jump host may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct JumpParts {
    pub store: Store,
    pub remote: Arc<dyn RemoteAdapter>,
    pub vault: Arc<dyn Vault>,
    pub known_hosts: Arc<KnownHosts>,
    pub guard: LoginGuard,
    pub terminals: Terminals,
}

#[derive(Default)]
struct Kept {
    connection: Option<Arc<dyn ExecSession>>,
    spec_key: String,
    used: Option<Instant>,
    /// MO-08: a health check holds it open until then (its next run), whatever the idle time.
    held_until: Option<Instant>,
}

pub(super) struct JumpConnections {
    parts: JumpParts,
    kept: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<Kept>>>>,
    /// How long a kept connection may sit unused; tests shorten it.
    idle: Mutex<Duration>,
    /// Wakes the sweep when `idle` changes.
    wake: Arc<Notify>,
}

impl JumpConnections {
    pub(super) fn new(parts: JumpParts) -> Self {
        Self {
            parts,
            kept: Mutex::default(),
            idle: Mutex::new(KEPT_IDLE),
            wake: Arc::new(Notify::new()),
        }
    }

    pub(super) fn set_idle(&self, idle: Duration) {
        *locks::lock(&self.idle) = idle;
        self.wake.notify_one();
    }

    /// How long the sweep sleeps between two looks.
    pub(super) fn sweep_every(&self) -> Duration {
        locks::lock(&self.idle).min(SWEEP_EVERY).max(Duration::from_millis(10))
    }

    pub(super) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// Kept connections open now (an open terminal's are not counted).
    pub(super) fn kept_open(&self) -> usize {
        let slots: Vec<Arc<tokio::sync::Mutex<Kept>>> = locks::lock(&self.kept).values().cloned().collect();
        slots
            .iter()
            .filter(|slot| {
                slot.try_lock()
                    .map_or(true, |kept| kept.connection.as_ref().is_some_and(|c| !c.is_closed()))
            })
            .count()
    }

    /// A connection to the session `jump_id` (a jump host, or MO-08's service check's own host): an open terminal's,
    /// or the toolbox's own. A kept one is held open for `hold` after this use (MO-08's checks), until released.
    pub(super) async fn connection_held(
        &self,
        ctx: &Context,
        jump_id: Uuid,
        hold: Option<Duration>,
    ) -> Result<Arc<dyn ExecSession>> {
        self.close_idle().await;
        if let Some(exec) = self.parts.terminals.commands_for(jump_id) {
            return Ok(exec);
        }
        let spec = self
            .parts
            .store
            .session_spec(ctx, jump_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {jump_id}")))?;
        let slot = Arc::clone(locks::lock(&self.kept).entry(spec.id).or_default());
        let mut kept = slot.lock().await;
        let key = spec_key(&spec);
        if kept.spec_key != key || kept.connection.as_ref().is_some_and(|c| c.is_closed()) {
            if let Some(old) = kept.connection.take() {
                old.close().await;
            }
        }
        if kept.connection.is_none() {
            kept.connection = Some(self.connect(ctx, &spec).await?);
            kept.spec_key = key;
        }
        let now = Instant::now();
        kept.used = Some(now);
        if let Some(hold) = hold {
            let until = now + hold;
            kept.held_until = Some(kept.held_until.map_or(until, |held| held.max(until)));
        }
        kept.connection
            .clone()
            .ok_or_else(|| CoreError::Ssh("no connection".into()))
    }

    /// MO-08: every hold on a kept connection to a session not in `keep` ends; the idle time applies again.
    pub(super) async fn release_holds(&self, keep: &std::collections::HashSet<Uuid>) {
        let slots: Vec<(Uuid, Arc<tokio::sync::Mutex<Kept>>)> = locks::lock(&self.kept)
            .iter()
            .filter(|(id, _)| !keep.contains(*id))
            .map(|(id, s)| (*id, Arc::clone(s)))
            .collect();
        for (_, slot) in slots {
            slot.lock().await.held_until = None;
        }
        self.wake.notify_one();
    }

    pub(super) async fn close_all(&self) {
        let slots: Vec<Arc<tokio::sync::Mutex<Kept>>> = locks::lock(&self.kept).drain().map(|(_, s)| s).collect();
        for slot in slots {
            let mut kept = slot.lock().await;
            if let Some(connection) = kept.connection.take() {
                connection.close().await;
            }
        }
    }

    /// Closes the kept connections unused for the idle time, unless a check still holds one.
    pub(super) async fn close_idle(&self) {
        let idle = *locks::lock(&self.idle);
        let slots: Vec<(Uuid, Arc<tokio::sync::Mutex<Kept>>)> = locks::lock(&self.kept)
            .iter()
            .map(|(id, s)| (*id, Arc::clone(s)))
            .collect();
        for (id, slot) in slots {
            let Ok(mut kept) = slot.try_lock() else {
                continue;
            };
            // A check running now holds a clone of the connection; a health check may hold it until its next run.
            let in_use = kept.connection.as_ref().is_some_and(|c| Arc::strong_count(c) > 1);
            let held = kept.held_until.is_some_and(|until| Instant::now() < until);
            if !in_use && !held && kept.used.is_none_or(|used| used.elapsed() >= idle) {
                if let Some(connection) = kept.connection.take() {
                    connection.close().await;
                }
                drop(kept);
                locks::lock(&self.kept).remove(&id);
            }
        }
    }

    /// Logs in to the jump host with its saved login only, through the login guard.
    async fn connect(&self, ctx: &Context, spec: &SessionSpec) -> Result<Arc<dyn ExecSession>> {
        let guard = &self.parts.guard;
        let key = login_guard::login_key(spec);
        let park = |reason: ParkReason, what: &str| {
            let parked = Parked {
                reason,
                message: login_guard::parked_message(what),
            };
            guard.park(spec.id, ParkScope::Login, &key, parked.clone());
            parked.error()
        };
        if let Some(parked) = guard.parked(spec.id, ParkScope::Login, &key) {
            return Err(parked.error());
        }
        if let Some(what) = login_guard::missing_password(spec) {
            return Err(park(
                ParkReason::SecretMissing,
                &format!(
                    "no password is saved for {what}. Save it in the vault and choose it in that session, or open a terminal to the jump host first"
                ),
            ));
        }
        let mut hops = spec.jumps();
        hops.push(spec);
        for hop in &hops {
            let needs_vault = matches!(hop.auth, AuthMethod::Password(Some(_)) | AuthMethod::PrivateKey { .. });
            if needs_vault && self.parts.vault.status() != VaultStatus::Unlocked {
                return Err(CoreError::VaultLocked);
            }
        }
        let missing = |err: CoreError| match err {
            CoreError::UnknownTarget(_) => park(
                ParkReason::SecretMissing,
                &format!(
                    "a secret the login to '{}' needs is no longer in the vault. Choose another one in the session",
                    spec.name
                ),
            ),
            other => other,
        };
        let credentials = crate::sessions::credentials(self.parts.vault.as_ref(), ctx, spec, None)
            .await
            .map_err(missing)?;
        let jump_credentials = crate::sessions::jump_credentials(self.parts.vault.as_ref(), ctx, spec, &HashMap::new())
            .await
            .map_err(missing)?;
        if let Err(wait) = guard.admit(spec.id, &login_guard::login_hosts(spec)) {
            let host = crate::known_hosts::address(&spec.host, spec.port);
            return Err(CoreError::LoginsCapped {
                message: login_guard::capped_message(&host, guard.per_hour(), wait),
                wait_secs: wait.as_secs(),
            });
        }
        let options = ConnectOptions {
            connect_timeout: CONNECT_TIMEOUT,
            keepalive_interval: Some(Duration::from_secs(30)),
            ..ConnectOptions::default()
        };
        let verifier = Arc::new(GuestVerifier {
            known_hosts: Arc::clone(&self.parts.known_hosts),
            ctx: *ctx,
            target: Target {
                target: TargetRef::Session { session_id: spec.id },
                name: spec.name.clone(),
                environment: spec.environment,
                protected: false,
            },
            record_blocked: true,
        });
        let limit = CONNECT_TIMEOUT.saturating_mul(2);
        let connected = tokio::time::timeout(
            limit,
            self.parts.remote.connect(ConnectRequest {
                session: spec,
                credentials,
                jump_credentials,
                options: &options,
                verifier,
                who: "the toolbox",
            }),
        )
        .await
        .map_err(|_| CoreError::Timeout {
            command: format!("logging in to the jump host '{}'", spec.name),
            seconds: limit.as_secs(),
        })?;
        match connected {
            Ok(connection) => Ok(Arc::from(connection)),
            Err(CoreError::HostKeyUnknown { address, jump }) => {
                let place = match &jump {
                    Some(name) => format!("the jump host '{name}' ({address})"),
                    None => format!("the jump host '{}' ({address})", spec.name),
                };
                Err(CoreError::Ssh(format!(
                    "the host key of {place} is not trusted yet. Connect to it once in a terminal to check and trust it"
                )))
            }
            Err(err) => match ParkReason::of(&err) {
                Some(reason) => Err(park(reason, &err.to_string())),
                None => Err(err),
            },
        }
    }
}
