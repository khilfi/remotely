//! MO-02, CT-01: what keeps background logins from locking customer accounts or getting this PC
//! banned. Background logins are the dashboard's guest polling and the Containers page's reads: no one
//! types anything, so a wrong saved password would otherwise be tried again and again, and pam_faillock,
//! Active Directory or fail2ban count every try.
//!
//! * **Parked.** A login the host refused, a sudo password it refused, a host key that changed, or a
//!   secret that isn't saved parks the session: no background login (or sudo) is tried for it again
//!   until the session or its credentials change, the vault is unlocked, a host key is trusted or
//!   removed, or the user presses Retry. A changed host key is audited by the try that parks, so once
//!   per park.
//! * **Capped.** Every background login counts against a limit per host per hour, each jump host on
//!   the way included. Over the limit, the next login waits until the oldest one leaves the hour.
//!
//! Interactive terminals don't come through here: they never retry a refused login on their own.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use uuid::Uuid;

use crate::adapters::remote::{AuthMethod, SessionSpec};
use crate::error::CoreError;
use crate::locks;

/// Background logins one host takes in an hour, at most.
pub const DEFAULT_LOGINS_PER_HOUR: usize = 10;

/// What a park stops: every login to the session, or only sudo on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParkScope {
    Login,
    Sudo,
}

/// Why background logins to a session stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ParkReason {
    /// The host refused the login (or the agent had no key it took).
    LoginRefused,
    /// sudo refused the saved password.
    SudoRefused,
    /// The host key changed: the connection was blocked and audited.
    HostKeyChanged,
    /// The login needs a secret that isn't saved.
    SecretMissing,
}

impl ParkReason {
    /// The reason to park after `err`, if it is one: retrying can't help until something changes.
    pub fn of(err: &CoreError) -> Option<Self> {
        match err {
            CoreError::AuthFailed(_) | CoreError::AgentUnavailable(_) => Some(Self::LoginRefused),
            CoreError::SudoPasswordRefused => Some(Self::SudoRefused),
            CoreError::HostKeyChanged { .. } => Some(Self::HostKeyChanged),
            CoreError::CertificateChanged { .. } => Some(Self::HostKeyChanged),
            CoreError::NoSudoPassword(_) | CoreError::UnknownTarget(_) => Some(Self::SecretMissing),
            _ => None,
        }
    }
}

/// A parked session, as the caller shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parked {
    pub reason: ParkReason,
    /// What went wrong, in words. Never holds a secret.
    pub message: String,
}

impl Parked {
    /// The error a read returns while parked.
    pub fn error(&self) -> CoreError {
        CoreError::LoginParked {
            message: self.message.clone(),
        }
    }
}

/// The limits; tests change them.
#[derive(Debug, Clone)]
pub struct LoginLimits {
    pub per_hour: usize,
    pub window: Duration,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self {
            per_hour: DEFAULT_LOGINS_PER_HOUR,
            window: Duration::from_secs(3600),
        }
    }
}

struct Park {
    parked: Parked,
    /// What the session's login was when it parked ([`login_key`]): a session edited since then tries again.
    key: String,
    /// [`State::generation`] when it parked: credentials changed since then try again.
    generation: u64,
}

#[derive(Default)]
struct State {
    /// Moves on when the vault is unlocked, a secret is added, replaced or deleted, or a host key is
    /// trusted or removed.
    generation: u64,
    parks: HashMap<(Uuid, ParkScope), Park>,
    /// Background logins in the last window, by `host:port`.
    logins: HashMap<String, VecDeque<Instant>>,
    /// Sessions whose next login skips the cap once (Retry was pressed).
    granted: HashSet<Uuid>,
}

/// Review C2: a per-account sign-in gate so WinRM hosts that share one login (lower-cased user and vault item) don't
/// all sign in at once and lock a domain account. The first host to use an account signs in alone; the others wait.
/// Only an accepted sign-in opens the gate (they then go in parallel); a refused one closes it (they are skipped until
/// credentials change); any other result — unreachable, timeout, a changed certificate, a cancel, or a leader dropped
/// without a result — leaves the account unverified and hands the lead to the next waiting host, since the password was
/// never checked. The map lives in the login guard, so it is shared by every job and cleared on the same events as
/// parks (credentials changed, Retry).
type WinrmGate = Arc<Mutex<HashMap<String, Arc<AccountGate>>>>;

#[derive(Default)]
struct GateInner {
    /// `None` until a sign-in is accepted (`Some(true)`) or refused (`Some(false)`); an inconclusive leader leaves it
    /// `None` so the lead passes on.
    outcome: Option<bool>,
    /// A host is signing in with this account right now.
    leader_busy: bool,
}

/// One account's gate. The watch wakes waiters whenever leadership frees up or the outcome is set.
struct AccountGate {
    inner: Mutex<GateInner>,
    wake: tokio::sync::watch::Sender<u64>,
}

impl Default for AccountGate {
    fn default() -> Self {
        Self {
            inner: Mutex::new(GateInner::default()),
            wake: tokio::sync::watch::channel(0).0,
        }
    }
}

/// What a host does at an account's gate.
pub enum GateRole {
    /// Be the first to sign in with this account; report the result with [`Leader::finish`].
    Leader(Leader),
    /// The account is verified, or this host is not password auth: go now.
    Proceed,
    /// The account's password was refused: skip, don't try it again.
    Skip,
}

/// The leader of an account's first sign-in. Dropped without [`Self::finish`] (a cancel or panic), it leaves the
/// account unverified and hands the lead on, never opening the gate.
pub struct Leader {
    map: WinrmGate,
    account: String,
    gate: Arc<AccountGate>,
    done: bool,
}

impl Leader {
    /// Report the sign-in: `Some(true)` accepted (the gate opens for the others), `Some(false)` refused (it closes,
    /// the others skip), `None` inconclusive (a network or certificate error, a timeout or a cancel — the account is
    /// still unverified, so the lead passes to the next waiting host).
    pub fn finish(mut self, outcome: Option<bool>) {
        self.settle(outcome);
    }

    fn settle(&mut self, outcome: Option<bool>) {
        if self.done {
            return;
        }
        self.done = true;
        {
            let mut inner = locks::lock(&self.gate.inner);
            inner.leader_busy = false;
            if let Some(accepted) = outcome {
                inner.outcome = Some(accepted);
            }
        }
        self.gate.wake.send_modify(|g| *g = g.wrapping_add(1));
        // A refused account stays in the map, so later hosts skip it until credentials change. An accepted or
        // still-unverified one is dropped, so a later run re-verifies it (catching a password changed on the host
        // itself). Waiting hosts hold their own `Arc` to the gate, so removing it here never cuts them off.
        if outcome != Some(false) {
            let mut map = locks::lock(&self.map);
            if map.get(&self.account).is_some_and(|g| Arc::ptr_eq(g, &self.gate)) {
                map.remove(&self.account);
            }
        }
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        self.settle(None);
    }
}

/// Shared by the dashboard and the Containers page. Cloning gives another handle to the same one.
#[derive(Clone, Default)]
pub struct LoginGuard {
    state: Arc<Mutex<State>>,
    limits: Arc<RwLock<LoginLimits>>,
    /// Review C2: the per-account WinRM sign-in gate, shared by every job and cleared with the parks.
    winrm_gate: WinrmGate,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_limits(&self, limits: LoginLimits) {
        *locks::write(&self.limits) = limits;
    }

    /// The vault was unlocked, a secret changed, or a host key was trusted or removed: every parked
    /// session gets one more try, and every account gate is forgotten so runs re-verify.
    pub fn credentials_changed(&self) {
        {
            let mut state = locks::lock(&self.state);
            state.generation = state.generation.wrapping_add(1);
        }
        self.clear_winrm_gate();
    }

    /// Review C2: a host's role at `account`'s gate (lower-cased user and vault item). See [`GateRole`].
    pub async fn winrm_gate_role(&self, account: &str) -> GateRole {
        let entry = {
            let mut map = locks::lock(&self.winrm_gate);
            Arc::clone(map.entry(account.to_owned()).or_default())
        };
        let mut rx = entry.wake.subscribe();
        loop {
            {
                let mut inner = locks::lock(&entry.inner);
                match inner.outcome {
                    Some(true) => return GateRole::Proceed,
                    Some(false) => return GateRole::Skip,
                    None if !inner.leader_busy => {
                        inner.leader_busy = true;
                        return GateRole::Leader(Leader {
                            map: Arc::clone(&self.winrm_gate),
                            account: account.to_owned(),
                            gate: Arc::clone(&entry),
                            done: false,
                        });
                    }
                    None => {}
                }
            }
            // A leader is signing in: wait for it to set the outcome or hand the lead on.
            if rx.changed().await.is_err() {
                return GateRole::Proceed;
            }
        }
    }

    /// Review C2: forget every account gate, so later runs re-verify. Called whenever parks are cleared.
    fn clear_winrm_gate(&self) {
        let mut map = locks::lock(&self.winrm_gate);
        for gate in map.values() {
            gate.wake.send_modify(|g| *g = g.wrapping_add(1));
        }
        map.clear();
    }

    /// The park for `session`, if it still holds: the session's login (`key`) and the credentials are
    /// what they were when it parked. One that no longer holds is dropped.
    pub fn parked(&self, session: Uuid, scope: ParkScope, key: &str) -> Option<Parked> {
        let mut state = locks::lock(&self.state);
        let generation = state.generation;
        let holds = state
            .parks
            .get(&(session, scope))
            .map(|park| park.key == key && park.generation == generation)?;
        if holds {
            state.parks.get(&(session, scope)).map(|park| park.parked.clone())
        } else {
            state.parks.remove(&(session, scope));
            None
        }
    }

    /// Stops background logins (or sudo) for `session` until something changes.
    pub fn park(&self, session: Uuid, scope: ParkScope, key: &str, parked: Parked) {
        let mut state = locks::lock(&self.state);
        let generation = state.generation;
        state.parks.insert(
            (session, scope),
            Park {
                parked,
                key: key.to_owned(),
                generation,
            },
        );
    }

    /// The user pressed Retry: the session's parks are lifted, its next login skips the hourly cap, and every account
    /// gate is forgotten so a shared login is re-verified.
    pub fn retry(&self, session: Uuid) {
        {
            let mut state = locks::lock(&self.state);
            state.parks.retain(|(id, _), _| *id != session);
            state.granted.insert(session);
        }
        self.clear_winrm_gate();
    }

    /// Counts one background login to each of `hosts` (`host:port`, the jump hosts and the target).
    /// `Err` holds the wait until the busiest one is under the cap again; nothing is counted then.
    pub fn admit(&self, session: Uuid, hosts: &[String]) -> std::result::Result<(), Duration> {
        let limits = locks::read(&self.limits).clone();
        let now = Instant::now();
        let mut state = locks::lock(&self.state);
        let granted = state.granted.remove(&session);
        let mut wait = Duration::ZERO;
        for host in hosts {
            let times = state.logins.entry(host.clone()).or_default();
            while times.front().is_some_and(|t| now.duration_since(*t) >= limits.window) {
                times.pop_front();
            }
            if !granted && times.len() >= limits.per_hour.max(1) {
                if let Some(oldest) = times.front() {
                    wait = wait.max(limits.window.saturating_sub(now.duration_since(*oldest)));
                }
            }
        }
        if !wait.is_zero() {
            // Retry stays granted until it is used.
            if granted {
                state.granted.insert(session);
            }
            return Err(wait);
        }
        for host in hosts {
            state.logins.entry(host.clone()).or_default().push_back(now);
        }
        state.logins.retain(|_, times| !times.is_empty());
        Ok(())
    }
}

/// What a session's background login depends on: host, port, user, login method and its vault ids
/// for the session and each jump host on the way (SS-07).
pub fn login_key(spec: &SessionSpec) -> String {
    let hop = |s: &SessionSpec| format!("{}|{}|{}|{:?}", s.host, s.port, s.username, s.auth);
    let mut key: Vec<String> = spec.jumps().into_iter().map(hop).collect();
    key.push(hop(spec));
    key.join(" > ")
}

/// The hosts a login to `spec` reaches, each jump host first: what the hourly cap counts.
pub fn login_hosts(spec: &SessionSpec) -> Vec<String> {
    let mut hops = spec.jumps();
    hops.push(spec);
    hops.iter()
        .map(|s| crate::known_hosts::address(&s.host.to_lowercase(), s.port))
        .collect()
}

/// The first session on the way to `spec` (a jump host or itself) whose login needs a password that
/// isn't saved, by name: such a login can't work in the background.
pub fn missing_password(spec: &SessionSpec) -> Option<String> {
    let mut hops = spec.jumps();
    hops.push(spec);
    hops.into_iter()
        .find(|hop| hop.auth == AuthMethod::Password(None))
        .map(|hop| {
            if hop.id == spec.id {
                format!("'{}'", hop.name)
            } else {
                format!("the jump host '{}'", hop.name)
            }
        })
}

/// "Not tried again on its own" in words, after what went wrong.
pub fn parked_message(what: &str) -> String {
    let what = what.trim_end_matches('.');
    format!("{what}. Remotely won't log in again on its own: fix it (or change the session), then press Retry")
}

/// The wait for the hourly cap, in words.
pub fn capped_message(host: &str, limits_per_hour: usize, wait: Duration) -> String {
    let minutes = wait.as_secs().div_ceil(60).max(1);
    format!(
        "{limits_per_hour} background logins to {host} in the last hour, the most Remotely makes; the next is in {minutes} min at most"
    )
}

impl LoginGuard {
    /// The cap per hour, for messages.
    pub fn per_hour(&self) -> usize {
        locks::read(&self.limits).per_hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parked(reason: ParkReason) -> Parked {
        Parked {
            reason,
            message: "login failed".into(),
        }
    }

    #[test]
    fn a_park_holds_until_the_session_or_the_credentials_change_or_retry() {
        let guard = LoginGuard::new();
        let web = Uuid::new_v4();
        guard.park(web, ParkScope::Login, "k1", parked(ParkReason::LoginRefused));
        assert!(guard.parked(web, ParkScope::Login, "k1").is_some());
        assert!(guard.parked(web, ParkScope::Login, "k1").is_some(), "still parked");
        assert!(
            guard.parked(web, ParkScope::Sudo, "k1").is_none(),
            "sudo is its own scope"
        );

        // The session was edited: one more try.
        assert!(guard.parked(web, ParkScope::Login, "k2").is_none());
        assert!(guard.parked(web, ParkScope::Login, "k1").is_none(), "dropped for good");

        guard.park(web, ParkScope::Login, "k1", parked(ParkReason::LoginRefused));
        guard.credentials_changed();
        assert!(guard.parked(web, ParkScope::Login, "k1").is_none());

        guard.park(web, ParkScope::Sudo, "k1", parked(ParkReason::SudoRefused));
        guard.retry(web);
        assert!(guard.parked(web, ParkScope::Sudo, "k1").is_none());
    }

    #[test]
    fn logins_are_capped_per_host_per_hour_and_retry_skips_the_cap_once() {
        let guard = LoginGuard::new();
        guard.set_limits(LoginLimits {
            per_hour: 3,
            window: Duration::from_secs(3600),
        });
        let web = Uuid::new_v4();
        let hosts = vec!["bastion.example.com:22".to_owned(), "web01.example.com:22".to_owned()];
        for _ in 0..3 {
            assert!(guard.admit(web, &hosts).is_ok());
        }
        let wait = guard.admit(web, &hosts).unwrap_err();
        assert!(wait > Duration::from_secs(3500), "{wait:?}");
        // Another host behind the same jump host is capped by the jump host.
        let db = Uuid::new_v4();
        assert!(guard
            .admit(
                db,
                &["bastion.example.com:22".to_owned(), "db01.example.com:22".to_owned()]
            )
            .is_err());
        assert!(guard.admit(db, &["db01.example.com:22".to_owned()]).is_ok());

        guard.retry(web);
        assert!(guard.admit(web, &hosts).is_ok(), "Retry gets one login past the cap");
        assert!(guard.admit(web, &hosts).is_err());
    }

    #[test]
    fn the_cap_forgets_logins_older_than_the_window() {
        let guard = LoginGuard::new();
        guard.set_limits(LoginLimits {
            per_hour: 1,
            window: Duration::from_millis(30),
        });
        let web = Uuid::new_v4();
        let hosts = vec!["web01.example.com:22".to_owned()];
        assert!(guard.admit(web, &hosts).is_ok());
        assert!(guard.admit(web, &hosts).is_err());
        std::thread::sleep(Duration::from_millis(40));
        assert!(guard.admit(web, &hosts).is_ok());
    }

    #[test]
    fn errors_that_retrying_cannot_fix_park() {
        assert_eq!(
            ParkReason::of(&CoreError::AuthFailed("password for alice".into())),
            Some(ParkReason::LoginRefused)
        );
        assert_eq!(
            ParkReason::of(&CoreError::AgentUnavailable("no agent".into())),
            Some(ParkReason::LoginRefused)
        );
        assert_eq!(
            ParkReason::of(&CoreError::SudoPasswordRefused),
            Some(ParkReason::SudoRefused)
        );
        assert_eq!(
            ParkReason::of(&CoreError::HostKeyChanged {
                address: "web01.example.com:22".into(),
                jump: None
            }),
            Some(ParkReason::HostKeyChanged)
        );
        assert_eq!(ParkReason::of(&CoreError::Ssh("refused".into())), None);
        assert_eq!(
            ParkReason::of(&CoreError::HostKeyUnknown {
                address: "web01.example.com:22".into(),
                jump: None
            }),
            None,
            "an unknown key never reaches the login"
        );
        assert_eq!(ParkReason::of(&CoreError::VaultLocked), None);
    }

    #[test]
    fn messages_say_what_happens_next() {
        assert!(parked_message("login failed: password for alice.").ends_with("then press Retry"));
        let capped = capped_message("web01.example.com:22", 10, Duration::from_secs(61));
        assert!(capped.contains("10 background logins"), "{capped}");
        assert!(capped.contains("2 min"), "{capped}");
    }

    fn role(role: &GateRole) -> &'static str {
        match role {
            GateRole::Leader(_) => "leader",
            GateRole::Proceed => "proceed",
            GateRole::Skip => "skip",
        }
    }

    #[tokio::test]
    async fn an_inconclusive_leader_hands_the_lead_on_without_opening_the_gate() {
        // Review C2: a leader whose sign-in failed for any reason but a refusal — unreachable, timeout, a changed
        // certificate, a cancel — never checked the password, so the account stays unverified and the next host leads.
        let guard = LoginGuard::new();
        let GateRole::Leader(leader) = guard.winrm_gate_role("alice|Some(1)").await else {
            panic!("the first host leads");
        };
        leader.finish(None);
        assert_eq!(
            role(&guard.winrm_gate_role("alice|Some(1)").await),
            "leader",
            "the next host must verify the password itself, not proceed or skip",
        );
    }

    #[tokio::test]
    async fn a_dropped_leader_hands_the_lead_on_too() {
        // Review C2: a leader dropped without a result (a cancel) must not open the gate.
        let guard = LoginGuard::new();
        let GateRole::Leader(leader) = guard.winrm_gate_role("alice|Some(1)").await else {
            panic!("the first host leads");
        };
        drop(leader);
        assert_eq!(role(&guard.winrm_gate_role("alice|Some(1)").await), "leader");
    }

    #[tokio::test]
    async fn a_refused_leader_closes_the_gate_and_an_accepted_one_is_re_verified() {
        let guard = LoginGuard::new();
        let GateRole::Leader(leader) = guard.winrm_gate_role("bob|Some(2)").await else {
            panic!("leads");
        };
        leader.finish(Some(false));
        assert_eq!(
            role(&guard.winrm_gate_role("bob|Some(2)").await),
            "skip",
            "a refused login stays refused until credentials change",
        );
        assert_eq!(role(&guard.winrm_gate_role("bob|Some(2)").await), "skip");

        // An accepted account is dropped from the map, so a later run re-verifies it (catching a password changed on
        // the host itself).
        let GateRole::Leader(leader) = guard.winrm_gate_role("carol|Some(3)").await else {
            panic!("leads");
        };
        leader.finish(Some(true));
        assert_eq!(role(&guard.winrm_gate_role("carol|Some(3)").await), "leader");
    }

    #[tokio::test]
    async fn credentials_changed_and_retry_forget_a_refused_gate() {
        let guard = LoginGuard::new();
        let GateRole::Leader(leader) = guard.winrm_gate_role("dan|Some(4)").await else {
            panic!("leads");
        };
        leader.finish(Some(false));
        assert_eq!(role(&guard.winrm_gate_role("dan|Some(4)").await), "skip");
        guard.credentials_changed();
        assert_eq!(
            role(&guard.winrm_gate_role("dan|Some(4)").await),
            "leader",
            "a credentials change re-verifies the account",
        );

        let GateRole::Leader(leader) = guard.winrm_gate_role("dan|Some(4)").await else {
            panic!("leads");
        };
        leader.finish(Some(false));
        guard.retry(Uuid::new_v4());
        assert_eq!(
            role(&guard.winrm_gate_role("dan|Some(4)").await),
            "leader",
            "Retry re-verifies too"
        );
    }
}
