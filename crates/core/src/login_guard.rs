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

/// Shared by the dashboard and the Containers page. Cloning gives another handle to the same one.
#[derive(Clone, Default)]
pub struct LoginGuard {
    state: Arc<Mutex<State>>,
    limits: Arc<RwLock<LoginLimits>>,
}

impl LoginGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_limits(&self, limits: LoginLimits) {
        *locks::write(&self.limits) = limits;
    }

    /// The vault was unlocked, a secret changed, or a host key was trusted or removed: every parked
    /// session gets one more try.
    pub fn credentials_changed(&self) {
        let mut state = locks::lock(&self.state);
        state.generation = state.generation.wrapping_add(1);
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

    /// The user pressed Retry: the session's parks are lifted, and its next login skips the hourly cap.
    pub fn retry(&self, session: Uuid) {
        let mut state = locks::lock(&self.state);
        state.parks.retain(|(id, _), _| *id != session);
        state.granted.insert(session);
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
}
