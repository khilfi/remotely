//! MO-08: how a service check reads a service on a session's host.
//!
//! [`SystemdOverSsh`] runs `systemctl is-active '<unit>'` on the session's own SSH connection: an open terminal's,
//! else one the toolbox keeps, logged in with the saved login only through [`crate::login_guard`] (a refused login
//! parks the session, and every login counts against the hourly cap), held open until the check's next run so a check
//! every minute logs in once. The unit's name is checked against a strict pattern and shell-quoted; the command only
//! reads, and classifies as read-only under the default rules (the tests check it).
//!
//! **F4 (WinRM):** [`WindowsServices`] reads a Windows service with `Get-Service` over WinRM, in the PowerShell a kept
//! connection holds open (one sign-in and one PowerShell per host, not one a run), through the same parks and caps;
//! [`ByKind`] picks the reader by the session's kind (SSH: systemd; WinRM: Windows). A Windows service's name follows
//! [`check_windows_service`]: no wildcards, no quotes, quoted for PowerShell.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use uuid::Uuid;

use super::spec::check_unit;
use crate::adapters::remote::sh_quote;
use crate::adapters::winrm::{WinrmAdapter, WinrmConnect, WinrmSession, WinrmTuning};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::known_hosts::KnownHosts;
use crate::locks;
use crate::login_guard::{self, LoginGuard, ParkReason, ParkScope, Parked};
use crate::metrics::guest::GuestVerifier;
use crate::sessions::SessionKind;
use crate::store::Store;
use crate::toolbox::Toolbox;
use crate::vault::{Vault, VaultStatus};

/// What `systemctl is-active` may print, at most (it prints one word).
const MAX_OUTPUT: usize = 4096;

/// One read of a service.
pub struct ServiceRequest<'a> {
    pub ctx: &'a Context,
    pub session_id: Uuid,
    /// The unit (or, from F4, the Windows service) as the check names it.
    pub unit: &'a str,
    pub timeout: Duration,
    /// How long a kept connection stays open after this read (the check's next run), if at all.
    pub hold: Option<Duration>,
}

/// What a service read found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    /// Running: the check is up.
    pub running: bool,
    /// The service manager's own word: "active", "inactive", "failed", "activating"... (F4: "Running", "Stopped").
    pub state: String,
    pub took_ms: u64,
}

/// Reads a service's state on a session's host. The checks hold one reader ([`super::Checks::set_service_reader`]
/// replaces it): F4 wraps [`SystemdOverSsh`] and its Windows reader in one that picks by the session's kind.
#[async_trait]
pub trait ServiceReader: Send + Sync {
    async fn read(&self, request: ServiceRequest<'_>) -> Result<ServiceState>;

    /// Closes the connections it keeps (a vault lock, a workspace switch). Nothing by default.
    async fn close_all(&self) {}
}

/// A service's name as a check on a session of `kind` may take it: a systemd unit over SSH ([`check_unit`]), a
/// Windows service over WinRM ([`check_windows_service`]). Other kinds have no service check.
pub fn check_service_name(kind: &SessionKind, session: &str, name: &str) -> Result<String> {
    if kind.is_ssh() {
        return check_unit(name);
    }
    if kind.is_winrm() {
        return check_windows_service(name);
    }
    Err(CoreError::WrongSessionKind {
        session: session.to_owned(),
        kind: kind.label(),
        needs: "a service check reads a systemd unit over SSH or a Windows service over WinRM".into(),
    })
}

/// The longest Windows service name (the service control manager's limit).
pub const MAX_WINDOWS_SERVICE: usize = 256;

/// F4: a Windows service's name (not its display name): letters, digits, spaces and `_ - . $ @ + #` (so
/// `MSSQL$SQLEXPRESS`, `postgresql-x64-16`), at most 256 characters. No wildcards (`Get-Service` would match several),
/// quotes or anything PowerShell reads in a string.
pub fn check_windows_service(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput(
            "Enter the service's name, such as Spooler or W3SVC.".into(),
        ));
    }
    if name.chars().count() > MAX_WINDOWS_SERVICE {
        return Err(CoreError::InvalidInput(format!(
            "A Windows service's name is at most {MAX_WINDOWS_SERVICE} characters."
        )));
    }
    let ok = name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '$' | '@' | '+' | '#'));
    if !ok {
        return Err(CoreError::InvalidInput(
            "A Windows service's name holds letters, digits, spaces and _ - . $ @ + # only (its name, not its display name; no wildcards).".into(),
        ));
    }
    Ok(name.to_owned())
}

/// F4: the lines that read a Windows service's status in the kept PowerShell: the name checked and single-quoted
/// (it can't hold a quote), each line one statement, reads only.
pub fn get_service_script(name: &str) -> Result<String> {
    let name = check_windows_service(name)?;
    Ok(format!(
        "# remotely:service\n$remotelyService = Get-Service -Name '{name}' -ErrorAction SilentlyContinue\n\
if ($remotelyService) {{ '@@service ' + $remotelyService.Status }} else {{ '@@service missing' }}"
    ))
}

/// `Get-Service`'s answer: whether it runs and the status word (`Running`, `Stopped`, `StartPending`, `Paused`...,
/// or `missing` when the host has no such service); `None` for an answer without the state line. Up only while
/// `Running`.
pub fn parse_get_service(stdout: &str) -> Option<(bool, String)> {
    let line = stdout.lines().map(str::trim).find(|l| l.starts_with("@@service "))?;
    let word: String = line
        .strip_prefix("@@service ")?
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .take(32)
        .collect();
    if word.is_empty() {
        return None;
    }
    Some((word == "Running", word))
}

/// What a kept WinRM connection is and until when it stays.
#[derive(Default)]
struct KeptWindows {
    key: String,
    session: Option<Arc<dyn WinrmSession>>,
    until: Option<Instant>,
}

struct WindowsInner {
    store: Store,
    vault: Arc<dyn Vault>,
    known_hosts: Arc<KnownHosts>,
    guard: LoginGuard,
    winrm: RwLock<Arc<dyn WinrmAdapter>>,
    kept: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<KeptWindows>>>>,
}

/// F4: Windows services over WinRM, each host's connection kept until the check's next run (then closed by a sweep),
/// and on a vault lock or a workspace switch ([`ServiceReader::close_all`]). Cloning gives another handle.
#[derive(Clone)]
pub struct WindowsServices {
    inner: Arc<WindowsInner>,
}

/// How often the sweep looks for connections whose hold is over.
const SWEEP: Duration = Duration::from_secs(15);
/// A read with no hold keeps its connection this long (a Refresh right after reuses it).
const NO_HOLD: Duration = Duration::from_secs(60);

impl WindowsServices {
    pub fn new(
        store: Store,
        vault: Arc<dyn Vault>,
        known_hosts: Arc<KnownHosts>,
        guard: LoginGuard,
        winrm: Arc<dyn WinrmAdapter>,
    ) -> Self {
        let inner = Arc::new(WindowsInner {
            store,
            vault,
            known_hosts,
            guard,
            winrm: RwLock::new(winrm),
            kept: Mutex::default(),
        });
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak: Weak<WindowsInner> = Arc::downgrade(&inner);
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(SWEEP).await;
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    sweep(&inner).await;
                }
            });
        }
        Self { inner }
    }

    /// Tests: the connections kept now.
    pub fn kept(&self) -> usize {
        locks::lock(&self.inner.kept).len()
    }

    async fn connection(&self, ctx: &Context, session_id: Uuid, hold: Duration) -> Result<Arc<dyn WinrmSession>> {
        let spec = self
            .inner
            .store
            .winrm_spec(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
        let slot = Arc::clone(locks::lock(&self.inner.kept).entry(session_id).or_default());
        let mut kept = slot.lock().await;
        let key = spec.login_key();
        if kept.key != key || kept.session.as_ref().is_some_and(|s| s.is_closed()) {
            if let Some(old) = kept.session.take() {
                old.close().await;
            }
        }
        kept.until = Some(Instant::now() + hold);
        if let Some(session) = &kept.session {
            return Ok(Arc::clone(session));
        }
        let park = |reason: ParkReason, message: String| {
            let parked = Parked {
                reason,
                message: login_guard::parked_message(&message),
            };
            self.inner.guard.park(spec.id, ParkScope::Login, &key, parked.clone());
            parked.error()
        };
        if let Some(parked) = self.inner.guard.parked(spec.id, ParkScope::Login, &key) {
            return Err(parked.error());
        }
        if spec.missing_password() {
            return Err(park(
                ParkReason::SecretMissing,
                format!(
                    "no password is saved for '{}'. Save it in the vault and choose it in that session, so checks can sign in",
                    spec.name
                ),
            ));
        }
        let password = match spec.password_id {
            Some(id) => {
                if self.inner.vault.status() != VaultStatus::Unlocked {
                    return Err(CoreError::VaultLocked);
                }
                Some(self.inner.vault.get(ctx, id).await?)
            }
            None => None,
        };
        if let Err(wait) = self.inner.guard.admit(spec.id, &[spec.login_host()]) {
            return Err(CoreError::LoginsCapped {
                message: login_guard::capped_message(&spec.login_host(), self.inner.guard.per_hour(), wait),
                wait_secs: wait.as_secs(),
            });
        }
        let verifier = Arc::new(GuestVerifier {
            known_hosts: Arc::clone(&self.inner.known_hosts),
            ctx: *ctx,
            target: Target {
                target: TargetRef::Session { session_id: spec.id },
                name: spec.name.clone(),
                environment: spec.environment,
                protected: false,
            },
            record_blocked: true,
        });
        let adapter = Arc::clone(&*locks::read(&self.inner.winrm));
        let connected = adapter
            .connect(WinrmConnect {
                spec: &spec,
                password,
                verifier,
                tuning: WinrmTuning::default(),
            })
            .await;
        match connected {
            Ok(session) => {
                kept.session = Some(Arc::clone(&session));
                kept.key = key;
                Ok(session)
            }
            Err(err) => match ParkReason::of(&err) {
                Some(reason) => Err(park(reason, err.to_string())),
                None => Err(err),
            },
        }
    }
}

async fn sweep(inner: &WindowsInner) {
    let slots: Vec<(Uuid, Arc<tokio::sync::Mutex<KeptWindows>>)> = locks::lock(&inner.kept)
        .iter()
        .map(|(id, slot)| (*id, Arc::clone(slot)))
        .collect();
    for (id, slot) in slots {
        // In use now: its read sets a new hold.
        let Ok(mut kept) = slot.try_lock() else {
            continue;
        };
        if kept.until.is_none_or(|until| Instant::now() >= until) {
            if let Some(session) = kept.session.take() {
                session.close().await;
            }
            drop(kept);
            locks::lock(&inner.kept).remove(&id);
        }
    }
}

#[async_trait]
impl ServiceReader for WindowsServices {
    async fn read(&self, request: ServiceRequest<'_>) -> Result<ServiceState> {
        let script = get_service_script(request.unit)?;
        let hold = request.hold.unwrap_or(NO_HOLD);
        let session = self.connection(request.ctx, request.session_id, hold).await?;
        let started = Instant::now();
        let read = tokio::time::timeout(request.timeout, session.read(&script, MAX_OUTPUT, request.timeout)).await;
        let text = match read {
            Ok(Ok(text)) => text,
            Ok(Err(err)) => {
                self.forget(request.session_id).await;
                // Review F4 #2: a sign-in refused on a later connection parks the session, as at the first.
                if let Some(reason) = ParkReason::of(&err) {
                    self.park(request.ctx, request.session_id, reason, &err).await;
                }
                return Err(err);
            }
            Err(_) => {
                self.forget(request.session_id).await;
                return Err(CoreError::CommandTimedOut {
                    seconds: request.timeout.as_secs(),
                });
            }
        };
        let took_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Review F4 #5: a service the host no longer has is down (as systemd's missing unit is inactive), so the
        // check-down alert fires. An answer without the state line is Remotely not knowing, not the service down.
        let (running, state) = parse_get_service(&text)
            .ok_or_else(|| CoreError::Winrm("the host's answer held no service state".into()))?;
        Ok(ServiceState {
            running,
            state,
            took_ms,
        })
    }

    async fn close_all(&self) {
        let slots: Vec<Arc<tokio::sync::Mutex<KeptWindows>>> =
            locks::lock(&self.inner.kept).drain().map(|(_, slot)| slot).collect();
        for slot in slots {
            if let Some(session) = slot.lock().await.session.take() {
                session.close().await;
            }
        }
    }
}

impl WindowsServices {
    /// Parks the session's background sign-ins after the host refused one, until its login or credentials change.
    async fn park(&self, ctx: &Context, session_id: Uuid, reason: ParkReason, err: &CoreError) {
        if let Ok(Some(spec)) = self.inner.store.winrm_spec(ctx, session_id).await {
            let parked = Parked {
                reason,
                message: login_guard::parked_message(&err.to_string()),
            };
            self.inner
                .guard
                .park(spec.id, ParkScope::Login, &spec.login_key(), parked);
        }
    }

    /// Drops a host's kept connection after a read failed on it (the next run signs in again).
    async fn forget(&self, session_id: Uuid) {
        let slot = locks::lock(&self.inner.kept).remove(&session_id);
        if let Some(slot) = slot {
            if let Some(session) = slot.lock().await.session.take() {
                session.close().await;
            }
        }
    }
}

/// F4: picks the reader by the session's kind: systemd over SSH, Windows services over WinRM.
pub struct ByKind {
    store: Store,
    systemd: Arc<dyn ServiceReader>,
    windows: Arc<dyn ServiceReader>,
}

impl ByKind {
    pub fn new(store: Store, systemd: Arc<dyn ServiceReader>, windows: Arc<dyn ServiceReader>) -> Self {
        Self {
            store,
            systemd,
            windows,
        }
    }
}

#[async_trait]
impl ServiceReader for ByKind {
    async fn read(&self, request: ServiceRequest<'_>) -> Result<ServiceState> {
        let kind = self
            .store
            .get_session(request.ctx, request.session_id)
            .await?
            .map(|s| s.kind)
            .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
        if kind.is_winrm() {
            self.windows.read(request).await
        } else {
            self.systemd.read(request).await
        }
    }

    async fn close_all(&self) {
        self.systemd.close_all().await;
        self.windows.close_all().await;
    }
}

/// The command a systemd check runs: the unit checked and quoted as one word.
pub fn systemctl_script(unit: &str) -> Result<String> {
    Ok(format!("systemctl is-active {}", sh_quote(&check_unit(unit)?)))
}

/// `systemctl is-active`'s answer: its first word (letters and `-` only, at most 32 characters). Up while `active` or
/// `reloading`; anything else (`inactive`, `failed`, `activating`, `deactivating`, `unknown`) is down.
pub fn parse_is_active(stdout: &str) -> (bool, String) {
    let word: String = stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphabetic() || *c == '-')
        .take(32)
        .collect();
    let running = matches!(word.as_str(), "active" | "reloading");
    (running, word)
}

/// systemd units over SSH.
pub struct SystemdOverSsh {
    toolbox: Toolbox,
}

impl SystemdOverSsh {
    pub fn new(toolbox: Toolbox) -> Self {
        Self { toolbox }
    }
}

#[async_trait]
impl ServiceReader for SystemdOverSsh {
    async fn read(&self, request: ServiceRequest<'_>) -> Result<ServiceState> {
        let script = systemctl_script(request.unit)?;
        let connection = self
            .toolbox
            .session_connection(request.ctx, request.session_id, request.hold)
            .await?;
        let started = Instant::now();
        let ran = tokio::time::timeout(request.timeout, connection.run(&script, MAX_OUTPUT))
            .await
            .map_err(|_| CoreError::CommandTimedOut {
                seconds: request.timeout.as_secs(),
            })??;
        let took_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if ran.exit_code == Some(127) {
            return Err(CoreError::InvalidInput(
                "systemctl isn't on this host: a service check reads systemd units.".into(),
            ));
        }
        let (running, state) = parse_is_active(&ran.output.stdout);
        Ok(ServiceState {
            running,
            state: if state.is_empty() {
                "no answer from systemctl".into()
            } else {
                state
            },
            took_ms,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::policy::{ActionKind, PolicyEngine, PolicyRules};

    #[test]
    fn the_command_quotes_a_checked_unit_and_only_reads() {
        assert_eq!(
            systemctl_script(" nginx.service ").unwrap(),
            "systemctl is-active 'nginx.service'"
        );
        assert!(systemctl_script("nginx; reboot").is_err());
        assert!(systemctl_script("--all").is_err());
        let policy = PolicyEngine::new(PolicyRules::default()).unwrap();
        for unit in ["nginx", "getty@tty1.service", "dev-sda1.device", "a:b_c.service"] {
            let script = systemctl_script(unit).unwrap();
            assert_eq!(
                policy.classify_script(&script),
                ActionKind::ExecReadOnly,
                "{script} must rate as a read"
            );
        }
    }

    #[test]
    fn a_service_name_follows_the_sessions_kind() {
        use crate::sessions::kinds::RdpOptions;
        let ssh = SessionKind::default();
        assert_eq!(check_service_name(&ssh, "app01", "nginx").unwrap(), "nginx");
        // A Windows service's name isn't a systemd unit.
        assert!(check_service_name(&ssh, "app01", "MSSQL$SQLEXPRESS").is_err());
        let winrm = SessionKind::Winrm(crate::sessions::kinds::WinrmOptions::default());
        assert_eq!(
            check_service_name(&winrm, "win01", " MSSQL$SQLEXPRESS ").unwrap(),
            "MSSQL$SQLEXPRESS"
        );
        let rdp = SessionKind::Rdp(RdpOptions::default());
        let refused = check_service_name(&rdp, "win01", "Spooler").unwrap_err().to_string();
        assert!(refused.contains("over SSH"), "{refused}");
    }

    #[test]
    fn a_windows_service_is_named_exactly_and_read_only() {
        for good in [
            "Spooler",
            "W3SVC",
            "MSSQL$SQLEXPRESS",
            "postgresql-x64-16",
            "Apache2.4",
            "My Service",
        ] {
            assert!(check_windows_service(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "Spool*",
            "a?b",
            "[ab]",
            "x'; Stop-Computer; '",
            "a`b",
            "a\"b",
            "a|b",
            "a;b",
            "a\nb",
        ] {
            assert!(check_windows_service(bad).is_err(), "{bad:?}");
        }
        assert!(check_windows_service(&"a".repeat(257)).is_err());
        let script = get_service_script("MSSQL$SQLEXPRESS").unwrap();
        assert!(script.contains("Get-Service -Name 'MSSQL$SQLEXPRESS'"), "{script}");
        crate::host_details::windows::assert_only_reads(&script);
        for line in script.lines() {
            let mut syntax = crate::adapters::winrm::console::Syntax::default();
            syntax.feed(line);
            assert!(syntax.complete(), "{line}");
        }
    }

    #[test]
    fn get_service_answers_are_one_word() {
        assert_eq!(
            parse_get_service("@@service Running\r\n"),
            Some((true, "Running".into()))
        );
        assert_eq!(parse_get_service("@@service Stopped"), Some((false, "Stopped".into())));
        assert_eq!(
            parse_get_service("@@service StartPending"),
            Some((false, "StartPending".into()))
        );
        assert_eq!(parse_get_service("@@service missing"), Some((false, "missing".into())));
        assert_eq!(parse_get_service("nothing"), None);
        assert_eq!(
            parse_get_service("@@service Run\u{202e}ning\u{7}"),
            Some((true, "Running".into()))
        );
    }

    #[test]
    fn is_active_answers_are_read_as_one_word() {
        assert_eq!(parse_is_active("active\n"), (true, "active".into()));
        assert_eq!(parse_is_active("reloading"), (true, "reloading".into()));
        assert_eq!(parse_is_active("inactive\n"), (false, "inactive".into()));
        assert_eq!(parse_is_active("failed"), (false, "failed".into()));
        assert_eq!(parse_is_active(""), (false, String::new()));
        // Whatever a hostile host prints, one short word of letters is kept.
        let (running, word) = parse_is_active("act\u{202e}ive\u{7}\x1b[31m and more");
        assert!(!running);
        assert_eq!(word, "activem");
        assert_eq!(parse_is_active(&"a".repeat(10_000)).1.len(), 32);
    }
}
