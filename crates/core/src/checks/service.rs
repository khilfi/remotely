//! MO-08: how a service check reads a service on a session's host.
//!
//! [`SystemdOverSsh`] runs `systemctl is-active '<unit>'` on the session's own SSH connection: an open terminal's,
//! else one the toolbox keeps, logged in with the saved login only through [`crate::login_guard`] (a refused login
//! parks the session, and every login counts against the hourly cap), held open until the check's next run so a check
//! every minute logs in once. The unit's name is checked against a strict pattern and shell-quoted; the command only
//! reads, and classifies as read-only under the default rules (the tests check it).
//!
//! **F4 (WinRM):** a Windows service is read with `Get-Service` over WinRM. Implement [`ServiceReader`] for it, and put
//! both behind one reader that picks by the session's kind (SSH: systemd; WinRM: Windows), set with
//! [`super::Checks::set_service_reader`]. The service name's own rules go beside [`super::spec::check_unit`], picked by
//! the session's kind when a check is saved ([`super::Checks`]'s `check_target`).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use uuid::Uuid;

use super::spec::check_unit;
use crate::adapters::remote::sh_quote;
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::sessions::SessionKind;
use crate::toolbox::Toolbox;

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
}

/// A service's name as a check on a session of `kind` may take it. SSH sessions read systemd units, so the name
/// follows [`check_unit`]'s pattern. Other kinds have no service check yet.
///
/// **F4 (WinRM):** add the WinRM kind here with Windows service names' own rule (`MSSQL$SQLEXPRESS` has a `$`, and
/// display names have spaces), and quote it for PowerShell where the reader builds its command.
pub fn check_service_name(kind: &SessionKind, session: &str, name: &str) -> Result<String> {
    if kind.is_ssh() {
        return check_unit(name);
    }
    Err(CoreError::WrongSessionKind {
        session: session.to_owned(),
        kind: kind.label(),
        needs: "a service check reads a systemd unit over SSH".into(),
    })
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
        // A Windows service's name isn't a systemd unit: F4 adds the WinRM kind's own rule here.
        assert!(check_service_name(&ssh, "app01", "MSSQL$SQLEXPRESS").is_err());
        let rdp = SessionKind::Rdp(RdpOptions::default());
        let refused = check_service_name(&rdp, "win01", "Spooler").unwrap_err().to_string();
        assert!(refused.contains("over SSH"), "{refused}");
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
