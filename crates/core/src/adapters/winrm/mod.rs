//! SS-12, MO-05, MO-13: Remotely's own WinRM client (WS-Management remote shells, MS-WSMV), behind
//! [`WinrmAdapter`], so nothing on this PC changes (no TrustedHosts, no WinRM client service settings).
//!
//! * [`http`]: HTTPS with the session's certificate rule, or HTTP with every message sealed by the sign-in; Basic
//!   (HTTPS only), NTLM with the vault password, or the Windows sign-in (Kerberos) through Windows' SSPI ([`sspi`],
//!   [`encryption`]).
//! * [`soap`]: the shell's messages (create, command, send, receive, signal, delete), answers read as untrusted XML.
//! * [`shell`]: PowerShell runs ([`ExecSession::run`]) and the kept PowerShell for the dashboard's reads
//!   ([`WinrmSession::read`]).
//! * [`console`]: the PowerShell console pane ([`WinrmSession::console`]).
//!
//! Tests run the real client against `fakes::winrm_server` on 127.0.0.1 (HTTPS with a run-time certificate and Basic;
//! HTTP with NTLM sealing, the server's NTLM checked against MS-NLMP's published values). Kerberos can only be tried
//! by hand against a domain host.

pub mod console;
pub mod encryption;
pub mod http;
pub mod shell;
pub mod soap;
pub mod sspi;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use self::console::ConsoleShell;
use self::http::{Client, Endpoint, SignIn};
use self::shell::{RemoteShell, Runner};
use self::sspi::{Identity, Package};
use crate::adapters::net_tools::NetworkTools;
use crate::adapters::remote::{ExecResult, ExecSession, HostKeyVerifier, ScriptKind, SecretPromptShown};
use crate::domain::Environment;
use crate::error::{CoreError, Result};
use crate::known_hosts::address;
use crate::sessions::kinds::{WinrmOptions, WinrmSignIn};
use crate::vault::{SecretId, SecretString};

/// Shells one connection has open at most (the console, the kept PowerShell and runs).
pub const MAX_SHELLS: usize = 4;
/// The longest a run may take before Remotely stops it, whatever its caller's own limit.
pub const MAX_RUN: Duration = Duration::from_secs(30 * 60);

/// What a WinRM connection needs, from a saved session ([`crate::store::Store::winrm_spec`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinrmSpec {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// The vault password of the user (NTLM, Basic); `None` with the Windows sign-in.
    pub password_id: Option<SecretId>,
    pub options: WinrmOptions,
    pub environment: Environment,
}

impl WinrmSpec {
    /// `alice@win01.example.com:5986`.
    pub fn address(&self) -> String {
        let user = self
            .username
            .as_deref()
            .filter(|_| self.options.uses_password())
            .map(|u| format!("{u}@"))
            .unwrap_or_default();
        format!("{user}{}", address(&self.host, self.port))
    }

    /// What a kept connection depends on: a session edited since connects again.
    pub fn login_key(&self) -> String {
        format!(
            "winrm|{}|{}|{:?}|{:?}|{:?}",
            self.host.to_lowercase(),
            self.port,
            self.username,
            self.password_id,
            self.options
        )
    }

    /// The host the hourly login cap counts.
    pub fn login_host(&self) -> String {
        address(&self.host.to_lowercase(), self.port)
    }

    /// A sign-in that needs a password the session doesn't save can't work where no one can type it.
    pub fn missing_password(&self) -> bool {
        self.options.uses_password() && self.password_id.is_none()
    }
}

/// Time limits. The defaults suit real networks; tests shorten them.
#[derive(Debug, Clone)]
pub struct WinrmTuning {
    pub connect_timeout: Duration,
    /// One message's answer, on top of the operation's own wait on the host.
    pub request_timeout: Duration,
    /// How long the host keeps a shell nobody uses.
    pub idle: Duration,
}

impl Default for WinrmTuning {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(20),
            idle: Duration::from_secs(30 * 60),
        }
    }
}

/// One connection's request.
pub struct WinrmConnect<'a> {
    pub spec: &'a WinrmSpec,
    /// The user's password from the vault (NTLM, Basic); `None` with the Windows sign-in. Zeroized when dropped.
    pub password: Option<SecretString>,
    /// Asks about (or checks) a certificate Windows doesn't trust, by its fingerprint (the session's rule).
    pub verifier: Arc<dyn HostKeyVerifier>,
    pub tuning: WinrmTuning,
}

/// Connects to WinRM hosts (tests: the real client against `fakes::winrm_server`).
#[async_trait]
pub trait WinrmAdapter: Send + Sync {
    /// Signs in on a first connection (so a refused sign-in or an untrusted certificate shows at once).
    async fn connect(&self, request: WinrmConnect<'_>) -> Result<Arc<dyn WinrmSession>>;
}

/// A signed-in WinRM connection. Its [`ExecSession::run`] runs a PowerShell script ([`ScriptKind::PowerShell`]).
#[async_trait]
pub trait WinrmSession: ExecSession {
    /// SS-12: a PowerShell console on this connection.
    async fn console(&self, secret_prompt: SecretPromptShown) -> Result<ConsoleShell>;
    /// MO-05: `script` (one statement a line) in a PowerShell kept open between reads: its stdout.
    async fn read(&self, script: &str, max_output: usize, deadline: Duration) -> Result<String>;
    /// This connection as an [`ExecSession`], for code that takes one.
    fn exec(self: Arc<Self>) -> Arc<dyn ExecSession>;
}

/// The adapter until Core gives the real one: every connection is refused.
pub struct NoWinrm;

#[async_trait]
impl WinrmAdapter for NoWinrm {
    async fn connect(&self, _request: WinrmConnect<'_>) -> Result<Arc<dyn WinrmSession>> {
        Err(CoreError::Winrm("WinRM isn't set up in this build".into()))
    }
}

/// The real client.
pub struct HttpWinrm {
    tools: Arc<dyn NetworkTools>,
}

impl HttpWinrm {
    /// `tools` checks an HTTPS certificate against Windows' trust store.
    pub fn new(tools: Arc<dyn NetworkTools>) -> Self {
        Self { tools }
    }
}

fn needs_user(spec: &WinrmSpec) -> Result<&str> {
    spec.username.as_deref().filter(|u| !u.trim().is_empty()).ok_or_else(|| {
        CoreError::InvalidInput(format!(
            "'{}' signs in with a user and password: enter the user in the session (DOMAIN\\user, user@domain or a local user).",
            spec.name
        ))
    })
}

#[async_trait]
impl WinrmAdapter for HttpWinrm {
    async fn connect(&self, request: WinrmConnect<'_>) -> Result<Arc<dyn WinrmSession>> {
        let spec = request.spec;
        let options = spec.options;
        let missing = || {
            CoreError::AuthFailed(format!(
                "no password is saved for '{}'. Choose one from the vault in the session",
                spec.name
            ))
        };
        let sign_in = match options.sign_in {
            WinrmSignIn::Basic => {
                let user = needs_user(spec)?;
                let password = request.password.as_ref().ok_or_else(missing)?;
                SignIn::basic(user, password)
            }
            WinrmSignIn::Ntlm => {
                let user = needs_user(spec)?;
                let password = request.password.as_ref().ok_or_else(missing)?;
                SignIn::Sspi {
                    package: Package::Ntlm,
                    credentials: sspi::acquire(Package::Ntlm, Some(Identity { user, password }))?,
                }
            }
            WinrmSignIn::Windows => {
                // Review F4 #1: Kerberos needs the host's name; this PC's account never goes to an address.
                if crate::adapters::network::ip_literal(&spec.host).is_some() {
                    return Err(CoreError::AuthFailed(format!(
                        "'{}' is reached by its IP address, and Kerberos needs the host's name. Use the name, or sign in with NTLM and a password from the vault",
                        spec.name
                    )));
                }
                SignIn::Sspi {
                    package: Package::KerberosOnly,
                    credentials: sspi::acquire(Package::KerberosOnly, None)?,
                }
            }
        };
        let endpoint = Endpoint {
            host: spec.host.clone(),
            port: spec.port,
            https: options.https(),
            certificate: options.certificate,
            tools: Arc::clone(&self.tools),
            verifier: request.verifier,
            connect_timeout: request.tuning.connect_timeout,
        };
        let client = Arc::new(Client::new(endpoint, sign_in));
        client.warm().await?;
        Ok(Arc::new(HttpSession {
            client,
            secrets: request.password.into_iter().collect(),
            shells: Arc::new(Semaphore::new(MAX_SHELLS)),
            runner: tokio::sync::Mutex::new(None),
            tuning: request.tuning,
        }))
    }
}

/// The kept PowerShell and the shell it holds.
struct KeptRunner {
    runner: Runner,
    _permit: OwnedSemaphorePermit,
}

/// A connection of [`HttpWinrm`].
pub struct HttpSession {
    client: Arc<Client>,
    /// The sign-in's password, scrubbed from what runs print.
    secrets: Vec<SecretString>,
    shells: Arc<Semaphore>,
    runner: tokio::sync::Mutex<Option<KeptRunner>>,
    tuning: WinrmTuning,
}

impl HttpSession {
    fn too_many() -> CoreError {
        CoreError::Winrm(format!(
            "this connection has {MAX_SHELLS} shells open already; close a console or wait for a run to end"
        ))
    }
}

#[async_trait]
impl ExecSession for HttpSession {
    async fn run(&self, script: &str, max_output: usize) -> Result<ExecResult> {
        let _permit = Arc::clone(&self.shells)
            .acquire_owned()
            .await
            .map_err(|_| CoreError::Winrm("the connection is closed".into()))?;
        let mut result = shell::run_script(
            Arc::clone(&self.client),
            script,
            &self.secrets,
            max_output,
            MAX_RUN,
            self.tuning.request_timeout,
        )
        .await?;
        result.peer_ip = self.client.peer_ip();
        Ok(result)
    }

    async fn run_sudo(&self, _script: &str, _password: &SecretString, _max_output: usize) -> Result<ExecResult> {
        Err(CoreError::InvalidInput(
            "sudo is for Linux hosts: over WinRM, PowerShell runs as the user the session signs in as.".into(),
        ))
    }

    fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    async fn close(&self) {
        // A read in progress holds the runner: it is dropped (and stopped) when that read ends.
        if let Ok(mut kept) = self.runner.try_lock() {
            if let Some(kept) = kept.take() {
                kept.runner.stop().await;
            }
        }
        // Review F4 #6: refuse new work, then delete every shell still on the host (runs in flight, a console), on a
        // connection of their own, so a vault lock or a workspace switch leaves nothing running there.
        self.client.close();
        for id in self.client.live_shells() {
            self.client.delete_shell(&id).await;
        }
    }

    fn peer_ip(&self) -> Option<IpAddr> {
        self.client.peer_ip()
    }

    fn script_kind(&self) -> ScriptKind {
        ScriptKind::PowerShell
    }
}

#[async_trait]
impl WinrmSession for HttpSession {
    async fn console(&self, secret_prompt: SecretPromptShown) -> Result<ConsoleShell> {
        let permit = Arc::clone(&self.shells)
            .try_acquire_owned()
            .map_err(|_| Self::too_many())?;
        let shell = Arc::new(
            RemoteShell::create(Arc::clone(&self.client), self.tuning.idle, self.tuning.request_timeout).await?,
        );
        console::start(shell, secret_prompt, permit).await
    }

    async fn read(&self, script: &str, max_output: usize, deadline: Duration) -> Result<String> {
        let mut kept = self.runner.lock().await;
        // Review F4 #3: the runner is taken out for the read and put back only when it went well. A read dropped half
        // way (its caller's time limit) drops the runner with it, which stops its PowerShell, so the next read starts a
        // new one instead of reading the old read's output as its own.
        let mut current = match kept.take() {
            Some(current) => current,
            None => {
                let permit = Arc::clone(&self.shells)
                    .try_acquire_owned()
                    .map_err(|_| Self::too_many())?;
                let runner =
                    Runner::start(Arc::clone(&self.client), self.tuning.idle, self.tuning.request_timeout).await?;
                KeptRunner {
                    runner,
                    _permit: permit,
                }
            }
        };
        match current.runner.read(script, max_output, deadline).await {
            Ok(text) => {
                *kept = Some(current);
                Ok(text)
            }
            Err(err) => {
                // A read that failed leaves its PowerShell in an unknown state: the next read starts another.
                current.runner.stop().await;
                Err(err)
            }
        }
    }

    fn exec(self: Arc<Self>) -> Arc<dyn ExecSession> {
        self
    }
}
