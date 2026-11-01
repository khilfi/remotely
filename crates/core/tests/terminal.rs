//! SS-03 terminal and SS-05 known hosts, end to end: the real russh adapter against an SSH server
//! on 127.0.0.1 (`fakes::ssh_server`), with keys and passwords made at run time and the app's own
//! vault (fake DPAPI). No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::Setup;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{fingerprint, generate_key, private_key_text, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning, WakeReason};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

/// A password nobody wrote down: made at run time, so none is committed.
fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn tuning() -> TerminalTuning {
    TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    }
}

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    core
}

fn session(server: &TestSshServer, auth: SessionAuth) -> SessionInput {
    SessionInput {
        name: "lab box".into(),
        folder_id: None,
        host: "127.0.0.1".into(),
        port: server.port(),
        username: Some("alice".into()),
        auth,
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    }
}

async fn secret(core: &Core, kind: SecretKind, label: &str, value: &SecretString) -> SecretId {
    core.vault
        .add(&core.ctx(), kind, label, value.clone())
        .await
        .unwrap()
        .id
}

async fn trust_server(core: &Core, server: &TestSshServer) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
}

async fn create(core: &Core, input: SessionInput) -> Uuid {
    core.sessions.create(&core.ctx(), input).await.unwrap().id
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx(), 200).await.unwrap()
}

/// A pane under test: everything it printed so far, and its events.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    /// Every output chunk, as it arrived.
    chunks: Vec<Vec<u8>>,
    /// Bytes not yet matched by `expect_output`.
    unread: Vec<u8>,
}

impl Pane {
    fn new(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            chunks: Vec::new(),
            unread: Vec::new(),
        }
    }

    async fn open(core: &Core, session: Uuid) -> Self {
        Self::new(core.terminals.open(&core.ctx(), session, SIZE).await.unwrap())
    }

    /// Reads output until `needle` appears; returns what came up to and including it.
    async fn expect_output(&mut self, needle: &str) -> String {
        let result = timeout(WAIT, async {
            loop {
                let text = String::from_utf8_lossy(&self.unread).into_owned();
                if let Some(at) = text.find(needle) {
                    let upto = at + needle.len();
                    self.unread = text.as_bytes()[upto..].to_vec();
                    return text[..upto].to_owned();
                }
                let chunk = self.output.recv().await.expect("output ended");
                self.unread.extend_from_slice(&chunk);
                self.chunks.push(chunk);
            }
        })
        .await;
        result.unwrap_or_else(|_| {
            panic!(
                "no {needle:?} in the output; got {:?}",
                String::from_utf8_lossy(&self.unread)
            )
        })
    }

    /// Reads events until one matches.
    async fn expect_event<T>(&mut self, mut pick: impl FnMut(&TerminalEvent) -> Option<T>) -> T {
        let mut seen = Vec::new();
        let result = timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.expect("events ended");
                if let Some(found) = pick(&event) {
                    return found;
                }
                seen.push(event);
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("the expected event did not come; saw {seen:?}"))
    }

    async fn expect_status(&mut self, want: impl Fn(&TerminalStatus) -> bool) -> TerminalStatus {
        self.expect_event(|e| match e {
            TerminalEvent::Status { status } if want(status) => Some(status.clone()),
            _ => None,
        })
        .await
    }

    async fn connected(&mut self) {
        self.expect_status(|s| *s == TerminalStatus::Connected).await;
    }

    async fn type_text(&self, core: &Core, text: &str) {
        core.terminals.write(self.id, text.as_bytes().to_vec()).await;
    }

    /// Everything printed so far, as one string.
    fn all_output(&self) -> String {
        String::from_utf8_lossy(&self.chunks.concat()).into_owned()
    }
}

#[tokio::test]
async fn a_password_from_the_vault_opens_a_shell_after_the_host_key_is_trusted() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;

    let mut pane = Pane::open(&core, session).await;
    // SS-05: first contact shows the fingerprint and waits for an answer.
    let key = pane
        .expect_event(|e| match e {
            TerminalEvent::HostKeyUnknown {
                key,
                other_key_types,
                jump,
            } => {
                assert!(other_key_types.is_empty());
                assert_eq!(*jump, None, "the session's own host");
                Some(key.clone())
            }
            _ => None,
        })
        .await;
    assert_eq!(key.fingerprint, server.host_key_fingerprint());
    assert_eq!(key.key_type, "ssh-ed25519");
    assert!(key.fingerprint.starts_with("SHA256:"));
    core.terminals.answer_host_key(pane.id, true).unwrap();
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;

    pane.type_text(&core, "whoami\r").await;
    pane.expect_output("alice\r\n$ ").await;
    core.terminals.resize(pane.id, 120, 40).await;
    pane.type_text(&core, "echo resized\r").await;
    pane.expect_output("resized\r\n").await;
    let log = server.log();
    assert!(log.contains(&"pty xterm-256color 80x24".to_owned()), "{log:?}");
    assert!(log.contains(&"resize 120x40".to_owned()), "{log:?}");
    assert!(log.contains(&"password alice ok".to_owned()), "{log:?}");

    let saved = core.known_hosts.list(&core.ctx()).await.unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].fingerprint, server.host_key_fingerprint());

    core.terminals.close(pane.id).await;
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
    let entries = audit(&core).await;
    let events: Vec<&str> = entries.iter().map(|e| e.event.as_str()).collect();
    assert!(events.contains(&"terminal_opened"), "{events:?}");
    assert!(events.contains(&"host_key_trusted"), "{events:?}");
    assert!(events.contains(&"terminal_closed"), "{events:?}");
    let opened = entries.iter().find(|e| e.event == "terminal_opened").unwrap();
    assert_eq!(opened.action, "Opened a terminal to 'lab box'");
    assert!(opened.targets_json.contains(&session.to_string()));
    let closed = entries.iter().find(|e| e.event == "terminal_closed").unwrap();
    assert!(
        closed.detail.as_deref().unwrap().contains("connected once"),
        "{closed:?}"
    );
    // Never a secret, a keystroke or output in the audit log.
    for entry in &entries {
        let text = format!("{entry:?}");
        assert!(!text.contains(&password), "{text}");
        assert!(!text.contains("whoami"), "{text}");
        assert!(!text.contains("Welcome"), "{text}");
    }
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
}

#[tokio::test]
async fn output_reaches_the_pane_as_raw_bytes() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session).await;
    pane.connected().await;
    pane.expect_output("$ ").await;

    // The server sends "é" split inside the character. Nothing on the way decodes it, so the two
    // halves arrive as they were sent and xterm.js puts them back together.
    pane.type_text(&core, "split-utf8\r").await;
    pane.expect_output("é\r\n").await;
    assert!(pane.chunks.iter().any(|c| c.as_slice() == [0xC3]), "{:?}", pane.chunks);
    assert!(!pane.all_output().contains('\u{FFFD}'));
}

#[tokio::test]
async fn a_password_that_is_not_saved_is_typed_in_the_terminal_and_never_echoed() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let session = create(&core, session(&server, SessionAuth::Password { password_id: None })).await;
    let mut pane = Pane::open(&core, session).await;

    pane.expect_output("alice's password: ").await;
    pane.type_text(&core, "wrong-guess\r").await;
    pane.expect_output("Access denied").await;
    pane.expect_output("alice's password: ").await;
    // Arrow keys and a typo fixed with backspace are handled like a real prompt.
    pane.type_text(&core, &format!("{password}x\x7f\x1b[D\r")).await;
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;
    assert!(!pane.all_output().contains(&password));
    assert!(!pane.all_output().contains("wrong-guess"));

    // SS-03: a dropped connection comes back without asking again.
    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { attempt: 1, .. }))
        .await;
    pane.connected().await;
    assert_eq!(server.connections(), 2);
    let log = server.log();
    assert_eq!(log.iter().filter(|l| *l == "password alice ok").count(), 2, "{log:?}");
}

#[tokio::test]
async fn keys_from_the_vault_log_in_with_or_without_a_saved_passphrase() {
    let key = generate_key();
    let server = TestSshServer::start().await.with_key("alice", key.public_key());
    let core = core().await;
    trust_server(&core, &server).await;

    // A plain key.
    let plain = secret(
        &core,
        SecretKind::PrivateKey,
        "plain key",
        &private_key_text(&key, None),
    )
    .await;
    let plain_session = create(
        &core,
        session(
            &server,
            SessionAuth::Key {
                key_id: Some(plain),
                passphrase_id: None,
            },
        ),
    )
    .await;
    let mut pane = Pane::open(&core, plain_session).await;
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;

    // An encrypted key with its passphrase in the vault.
    let passphrase = SecretString::new(new_password());
    let locked_key = private_key_text(&key, Some(passphrase.expose()));
    let encrypted = secret(&core, SecretKind::PrivateKey, "encrypted key", &locked_key).await;
    let saved = secret(&core, SecretKind::Passphrase, "encrypted key passphrase", &passphrase).await;
    let mut with_passphrase = session(
        &server,
        SessionAuth::Key {
            key_id: Some(encrypted),
            passphrase_id: Some(saved),
        },
    );
    with_passphrase.name = "with passphrase".into();
    let mut pane = Pane::open(&core, create(&core, with_passphrase).await).await;
    pane.connected().await;

    // The same key without a saved passphrase: asked in the terminal.
    let mut ask = session(
        &server,
        SessionAuth::Key {
            key_id: Some(encrypted),
            passphrase_id: None,
        },
    );
    ask.name = "ask passphrase".into();
    let mut pane = Pane::open(&core, create(&core, ask).await).await;
    pane.expect_output("Passphrase for key 'encrypted key': ").await;
    pane.type_text(&core, &format!("{}\r", passphrase.expose())).await;
    pane.connected().await;
    assert!(!pane.all_output().contains(passphrase.expose()));
}

#[tokio::test]
async fn keyboard_interactive_servers_and_one_time_codes_work() {
    let password = new_password();
    // A PAM-style server: passwords only through keyboard-interactive.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .interactive_only();
    let core = core().await;
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    assert!(server.log().contains(&"interactive alice ok".to_owned()));

    // A key, then a one-time code typed in the terminal.
    let key = generate_key();
    let otp = TestSshServer::start()
        .await
        .with_key("alice", key.public_key())
        .with_otp("246810")
        .with_banner("Authorized use only\n");
    trust_server(&core, &otp).await;
    let key_id = secret(&core, SecretKind::PrivateKey, "otp key", &private_key_text(&key, None)).await;
    let mut input = session(
        &otp,
        SessionAuth::Key {
            key_id: Some(key_id),
            passphrase_id: None,
        },
    );
    input.name = "with code".into();
    let mut pane = Pane::open(&core, create(&core, input).await).await;
    pane.expect_output("Authorized use only\r\n").await;
    pane.expect_output("Verification code: ").await;
    pane.type_text(&core, "246810\r").await;
    pane.connected().await;
    let log = otp.log();
    assert!(log.contains(&"publickey alice ok".to_owned()), "{log:?}");
    assert!(log.contains(&"otp alice ok".to_owned()), "{log:?}");
}

#[cfg(windows)]
#[tokio::test]
async fn the_ssh_agent_logs_in_with_the_keys_it_holds() {
    let key = generate_key();
    let server = TestSshServer::start().await.with_key("alice", key.public_key());
    let pipe = format!(r"\\.\pipe\remotely-test-agent-{}", Uuid::new_v4());
    // The agent holds another key first, which the server refuses, then the right one.
    let agent = remotely_core::fakes::ssh_server::start_test_agent(&pipe, &[generate_key(), key]).await;
    let core = core().await;
    core.terminals.set_tuning(TerminalTuning {
        agent: AgentSource::NamedPipe(pipe),
        ..tuning()
    });
    trust_server(&core, &server).await;
    let session_id = create(&core, session(&server, SessionAuth::Agent)).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    let log = server.log();
    assert!(log.contains(&"publickey alice ok".to_owned()), "{log:?}");
    agent.abort();
}

#[tokio::test]
async fn without_an_agent_the_terminal_says_how_to_start_one() {
    let server = TestSshServer::start()
        .await
        .with_key("alice", generate_key().public_key());
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = create(&core, session(&server, SessionAuth::Agent)).await;
    let mut pane = Pane::open(&core, session_id).await;
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert_eq!(code, "agent_unavailable");
}

#[tokio::test]
async fn a_refused_login_is_not_retried() {
    let server = TestSshServer::start().await.with_password("alice", &new_password());
    let core = core().await;
    trust_server(&core, &server).await;
    let wrong = secret(&core, SecretKind::Password, "stale", &SecretString::new(new_password())).await;
    let session_id = create(
        &core,
        session(
            &server,
            SessionAuth::Password {
                password_id: Some(wrong),
            },
        ),
    )
    .await;
    let mut pane = Pane::open(&core, session_id).await;
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    assert_eq!(
        status,
        TerminalStatus::Disconnected {
            code: "auth_failed".into(),
            message: "login failed: the server refused the password for alice".into()
        }
    );
    pane.expect_output("Not connected").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn a_host_key_that_is_not_trusted_stops_the_connection() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.expect_event(|e| matches!(e, TerminalEvent::HostKeyUnknown { .. }).then_some(()))
        .await;
    core.terminals.answer_host_key(pane.id, false).unwrap();
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert_eq!(code, "host_key_rejected");
    assert!(core.known_hosts.list(&core.ctx()).await.unwrap().is_empty());
    assert!(
        !server.log().iter().any(|l| l.starts_with("password")),
        "no login was tried"
    );
}

#[tokio::test]
async fn a_changed_host_key_blocks_the_connection_until_it_is_replaced() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let old = server.host_key_fingerprint();
    server.rotate_host_key();
    let new = server.host_key_fingerprint();
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;

    let mut pane = Pane::open(&core, session_id).await;
    let (key, previous) = pane
        .expect_event(|e| match e {
            TerminalEvent::HostKeyChanged { key, previous, .. } => Some((key.clone(), previous.clone())),
            _ => None,
        })
        .await;
    assert_eq!(key.fingerprint, new);
    assert_eq!(previous.fingerprint, old);
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, message } = status else {
        unreachable!()
    };
    assert_eq!(code, "host_key_changed");
    assert!(message.contains("has changed"), "{message}");
    assert!(
        !server.log().iter().any(|l| l.starts_with("password")),
        "nothing was sent"
    );
    // Still the old key, and no automatic retry.
    assert_eq!(core.known_hosts.list(&core.ctx()).await.unwrap()[0].fingerprint, old);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.connections(), 1);
    let blocked = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "host_key_changed")
        .unwrap();
    assert!(blocked.detail.as_deref().unwrap().contains(&old));
    assert!(blocked.detail.as_deref().unwrap().contains(&new));

    // Pressing Enter tries again, and is blocked again.
    pane.type_text(&core, "\r").await;
    pane.expect_event(|e| matches!(e, TerminalEvent::HostKeyChanged { .. }).then_some(()))
        .await;

    // Replacing is explicit and audited, with both fingerprints, then it connects.
    core.terminals.replace_host_key(&core.ctx(), pane.id).await.unwrap();
    pane.connected().await;
    assert_eq!(core.known_hosts.list(&core.ctx()).await.unwrap()[0].fingerprint, new);
    let retrusted = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "host_key_retrusted")
        .unwrap();
    let detail = retrusted.detail.unwrap();
    assert!(detail.contains(&format!("{old} -> {new}")), "{detail}");
    assert!(core.terminals.replace_host_key(&core.ctx(), pane.id).await.is_err());
}

#[tokio::test]
async fn keep_alives_hold_an_idle_connection_open() {
    let password = new_password();
    // The server hangs up on connections idle for 600 ms; keep-alives every 150 ms prevent that.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_inactivity_timeout(Duration::from_millis(600));
    let core = core().await;
    core.terminals.set_tuning(TerminalTuning {
        keepalive_interval: Some(Duration::from_millis(150)),
        ..tuning()
    });
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    pane.type_text(&core, "whoami\r").await;
    pane.expect_output("alice\r\n").await;
    assert_eq!(server.connections(), 1, "the connection stayed up");
}

#[tokio::test]
async fn keep_alives_notice_a_dead_link_and_the_pane_reconnects() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    core.terminals.set_tuning(TerminalTuning {
        keepalive_interval: Some(Duration::from_millis(100)),
        keepalive_max: 2,
        ..tuning()
    });
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;

    // The link goes silent without closing, like a dead VPN.
    server.freeze_connections();
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    let TerminalStatus::Reconnecting { attempt, reason, .. } = status else {
        unreachable!()
    };
    assert_eq!(attempt, 1);
    assert!(reason.contains("keep-alive"), "{reason}");
    pane.expect_output("Reconnecting in").await;
    pane.connected().await;
    assert_eq!(server.connections(), 2);

    core.terminals.close(pane.id).await;
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
    let closed = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "terminal_closed")
        .unwrap();
    assert!(closed.detail.unwrap().contains("connected 2 times"));
}

#[tokio::test]
async fn reconnecting_gives_up_after_its_tries_and_waits_for_the_user() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    // Windows takes about 2 s to refuse a connection to a closed local port, so keep the tries few.
    core.terminals.set_tuning(TerminalTuning {
        max_attempts: 2,
        ..tuning()
    });
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;

    // The host goes away for good: every try is refused.
    drop(server);
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert!(code == "ssh" || code == "timeout", "{code}");
    pane.expect_output("Not connected").await;
    assert_eq!(pane.all_output().matches("Reconnecting in").count(), 2);
}

#[tokio::test]
async fn a_pane_that_gave_up_tries_again_when_the_network_comes_back() {
    // R9: Windows says the network changed (the shell's wake.rs): a pane out of tries starts again.
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    core.terminals.set_tuning(TerminalTuning {
        max_attempts: 2,
        ..tuning()
    });
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    assert_eq!(
        core.terminals.wake_reconnects(WakeReason::NetworkChanged),
        0,
        "a connected pane is not waiting"
    );

    // The network goes away: both tries fail and the pane waits.
    server.set_refusing(true);
    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    pane.expect_output("it tries by itself when the network comes back")
        .await;
    let tried = server.connections();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.connections(), tried, "no more tries on its own");

    server.set_refusing(false);
    assert_eq!(core.terminals.wake_reconnects(WakeReason::NetworkChanged), 1);
    pane.expect_output("The network changed: reconnecting").await;
    pane.connected().await;
}

#[tokio::test]
async fn a_resume_cuts_the_wait_before_the_next_try_short() {
    // R9: a minute's backoff, but Windows resumed: the pane tries within the wake spread.
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    core.terminals.set_tuning(TerminalTuning {
        first_retry: Duration::from_secs(60),
        max_retry: Duration::from_secs(60),
        ..tuning()
    });
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;

    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    let woke = std::time::Instant::now();
    assert_eq!(core.terminals.wake_reconnects(WakeReason::Resumed), 1);
    pane.expect_output("Windows resumed: reconnecting now").await;
    pane.connected().await;
    assert!(woke.elapsed() < Duration::from_secs(10), "{:?}", woke.elapsed());
    assert_eq!(server.connections(), 2);
}

#[tokio::test]
async fn an_ended_shell_waits_for_enter_and_the_startup_command_runs_each_time() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let mut input = session(&server, SessionAuth::Password { password_id: Some(id) });
    input.startup_command = Some("echo started".into());
    let session_id = create(&core, input).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    pane.expect_output("started\r\n").await;

    pane.type_text(&core, "exit 3\r").await;
    let status = pane.expect_status(|s| matches!(s, TerminalStatus::Ended { .. })).await;
    assert_eq!(status, TerminalStatus::Ended { exit_status: Some(3) });
    pane.expect_output("Session ended (exit status 3)").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.connections(), 1, "an ended shell is not reconnected by itself");

    pane.type_text(&core, "\r").await;
    pane.connected().await;
    pane.expect_output("started\r\n").await;
    assert_eq!(server.connections(), 2);
    let starts = server.log().iter().filter(|l| *l == "line echo started").count();
    assert_eq!(starts, 2);
}

/// SS-07: the library refuses a jump host loop when a session is saved; one that got into the data
/// some other way is refused when connecting, naming the hops, and nothing opens.
#[tokio::test]
async fn jump_hosts_that_go_round_in_a_loop_are_refused() {
    let core = core().await;
    let mut bastion = SessionInput {
        name: "bastion".into(),
        folder_id: None,
        host: "bastion.example.com".into(),
        port: 22,
        username: Some("bob".into()),
        auth: SessionAuth::Agent,
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::None,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    };
    let bastion_id = create(&core, bastion.clone()).await;
    bastion.name = "inner".into();
    bastion.host = "inner.example.com".into();
    bastion.jump_session_id = Some(bastion_id);
    let inner = create(&core, bastion.clone()).await;
    // The editor won't save it.
    let back = core.sessions.get(&core.ctx(), bastion_id).await.unwrap();
    let input = SessionInput {
        jump_session_id: Some(inner),
        name: back.name.clone(),
        host: back.host.clone(),
        ..bastion
    };
    let refused = core.sessions.update(&core.ctx(), bastion_id, input).await.unwrap_err();
    assert!(refused.to_string().contains("through its own jump host"), "{refused}");
    // Written behind the library's back, it can't connect.
    sqlx::query("UPDATE sessions SET jump_session_id = ? WHERE id = ?")
        .bind(inner.to_string())
        .bind(bastion_id.to_string())
        .execute(core.store.pool())
        .await
        .unwrap();
    let before = audit(&core).await.len();
    let err = core.terminals.open(&core.ctx(), inner, SIZE).await.err().unwrap();
    assert_eq!(err.code(), "jump_chain", "{err}");
    assert!(err.to_string().contains("'inner' -> 'bastion' -> 'inner'"), "{err}");
    assert_eq!(audit(&core).await.len(), before, "nothing was opened");
    assert_eq!(core.terminals.open_count(), 0);
}

#[tokio::test]
async fn a_locked_vault_is_reported_and_unlocking_lets_enter_retry() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: Some(id) })).await;
    core.vault.lock(&core.ctx()).await.unwrap();

    let mut pane = Pane::open(&core, session_id).await;
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert_eq!(code, "vault_locked");
    assert_eq!(server.connections(), 0, "nothing was sent without the secret");

    core.vault
        .unlock(
            &core.ctx(),
            remotely_core::vault::UnlockMethod::MasterPassword(SecretString::new(common::VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    core.terminals.reconnect(pane.id).await;
    pane.connected().await;
}

#[tokio::test]
async fn closing_a_pane_during_the_host_key_question_closes_it_cleanly() {
    let server = TestSshServer::start().await.with_password("alice", &new_password());
    let core = core().await;
    let session_id = create(&core, session(&server, SessionAuth::Password { password_id: None })).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.expect_event(|e| matches!(e, TerminalEvent::HostKeyUnknown { .. }).then_some(()))
        .await;
    core.terminals.close(pane.id).await;
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
    assert_eq!(core.terminals.open_count(), 0);
    assert!(core.known_hosts.list(&core.ctx()).await.unwrap().is_empty());
    assert!(core.terminals.answer_host_key(pane.id, true).is_err());
    let closed = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "terminal_closed")
        .unwrap();
    assert!(closed.detail.unwrap().contains("never connected"));
}

#[tokio::test]
async fn known_hosts_can_be_listed_and_removed_and_removal_is_audited() {
    let core = core().await;
    let key = generate_key();
    let host_key = HostKey {
        host: "web01.example.com".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        fingerprint: fingerprint(&key),
    };
    core.known_hosts.trust(&core.ctx(), &host_key, None).await.unwrap();
    // Trusting the same key again changes nothing.
    core.known_hosts.trust(&core.ctx(), &host_key, None).await.unwrap();
    let saved = core.known_hosts.list(&core.ctx()).await.unwrap();
    assert_eq!(saved.len(), 1);
    let trusted: Vec<AuditEntry> = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "host_key_trusted")
        .collect();
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].action, "Trusted the host key of web01.example.com:22");

    // Host names compare without letter case.
    let upper = HostKey {
        host: "WEB01.example.com".into(),
        ..host_key.clone()
    };
    assert_eq!(
        core.known_hosts.check(&core.ctx(), &upper).await.unwrap(),
        remotely_core::known_hosts::HostKeyCheck::Trusted
    );

    core.known_hosts.remove(&core.ctx(), saved[0].id).await.unwrap();
    assert!(core.known_hosts.list(&core.ctx()).await.unwrap().is_empty());
    let removed = audit(&core).await.remove(0);
    assert_eq!(removed.event, "host_key_removed");
    assert_eq!(removed.action, "Removed the trusted host key of web01.example.com:22");
    assert!(removed.detail.unwrap().contains(&host_key.fingerprint));
    assert!(core.known_hosts.remove(&core.ctx(), saved[0].id).await.is_err());
}

/// SS-01: the startup command is typed on the connections the user opens. After the pane reconnects by
/// itself it is not typed again, unless the session asks for that.
#[tokio::test]
async fn the_startup_command_is_not_typed_again_after_an_automatic_reconnect_unless_asked() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust_server(&core, &server).await;
    let id = secret(&core, SecretKind::Password, "lab alice", &SecretString::new(&password)).await;
    let mut input = session(&server, SessionAuth::Password { password_id: Some(id) });
    input.startup_command = Some("echo started".into());
    let session_id = create(&core, input.clone()).await;
    let starts = |server: &TestSshServer| server.log().iter().filter(|l| *l == "line echo started").count();
    let mut pane = Pane::open(&core, session_id).await;
    pane.connected().await;
    pane.expect_output("started\r\n").await;

    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    pane.connected().await;
    pane.expect_output("startup command was not typed again").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(starts(&server), 1);

    // The session asks for it: typed after the next automatic reconnect.
    input.startup_on_reconnect = true;
    core.sessions.update(&core.ctx(), session_id, input).await.unwrap();
    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    pane.connected().await;
    pane.expect_output("started\r\n").await;
    assert_eq!(starts(&server), 2);
}
