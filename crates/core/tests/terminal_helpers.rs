//! Post-MVP P5 terminal helpers, end to end: QL-06 "Type vault password" (only at a password prompt
//! unless forced, never leaking the value), QL-05 selection copies scrubbed of the terminal's secrets, and
//! QL-07 notifications when a long command finishes (the prompt comes back, or the output stops).
//!
//! SSH goes to `fakes::ssh_server` on 127.0.0.1 with passwords made at run time; its toy shell's
//! `sudo` asks for a password without echoing it. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::activity::FinishedHow;
use remotely_core::terminal::output::{SaveLayout, TerminalText};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalSettings, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn tuning(notify: Option<(Duration, Option<Duration>)>) -> TerminalTuning {
    TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: notify,
    }
}

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(tuning(None));
    core
}

async fn trust_server(core: &Core, server: &TestSshServer) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
}

async fn secret(core: &Core, kind: SecretKind, label: &str, value: &str) -> SecretId {
    core.vault
        .add(&core.ctx, kind, label, SecretString::new(value))
        .await
        .unwrap()
        .id
}

/// A saved session `web01` that logs in as alice with `password` from the vault.
async fn session(core: &Core, server: &TestSshServer, password: &str) -> Uuid {
    let login = secret(core, SecretKind::Password, "alice login", password).await;
    core.sessions
        .create(
            &core.ctx,
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port: server.port(),
                username: Some("alice".into()),
                auth: SessionAuth::Password {
                    password_id: Some(login),
                },
                jump_session_id: None,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 300).await.unwrap()
}

/// A pane under test: what it printed so far, and its events.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    printed: Vec<u8>,
    unread: Vec<u8>,
    seen: Vec<TerminalEvent>,
}

impl Pane {
    async fn open(core: &Core, session_id: Uuid) -> Self {
        let handle: TerminalHandle = core.terminals.open(&core.ctx, session_id, SIZE).await.unwrap();
        let mut pane = Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            printed: Vec::new(),
            unread: Vec::new(),
            seen: Vec::new(),
        };
        pane.expect_event(|e| {
            matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Connected).then_some(())
        })
        .await;
        pane.expect_output("Welcome, alice\r\n$ ").await;
        pane
    }

    async fn expect_output(&mut self, needle: &str) {
        let found = timeout(WAIT, async {
            loop {
                let text = String::from_utf8_lossy(&self.unread).into_owned();
                if let Some(at) = text.find(needle) {
                    self.unread = text.as_bytes()[at + needle.len()..].to_vec();
                    return;
                }
                tokio::select! {
                    chunk = self.output.recv() => {
                        let chunk = chunk.expect("output ended");
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                    Some(event) = self.events.recv() => self.seen.push(event),
                }
            }
        })
        .await;
        assert!(
            found.is_ok(),
            "no {needle:?} in the output; got {:?}",
            String::from_utf8_lossy(&self.unread)
        );
    }

    /// Reads events until one matches, keeping the output flowing meanwhile.
    async fn expect_event<T>(&mut self, mut pick: impl FnMut(&TerminalEvent) -> Option<T>) -> T {
        if let Some(found) = self.seen.iter().find_map(&mut pick) {
            return found;
        }
        let result = timeout(WAIT, async {
            loop {
                tokio::select! {
                    event = self.events.recv() => {
                        let event = event.expect("events ended");
                        if let Some(found) = pick(&event) {
                            return found;
                        }
                        self.seen.push(event);
                    }
                    Some(chunk) = self.output.recv() => {
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("the expected event did not come; saw {:?}", self.seen))
    }

    /// Keeps reading for `how_long`, then says whether a command was reported finished.
    async fn finished_within(&mut self, how_long: Duration) -> Option<FinishedHow> {
        let _ = timeout(how_long, async {
            loop {
                tokio::select! {
                    Some(event) = self.events.recv() => self.seen.push(event),
                    Some(chunk) = self.output.recv() => {
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                }
            }
        })
        .await;
        self.take_finished()
    }

    fn take_finished(&mut self) -> Option<FinishedHow> {
        let at = self
            .seen
            .iter()
            .position(|e| matches!(e, TerminalEvent::CommandFinished { .. }))?;
        match self.seen.remove(at) {
            TerminalEvent::CommandFinished { how, .. } => Some(how),
            _ => None,
        }
    }

    async fn type_text(&self, core: &Core, text: &str) {
        core.terminals.write(self.id, text.as_bytes().to_vec()).await;
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.printed).into_owned()
    }

    fn events_text(&self) -> String {
        format!("{:?}", self.seen)
    }
}

// ---- QL-06: Type vault password ------------------------------------------------------------------------

#[tokio::test]
async fn a_vault_password_answers_sudo_without_ever_showing() {
    let login = new_password();
    let sudo = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::Password(sudo.clone()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let sudo_id = secret(&core, SecretKind::Password, "web sudo", &sudo).await;
    let mut pane = Pane::open(&core, session_id).await;

    pane.type_text(&core, "sudo whoami\r").await;
    pane.expect_output("[sudo] password for alice: ").await;
    core.terminals
        .type_secret(&core.ctx, pane.id, sudo_id, false, None)
        .await
        .unwrap();
    pane.expect_output("ok\r\n$ ").await;
    assert!(server.log().contains(&"sudo alice ok".to_owned()), "{:?}", server.log());

    // The value went to the shell only: not the output, the events, the audit log, or the server's log.
    assert!(!pane.text().contains(&sudo), "{}", pane.text());
    assert!(!pane.events_text().contains(&sudo));
    assert!(!server.log().iter().any(|l| l.contains(&sudo)));
    let entries = audit(&core).await;
    for entry in &entries {
        let text = format!("{entry:?}");
        assert!(!text.contains(&sudo) && !text.contains(&login), "{text}");
    }
    let typed = entries.iter().find(|e| e.event == "vault_secret_typed").unwrap();
    assert_eq!(
        typed.action,
        "Typed the password 'web sudo' into the terminal to 'web01'"
    );
    assert_eq!(typed.detail.as_deref(), Some("at a password prompt"));
    assert!(
        typed.targets_json.contains(&session_id.to_string()),
        "{}",
        typed.targets_json
    );
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn at_a_shell_prompt_the_password_is_held_back_unless_the_user_insists() {
    let login = new_password();
    let sudo = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::Password(sudo.clone()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let sudo_id = secret(&core, SecretKind::Password, "web sudo", &sudo).await;
    let mut pane = Pane::open(&core, session_id).await;

    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, sudo_id, false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "no_password_prompt");
    assert!(!err.to_string().contains(&sudo));
    pane.type_text(&core, "echo still here\r").await;
    pane.expect_output("still here\r\n$ ").await;
    // Nothing was typed: the shell saw only the echo.
    assert!(!server.log().iter().any(|l| l.contains(&sudo)), "{:?}", server.log());
    assert!(!pane.text().contains(&sudo));
    assert!(!audit(&core).await.iter().any(|e| e.event == "vault_secret_typed"));

    // Insisting needs the vault password (SS-04, AP-06), then types it (the toy shell echoes it as a
    // command, as a real one would).
    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, sudo_id, true, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "reauth_required");
    assert!(err.to_string().contains("No password prompt is showing"), "{err}");
    core.terminals
        .type_secret(
            &core.ctx,
            pane.id,
            sudo_id,
            true,
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    pane.expect_output(": command not found\r\n$ ").await;
    let typed = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "vault_secret_typed")
        .unwrap();
    assert_eq!(
        typed.detail.as_deref(),
        Some("no password prompt was showing; typed at the user's request; the vault password was asked again (AP-06)")
    );
    // What showed on screen is scrubbed from copies and saved output.
    let copied = core.terminals.scrub_output(vec![TerminalText {
        terminal_id: Some(pane.id),
        title: "web01".into(),
        text: pane.text(),
    }]);
    assert!(pane.text().contains(&sudo), "the toy shell echoed it");
    assert!(!copied[0].text.contains(&sudo));
    assert!(
        copied[0].text.contains("[redacted]: command not found"),
        "{}",
        copied[0].text
    );
}

#[tokio::test]
async fn a_typed_password_is_scrubbed_from_saved_output_and_the_session_log() {
    let login = new_password();
    let sudo = new_password();
    // A broken sudo that prints the password it read back.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::EchoesPassword(sudo.clone()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let sudo_id = secret(&core, SecretKind::Passphrase, "web sudo", &sudo).await;
    let mut pane = Pane::open(&core, session_id).await;
    let dir = common::temp_folder("typed-secret");
    let log_path = dir.join("web01.log");
    core.terminals.start_log(&core.ctx, pane.id, &log_path).await.unwrap();

    pane.type_text(&core, "sudo id\r").await;
    pane.expect_output("password for alice: ").await;
    core.terminals
        .type_secret(&core.ctx, pane.id, sudo_id, false, None)
        .await
        .unwrap();
    pane.expect_output(&format!("ok {sudo}\r\n$ ")).await;
    core.terminals.stop_log(&core.ctx, pane.id).await.unwrap();

    let saved_path = dir.join("saved.txt");
    core.terminals
        .save_output(
            &core.ctx,
            vec![TerminalText {
                terminal_id: Some(pane.id),
                title: "web01".into(),
                text: pane.text(),
            }],
            SaveLayout::OneFile,
            &saved_path,
        )
        .await
        .unwrap();
    let saved = std::fs::read_to_string(&saved_path).unwrap();
    assert!(!saved.contains(&sudo), "{saved}");
    assert!(saved.contains("ok [redacted]"), "{saved}");
    let mut log = String::new();
    for _ in 0..100 {
        log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log.contains("stopped logging") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!log.contains(&sudo), "{log}");
    assert!(log.contains("ok [redacted]"), "{log}");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn only_passwords_and_passphrases_of_an_unlocked_vault_are_typed() {
    let login = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::Password(new_password()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let key = secret(&core, SecretKind::PrivateKey, "alice key", &common::fake_private_key()).await;
    let sudo_id = secret(&core, SecretKind::Password, "web sudo", &new_password()).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.type_text(&core, "sudo id\r").await;
    pane.expect_output("password for alice: ").await;

    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, key, false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, SecretId(Uuid::new_v4()), false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    let err = core
        .terminals
        .type_secret(&core.ctx, Uuid::new_v4(), sudo_id, false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    core.vault.lock(&core.ctx).await.unwrap();
    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, sudo_id, false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "vault_locked");
    assert!(!audit(&core).await.iter().any(|e| e.event == "vault_secret_typed"));
}

#[tokio::test]
async fn nothing_is_typed_into_a_terminal_that_is_not_connected() {
    let login = new_password();
    let server = TestSshServer::start().await.with_password("alice", &login);
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let sudo_id = secret(&core, SecretKind::Password, "web sudo", &new_password()).await;
    let mut pane = Pane::open(&core, session_id).await;
    pane.type_text(&core, "exit\r").await;
    pane.expect_event(|e| {
        matches!(
            e,
            TerminalEvent::Status {
                status: TerminalStatus::Ended { .. }
            }
        )
        .then_some(())
    })
    .await;
    let err = core
        .terminals
        .type_secret(
            &core.ctx,
            pane.id,
            sudo_id,
            true,
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    assert!(err.to_string().contains("not connected"), "{err}");
}

#[tokio::test]
async fn a_password_no_saved_session_sends_to_this_host_needs_the_vault_password_before_it_is_typed() {
    let login = new_password();
    let sudo = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::Password(sudo.clone()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    // In the vault before this run, and used by no session here: someone else's customer password, as far as
    // this host is concerned.
    let other = core
        .vault
        .vault()
        .put(
            &core.ctx,
            SecretKind::Password,
            "customer root",
            SecretString::new(&sudo),
        )
        .await
        .unwrap();
    let mut pane = Pane::open(&core, session_id).await;
    pane.type_text(&core, "sudo whoami\r").await;
    pane.expect_output("[sudo] password for alice: ").await;

    let err = core
        .terminals
        .type_secret(&core.ctx, pane.id, other, false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "reauth_required");
    assert!(err.to_string().contains("password 'customer root'"), "{err}");
    assert!(
        !server.log().iter().any(|l| l.contains("sudo alice")),
        "nothing typed: {:?}",
        server.log()
    );
    let err = core
        .terminals
        .type_secret(
            &core.ctx,
            pane.id,
            other,
            false,
            Some(&SecretString::new("guess-guess-guess")),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "wrong_vault_password");
    assert!(audit(&core).await.iter().any(|e| e.event == "vault_auth_failed"));

    core.terminals
        .type_secret(
            &core.ctx,
            pane.id,
            other,
            false,
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    pane.expect_output("ok\r\n$ ").await;
    let entries = audit(&core).await;
    let typed = entries.iter().find(|e| e.event == "vault_secret_typed").unwrap();
    assert_eq!(
        typed.detail.as_deref(),
        Some("at a password prompt; the vault password was asked again (AP-06)")
    );
    let allowed = entries.iter().find(|e| e.event == "vault_secret_allowed").unwrap();
    assert_eq!(
        allowed.action,
        "Let session 'web01' use the password 'customer root' from now on"
    );

    // From now on it goes to this host without asking.
    pane.type_text(&core, "sudo whoami\r").await;
    pane.expect_output("[sudo] password for alice: ").await;
    core.terminals
        .type_secret(&core.ctx, pane.id, other, false, None)
        .await
        .unwrap();
    pane.expect_output("ok\r\n$ ").await;
}

// ---- QL-05: selection copies ---------------------------------------------------------------------------

#[tokio::test]
async fn a_copied_selection_is_scrubbed_of_the_terminals_secrets() {
    let login = new_password();
    let sudo = new_password();
    // A broken sudo that prints the password it read back.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(SudoMode::EchoesPassword(sudo.clone()));
    let core = core().await;
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let sudo_id = secret(&core, SecretKind::Password, "web sudo", &sudo).await;
    let mut pane = Pane::open(&core, session_id).await;

    // The vault secret typed at sudo's prompt, and the login password (from the vault), both on screen.
    pane.type_text(&core, "sudo id\r").await;
    pane.expect_output("password for alice: ").await;
    core.terminals
        .type_secret(&core.ctx, pane.id, sudo_id, false, None)
        .await
        .unwrap();
    pane.expect_output(&format!("ok {sudo}\r\n$ ")).await;
    pane.type_text(&core, &format!("echo {login}\r")).await;
    pane.expect_output(&format!("{login}\r\n$ ")).await;

    // What the user selected, as xterm.js reads it.
    let selection = format!("ok {sudo}\r\n$ echo {login}\r\n{login}\r\n$ ");
    let copied = core.terminals.scrub_for_copy(Some(pane.id), &selection).unwrap();
    assert_eq!(copied, "ok [redacted]\r\n$ echo [redacted]\r\n[redacted]\r\n$ ");
    // A selection without a secret is copied as it is.
    assert_eq!(
        core.terminals.scrub_for_copy(Some(pane.id), "$ uptime\r\n").unwrap(),
        "$ uptime\r\n"
    );

    // The shell ending leaves the pane, and its secrets, until it is closed.
    pane.type_text(&core, "exit\r").await;
    pane.expect_event(|e| {
        matches!(
            e,
            TerminalEvent::Status {
                status: TerminalStatus::Ended { .. }
            }
        )
        .then_some(())
    })
    .await;
    let copied = core.terminals.scrub_for_copy(Some(pane.id), &selection).unwrap();
    assert!(!copied.contains(&sudo) && !copied.contains(&login), "{copied}");

    // A closed terminal has dropped its secrets, so its text is refused rather than copied unchecked.
    core.terminals.close(pane.id).await;
    pane.expect_event(|e| {
        matches!(
            e,
            TerminalEvent::Status {
                status: TerminalStatus::Closed
            }
        )
        .then_some(())
    })
    .await;
    let err = core.terminals.scrub_for_copy(Some(pane.id), &selection).unwrap_err();
    assert_eq!(err.code(), "unknown_target");
    assert!(
        !err.to_string().contains(&sudo) && !err.to_string().contains(&login),
        "{err}"
    );

    // A pane that never opened holds only the app's own lines: what looks like a password is redacted.
    let copied = core
        .terminals
        .scrub_for_copy(None, &format!("[Not connected: refused]\r\nmysql --password={login}"))
        .unwrap();
    assert_eq!(copied, "[Not connected: refused]\r\nmysql --password=[redacted]");
}

// ---- QL-07: notifications when a long command finishes -------------------------------------------------

const SHORT: Duration = Duration::from_millis(300);

#[tokio::test]
async fn a_long_command_is_reported_when_its_prompt_comes_back() {
    let login = new_password();
    let server = TestSshServer::start().await.with_password("alice", &login);
    let core = core().await;
    core.terminals.set_tuning(tuning(Some((SHORT, None))));
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let mut pane = Pane::open(&core, session_id).await;

    // A quick one is not.
    pane.type_text(&core, "echo quick\r").await;
    pane.expect_output("quick\r\n$ ").await;
    assert_eq!(pane.finished_within(Duration::from_millis(500)).await, None);

    pane.type_text(&core, "sleep 0.8\r").await;
    let after = pane
        .expect_event(|e| match e {
            TerminalEvent::CommandFinished { after_secs, how } => Some((*after_secs, *how)),
            _ => None,
        })
        .await;
    assert_eq!(after, (0, FinishedHow::Prompt));
    pane.expect_output("$ ").await;
}

#[tokio::test]
async fn a_long_command_whose_output_stops_is_reported_as_quiet() {
    let login = new_password();
    let server = TestSshServer::start().await.with_password("alice", &login);
    let core = core().await;
    core.terminals.set_tuning(tuning(Some((SHORT, Some(SHORT)))));
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let mut pane = Pane::open(&core, session_id).await;

    // Output for a while, then silence without a prompt.
    pane.type_text(&core, "work 0.8\r").await;
    pane.expect_output("done, waiting\r\n").await;
    let how = pane
        .expect_event(|e| match e {
            TerminalEvent::CommandFinished { how, .. } => Some(*how),
            _ => None,
        })
        .await;
    assert_eq!(how, FinishedHow::Quiet);
    // A command that printed briefly and then waited is no long run.
    pane.type_text(&core, "\r").await;
    pane.type_text(&core, "work 0.1\r").await;
    pane.expect_output("done, waiting\r\n").await;
    assert_eq!(pane.finished_within(Duration::from_millis(900)).await, None);
}

#[tokio::test]
async fn notifications_turned_off_in_the_settings_stop_at_once_and_come_back() {
    let login = new_password();
    let server = TestSshServer::start().await.with_password("alice", &login);
    let core = core().await;
    core.terminals.set_tuning(tuning(Some((SHORT, None))));
    trust_server(&core, &server).await;
    let session_id = session(&core, &server, &login).await;
    let mut pane = Pane::open(&core, session_id).await;

    let mut settings = core.terminal_settings().await.unwrap();
    assert!(settings.notify_finished, "on by default");
    settings.notify_finished = false;
    core.set_terminal_settings(settings).await.unwrap();
    pane.type_text(&core, "sleep 0.6\r").await;
    assert_eq!(pane.finished_within(Duration::from_millis(1200)).await, None);
    pane.expect_output("$ ").await;

    core.set_terminal_settings(TerminalSettings {
        notify_finished: true,
        ..settings
    })
    .await
    .unwrap();
    pane.type_text(&core, "sleep 0.6\r").await;
    let how = pane
        .expect_event(|e| match e {
            TerminalEvent::CommandFinished { how, .. } => Some(*how),
            _ => None,
        })
        .await;
    assert_eq!(how, FinishedHow::Prompt);
    let changed = audit(&core)
        .await
        .into_iter()
        .find(|e| e.action == "Set the terminal settings")
        .unwrap();
    assert!(changed.detail.unwrap().contains("notify after commands of 30 s"));
}
