//! Post-MVP P4, the terminal workspace, end to end: QL-02 quick connect (saved and not), QL-03 host
//! name and IP (DNS before connecting, the host itself after), QL-04 the session tree and the
//! reachability checks, and SS-11 saving, copying, printing and logging terminal output.
//!
//! SSH goes to `fakes::ssh_server` on 127.0.0.1 with keys and passwords made at run time; DNS and
//! reachability go through `FakeNetwork`, except one probe of a port this test opens itself. No real
//! host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::Setup;
use remotely_core::adapters::containers::EngineKind;
use remotely_core::adapters::network::SystemNetwork;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::containers::{MarkInput, SudoMode};
use remotely_core::domain::{ContainerHost, Environment};
use remotely_core::fakes::containers::Fixture;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeContainers, FakeNetwork, FakeVmware};
use remotely_core::known_hosts::HostKey;
use remotely_core::reachability::{ReachState, ReachabilityTuning};
use remotely_core::sessions::tree::TreeGrouping;
use remotely_core::sessions::{SessionAuth, SessionFilter, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::output::{SaveLayout, TerminalText};
use remotely_core::terminal::quick::{QuickConnect, SaveAs};
use remotely_core::terminal::{
    FactSource, HostFacts, ReachabilityMode, TerminalEvent, TerminalHandle, TerminalSettings, TerminalStatus,
    TerminalTuning,
};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

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

/// The real russh adapter and vault, with DNS answered by `network`.
async fn core_with(network: FakeNetwork) -> (Core, Arc<FakeNetwork>) {
    let network = Arc::new(network);
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .with_network(network.clone())
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    (core, network)
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

async fn secret(core: &Core, label: &str, value: &str) -> SecretId {
    core.vault
        .add(&core.ctx, SecretKind::Password, label, SecretString::new(value))
        .await
        .unwrap()
        .id
}

fn session_input(name: &str, host: &str, port: u16, auth: SessionAuth) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth,
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 300).await.unwrap()
}

/// Nothing secret in the audit log, ever.
async fn assert_audit_clean(core: &Core, secrets: &[&str]) {
    for entry in audit(core).await {
        let text = format!("{entry:?}");
        for secret in secrets {
            assert!(!text.contains(secret), "{text}");
        }
    }
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

/// A pane under test: what it printed so far, and its events.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    printed: Vec<u8>,
    unread: Vec<u8>,
}

impl Pane {
    fn new(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            printed: Vec::new(),
            unread: Vec::new(),
        }
    }

    async fn expect_output(&mut self, needle: &str) {
        let found = timeout(WAIT, async {
            loop {
                if String::from_utf8_lossy(&self.unread).contains(needle) {
                    let text = String::from_utf8_lossy(&self.unread).into_owned();
                    let at = text.find(needle).unwrap() + needle.len();
                    self.unread = text.as_bytes()[at..].to_vec();
                    return;
                }
                let chunk = self.output.recv().await.expect("output ended");
                self.unread.extend_from_slice(&chunk);
                self.printed.extend_from_slice(&chunk);
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
        let mut seen = Vec::new();
        let result = timeout(WAIT, async {
            loop {
                tokio::select! {
                    event = self.events.recv() => {
                        let event = event.expect("events ended");
                        if let Some(found) = pick(&event) {
                            return found;
                        }
                        seen.push(event);
                    }
                    Some(chunk) = self.output.recv() => {
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("the expected event did not come; saw {seen:?}"))
    }

    async fn connected(&mut self) {
        self.expect_event(|e| {
            matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Connected).then_some(())
        })
        .await;
    }

    async fn closed(&mut self) {
        self.expect_event(|e| {
            matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Closed).then_some(())
        })
        .await;
    }

    /// The first host facts that satisfy `want`.
    async fn facts(&mut self, want: impl Fn(&HostFacts) -> bool) -> HostFacts {
        self.expect_event(|e| match e {
            TerminalEvent::Host { facts } if want(facts) => Some(facts.clone()),
            _ => None,
        })
        .await
    }

    async fn type_text(&self, core: &Core, text: &str) {
        core.terminals.write(self.id, text.as_bytes().to_vec()).await;
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.printed).into_owned()
    }
}

fn quick(server: &TestSshServer, password: Option<&str>, save: Option<SaveAs>) -> QuickConnect {
    QuickConnect {
        host: format!("alice@127.0.0.1:{}", server.port()),
        port: None,
        username: None,
        auth: SessionAuth::Password { password_id: None },
        password: password.map(SecretString::new),
        save,
        vault_password: None,
    }
}

// ---- QL-02 quick connect ----------------------------------------------------------------------------

#[tokio::test]
async fn a_quick_connection_that_is_not_saved_keeps_only_a_history_entry() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;

    let opened = core
        .terminals
        .quick_connect(&core.ctx, quick(&server, Some(&password), None), SIZE)
        .await
        .unwrap();
    assert!(opened.session.is_none());
    let mut pane = Pane::new(opened.handle);
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;
    pane.type_text(&core, "whoami\r").await;
    pane.expect_output("alice\r\n$ ").await;
    // The typed password logged in without a prompt, and nothing printed it.
    assert!(!pane.text().contains("password:"), "{}", pane.text());
    assert!(!pane.text().contains(&password));

    // A split opens a second pane like it, without asking for the password again.
    let mut second = Pane::new(core.terminals.open_like(&core.ctx, pane.id, SIZE).await.unwrap());
    second.connected().await;
    assert_eq!(server.log().iter().filter(|l| *l == "password alice ok").count(), 2);

    // Nothing was saved as a session; the history has where it went and how, never the password.
    assert!(core
        .sessions
        .list(&core.ctx, &SessionFilter::default())
        .await
        .unwrap()
        .is_empty());
    let history = core.terminals.quick_connect_history(&core.ctx).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].host, "127.0.0.1");
    assert_eq!(history[0].port, server.port());
    assert_eq!(history[0].username.as_deref(), Some("alice"));
    assert_eq!(history[0].auth, SessionAuth::Password { password_id: None });
    assert!(!format!("{history:?}").contains(&password));

    core.terminals.close(pane.id).await;
    core.terminals.close(second.id).await;
    pane.closed().await;
    second.closed().await;
    assert_eq!(core.terminals.open_count(), 0);

    let entries = audit(&core).await;
    let opened = entries
        .iter()
        .find(|e| e.event == "terminal_opened" && e.action.starts_with("Opened a quick-connect terminal to"))
        .unwrap();
    assert!(opened.action.contains("alice@127.0.0.1:"), "{opened:?}");
    assert!(entries.iter().any(|e| e
        .action
        .starts_with("Opened another quick-connect terminal to alice@127.0.0.1:")));
    let detail = opened.detail.as_deref().unwrap();
    assert!(detail.contains("password typed in the quick-connect form"), "{detail}");
    assert!(detail.contains("not saved as a session"), "{detail}");
    assert_eq!(opened.targets_json, "[]");
    assert!(entries.iter().any(|e| e.event == "terminal_closed"
        && e.action.contains("alice@127.0.0.1")
        && e.action.contains("(not saved)")));
    assert_audit_clean(&core, &[&password]).await;

    // The same target again moves to the top instead of adding a row; forgetting is audited.
    let again = core
        .terminals
        .quick_connect(&core.ctx, quick(&server, Some(&password), None), SIZE)
        .await
        .unwrap();
    core.terminals.close(again.handle.id).await;
    assert_eq!(core.terminals.quick_connect_history(&core.ctx).await.unwrap().len(), 1);
    core.terminals.forget_quick_connects(&core.ctx, None).await.unwrap();
    assert!(core
        .terminals
        .quick_connect_history(&core.ctx)
        .await
        .unwrap()
        .is_empty());
    assert!(audit(&core)
        .await
        .iter()
        .any(|e| e.action == "Cleared the quick-connect history"));
}

#[tokio::test]
async fn a_wrong_typed_password_is_forgotten_so_the_next_try_asks_in_the_terminal() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;
    let opened = core
        .terminals
        .quick_connect(&core.ctx, quick(&server, Some("not-it"), None), SIZE)
        .await
        .unwrap();
    let mut pane = Pane::new(opened.handle);
    let status = pane
        .expect_event(|e| match e {
            TerminalEvent::Status {
                status: status @ TerminalStatus::Disconnected { .. },
            } => Some(status.clone()),
            _ => None,
        })
        .await;
    assert!(matches!(status, TerminalStatus::Disconnected { code, .. } if code == "auth_failed"));
    pane.type_text(&core, "\r").await;
    pane.expect_output("alice's password: ").await;
    pane.type_text(&core, &format!("{password}\r")).await;
    pane.connected().await;
}

#[tokio::test]
async fn a_quick_connection_saved_as_a_session_goes_to_its_folder_and_recent_sessions() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;
    let folder = core
        .sessions
        .create_folder(&core.ctx, "Customer A", None)
        .await
        .unwrap();

    let save = SaveAs {
        name: "lab web".into(),
        folder_id: Some(folder.id),
        environment: Environment::Staging,
        color: None,
    };
    let opened = core
        .terminals
        .quick_connect(&core.ctx, quick(&server, Some(&password), Some(save)), SIZE)
        .await
        .unwrap();
    let session = opened.session.clone().unwrap();
    assert_eq!(session.name, "lab web");
    assert_eq!(session.folder_id, Some(folder.id));
    assert_eq!(session.environment, Environment::Staging);
    assert_eq!(session.host, "127.0.0.1");
    assert_eq!(session.port, server.port());
    assert_eq!(session.username.as_deref(), Some("alice"));
    // The typed password was used, never saved: the session asks for it next time.
    assert_eq!(session.auth, SessionAuth::Password { password_id: None });
    assert!(core.vault.list(&core.ctx).await.unwrap().is_empty());

    let mut pane = Pane::new(opened.handle);
    pane.connected().await;
    let recent = core.sessions.recent(&core.ctx, 10).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, session.id);
    assert!(recent[0].last_opened_at.is_some());
    // Saved connections are in Recent sessions, not the quick-connect history.
    assert!(core
        .terminals
        .quick_connect_history(&core.ctx)
        .await
        .unwrap()
        .is_empty());

    core.terminals.close(pane.id).await;
    pane.closed().await;
    let entries = audit(&core).await;
    assert!(entries
        .iter()
        .any(|e| e.event == "session_changed" && e.action == "Created session 'lab web'"));
    let opened = entries.iter().find(|e| e.event == "terminal_opened").unwrap();
    assert_eq!(opened.action, "Opened a terminal to 'lab web'");
    assert!(opened
        .detail
        .as_deref()
        .unwrap()
        .ends_with("password typed in the quick-connect form"));
    assert!(opened.targets_json.contains(&session.id.to_string()));
    assert_audit_clean(&core, &[&password]).await;
}

#[tokio::test]
async fn quick_connect_checks_what_was_typed_before_opening_anything() {
    let (core, _) = core_with(FakeNetwork::default()).await;
    let bad = [
        QuickConnect {
            host: "web 01".into(),
            port: None,
            username: None,
            auth: SessionAuth::Agent,
            password: None,
            save: None,
            vault_password: None,
        },
        QuickConnect {
            host: "web01.example.com:0".into(),
            port: None,
            username: None,
            auth: SessionAuth::Agent,
            password: None,
            save: None,
            vault_password: None,
        },
        QuickConnect {
            host: "web01.example.com".into(),
            port: None,
            username: None,
            auth: SessionAuth::Key {
                key_id: None,
                passphrase_id: None,
            },
            password: None,
            save: None,
            vault_password: None,
        },
        QuickConnect {
            host: "web01.example.com".into(),
            port: None,
            username: None,
            auth: SessionAuth::Password {
                password_id: Some(SecretId(Uuid::new_v4())),
            },
            password: None,
            save: None,
            vault_password: None,
        },
    ];
    for request in bad {
        assert!(
            core.terminals.quick_connect(&core.ctx, request, SIZE).await.is_err(),
            "accepted"
        );
    }
    assert_eq!(core.terminals.open_count(), 0);
    assert!(core
        .terminals
        .quick_connect_history(&core.ctx)
        .await
        .unwrap()
        .is_empty());
    assert!(audit(&core).await.iter().all(|e| e.event != "terminal_opened"));
}

// ---- QL-03 host name and IP -------------------------------------------------------------------------

#[tokio::test]
async fn the_address_reached_and_the_servers_own_name_replace_dns_and_stay_on_the_session() {
    let password = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_hostname("web01");
    // Reverse DNS has another name for the address; the server's own name wins once connected.
    let (core, network) = core_with(FakeNetwork::default().with_name("lab-box.test", "127.0.0.1")).await;
    trust_server(&core, &server).await;
    let id = secret(&core, "lab alice", &password).await;
    let session = core
        .sessions
        .create(
            &core.ctx,
            session_input(
                "lab box",
                "127.0.0.1",
                server.port(),
                SessionAuth::Password { password_id: Some(id) },
            ),
        )
        .await
        .unwrap();

    let mut pane = Pane::new(core.terminals.open(&core.ctx, session.id, SIZE).await.unwrap());
    let dns = pane.facts(|f| f.hostname.is_some()).await;
    if dns.hostname_from == Some(FactSource::Dns) {
        assert_eq!(dns.hostname.as_deref(), Some("lab-box.test"));
    }
    let facts = pane
        .facts(|f| f.hostname_from == Some(FactSource::Host) && f.ip_from == Some(FactSource::Host))
        .await;
    assert_eq!(facts.hostname.as_deref(), Some("web01"));
    assert_eq!(facts.ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(facts.title().as_deref(), Some("web01 · 127.0.0.1"));
    assert_eq!(core.terminals.facts(pane.id).unwrap(), facts);
    assert!(network.calls().contains(&"reverse 127.0.0.1".to_owned()));
    // One `hostname` on the same connection as the shell.
    let log = server.log();
    assert_eq!(server.connections(), 1);
    assert!(log.contains(&"exec hostname".to_owned()), "{log:?}");

    let saved = core.sessions.get(&core.ctx, session.id).await.unwrap();
    assert_eq!(saved.last_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(saved.last_hostname.as_deref(), Some("web01"));
    assert!(saved.last_seen_at.is_some());
    // Seeing the host is not an edit of the session.
    assert_eq!(saved.updated_at, session.updated_at);
    core.terminals.close(pane.id).await;
    pane.closed().await;
}

#[tokio::test]
async fn when_the_server_does_not_say_its_name_dns_fills_in() {
    let password = new_password();
    // Network gear: `hostname` is an unknown command that prints an error.
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_hostname("% Unknown command");
    let (core, _) = core_with(FakeNetwork::default().with_name("switch01.test", "127.0.0.1")).await;
    trust_server(&core, &server).await;
    let id = secret(&core, "lab alice", &password).await;
    let session = core
        .sessions
        .create(
            &core.ctx,
            session_input(
                "switch",
                "127.0.0.1",
                server.port(),
                SessionAuth::Password { password_id: Some(id) },
            ),
        )
        .await
        .unwrap();
    let mut pane = Pane::new(core.terminals.open(&core.ctx, session.id, SIZE).await.unwrap());
    // The address reached comes before the connected status, so watch the facts alone.
    let facts = pane
        .facts(|f| f.ip_from == Some(FactSource::Host) && f.hostname.is_some())
        .await;
    assert_eq!(facts.hostname.as_deref(), Some("switch01.test"));
    assert_eq!(facts.hostname_from, Some(FactSource::Dns));
    // Wait for the `hostname` answer to be handled, then check what was kept.
    for _ in 0..100 {
        let saved = core.sessions.get(&core.ctx, session.id).await.unwrap();
        if saved.last_hostname.is_some() && saved.last_ip.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let saved = core.sessions.get(&core.ctx, session.id).await.unwrap();
    assert_eq!(saved.last_hostname.as_deref(), Some("switch01.test"));
    assert_eq!(saved.last_ip.as_deref(), Some("127.0.0.1"));
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn before_connecting_dns_gives_a_name_its_address_and_an_address_its_name() {
    // The fake SSH adapter connects nowhere, so only DNS can tell.
    let network = Arc::new(
        FakeNetwork::default()
            .with_name("web01.test", "192.0.2.10")
            .with_name("db01.example.com", "198.51.100.7"),
    );
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    let by_name = core
        .sessions
        .create(&core.ctx, session_input("web", "web01.test", 22, SessionAuth::Agent))
        .await
        .unwrap();
    let by_ip = core
        .sessions
        .create(&core.ctx, session_input("db", "198.51.100.7", 22, SessionAuth::Agent))
        .await
        .unwrap();

    let mut web = Pane::new(core.terminals.open(&core.ctx, by_name.id, SIZE).await.unwrap());
    let facts = web.facts(|f| f.ip.is_some()).await;
    assert_eq!(facts.hostname.as_deref(), Some("web01.test"));
    assert_eq!(facts.ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(facts.ip_from, Some(FactSource::Dns));

    let mut db = Pane::new(core.terminals.open(&core.ctx, by_ip.id, SIZE).await.unwrap());
    let facts = db.facts(|f| f.hostname.is_some()).await;
    assert_eq!(facts.hostname.as_deref(), Some("db01.example.com"));
    assert_eq!(facts.title().as_deref(), Some("db01.example.com · 198.51.100.7"));
    let calls = network.calls();
    assert!(calls.contains(&"resolve web01.test".to_owned()), "{calls:?}");
    assert!(calls.contains(&"reverse 198.51.100.7".to_owned()), "{calls:?}");

    // The name is kept; an address DNS guessed is not, since no connection reached it.
    for _ in 0..100 {
        if core
            .sessions
            .get(&core.ctx, by_name.id)
            .await
            .unwrap()
            .last_hostname
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let saved = core.sessions.get(&core.ctx, by_name.id).await.unwrap();
    assert_eq!(saved.last_hostname.as_deref(), Some("web01.test"));
    assert_eq!(saved.last_ip, None);
    core.terminals.close_all().await;
}

// ---- QL-04 session tree and reachability ------------------------------------------------------------

#[tokio::test]
async fn the_tree_groups_the_library_by_folder_tag_and_label() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let customer = core
        .sessions
        .create_folder(&core.ctx, "Customer A", None)
        .await
        .unwrap();
    let site = core
        .sessions
        .create_folder(&core.ctx, "Site 1", Some(customer.id))
        .await
        .unwrap();
    let mut web = session_input("web01", "web01.example.com", 22, SessionAuth::Agent);
    web.folder_id = Some(site.id);
    web.environment = Environment::Prod;
    web.tags = vec!["web".into()];
    let web = core.sessions.create(&core.ctx, web).await.unwrap();
    let mut db = session_input("db01", "db01.example.com", 22, SessionAuth::Agent);
    db.folder_id = Some(customer.id);
    let db = core.sessions.create(&core.ctx, db).await.unwrap();
    let jump = core
        .sessions
        .create(&core.ctx, session_input("jump", "192.0.2.1", 22, SessionAuth::Agent))
        .await
        .unwrap();

    let tree = core
        .sessions
        .tree(&core.ctx, TreeGrouping::Folder, &SessionFilter::default())
        .await
        .unwrap();
    assert_eq!(tree.nodes.len(), 1);
    assert_eq!(tree.nodes[0].name, "Customer A");
    assert_eq!(tree.nodes[0].count, 2);
    assert_eq!(tree.nodes[0].sessions, [db.id]);
    assert_eq!(tree.nodes[0].children[0].sessions, [web.id]);
    assert_eq!(tree.sessions, [jump.id]);
    assert_eq!(tree.records.len(), 3);

    let tags = core
        .sessions
        .tree(&core.ctx, TreeGrouping::Tag, &SessionFilter::default())
        .await
        .unwrap();
    assert_eq!(tags.nodes[0].name, "web");
    assert_eq!(tags.nodes[0].sessions, [web.id]);
    assert_eq!(tags.nodes[1].name, "No tag");
    assert_eq!(tags.nodes[1].count, 2);

    let labels = core
        .sessions
        .tree(&core.ctx, TreeGrouping::Label, &SessionFilter::default())
        .await
        .unwrap();
    let keys: Vec<&str> = labels.nodes.iter().map(|n| n.key.as_str()).collect();
    assert_eq!(keys, ["label:prod", "label:lab"]);

    // Searching keeps only the matches and the folders on their way.
    let found = core
        .sessions
        .tree(
            &core.ctx,
            TreeGrouping::Folder,
            &SessionFilter {
                text: "WEB0".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(found.records.len(), 1);
    assert_eq!(found.nodes[0].children[0].sessions, [web.id]);
    assert!(found.nodes[0].sessions.is_empty());
    assert!(found.sessions.is_empty());
}

async fn set_reachability(core: &Core, mode: ReachabilityMode) {
    core.set_terminal_settings(TerminalSettings {
        reachability: mode,
        ..Default::default()
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reachability_checks_the_watched_sessions_once_per_host_and_port() {
    let network = Arc::new(
        FakeNetwork::default()
            .with_open_port("web01.example.com", 22)
            .with_probe_delay(Duration::from_millis(30)),
    );
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    core.reachability.set_tuning(ReachabilityTuning {
        parallel: 3,
        ..Default::default()
    });
    let web = core
        .sessions
        .create(
            &core.ctx,
            session_input("web01", "web01.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    // A second session to the same host and port, as another user.
    let mut again = session_input("web01 as bob", "WEB01.example.com", 22, SessionAuth::Agent);
    again.username = Some("bob".into());
    let again = core.sessions.create(&core.ctx, again).await.unwrap();
    let down = core
        .sessions
        .create(
            &core.ctx,
            session_input("db01", "db01.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    let mut hidden = Vec::new();
    for n in 0..10 {
        let s = core
            .sessions
            .create(
                &core.ctx,
                session_input(
                    &format!("host{n}"),
                    &format!("host{n}.example.com"),
                    22,
                    SessionAuth::Agent,
                ),
            )
            .await
            .unwrap();
        hidden.push(s.id);
    }

    // Nothing is watched yet: nothing is probed.
    assert!(core.reachability.check_once().await.unwrap().is_empty());
    assert!(network.calls().is_empty());

    let mut updates = core.reachability.subscribe();
    core.reachability.set_watched([web.id, again.id, down.id]);
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(changed.len(), 3);
    let state = |id: Uuid| changed.iter().find(|r| r.session_id == id).unwrap().clone();
    assert_eq!(state(web.id).state, ReachState::Up);
    assert_eq!(state(again.id).state, ReachState::Up);
    assert!(state(web.id).latency_ms.is_some());
    assert_eq!(state(down.id).state, ReachState::Down);
    assert!(state(down.id).reason.unwrap().contains("refused"));
    let probes: Vec<String> = network.calls();
    assert_eq!(probes.len(), 2, "one probe per host and port: {probes:?}");
    let update = updates.try_recv().unwrap();
    assert!(update.enabled);
    assert_eq!(update.states.len(), 3);

    // Not due again before the interval: no new probes.
    assert!(core.reachability.check_once().await.unwrap().is_empty());
    assert_eq!(network.calls().len(), 2);

    // Watching more sessions checks them, a few at a time.
    core.reachability.set_watched(hidden.iter().copied());
    core.reachability.check_once().await.unwrap();
    assert_eq!(network.calls().len(), 12);
    assert!(network.max_in_flight() <= 3, "{}", network.max_in_flight());
    assert!(network.max_in_flight() >= 2);
    // Reads only: nothing in the audit log about probes.
    assert!(audit(&core).await.iter().all(|e| !e.action.contains("reach")));
}

/// SS-07: a session behind jump hosts is never probed from this PC; its dot is the first jump
/// host's, and says so.
#[tokio::test]
async fn sessions_behind_a_jump_host_show_the_first_hops_reachability() {
    let network = Arc::new(FakeNetwork::default().with_open_port("bastion.example.com", 22));
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    let bastion = core
        .sessions
        .create(
            &core.ctx,
            session_input("bastion", "bastion.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    let mut inner = session_input("inner", "inner.test", 22, SessionAuth::Agent);
    inner.jump_session_id = Some(bastion.id);
    let inner = core.sessions.create(&core.ctx, inner).await.unwrap();
    let mut db = session_input("db01", "db01.test", 22, SessionAuth::Agent);
    db.jump_session_id = Some(inner.id);
    let db = core.sessions.create(&core.ctx, db).await.unwrap();

    core.reachability.set_watched([inner.id, db.id]);
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(changed.len(), 2);
    for state in &changed {
        assert_eq!(state.state, ReachState::Up, "{state:?}");
        assert_eq!(state.via.as_deref(), Some("bastion"));
    }
    let probes = network.calls();
    assert_eq!(
        probes,
        ["probe bastion.example.com:22"],
        "the hidden hosts are never probed from here"
    );

    // The first hop down: honest about which one, never the session's own fault.
    network.set_open("bastion.example.com", 22, false);
    core.reachability.poke();
    let changed = core.reachability.check_once().await.unwrap();
    assert!(changed
        .iter()
        .all(|s| s.state == ReachState::Down && s.via.as_deref() == Some("bastion")));
    // A session reached directly has no `via`.
    core.reachability.set_watched([bastion.id]);
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(changed[0].via, None);
}

#[tokio::test]
async fn reachability_follows_the_setting_and_skips_large_libraries_on_auto() {
    let network = Arc::new(FakeNetwork::default().with_open_port("web01.example.com", 22));
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    core.reachability.set_tuning(ReachabilityTuning {
        auto_max_sessions: 2,
        ..Default::default()
    });
    let mut ids = Vec::new();
    for n in 0..3 {
        let s = core
            .sessions
            .create(
                &core.ctx,
                session_input(&format!("web{n}"), "web01.example.com", 22, SessionAuth::Agent),
            )
            .await
            .unwrap();
        ids.push(s.id);
    }
    core.reachability.set_watched(ids.iter().copied());

    // Three sessions is "large" here: auto checks nothing.
    core.reachability.check_once().await.unwrap();
    assert!(network.calls().is_empty());
    assert!(!core.reachability.snapshot().enabled);

    set_reachability(&core, ReachabilityMode::On).await;
    core.reachability.check_once().await.unwrap();
    assert_eq!(network.calls().len(), 1);
    assert!(core.reachability.snapshot().enabled);
    assert_eq!(core.reachability.snapshot().states.len(), 3);

    set_reachability(&core, ReachabilityMode::Off).await;
    core.reachability.check_once().await.unwrap();
    assert_eq!(network.calls().len(), 1);
    let off = core.reachability.snapshot();
    assert!(!off.enabled);
    assert!(off.states.is_empty());
}

/// QL-04: a host this PC already holds an SSH connection to (a terminal, the dashboard's kept
/// connection) is not probed: the connection says it answers, and a probe would only add a line to its
/// sshd log. Once the connection closes, the host is checked again when it is due.
#[tokio::test]
async fn hosts_with_an_open_connection_are_not_probed() {
    let network = Arc::new(
        FakeNetwork::default()
            .with_open_port("web01.example.com", 22)
            .with_open_port("bastion.example.com", 22)
            .with_open_port("other.example.com", 22),
    );
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    let create = |name: &str, host: &str| {
        core.sessions
            .create(&core.ctx, session_input(name, host, 22, SessionAuth::Agent))
    };
    let web = create("web01", "web01.example.com").await.unwrap();
    let again = create("web01 again", "WEB01.example.com").await.unwrap();
    let bastion = create("bastion", "bastion.example.com").await.unwrap();
    let mut inner = session_input("inner", "inner.test", 22, SessionAuth::Agent);
    inner.jump_session_id = Some(bastion.id);
    let inner = core.sessions.create(&core.ctx, inner).await.unwrap();
    let other = create("other", "other.example.com").await.unwrap();

    // A terminal to web01, and the dashboard watching inner (its kept connection goes through bastion).
    let mut pane = Pane::new(core.terminals.open(&core.ctx, web.id, SIZE).await.unwrap());
    pane.connected().await;
    core.metrics.set_watched(&core.ctx, inner.id, true).await.unwrap();
    core.metrics.collect_once().await;
    timeout(WAIT, async {
        while !core.terminals.connected_sessions().contains(&web.id) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the terminal's shell is up");

    core.reachability
        .set_watched([web.id, again.id, bastion.id, inner.id, other.id]);
    // The terminal's own DNS lookups (QL-03) are not probes.
    let probes = || -> Vec<String> {
        let mut probes: Vec<String> = network
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("probe "))
            .collect();
        probes.sort();
        probes
    };
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(
        probes(),
        ["probe other.example.com:22"],
        "only the host nobody is connected to"
    );
    let state = |id: Uuid| {
        core.reachability
            .snapshot()
            .states
            .into_iter()
            .find(|s| s.session_id == id)
            .unwrap()
    };
    for id in [web.id, again.id, bastion.id, inner.id] {
        let state = state(id);
        assert_eq!(state.state, ReachState::Up, "{state:?}");
        assert!(state.connected, "{state:?}");
        assert_eq!(state.latency_ms, None);
    }
    assert_eq!(state(inner.id).via.as_deref(), Some("bastion"));
    assert!(!state(other.id).connected);
    assert!(state(other.id).latency_ms.is_some());
    assert_eq!(changed.len(), 5);

    // Nothing new: nothing probed, nothing changed.
    assert!(core.reachability.check_once().await.unwrap().is_empty());
    assert_eq!(probes().len(), 1);

    // The terminal closes: web01 was up a moment ago, and is checked again one interval later.
    core.terminals.close(pane.id).await;
    pane.closed().await;
    timeout(WAIT, async {
        while core.terminals.connected_sessions().contains(&web.id) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the terminal closed");
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(probes().len(), 1, "no probe right after the connection closed");
    for id in [web.id, again.id] {
        let found = changed.iter().find(|s| s.session_id == id).unwrap();
        assert_eq!((found.state, found.connected), (ReachState::Up, false), "{found:?}");
    }
    core.reachability.poke();
    core.reachability.check_once().await.unwrap();
    assert_eq!(
        probes(),
        [
            "probe other.example.com:22",
            "probe other.example.com:22",
            "probe web01.example.com:22"
        ],
        "bastion is still held by the dashboard's connection"
    );
    assert!(state(inner.id).connected);
    core.terminals.close_all().await;
}

/// QL-04 and CT-01: the Containers page's kept connection counts too, until it is closed.
#[tokio::test]
async fn a_kept_containers_connection_counts_as_open_until_released() {
    let network = Arc::new(FakeNetwork::default().with_open_port("web.example.com", 22));
    let engines = FakeContainers::default().with_host("web", EngineKind::Docker, Fixture::sample());
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .with_containers(Arc::new(engines))
        .build()
        .await;
    let web = core
        .sessions
        .create(
            &core.ctx,
            session_input("web", "web.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    core.containers
        .marks()
        .set(
            &core.ctx,
            web.id,
            &[MarkInput {
                engine: EngineKind::Docker,
                sudo: SudoMode::Off,
            }],
        )
        .await
        .unwrap();
    let host = ContainerHost::Session { session_id: web.id };
    core.containers
        .containers(&core.ctx, host, EngineKind::Docker)
        .await
        .unwrap();

    core.reachability.set_watched([web.id]);
    let changed = core.reachability.check_once().await.unwrap();
    assert!(network.calls().is_empty(), "{:?}", network.calls());
    assert!(changed[0].connected, "{changed:?}");

    core.containers.release(web.id).await;
    core.reachability.poke();
    let changed = core.reachability.check_once().await.unwrap();
    assert_eq!(network.calls(), ["probe web.example.com:22"]);
    assert!(!changed[0].connected);
    assert!(changed[0].latency_ms.is_some());
}

/// QL-04: a host found down waits twice the interval before its next check (and longer each time it
/// is still down), while a host that is up is checked every interval.
#[tokio::test]
async fn a_host_that_is_down_is_checked_less_often() {
    let network = Arc::new(FakeNetwork::default().with_open_port("web01.example.com", 22));
    let core = Setup::new(FakeVmware::default())
        .with_network(network.clone())
        .build()
        .await;
    let interval = Duration::from_millis(1500);
    core.reachability.set_tuning(ReachabilityTuning {
        interval: Some(interval),
        ..Default::default()
    });
    let web = core
        .sessions
        .create(
            &core.ctx,
            session_input("web01", "web01.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    let db = core
        .sessions
        .create(
            &core.ctx,
            session_input("db01", "db01.example.com", 22, SessionAuth::Agent),
        )
        .await
        .unwrap();
    core.reachability.set_watched([web.id, db.id]);
    let started = std::time::Instant::now();
    core.reachability.check_once().await.unwrap();
    assert_eq!(network.calls().len(), 2);
    let probes_of = |host: &str| network.calls().iter().filter(|c| c.contains(host)).count();

    // One interval on: web01 is due again, db01 (down) is not.
    tokio::time::sleep(interval + Duration::from_millis(700)).await;
    core.reachability.check_once().await.unwrap();
    assert_eq!(probes_of("web01"), 2);
    // (A machine too busy to get here within twice the interval can't tell; the unit tests can.)
    if started.elapsed() < 2 * interval {
        assert_eq!(probes_of("db01"), 1, "a host that is down waits twice the interval");
    }

    // Twice the interval on: db01 is checked again.
    tokio::time::sleep((2 * interval + Duration::from_millis(700)).saturating_sub(started.elapsed())).await;
    core.reachability.check_once().await.unwrap();
    assert_eq!(probes_of("db01"), 2);

    // A change of settings checks everything at once, down or not.
    core.reachability.poke();
    core.reachability.check_once().await.unwrap();
    assert_eq!(probes_of("db01"), 3);
}

#[tokio::test]
async fn a_real_probe_tells_an_open_port_from_one_nobody_listens_on() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let open = listener.local_addr().unwrap().port();
    let closed = {
        let spare = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        spare.local_addr().unwrap().port()
    };
    let core = Setup::new(FakeVmware::default())
        .with_network(Arc::new(SystemNetwork))
        .build()
        .await;
    core.reachability.set_tuning(ReachabilityTuning {
        probe_timeout: Duration::from_millis(500),
        ..Default::default()
    });
    let up = core
        .sessions
        .create(&core.ctx, session_input("up", "127.0.0.1", open, SessionAuth::Agent))
        .await
        .unwrap();
    let down = core
        .sessions
        .create(
            &core.ctx,
            session_input("down", "127.0.0.1", closed, SessionAuth::Agent),
        )
        .await
        .unwrap();
    core.reachability.set_watched([up.id, down.id]);
    let changed = core.reachability.check_once().await.unwrap();
    let state = |id: Uuid| changed.iter().find(|r| r.session_id == id).unwrap().state;
    assert_eq!(state(up.id), ReachState::Up);
    assert_eq!(state(down.id), ReachState::Down);
}

// ---- SS-11 output -----------------------------------------------------------------------------------

/// Two connected panes (one saved session with a vault password, one quick connection) and what each
/// printed.
async fn two_panes(core: &Core, server: &TestSshServer, password: &str) -> (Pane, Pane, Uuid) {
    let id = secret(core, "lab alice", password).await;
    let session = core
        .sessions
        .create(
            &core.ctx,
            session_input(
                "web01",
                "127.0.0.1",
                server.port(),
                SessionAuth::Password { password_id: Some(id) },
            ),
        )
        .await
        .unwrap();
    let mut saved = Pane::new(core.terminals.open(&core.ctx, session.id, SIZE).await.unwrap());
    saved.connected().await;
    saved.expect_output("$ ").await;
    let opened = core
        .terminals
        .quick_connect(&core.ctx, quick(server, Some(password), None), SIZE)
        .await
        .unwrap();
    let mut unsaved = Pane::new(opened.handle);
    unsaved.connected().await;
    unsaved.expect_output("$ ").await;
    (saved, unsaved, session.id)
}

#[tokio::test]
async fn several_terminals_save_to_one_file_or_one_each_with_secrets_scrubbed() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;
    let (saved, unsaved, session_id) = two_panes(&core, &server, &password).await;

    // What xterm.js would hand over: the buffers, one of them showing the password by accident.
    let items = vec![
        TerminalText {
            terminal_id: Some(saved.id),
            title: "web01 · 127.0.0.1".into(),
            text: format!("$ echo {password}\n{password}\n$ uptime\n up 3 days\n"),
        },
        TerminalText {
            terminal_id: Some(unsaved.id),
            title: "test-host · 127.0.0.1".into(),
            text: "$ whoami\nalice\n".into(),
        },
    ];

    // Copy and print get the same scrubbed text.
    let copied = core.terminals.scrub_output(items.clone());
    assert!(!copied[0].text.contains(&password));
    assert!(copied[0].text.contains("$ echo [redacted]\n[redacted]\n"));
    assert_eq!(copied[1].text, items[1].text);
    core.terminals.record_printed(&core.ctx, &copied).await.unwrap();

    // One combined file, a header per terminal.
    let folder = common::temp_folder("ss11");
    let combined = folder.join("both.txt");
    let report = core
        .terminals
        .save_output(&core.ctx, items.clone(), SaveLayout::OneFile, &combined)
        .await
        .unwrap();
    assert_eq!(report.terminals, 2);
    assert_eq!(report.files, [combined.display().to_string()]);
    let text = std::fs::read_to_string(&combined).unwrap();
    assert!(
        text.starts_with("Output of 2 terminals, saved by Remotely on "),
        "{text}"
    );
    assert!(
        text.contains("\r\n===== web01 · 127.0.0.1 =====\r\n$ echo [redacted]\r\n"),
        "{text}"
    );
    assert!(
        text.contains("\r\n===== test-host · 127.0.0.1 =====\r\n$ whoami\r\nalice\r\n"),
        "{text}"
    );
    assert!(text.contains("$ uptime\r\n up 3 days\r\n"), "{text}");
    assert!(!text.contains(&password));

    // One file per terminal, named after each.
    let each = folder.join("each");
    std::fs::create_dir_all(&each).unwrap();
    let report = core
        .terminals
        .save_output(&core.ctx, items.clone(), SaveLayout::FilePerTerminal, &each)
        .await
        .unwrap();
    assert_eq!(report.files.len(), 2);
    let mut names: Vec<String> = std::fs::read_dir(&each)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(names[0].starts_with("test-host - 127.0.0.1 "), "{names:?}");
    assert!(names[1].starts_with("web01 - 127.0.0.1 "), "{names:?}");
    let web = std::fs::read_to_string(each.join(&names[1])).unwrap();
    assert_eq!(web, "$ echo [redacted]\r\n[redacted]\r\n$ uptime\r\n up 3 days\r\n");

    // A single terminal's file holds just its text.
    let single = folder.join("web01.txt");
    core.terminals
        .save_output(&core.ctx, items[..1].to_vec(), SaveLayout::OneFile, &single)
        .await
        .unwrap();
    assert!(std::fs::read_to_string(&single)
        .unwrap()
        .starts_with("$ echo [redacted]\r\n"));

    // Audited: which sessions and which files, never the text.
    let entries = audit(&core).await;
    let saves: Vec<&AuditEntry> = entries.iter().filter(|e| e.event == "terminal_output_saved").collect();
    assert_eq!(saves.len(), 3);
    let both = saves
        .iter()
        .find(|e| e.action == "Saved the output of 2 terminals to a file")
        .unwrap();
    assert!(both.targets_json.contains(&session_id.to_string()));
    let detail = both.detail.as_deref().unwrap();
    assert!(detail.contains("'web01'"), "{detail}");
    assert!(detail.contains("alice@127.0.0.1"), "{detail}");
    assert!(detail.contains("(not saved)"), "{detail}");
    assert!(detail.contains(&combined.display().to_string()), "{detail}");
    assert!(saves
        .iter()
        .any(|e| e.action == "Saved the output of 2 terminals to 2 files"));
    assert!(saves
        .iter()
        .any(|e| e.action == "Saved the output of 'web01' to a file"));
    assert!(entries
        .iter()
        .any(|e| e.event == "terminal_output_printed" && e.action == "Printed the output of 2 terminals"));
    assert_audit_clean(&core, &[&password, "uptime", "whoami", "up 3 days"]).await;
    let _ = std::fs::remove_dir_all(&folder);
    core.terminals.close_all().await;
}

#[tokio::test]
async fn a_session_log_stamps_each_line_and_is_audited_with_its_path() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;
    let (mut pane, _other, session_id) = two_panes(&core, &server, &password).await;

    let folder = common::temp_folder("ss11-log");
    let path = folder.join("web01.log");
    core.terminals.start_log(&core.ctx, pane.id, &path).await.unwrap();
    assert_eq!(core.terminals.log_path(pane.id), Some(path.clone()));
    assert!(
        core.terminals.start_log(&core.ctx, pane.id, &path).await.is_err(),
        "already logging"
    );
    pane.type_text(&core, "echo logged line\r").await;
    pane.expect_output("logged line\r\n$ ").await;
    pane.type_text(&core, &format!("echo {password}\r")).await;
    pane.expect_output("$ ").await;

    // Closing the terminal stops the log too.
    core.terminals.close(pane.id).await;
    pane.closed().await;
    let mut text = String::new();
    for _ in 0..100 {
        text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("Remotely stopped logging") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        text.starts_with("Remotely session log of 'web01'") || text.starts_with("Remotely session log of web01"),
        "{text}"
    );
    let stamped = text
        .lines()
        .find(|l| l.ends_with("] logged line"))
        .unwrap_or_else(|| panic!("{text}"));
    // `[YYYY-MM-DD HH:MM:SS] logged line`
    assert_eq!(&stamped[..1], "[");
    assert_eq!(&stamped[20..22], "] ");
    assert!(!text.contains(&password), "{text}");
    assert!(text.contains("[redacted]"), "{text}");

    let entries = audit(&core).await;
    let started = entries.iter().find(|e| e.event == "terminal_log_started").unwrap();
    assert!(started.detail.as_deref().unwrap().contains(&path.display().to_string()));
    assert!(started.targets_json.contains(&session_id.to_string()));
    assert!(entries.iter().any(|e| e.event == "terminal_log_stopped"));
    assert_audit_clean(&core, &[&password, "logged line"]).await;
    let _ = std::fs::remove_dir_all(&folder);
    core.terminals.close_all().await;
}

#[tokio::test]
async fn locking_the_vault_forgets_a_typed_login_password_but_keeps_the_open_shell() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let (core, _) = core_with(FakeNetwork::default()).await;
    trust_server(&core, &server).await;
    let opened = core
        .terminals
        .quick_connect(&core.ctx, quick(&server, Some(&password), None), SIZE)
        .await
        .unwrap();
    let mut pane = Pane::new(opened.handle);
    pane.connected().await;

    // SS-04: the vault locks; the shell stays open, but a new login asks for the password again.
    core.vault.lock(&core.ctx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    pane.type_text(&core, "whoami\r").await;
    pane.expect_output("alice\r\n$ ").await;
    let mut second = Pane::new(core.terminals.open_like(&core.ctx, pane.id, SIZE).await.unwrap());
    second.expect_output("alice's password: ").await;
    assert_eq!(server.log().iter().filter(|l| *l == "password alice ok").count(), 1);
    core.terminals.close(second.id).await;
    core.terminals.close(pane.id).await;
}
