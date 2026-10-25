//! SS-07 jump host chains, end to end: three toy SSH servers on 127.0.0.1, where the second is
//! reachable only through the first (by the name `inner.test`, which this PC can't resolve) and the
//! third only through the second (`db01.test`): a two-hop chain. The real russh adapter, the app's
//! vault (fake DPAPI) and passwords made at run time. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{temp_folder, wait_finished, Setup};
use remotely_core::adapters::remote::AgentSource;
use remotely_core::command_bus::{Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::{ExecTuning, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::procfs::samples;
use remotely_core::metrics::{GuestState, GuestTuning};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn no_agent() -> AgentSource {
    AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4()))
}

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: no_agent(),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core.jobs.set_exec_tuning(ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: no_agent(),
        ..ExecTuning::default()
    });
    core
}

/// bastion (127.0.0.1, bob) -> inner (inner.test, carol) -> db01 (db01.test, alice).
struct Chain {
    bastion: TestSshServer,
    inner: TestSshServer,
    db: TestSshServer,
    bastion_password: String,
    bastion_id: Uuid,
    inner_id: Uuid,
    db_id: Uuid,
}

impl Chain {
    /// The servers and the three sessions. `typed_bastion`: the bastion's password is not saved,
    /// so the terminal asks for it.
    async fn new(core: &Core, typed_bastion: bool) -> Self {
        let passwords = [new_password(), new_password(), new_password()];
        let db = TestSshServer::start()
            .await
            .with_password("alice", &passwords[2])
            .with_hostname("db01")
            .with_sftp_file("/home/alice/report.txt", b"rows: 42\n");
        let inner = TestSshServer::start()
            .await
            .with_password("carol", &passwords[1])
            .with_route("db01.test", db.port());
        let bastion = TestSshServer::start()
            .await
            .with_password("bob", &passwords[0])
            .with_route("inner.test", inner.port());
        let saved = |label: &str, password: &str| {
            let label = label.to_owned();
            let password = SecretString::new(password);
            async move {
                core.vault
                    .add(&core.ctx, SecretKind::Password, &label, password)
                    .await
                    .unwrap()
                    .id
            }
        };
        let bastion_auth = match typed_bastion {
            true => None,
            false => Some(saved("bastion bob", &passwords[0]).await),
        };
        let input = |name: &str, host: &str, port: u16, user: &str, jump: Option<Uuid>| SessionInput {
            name: name.into(),
            folder_id: None,
            host: host.into(),
            port,
            username: Some(user.into()),
            auth: SessionAuth::Password { password_id: None },
            jump_session_id: jump,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: Environment::Lab,
            color: None,
            tags: vec![],
            vm_id: None,
        };
        let create = |mut input: SessionInput, password: Option<remotely_core::vault::SecretId>| {
            input.auth = SessionAuth::Password { password_id: password };
            async move { core.sessions.create(&core.ctx, input).await.unwrap().id }
        };
        let bastion_id = create(input("bastion", "127.0.0.1", bastion.port(), "bob", None), bastion_auth).await;
        let inner_password = saved("inner carol", &passwords[1]).await;
        let inner_id = create(
            input("inner", "inner.test", 22, "carol", Some(bastion_id)),
            Some(inner_password),
        )
        .await;
        let db_password = saved("db01 alice", &passwords[2]).await;
        let db_id = create(
            input("db01", "db01.test", 22, "alice", Some(inner_id)),
            Some(db_password),
        )
        .await;
        Self {
            bastion,
            inner,
            db,
            bastion_password: passwords[0].clone(),
            bastion_id,
            inner_id,
            db_id,
        }
    }

    /// Trusts the three host keys, as the hops present them: by the name each is reached by.
    async fn trust_all(&self, core: &Core) {
        for (host, port, server) in [
            ("127.0.0.1", self.bastion.port(), &self.bastion),
            ("inner.test", 22, &self.inner),
            ("db01.test", 22, &self.db),
        ] {
            let key = HostKey {
                host: host.into(),
                port,
                key_type: "ssh-ed25519".into(),
                fingerprint: server.host_key_fingerprint(),
            };
            core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
        }
    }
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 200).await.unwrap()
}

struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    unread: Vec<u8>,
    all: Vec<u8>,
}

impl Pane {
    async fn open(core: &Core, session: Uuid) -> Self {
        let handle: TerminalHandle = core
            .terminals
            .open(
                &core.ctx,
                session,
                remotely_core::adapters::remote::PtySize { cols: 80, rows: 24 },
            )
            .await
            .unwrap();
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            unread: Vec::new(),
            all: Vec::new(),
        }
    }

    async fn expect_output(&mut self, needle: &str) -> String {
        let found = timeout(WAIT, async {
            loop {
                let text = String::from_utf8_lossy(&self.unread).into_owned();
                if let Some(at) = text.find(needle) {
                    let upto = at + needle.len();
                    self.unread = text.as_bytes()[upto..].to_vec();
                    return text[..upto].to_owned();
                }
                let chunk = self.output.recv().await.expect("output ended");
                self.all.extend_from_slice(&chunk);
                self.unread.extend_from_slice(&chunk);
            }
        })
        .await;
        found.unwrap_or_else(|_| panic!("no {needle:?}; got {:?}", String::from_utf8_lossy(&self.unread)))
    }

    async fn expect_event<T>(&mut self, mut pick: impl FnMut(&TerminalEvent) -> Option<T>) -> T {
        let mut seen = Vec::new();
        let found = timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.expect("events ended");
                if let Some(found) = pick(&event) {
                    return found;
                }
                seen.push(event);
            }
        })
        .await;
        found.unwrap_or_else(|_| panic!("the expected event did not come; saw {seen:?}"))
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
}

#[tokio::test]
async fn a_two_hop_terminal_asks_about_each_hops_key_and_logs_in_at_each() {
    let core = core().await;
    let chain = Chain::new(&core, false).await;
    let mut pane = Pane::open(&core, chain.db_id).await;
    pane.expect_output("Connecting to alice@db01.test:22 via 'bastion' -> 'inner'")
        .await;

    // SS-05 at every hop, in the order they are reached, each naming its jump host.
    for (host, jump, server) in [
        ("127.0.0.1", Some("bastion"), &chain.bastion),
        ("inner.test", Some("inner"), &chain.inner),
        ("db01.test", None, &chain.db),
    ] {
        let (key, asked_for) = pane
            .expect_event(|e| match e {
                TerminalEvent::HostKeyUnknown { key, jump, .. } => Some((key.clone(), jump.clone())),
                _ => None,
            })
            .await;
        assert_eq!(key.host, host);
        assert_eq!(asked_for.as_deref(), jump);
        assert_eq!(key.fingerprint, server.host_key_fingerprint());
        core.terminals.answer_host_key(pane.id, true).unwrap();
    }
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;
    core.terminals.write(pane.id, b"whoami\r".to_vec()).await;
    pane.expect_output("alice\r\n").await;

    // Each hop logged in with its own session's password, and opened the next hop's channel.
    assert!(chain.bastion.log().contains(&"password bob ok".to_owned()));
    assert!(chain.bastion.log().contains(&"direct-tcpip inner.test:22".to_owned()));
    assert!(chain.inner.log().contains(&"password carol ok".to_owned()));
    assert!(chain.inner.log().contains(&"direct-tcpip db01.test:22".to_owned()));
    assert!(chain.db.log().contains(&"password alice ok".to_owned()));
    assert_eq!(
        (
            chain.bastion.connections(),
            chain.inner.connections(),
            chain.db.connections()
        ),
        (1, 1, 1)
    );

    // The tab shows the chain; the host's own name comes from the far end.
    let facts = pane
        .expect_event(|e| match e {
            TerminalEvent::Host { facts } if facts.hostname.is_some() => Some(facts.clone()),
            _ => None,
        })
        .await;
    assert_eq!(facts.via, ["bastion", "inner"]);
    assert_eq!(facts.hostname.as_deref(), Some("db01"));
    assert_eq!(facts.ip, None, "this PC never reached db01 itself");

    let entries = audit(&core).await;
    let opened = entries.iter().find(|e| e.event == "terminal_opened").unwrap();
    assert!(
        opened.detail.as_deref().unwrap().ends_with("via 'bastion' -> 'inner'"),
        "{opened:?}"
    );
    assert_eq!(entries.iter().filter(|e| e.event == "host_key_trusted").count(), 3);
    core.terminals.close(pane.id).await;
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
}

#[tokio::test]
async fn a_jump_hosts_typed_password_is_asked_for_it_and_kept_for_reconnects() {
    let core = core().await;
    let chain = Chain::new(&core, true).await;
    chain.trust_all(&core).await;
    let mut pane = Pane::open(&core, chain.db_id).await;
    pane.expect_output("bob@127.0.0.1's password: ").await;
    core.terminals
        .write(pane.id, format!("{}\r", chain.bastion_password).into_bytes())
        .await;
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;

    // A dropped jump host takes the session along; the reconnect logs in to it without asking.
    chain.bastion.drop_connections();
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    let TerminalStatus::Reconnecting { reason, .. } = status else {
        unreachable!()
    };
    assert!(reason.starts_with("jump host 'bastion': "), "{reason}");
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;
    let logins = chain.bastion.log().iter().filter(|l| *l == "password bob ok").count();
    assert_eq!(logins, 2);
    let shown = String::from_utf8_lossy(&pane.all).into_owned();
    assert_eq!(shown.matches("bob@127.0.0.1's password:").count(), 1, "asked once");
    assert!(!shown.contains(&chain.bastion_password), "never echoed");
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn a_changed_key_at_the_second_hop_blocks_the_connection_and_names_it() {
    let core = core().await;
    let chain = Chain::new(&core, false).await;
    chain.trust_all(&core).await;
    chain.inner.rotate_host_key();
    let mut pane = Pane::open(&core, chain.db_id).await;
    let (key, jump) = pane
        .expect_event(|e| match e {
            TerminalEvent::HostKeyChanged { key, jump, .. } => Some((key.clone(), jump.clone())),
            _ => None,
        })
        .await;
    assert_eq!((key.host.as_str(), key.port), ("inner.test", 22));
    assert_eq!(jump.as_deref(), Some("inner"));
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, message } = status else {
        unreachable!()
    };
    assert_eq!(code, "host_key_changed");
    assert!(message.contains("the jump host 'inner' (inner.test:22)"), "{message}");
    assert_eq!(chain.db.connections(), 0, "nothing went past the changed key");
    let blocked = audit(&core).await;
    let blocked = blocked.iter().find(|e| e.event == "host_key_changed").unwrap();
    assert_eq!(
        blocked.action,
        "Blocked the connection to inner.test:22: its host key changed"
    );

    // Trusting the new key (an explicit, audited step) lets it through.
    core.terminals.replace_host_key(&core.ctx, pane.id).await.unwrap();
    pane.connected().await;
    pane.expect_output("Welcome, alice").await;
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn commands_and_compare_runs_go_through_the_chain() {
    let core = core().await;
    let chain = Chain::new(&core, false).await;
    chain.trust_all(&core).await;
    let mut events = core.jobs.subscribe();
    let run = |trust_new_host_keys: bool| Command::RemoteExec {
        targets: vec![TargetRef::Session {
            session_id: chain.db_id,
        }],
        script: "hostname; whoami".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys,
        timeout_secs: Some(30),
    };
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, run(false)).await.unwrap() else {
        panic!("a read-only command on a Lab host runs at once");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    let targets = core.store.job_targets(&core.ctx, job_id).await.unwrap();
    assert_eq!(targets[0].output.as_deref(), Some("db01\nalice\n"));
    assert!(chain.inner.log().contains(&"direct-tcpip db01.test:22".to_owned()));
    assert!(chain.db.log().contains(&"exec hostname; whoami".to_owned()));

    // A run can't ask about a key; an unknown one at a hop fails and says which.
    let known = core.known_hosts.list(&core.ctx).await.unwrap();
    let inner_key = known.iter().find(|k| k.host == "inner.test").unwrap();
    core.known_hosts.remove(&core.ctx, inner_key.id).await.unwrap();
    let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, run(false)).await.unwrap() else {
        panic!("queued");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Failed);
    let targets = core.store.job_targets(&core.ctx, job_id).await.unwrap();
    let error = targets[0].error.clone().unwrap();
    assert!(error.contains("the jump host 'inner' (inner.test:22)"), "{error}");
    assert_eq!(targets[0].error_code.as_deref(), Some("host_key_unknown"));
}

#[tokio::test]
async fn files_ride_the_terminals_connection_through_the_chain() {
    let core = core().await;
    let chain = Chain::new(&core, false).await;
    chain.trust_all(&core).await;
    let mut pane = Pane::open(&core, chain.db_id).await;
    pane.connected().await;
    let listing = core.terminals.list_folder(pane.id, Some("/home/alice")).await.unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"report.txt"), "{names:?}");
    let dest = temp_folder("jump-download");
    core.terminals
        .download(&core.ctx, pane.id, &["/home/alice/report.txt".to_owned()], &dest)
        .await
        .unwrap();
    let saved = timeout(WAIT, async {
        loop {
            if let Ok(text) = std::fs::read_to_string(dest.join("report.txt")) {
                if !text.is_empty() {
                    return text;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(saved, "rows: 42\n");
    assert!(chain.db.log().contains(&"subsystem sftp".to_owned()));
    assert_eq!(chain.db.connections(), 1, "SFTP used the terminal's own connection");
    core.terminals.close(pane.id).await;
    let _ = std::fs::remove_dir_all(dest);
}

#[tokio::test]
async fn guest_metrics_are_read_through_the_chain() {
    let core = core().await;
    let chain = Chain::new(&core, false).await;
    chain.trust_all(&core).await;
    let s = samples::ubuntu(0);
    for (path, text) in [
        ("/proc/stat", &s.stat),
        ("/proc/meminfo", &s.meminfo),
        ("/proc/loadavg", &s.loadavg),
        ("/proc/uptime", &s.uptime),
        ("/proc/diskstats", &s.diskstats),
        ("/proc/net/dev", &s.netdev),
    ] {
        chain.db.set_file(path, text);
    }
    core.metrics.guest().set_interval(Duration::ZERO);
    core.metrics.guest().set_tuning(GuestTuning {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        round_budget: Duration::from_secs(10),
        backoff_min: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        parallel: 4,
        agent: no_agent(),
    });
    core.metrics.set_watched(&core.ctx, chain.db_id, true).await.unwrap();
    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&chain.db_id].clone();
    assert_eq!(status.state, GuestState::Ok, "{status:?}");
    assert!(chain.inner.log().contains(&"direct-tcpip db01.test:22".to_owned()));

    // A jump host whose password is not saved can't be logged in to by the dashboard: it says so.
    core.metrics.set_watched(&core.ctx, chain.db_id, false).await.unwrap();
    let bastion = core.sessions.get(&core.ctx, chain.bastion_id).await.unwrap();
    let input = SessionInput {
        name: bastion.name.clone(),
        folder_id: None,
        host: bastion.host.clone(),
        port: bastion.port,
        username: bastion.username.clone(),
        auth: SessionAuth::Password { password_id: None },
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    };
    core.sessions.update(&core.ctx, chain.bastion_id, input).await.unwrap();
    core.metrics.set_watched(&core.ctx, chain.inner_id, true).await.unwrap();
    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&chain.inner_id].clone();
    assert_eq!(status.state, GuestState::LoginFailed);
    assert!(
        status.message.as_deref().unwrap().contains("the jump host 'bastion'"),
        "{status:?}"
    );
}

#[tokio::test]
async fn a_tunnel_on_a_two_hop_session_starts_from_the_far_host() {
    use remotely_core::adapters::remote::forward::ForwardKind;
    use remotely_core::forwards::ForwardInput;
    use remotely_core::terminal::tunnels::TunnelState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let core = core().await;
    let chain = Chain::new(&core, false).await;
    chain.trust_all(&core).await;
    // An echo service on this PC that only db01 knows by name.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let echo = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    chain.db.set_route("echo.test", echo);
    let saved = core
        .forwards
        .save(
            &core.ctx,
            chain.db_id,
            &[ForwardInput {
                id: None,
                label: Some("echo".into()),
                kind: ForwardKind::Local,
                bind_address: "127.0.0.1".into(),
                bind_port: 0,
                dest_host: "echo.test".into(),
                dest_port: 7,
                auto_start: true,
            }],
        )
        .await
        .unwrap();
    let mut pane = Pane::open(&core, chain.db_id).await;
    pane.connected().await;
    let at = pane
        .expect_event(|e| match e {
            TerminalEvent::Tunnels { tunnels } => tunnels.iter().find_map(|t| match &t.state {
                TunnelState::Listening { at } if t.forward.id == saved[0].id => Some(at.clone()),
                _ => None,
            }),
            _ => None,
        })
        .await;
    let port: u16 = at.rsplit(':').next().unwrap().parse().unwrap();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(b"two hops").await.unwrap();
    let mut back = [0u8; 8];
    timeout(WAIT, socket.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"two hops");
    // The far host opened it; the jump hosts only carried the session.
    assert!(chain.db.log().contains(&"direct-tcpip echo.test:7".to_owned()));
    assert!(!chain.bastion.log().iter().any(|l| l.contains("echo.test")));
    let opened = audit(&core).await;
    let opened = opened.iter().find(|e| e.event == "tunnel_opened").unwrap();
    assert_eq!(
        opened.action,
        "Opened a tunnel on 'db01': 'echo' (local 127.0.0.1 (any free port) -> echo.test:7)"
    );
    core.terminals.close(pane.id).await;
}
