//! SS-07 tunnels, end to end: saved port forwards opened on a terminal's own connection through the
//! command bus, against toy SSH servers on 127.0.0.1. Bytes go to a small echo service this test
//! runs on 127.0.0.1; the servers reach it by the name `echo.test`. Every listener binds 127.0.0.1
//! (ports chosen by the system), so nothing is open to the network. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::Setup;
use remotely_core::adapters::remote::forward::ForwardKind;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::command_bus::ApprovalAnswers;
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::forwards::ForwardInput;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::tunnels::{TunnelInfo, TunnelStart, TunnelState};
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
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
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core
}

/// An echo service on 127.0.0.1: what comes in goes back. Returns its port.
async fn echo_service() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

/// A server that logs alice in with a saved password and reaches the echo service as `echo.test`,
/// a session to it with `environment`, and its key trusted.
async fn host(core: &Core, echo: u16, environment: Environment) -> (TestSshServer, Uuid) {
    let password = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_route("echo.test", echo);
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
    let name = match environment {
        Environment::Prod => "prod01",
        _ => "app01",
    };
    let secret = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            &format!("alice on {name}"),
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let session = core
        .sessions
        .create(
            &core.ctx,
            SessionInput {
                name: name.into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port: server.port(),
                username: Some("alice".into()),
                auth: SessionAuth::Password {
                    password_id: Some(secret),
                },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id;
    (server, session)
}

fn forward(kind: ForwardKind, dest_host: &str, dest_port: u16, auto_start: bool) -> ForwardInput {
    ForwardInput {
        id: None,
        label: None,
        kind,
        // Loopback, any free port: nothing is open to the network, and runs never collide.
        bind_address: match kind {
            ForwardKind::Remote => "localhost".into(),
            _ => "127.0.0.1".into(),
        },
        bind_port: 0,
        dest_host: dest_host.into(),
        dest_port,
        auto_start,
    }
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 300).await.unwrap()
}

struct Pane {
    id: Uuid,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    _output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tunnels: Vec<TunnelInfo>,
}

impl Pane {
    async fn open(core: &Core, session: Uuid) -> Self {
        let handle = core
            .terminals
            .open(&core.ctx, session, PtySize { cols: 80, rows: 24 })
            .await
            .unwrap();
        // The output is drained so the pane never waits on it.
        let mut output = handle.output;
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move { while output.recv().await.is_some() {} });
        Self {
            id: handle.id,
            events: handle.events,
            _output: rx,
            tunnels: Vec::new(),
        }
    }

    async fn expect_event<T>(&mut self, mut pick: impl FnMut(&TerminalEvent) -> Option<T>) -> T {
        let mut seen = Vec::new();
        let found = timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.expect("events ended");
                if let TerminalEvent::Tunnels { tunnels } = &event {
                    self.tunnels.clone_from(tunnels);
                }
                if let Some(found) = pick(&event) {
                    return found;
                }
                seen.push(event);
            }
        })
        .await;
        found.unwrap_or_else(|_| panic!("the expected event did not come; saw {seen:?}"))
    }

    async fn connected(&mut self) {
        self.expect_event(|e| {
            matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Connected).then_some(())
        })
        .await;
    }

    /// Waits until a tunnel's state matches.
    async fn expect_tunnel(&mut self, forward: Uuid, want: impl Fn(&TunnelState) -> bool) -> TunnelInfo {
        if let Some(found) = self.tunnels.iter().find(|t| t.forward.id == forward && want(&t.state)) {
            return found.clone();
        }
        self.expect_event(|e| match e {
            TerminalEvent::Tunnels { tunnels } => tunnels
                .iter()
                .find(|t| t.forward.id == forward && want(&t.state))
                .cloned(),
            _ => None,
        })
        .await
    }

    async fn listening(&mut self, forward: Uuid) -> String {
        let info = self
            .expect_tunnel(forward, |s| matches!(s, TunnelState::Listening { .. }))
            .await;
        let TunnelState::Listening { at } = info.state else {
            unreachable!()
        };
        at
    }
}

/// The port in `127.0.0.1:12345` or `localhost:12345 on the host`.
fn port_of(at: &str) -> u16 {
    let address = at.trim_end_matches(" on the host");
    address.rsplit(':').next().unwrap().parse().unwrap()
}

async fn ping(port: u16, text: &str) -> String {
    let mut socket = timeout(WAIT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .unwrap()
        .unwrap();
    socket.write_all(text.as_bytes()).await.unwrap();
    let mut back = vec![0u8; text.len()];
    timeout(WAIT, socket.read_exact(&mut back)).await.unwrap().unwrap();
    String::from_utf8(back).unwrap()
}

/// A SOCKS 5 client that asks for `host:port` by name, then sends `text` and reads it back.
async fn socks_ping(proxy: u16, host: &str, port: u16, text: &str) -> String {
    let mut socket = timeout(WAIT, TcpStream::connect(("127.0.0.1", proxy)))
        .await
        .unwrap()
        .unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut chosen = [0u8; 2];
    socket.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 0], "no login");
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(WAIT, socket.read_exact(&mut reply)).await.unwrap().unwrap();
    assert_eq!(reply[1], 0, "the proxy reached {host}");
    socket.write_all(text.as_bytes()).await.unwrap();
    let mut back = vec![0u8; text.len()];
    timeout(WAIT, socket.read_exact(&mut back)).await.unwrap().unwrap();
    String::from_utf8(back).unwrap()
}

fn confirmed() -> ApprovalAnswers {
    ApprovalAnswers {
        confirmed: true,
        ..ApprovalAnswers::default()
    }
}

#[tokio::test]
async fn local_and_socks_forwards_carry_bytes_and_are_audited_when_they_open_and_close() {
    let core = core().await;
    let echo = echo_service().await;
    let (server, session) = host(&core, echo, Environment::Lab).await;
    let saved = core
        .forwards
        .save(
            &core.ctx,
            session,
            &[
                forward(ForwardKind::Local, "echo.test", 7, false),
                forward(ForwardKind::Dynamic, "", 0, false),
            ],
        )
        .await
        .unwrap();
    let (local, socks) = (saved[0].id, saved[1].id);
    let changed = audit(&core).await;
    let changed = changed.iter().find(|e| e.event == "session_changed").unwrap();
    assert_eq!(changed.action, "Changed the port forwards of 'app01'");
    assert!(changed
        .detail
        .as_deref()
        .unwrap()
        .contains("added local 127.0.0.1 (any free port) -> echo.test:7 (started by hand)"));

    let mut pane = Pane::open(&core, session).await;
    pane.connected().await;
    // Started by hand: nothing opened with the terminal.
    let listed = core.terminals.tunnels(&core.ctx, pane.id).await.unwrap();
    assert!(listed.iter().all(|t| t.state == TunnelState::Stopped), "{listed:?}");

    // A tunnel only this PC can use, to a Lab host: Low, so it opens at once.
    let started = core.terminals.start_tunnel(&core.ctx, pane.id, local).await.unwrap();
    let TunnelStart::Opening { job_id } = started else {
        panic!("{started:?}")
    };
    let at = pane.listening(local).await;
    assert!(at.starts_with("127.0.0.1:"), "{at}");
    assert_eq!(
        ping(port_of(&at), "hello through the tunnel").await,
        "hello through the tunnel"
    );
    assert!(server.log().contains(&"direct-tcpip echo.test:7".to_owned()));
    let info = core.terminals.tunnels(&core.ctx, pane.id).await.unwrap();
    assert_eq!(info[0].connections, 1);

    // SOCKS: the client names where it goes, and the host reaches it.
    core.terminals.start_tunnel(&core.ctx, pane.id, socks).await.unwrap();
    let proxy = port_of(&pane.listening(socks).await);
    assert_eq!(socks_ping(proxy, "echo.test", 9, "via socks").await, "via socks");
    assert!(server.log().contains(&"direct-tcpip echo.test:9".to_owned()));

    // Stopping closes the listener and is audited with how much it carried, never what.
    core.terminals.stop_tunnel(&core.ctx, pane.id, local).await.unwrap();
    pane.expect_tunnel(local, |s| *s == TunnelState::Stopped).await;
    assert!(
        TcpStream::connect(("127.0.0.1", port_of(&at))).await.is_err(),
        "the listener closed"
    );
    let entries = audit(&core).await;
    let opened = entries
        .iter()
        .find(|e| e.event == "tunnel_opened" && e.action.contains("local"))
        .unwrap();
    assert_eq!(
        opened.action,
        "Opened a tunnel on 'app01': local 127.0.0.1 (any free port) -> echo.test:7"
    );
    assert_eq!(opened.tier.as_deref(), Some("low"));
    assert_eq!(opened.job_id.as_deref(), Some(job_id.to_string().as_str()));
    assert_eq!(opened.detail.as_deref(), Some(format!("listening on {at}").as_str()));
    assert!(opened.targets_json.contains(&session.to_string()));
    let closed = entries.iter().find(|e| e.event == "tunnel_closed").unwrap();
    assert!(
        closed
            .detail
            .as_deref()
            .unwrap()
            .starts_with(&format!("stopped by the user; listened on {at} for ")),
        "{closed:?}"
    );
    assert!(closed.detail.as_deref().unwrap().ends_with(", 1 connection"));
    let job = entries
        .iter()
        .find(|e| e.event == "job_finished" && e.job_id.as_deref() == Some(job_id.to_string().as_str()))
        .unwrap();
    assert!(
        job.detail.as_deref().unwrap().contains(&format!("listening on {at}")),
        "{job:?}"
    );
    for entry in &entries {
        assert!(!format!("{entry:?}").contains("hello through"), "never traffic");
    }

    // Closing the terminal closes the rest, audited.
    core.terminals.close(pane.id).await;
    pane.expect_event(|e| {
        matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Closed).then_some(())
    })
    .await;
    let closed: Vec<AuditEntry> = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "tunnel_closed" && e.action.contains("SOCKS"))
        .collect();
    assert_eq!(closed.len(), 1);
    assert!(closed[0].detail.as_deref().unwrap().starts_with("the terminal closed"));
    assert!(TcpStream::connect(("127.0.0.1", proxy)).await.is_err());
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn a_remote_forward_asks_first_and_brings_the_hosts_connections_back_here() {
    let core = core().await;
    let echo = echo_service().await;
    let (server, session) = host(&core, echo, Environment::Lab).await;
    let saved = core
        .forwards
        .save(
            &core.ctx,
            session,
            &[forward(ForwardKind::Remote, "127.0.0.1", echo, false)],
        )
        .await
        .unwrap();
    let id = saved[0].id;
    let mut pane = Pane::open(&core, session).await;
    pane.connected().await;
    // The host listens and its connections reach into this PC's network: Medium, one confirm.
    let started = core.terminals.start_tunnel(&core.ctx, pane.id, id).await.unwrap();
    let TunnelStart::NeedsApproval { request } = started else {
        panic!("{started:?}")
    };
    assert_eq!(request.action, ActionKind::TunnelRemote);
    assert_eq!(request.tier, Tier::Medium);
    let details = request.tunnel.as_ref().unwrap();
    assert!(
        details.exposes.contains("Programs on the host can reach 127.0.0.1"),
        "{details:?}"
    );
    pane.expect_tunnel(id, |s| *s == TunnelState::Asking).await;
    assert_eq!(core.terminals.tunnel_request(pane.id, id).unwrap().id, request.id);
    assert!(server.forwarded_ports().is_empty(), "nothing before the approval");

    core.terminals
        .approve_tunnel(&core.ctx, pane.id, id, confirmed())
        .await
        .unwrap();
    let at = pane.listening(id).await;
    assert!(at.starts_with("localhost:") && at.ends_with(" on the host"), "{at}");
    let port = port_of(&at);
    assert_eq!(server.forwarded_ports(), [u32::from(port)]);
    // A program on the host connects to its port; this PC carries it on to the echo service.
    assert_eq!(ping(port, "from the host side").await, "from the host side");

    core.terminals.stop_tunnel(&core.ctx, pane.id, id).await.unwrap();
    timeout(WAIT, async {
        while !server.forwarded_ports().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(server.log().contains(&format!("cancel-tcpip-forward localhost:{port}")));
    let entries = audit(&core).await;
    let opened = entries.iter().find(|e| e.event == "tunnel_opened").unwrap();
    assert_eq!(opened.tier.as_deref(), Some("medium"));
    assert!(entries.iter().any(|e| e.event == "approval_granted"));
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn prod_and_shared_tunnels_ask_first_and_a_declined_one_stays_closed() {
    let core = core().await;
    let echo = echo_service().await;
    let (_server, prod) = host(&core, echo, Environment::Prod).await;
    let mut shared = forward(ForwardKind::Dynamic, "", 0, false);
    shared.bind_address = "0.0.0.0".into();
    let saved = core
        .forwards
        .save(
            &core.ctx,
            prod,
            &[
                forward(ForwardKind::Local, "echo.test", 7, false),
                forward(ForwardKind::Remote, "127.0.0.1", echo, false),
                shared,
            ],
        )
        .await
        .unwrap();
    let mut pane = Pane::open(&core, prod).await;
    pane.connected().await;
    let ask = |n: usize| {
        let id = saved[n].id;
        let core = &core;
        let pane_id = pane.id;
        async move {
            match core.terminals.start_tunnel(&core.ctx, pane_id, id).await.unwrap() {
                TunnelStart::NeedsApproval { request } => request,
                other => panic!("{other:?}"),
            }
        }
    };
    // PRD tier table: a tunnel to a Prod host is Medium.
    let local = ask(0).await;
    assert_eq!((local.action, local.tier), (ActionKind::TunnelLocal, Tier::Medium));
    assert!(
        local.reasons.iter().any(|r| r.contains("labelled Prod: low -> medium")),
        "{:?}",
        local.reasons
    );
    // A remote one on Prod: Medium, raised to High.
    let remote = ask(1).await;
    assert_eq!((remote.action, remote.tier), (ActionKind::TunnelRemote, Tier::High));
    // Other computers could use this one: it says so, and Prod raises it too.
    let socks = ask(2).await;
    assert_eq!((socks.action, socks.tier), (ActionKind::TunnelShared, Tier::High));
    assert!(
        socks
            .reasons
            .iter()
            .any(|r| r.contains("which other computers can reach")),
        "{:?}",
        socks.reasons
    );
    assert!(socks
        .tunnel
        .as_ref()
        .unwrap()
        .exposes
        .contains("other computers that can reach this PC"));

    // Declining leaves each closed: nothing listens, nothing is audited as opened.
    for forward in &saved {
        core.terminals
            .decline_tunnel(&core.ctx, pane.id, forward.id)
            .await
            .unwrap();
    }
    let listed = core.terminals.tunnels(&core.ctx, pane.id).await.unwrap();
    assert!(listed.iter().all(|t| t.state == TunnelState::Stopped), "{listed:?}");
    let entries = audit(&core).await;
    assert_eq!(entries.iter().filter(|e| e.event == "approval_cancelled").count(), 3);
    assert!(!entries.iter().any(|e| e.event == "tunnel_opened"));
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn forwards_start_with_the_terminal_and_open_again_after_a_reconnect() {
    let core = core().await;
    let echo = echo_service().await;
    let (lab_server, lab) = host(&core, echo, Environment::Lab).await;
    let saved = core
        .forwards
        .save(&core.ctx, lab, &[forward(ForwardKind::Local, "echo.test", 7, true)])
        .await
        .unwrap();
    let id = saved[0].id;
    let mut pane = Pane::open(&core, lab).await;
    pane.connected().await;
    // It starts with the terminal (through the bus: Low on a Lab host, so no question).
    let first = pane.listening(id).await;
    assert_eq!(ping(port_of(&first), "one").await, "one");

    // The connection drops: the tunnel closes and opens again on the next one, without asking.
    lab_server.drop_connections();
    let waiting = pane
        .expect_tunnel(id, |s| matches!(s, TunnelState::Waiting { .. }))
        .await;
    let TunnelState::Waiting { reason } = waiting.state else {
        unreachable!()
    };
    assert!(reason.contains("connection"), "why it waits: {reason}");
    let again = pane.listening(id).await;
    assert_eq!(ping(port_of(&again), "two").await, "two");
    let entries = audit(&core).await;
    let opened: Vec<&AuditEntry> = entries.iter().filter(|e| e.event == "tunnel_opened").collect();
    assert_eq!(opened.len(), 2, "{opened:?}");
    assert!(opened.iter().any(|e| e
        .detail
        .as_deref()
        .unwrap()
        .ends_with("again after the terminal reconnected")));
    let closed = entries.iter().find(|e| e.event == "tunnel_closed").unwrap();
    assert!(closed
        .detail
        .as_deref()
        .unwrap()
        .contains("it opens again when the terminal reconnects"));
    assert_eq!(
        entries.iter().filter(|e| e.event == "job_started").count(),
        1,
        "one approval (a job) for the terminal's life"
    );
    core.terminals.close(pane.id).await;

    // On a Prod host the one that starts with the terminal asks first.
    let (_prod_server, prod) = host(&core, echo, Environment::Prod).await;
    let saved = core
        .forwards
        .save(&core.ctx, prod, &[forward(ForwardKind::Local, "echo.test", 7, true)])
        .await
        .unwrap();
    let id = saved[0].id;
    let mut pane = Pane::open(&core, prod).await;
    pane.connected().await;
    pane.expect_tunnel(id, |s| *s == TunnelState::Asking).await;
    let request = core.terminals.tunnel_request(pane.id, id).unwrap();
    assert_eq!(request.tier, Tier::Medium);
    let wrong = core
        .terminals
        .approve_tunnel(&core.ctx, pane.id, id, ApprovalAnswers::default())
        .await;
    assert!(wrong.is_err(), "not confirmed");
    assert!(core.terminals.tunnel_request(pane.id, id).is_some(), "still asking");
    core.terminals
        .approve_tunnel(&core.ctx, pane.id, id, confirmed())
        .await
        .unwrap();
    let at = pane.listening(id).await;
    assert_eq!(ping(port_of(&at), "prod").await, "prod");
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn tunnels_need_a_connected_terminal_and_refuse_a_taken_port() {
    let core = core().await;
    let echo = echo_service().await;
    let (_server, session) = host(&core, echo, Environment::Lab).await;
    // A port on this PC that is taken already.
    let taken = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut clash = forward(ForwardKind::Local, "echo.test", 7, false);
    clash.bind_port = taken.local_addr().unwrap().port();
    let saved = core.forwards.save(&core.ctx, session, &[clash]).await.unwrap();
    let id = saved[0].id;
    let mut pane = Pane::open(&core, session).await;
    pane.connected().await;
    core.terminals.start_tunnel(&core.ctx, pane.id, id).await.unwrap();
    let failed = pane
        .expect_tunnel(id, |s| matches!(s, TunnelState::Failed { .. }))
        .await;
    let TunnelState::Failed { message } = failed.state else {
        unreachable!()
    };
    assert!(message.contains("is in use by another program on this PC"), "{message}");
    // Started twice while asking or open is refused; a failed one can be started again.
    assert!(core.terminals.start_tunnel(&core.ctx, pane.id, id).await.is_ok());
    pane.expect_tunnel(id, |s| matches!(s, TunnelState::Failed { .. }))
        .await;
    drop(taken);
    core.terminals.close(pane.id).await;
}
