//! SS-12 consoles, end to end: RDP and VNC windows through the fake launcher (nothing is started), Telnet panes
//! against the Telnet server on 127.0.0.1, serial panes on in-memory COM ports, and an RDP session behind a jump host
//! through a tunnel tab on a toy SSH server. No real host, program or COM port is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, vault_password_given, Setup, VAULT_PASSWORD};
use remotely_core::adapters::launcher::Launch;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::bulk::TargetPicks;
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeLauncher, FakeSerialPorts, FakeVmware, TelnetTestServer};
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::kinds::{
    FlowControl, LineEnding, RdpOptions, RdpScreen, SerialOptions, TelnetOptions, VncOptions,
};
use remotely_core::sessions::{FolderDefaults, SessionAuth, SessionInput, SessionKind};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::{PaneKind, TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning, WindowState};
use remotely_core::toolbox::ProbeTarget;
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::{Core, CoreError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

/// A core with the app's vault, the real SSH adapter, and the fakes for windows and COM ports.
async fn core() -> (Core, FakeLauncher, FakeSerialPorts) {
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
    let launcher = FakeLauncher::default();
    let ports = FakeSerialPorts::default();
    core.terminals.set_launcher(Arc::new(launcher.clone()));
    core.terminals.set_serial_ports(Arc::new(ports.clone()));
    (core, launcher, ports)
}

fn input(name: &str, host: &str, port: u16, kind: SessionKind) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id: None },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind,
    }
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
    unread: Vec<u8>,
}

impl Pane {
    fn new(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            unread: Vec::new(),
        }
    }

    async fn open(core: &Core, session: Uuid) -> Self {
        Self::new(core.terminals.open(&core.ctx(), session, SIZE).await.unwrap())
    }

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
}

// ---- RDP and VNC ----------------------------------------------------------------------------------------

#[tokio::test]
async fn rdp_opens_mstsc_on_a_file_without_a_password_and_is_audited() {
    let (core, launcher, _) = core().await;
    let kind = SessionKind::Rdp(RdpOptions {
        screen: RdpScreen::Window {
            width: 1600,
            height: 900,
        },
        drives: true,
        ..RdpOptions::default()
    });
    let id = create(&core, input("win01", "win01.example.com", 3389, kind)).await;
    let opened = core.terminals.open_window(&core.ctx(), id).await.unwrap();
    assert_eq!(
        (opened.protocol.as_str(), opened.address.as_str()),
        ("rdp", "win01.example.com:3389")
    );

    let launched = launcher.launched();
    assert_eq!(launched.len(), 1);
    let Launch::Rdp { name, file } = &launched[0] else {
        panic!("not an RDP launch: {launched:?}")
    };
    assert_eq!(name, "win01");
    assert!(file.contains("full address:s:win01.example.com:3389\n"), "{file}");
    assert!(file.contains("username:s:alice\n") && file.contains("prompt for credentials:i:1\n"));
    assert!(file.contains("desktopwidth:i:1600\n") && file.contains("redirectdrives:i:1\n"));
    assert!(!file.to_lowercase().contains("password"), "mstsc asks for it: {file}");

    let entries = audit(&core).await;
    let entry = entries.iter().find(|e| e.event == "rdp_opened").expect("audited");
    assert_eq!(entry.action, "Opened the remote desktop of 'win01'");
    assert!(entry.detail.as_deref().unwrap().contains("mstsc asks for the password"));
    assert!(entry.targets_json.contains(&id.to_string()), "{}", entry.targets_json);
    // QL-02: it counts as opened.
    let recent = core.sessions.recent(&core.ctx(), 5).await.unwrap();
    assert_eq!(recent.first().map(|s| s.id), Some(id));
}

#[tokio::test]
async fn vnc_starts_the_chosen_viewer_with_host_and_port() {
    let (core, launcher, _) = core().await;
    let kind = SessionKind::Vnc(VncOptions { view_only: true });
    let id = create(&core, input("vnc01", "vnc01.example.com", 5901, kind)).await;
    if core.vnc_viewer_path().await.unwrap().is_none() {
        let err = core.terminals.open_window(&core.ctx(), id).await.unwrap_err();
        assert!(matches!(err, CoreError::VncViewerNotFound), "{err}");
    }
    let dir = temp_folder("vnc-viewer");
    let exe = dir.join("TigerVNC").join("vncviewer.exe");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"").unwrap();
    assert!(core.set_vnc_viewer_path(Some(dir.join("notepad.exe"))).await.is_err());
    assert_eq!(
        core.set_vnc_viewer_path(Some(exe.clone())).await.unwrap(),
        Some(exe.clone())
    );

    core.terminals.open_window(&core.ctx(), id).await.unwrap();
    assert_eq!(
        launcher.launched(),
        [Launch::Viewer {
            exe: exe.clone(),
            args: vec!["-ViewOnly".into(), "vnc01.example.com::5901".into()],
        }]
    );
    let entries = audit(&core).await;
    let entry = entries.iter().find(|e| e.event == "vnc_opened").expect("audited");
    assert!(entry
        .detail
        .as_deref()
        .unwrap()
        .contains("many VNC servers don't encrypt"));
    // A window session is not a terminal, and an SSH one is not a window.
    let ssh = create(&core, input("web01", "web01.example.com", 22, SessionKind::Ssh)).await;
    assert!(matches!(
        core.terminals.open_window(&core.ctx(), ssh).await.unwrap_err(),
        CoreError::WrongSessionKind { .. }
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An echo service on 127.0.0.1, standing in for a remote desktop's port.
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

#[tokio::test]
async fn behind_a_jump_host_a_tunnel_tab_opens_the_window_and_closes_with_it() {
    let (core, launcher, _) = core().await;
    let echo = echo_service().await;
    let password = new_password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_route("win01.test", echo);
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "alice on bastion",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let mut bastion = input("bastion", "127.0.0.1", server.port(), SessionKind::Ssh);
    bastion.auth = SessionAuth::Password {
        password_id: Some(secret),
    };
    let bastion = create(&core, bastion).await;
    let mut rdp = input("win01", "win01.test", echo, SessionKind::Rdp(RdpOptions::default()));
    rdp.jump_session_id = Some(bastion);
    let rdp = create(&core, rdp).await;
    // Behind a jump host there is no window of its own yet: a tunnel tab opens it.
    assert!(core.terminals.open_window(&core.ctx(), rdp).await.is_err());

    let mut pane = Pane::open(&core, rdp).await;
    assert_eq!(core.terminals.pane_info(pane.id).unwrap().kind, PaneKind::Tunnel);
    pane.connected().await;
    let at = pane
        .expect_event(|e| match e {
            TerminalEvent::Window {
                window: WindowState::Open { at },
            } => Some(at.clone()),
            _ => None,
        })
        .await;
    let port: u16 = at.rsplit_once(':').unwrap().1.parse().unwrap();
    let launched = launcher.wait_for(1, WAIT).await;
    let Launch::Rdp { file, .. } = &launched[0] else {
        panic!("not an RDP launch")
    };
    assert!(file.contains(&format!("full address:s:127.0.0.1:{port}\n")), "{file}");
    // The tunnel carries the window's bytes to the session's host, through the jump host.
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(b"rdp-hello").await.unwrap();
    let mut back = [0u8; 9];
    timeout(WAIT, socket.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"rdp-hello");
    // It doesn't join Type in all tabs, nor Compare hosts (its connection is the jump host's, not a host to run on).
    assert!(core.multiexec.set_targets(vec![pane.id]).await.is_err());
    let resolved = core
        .bulk
        .resolve(
            &core.ctx(),
            &TargetPicks {
                terminal_ids: vec![pane.id],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(resolved.hosts.is_empty(), "{:?}", resolved.hosts);
    assert!(
        resolved.notes.iter().any(|n| n.contains("tunnel tab")),
        "{:?}",
        resolved.notes
    );

    // The window closes: so does the tab, and the tunnel with it.
    launcher.close(0);
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
    let events: Vec<String> = audit(&core).await.into_iter().map(|e| e.event).collect();
    for event in [
        "terminal_opened",
        "tunnel_opened",
        "rdp_opened",
        "tunnel_closed",
        "terminal_closed",
    ] {
        assert!(events.iter().any(|e| e == event), "{event} in {events:?}");
    }
    let rdp_entry = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "rdp_opened")
        .unwrap();
    assert!(rdp_entry.detail.unwrap().contains("through a tunnel to 'bastion'"));
}

// ---- Telnet -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_telnet_pane_negotiates_logs_in_and_reconnects() {
    let (core, _, _) = core().await;
    let password = new_password();
    let server = TelnetTestServer::start("alice", &password).await.unwrap();
    let kind = SessionKind::Telnet(TelnetOptions {
        line_ending: LineEnding::CrLf,
    });
    let id = create(&core, input("sw01", "127.0.0.1", server.port(), kind)).await;
    let mut pane = Pane::open(&core, id).await;
    assert_eq!(core.terminals.pane_info(pane.id).unwrap().kind, PaneKind::Telnet);
    pane.connected().await;
    pane.expect_output("login: ").await;
    pane.type_text(&core, "alice\r").await;
    pane.expect_output("Password: ").await;
    pane.type_text(&core, &format!("{password}\r")).await;
    pane.expect_output("router> ").await;
    pane.type_text(&core, "show version\r").await;
    pane.expect_output("Remotely test router, version 1.0").await;
    core.terminals.resize(pane.id, 132, 50).await;
    pane.type_text(&core, "show clock\r").await;
    pane.expect_output("12:00:00 UTC").await;

    let first = &server.connections()[0];
    assert_eq!(first.login, Some(("alice".to_owned(), password.clone())));
    assert_eq!(first.terminal_type.as_deref(), Some("XTERM-256COLOR"));
    assert_eq!(first.sizes.first(), Some(&(80, 24)));
    assert_eq!(first.sizes.last(), Some(&(132, 50)));
    assert!(
        first.raw.windows(b"alice\r\n".len()).any(|w| w == b"alice\r\n"),
        "Enter went as CR LF"
    );

    // A dropped connection comes back by itself, to a new login.
    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    pane.connected().await;
    pane.expect_output("login: ").await;
    assert!(server.wait_for_connections(2, WAIT).await);
    let opened = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "terminal_opened")
        .unwrap();
    assert_eq!(opened.action, "Opened a Telnet terminal to 'sw01'");
    assert!(opened.detail.unwrap().contains("clear text"));
}

#[tokio::test]
async fn a_server_that_wont_echo_gets_local_echo() {
    let (core, _, _) = core().await;
    let server = TelnetTestServer::without_echo("alice", "unused").await.unwrap();
    let id = create(
        &core,
        input(
            "old01",
            "127.0.0.1",
            server.port(),
            SessionKind::Telnet(TelnetOptions::default()),
        ),
    )
    .await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    pane.expect_output("login: ").await;
    pane.type_text(&core, "bob").await;
    pane.expect_output("bob").await;
}

#[tokio::test]
async fn a_vault_password_typed_into_telnet_asks_for_the_vault_password_on_each_connection() {
    let (core, _, _) = core().await;
    let password = new_password();
    let server = TelnetTestServer::start("alice", &password).await.unwrap();
    let id = create(
        &core,
        input(
            "sw02",
            "127.0.0.1",
            server.port(),
            SessionKind::Telnet(TelnetOptions::default()),
        ),
    )
    .await;
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "sw02 login",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    pane.expect_output("login: ").await;
    pane.type_text(&core, "alice\r").await;
    pane.expect_output("Password: ").await;
    // Given a moment ago does not count: Telnet asks on each connection.
    vault_password_given(&core).await;
    let err = core
        .terminals
        .type_secret(&core.ctx(), pane.id, secret, false, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::ReauthRequired { ref reason } if reason.contains("clear text")),
        "{err}"
    );
    let vault = SecretString::new(VAULT_PASSWORD);
    core.terminals
        .type_secret(&core.ctx(), pane.id, secret, false, Some(&vault))
        .await
        .unwrap();
    pane.expect_output("router> ").await;
    let typed = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "vault_secret_typed")
        .unwrap();
    assert!(typed.detail.unwrap().contains("over Telnet, in clear text"));

    // A new connection asks again.
    server.drop_connections();
    pane.expect_status(|s| matches!(s, TerminalStatus::Reconnecting { .. }))
        .await;
    pane.connected().await;
    pane.expect_output("login: ").await;
    pane.type_text(&core, "alice\r").await;
    pane.expect_output("Password: ").await;
    let again = core
        .terminals
        .type_secret(&core.ctx(), pane.id, secret, false, None)
        .await
        .unwrap_err();
    assert!(matches!(again, CoreError::ReauthRequired { .. }), "{again}");
}

// ---- Serial ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_serial_pane_sends_its_line_ending_and_breaks_and_holds_its_port() {
    let (core, _, ports) = core().await;
    let device = ports.with_port("COM7");
    let options = SerialOptions {
        speed: 115_200,
        flow_control: FlowControl::RtsCts,
        line_ending: LineEnding::CrLf,
        ..SerialOptions::default()
    };
    let id = create(&core, input("console", "com7", 1, SessionKind::Serial(options))).await;
    let saved = core.sessions.get(&core.ctx(), id).await.unwrap();
    assert_eq!((saved.host.as_str(), saved.protocol.as_str()), ("COM7", "serial"));
    assert_eq!(saved.username, Some("alice".into()));
    assert_eq!(
        core.terminals
            .serial_ports()
            .await
            .unwrap()
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["COM7"]
    );

    let mut pane = Pane::open(&core, id).await;
    assert_eq!(core.terminals.pane_info(pane.id).unwrap().kind, PaneKind::Serial);
    pane.connected().await;
    assert_eq!(device.opened_with(), Some(options));
    pane.type_text(&core, "show run\r").await;
    assert!(device.wait_for(b"show run\r\n", WAIT).await, "{:?}", device.received());
    assert!(device.send(b"Router#"));
    pane.expect_output("Router#").await;
    core.terminals.send_break(&core.ctx(), pane.id, false).await.unwrap();
    timeout(WAIT, async {
        while device.breaks() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    // One pane per COM port: no second one, no split.
    let second = core.terminals.open(&core.ctx(), id, SIZE).await.err().unwrap();
    assert!(matches!(second, CoreError::SerialPort(_)), "{second}");
    assert!(core.terminals.open_like(&core.ctx(), pane.id, SIZE).await.is_err());

    // Unplugged: the pane says so and waits; plugged back in, it opens again.
    device.unplug(true);
    pane.expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    device.unplug(false);
    core.terminals.reconnect(pane.id).await;
    pane.connected().await;
    let opened = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "terminal_opened")
        .unwrap();
    assert_eq!(opened.action, "Opened a serial terminal to 'console'");
    assert!(opened.detail.unwrap().contains("115200 8N1"));
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn telnet_and_serial_tabs_never_join_type_in_all_tabs_or_compare_hosts() {
    let (core, _, ports) = core().await;
    let _device = ports.with_port("COM9");
    let id = create(
        &core,
        input("console", "COM9", 1, SessionKind::Serial(SerialOptions::default())),
    )
    .await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    let err = core.multiexec.set_targets(vec![pane.id]).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("typing in all tabs is for SSH and PowerShell tabs only"),
        "{err}"
    );
    let resolved = core
        .bulk
        .resolve(
            &core.ctx(),
            &TargetPicks {
                terminal_ids: vec![pane.id],
                session_ids: vec![id],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(resolved.hosts.is_empty());
    assert!(
        resolved
            .notes
            .iter()
            .any(|n| n.contains("serial tab, so it was left out: this works over SSH only")),
        "{:?}",
        resolved.notes
    );
    core.terminals.close(pane.id).await;
}

// ---- What kinds may do ------------------------------------------------------------------------------------

#[tokio::test]
async fn only_ssh_sessions_log_in_with_the_vault_jump_or_reach_ssh_features() {
    let (core, _, _) = core().await;
    let ctx = core.ctx();
    let secret = core
        .vault
        .add(
            &ctx,
            SecretKind::Password,
            "lab login",
            SecretString::new(new_password()),
        )
        .await
        .unwrap()
        .id;
    let bastion = create(&core, input("bastion", "bastion.example.org", 22, SessionKind::Ssh)).await;
    // A folder that logs in with a vault password and goes through a jump host.
    let folder = core.sessions.create_folder(&ctx, "Lab", None).await.unwrap();
    vault_password_given(&core).await;
    core.sessions
        .set_folder_defaults(
            &ctx,
            folder.id,
            FolderDefaults {
                auth: Some(SessionAuth::Password {
                    password_id: Some(secret),
                }),
                jump_session_id: Some(bastion),
                ..FolderDefaults::default()
            },
        )
        .await
        .unwrap();
    let mut telnet = input(
        "sw01",
        "sw01.example.com",
        23,
        SessionKind::Telnet(TelnetOptions::default()),
    );
    telnet.folder_id = Some(folder.id);
    telnet.auth = SessionAuth::Folder;
    let telnet = core.sessions.create(&ctx, telnet).await.unwrap();
    // Neither the folder's vault password nor its jump host applies to a Telnet session.
    assert_eq!(telnet.auth, SessionAuth::Password { password_id: None });
    assert_eq!(telnet.jump_session_id, None);
    let mut rdp = input(
        "win01",
        "win01.example.com",
        3389,
        SessionKind::Rdp(RdpOptions::default()),
    );
    rdp.folder_id = Some(folder.id);
    let rdp = core.sessions.create(&ctx, rdp).await.unwrap();
    // An RDP session takes the folder's jump host (its tunnel), never its login.
    assert_eq!(rdp.jump_session_id, Some(bastion));
    assert_eq!(rdp.auth, SessionAuth::Password { password_id: None });

    // A jump host is an SSH session, so a Telnet one can't be one, and the bastion can't stop being SSH.
    let mut behind = input("db01", "db01.example.com", 22, SessionKind::Ssh);
    behind.jump_session_id = Some(telnet.id);
    assert!(core.sessions.create(&ctx, behind).await.is_err());
    let mut bastion_input = core.sessions.get(&ctx, bastion).await.unwrap().input();
    bastion_input.kind = SessionKind::Telnet(TelnetOptions::default());
    assert!(core.sessions.update(&ctx, bastion, bastion_input).await.is_err());

    // SSH-only features say so.
    assert!(matches!(
        core.store.session_spec(&ctx, telnet.id).await.unwrap_err(),
        CoreError::WrongSessionKind { .. }
    ));
    assert!(matches!(
        core.metrics.set_watched(&ctx, telnet.id, true).await.unwrap_err(),
        CoreError::WrongSessionKind { .. }
    ));
    // The toolbox probes every kind's own host and port, but a serial session's host is a COM port.
    let route = core
        .toolbox
        .route(&ctx, &ProbeTarget::Session { session_id: telnet.id })
        .await
        .unwrap();
    assert_eq!((route.host.as_str(), route.port), ("sw01.example.com", Some(23)));
    let serial = create(
        &core,
        input("console", "COM2", 1, SessionKind::Serial(SerialOptions::default())),
    )
    .await;
    assert!(matches!(
        core.toolbox
            .route(&ctx, &ProbeTarget::Session { session_id: serial })
            .await
            .unwrap_err(),
        CoreError::WrongSessionKind { .. }
    ));

    // The kind and its fields are kept, and the audit names them.
    let changed = core.sessions.get(&ctx, telnet.id).await.unwrap();
    assert_eq!(changed.kind, SessionKind::Telnet(TelnetOptions::default()));
    let created = audit(&core)
        .await
        .into_iter()
        .find(|e| e.action == "Created session 'sw01'")
        .unwrap();
    assert!(created.detail.unwrap().contains("Telnet, Enter sends CR LF"));
}

// ---- Review fixes ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_serial_reconnect_or_reopen_waits_for_the_old_connection_to_let_go_of_the_port() {
    let (core, _, ports) = core().await;
    let device = ports.with_port("COM5");
    // Closing the port takes a while (a write held up by flow control): the port stays taken meanwhile.
    device.set_release_delay(Duration::from_millis(400));
    let id = create(
        &core,
        input("console", "COM5", 1, SessionKind::Serial(SerialOptions::default())),
    )
    .await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    core.terminals.reconnect(pane.id).await;
    pane.connected().await;
    assert!(device.is_open());
    pane.type_text(&core, "again\r").await;
    assert!(device.wait_for(b"again\r", WAIT).await);

    // Closing the tab and opening it again at once waits too.
    core.terminals.close(pane.id).await;
    pane.expect_status(|s| *s == TerminalStatus::Closed).await;
    let mut again = Pane::open(&core, id).await;
    again.connected().await;
    core.terminals.close(again.id).await;
}

#[tokio::test]
async fn local_echo_shows_nothing_typed_at_a_password_prompt() {
    let (core, _, ports) = core().await;
    // Telnet: a server that won't echo, so what is typed is echoed here, but not the password.
    let server = TelnetTestServer::without_echo("alice", "unused").await.unwrap();
    let id = create(
        &core,
        input(
            "old02",
            "127.0.0.1",
            server.port(),
            SessionKind::Telnet(TelnetOptions::default()),
        ),
    )
    .await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    pane.expect_output("login: ").await;
    pane.type_text(&core, "bob\r").await;
    pane.expect_output("bob").await;
    pane.expect_output("Password: ").await;
    pane.type_text(&core, "s3cret-typed\r").await;
    let shown = pane.expect_output("% Login invalid").await;
    assert!(!shown.contains("s3cret-typed"), "{shown:?}");

    // Serial with local echo on: the device asks, and the answer isn't shown.
    let device = ports.with_port("COM6");
    let options = SerialOptions {
        local_echo: true,
        ..SerialOptions::default()
    };
    let id = create(&core, input("console", "COM6", 1, SessionKind::Serial(options))).await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    pane.type_text(&core, "enable\r").await;
    pane.expect_output("enable").await;
    assert!(device.send(b"\r\nPassword: "));
    pane.expect_output("Password: ").await;
    pane.type_text(&core, "hunter2-typed\r").await;
    assert!(
        device.wait_for(b"hunter2-typed\r", WAIT).await,
        "it still reaches the device"
    );
    assert!(device.send(b"\r\nRouter#"));
    let shown = pane.expect_output("Router#").await;
    assert!(!shown.contains("hunter2-typed"), "{shown:?}");
    core.terminals.close(pane.id).await;
}

#[tokio::test]
async fn a_window_is_audited_before_it_starts_and_again_when_it_does_not() {
    let (core, launcher, _) = core().await;
    let id = create(
        &core,
        input(
            "win02",
            "win02.example.com",
            3389,
            SessionKind::Rdp(RdpOptions::default()),
        ),
    )
    .await;
    launcher.set_failing(Some("mstsc.exe could not be started: test"));
    let err = core.terminals.open_window(&core.ctx(), id).await.unwrap_err();
    assert!(matches!(err, CoreError::Console(_)), "{err}");
    let entries: Vec<AuditEntry> = audit(&core)
        .await
        .into_iter()
        .filter(|e| e.event == "rdp_opened")
        .collect();
    // Newest first: the failure, then the entry written before it started.
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0].result.as_deref(), Some("failed"));
    assert!(entries[0].action.contains("did not start"));
    assert_eq!(entries[1].result, None);
    assert_eq!(entries[1].action, "Opened the remote desktop of 'win02'");
}

#[tokio::test]
async fn send_break_is_audited_and_asks_first_on_prod() {
    let (core, _, ports) = core().await;
    let device = ports.with_port("COM8");
    let mut prod = input("core-switch", "COM8", 1, SessionKind::Serial(SerialOptions::default()));
    prod.environment = Environment::Prod;
    let id = create(&core, prod).await;
    let mut pane = Pane::open(&core, id).await;
    pane.connected().await;
    let err = core
        .terminals
        .send_break(&core.ctx(), pane.id, false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("confirm it first"), "{err}");
    assert_eq!(device.breaks(), 0);
    core.terminals.send_break(&core.ctx(), pane.id, true).await.unwrap();
    timeout(WAIT, async {
        while device.breaks() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let entry = audit(&core)
        .await
        .into_iter()
        .find(|e| e.event == "terminal_break_sent")
        .expect("audited");
    assert_eq!(entry.action, "Sent a break to 'core-switch'");
    assert!(entry.detail.unwrap().contains("confirmed first"));
    // Not connected: nothing is sent.
    device.unplug(true);
    pane.expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    assert!(core.terminals.send_break(&core.ctx(), pane.id, true).await.is_err());
    core.terminals.close(pane.id).await;
}
