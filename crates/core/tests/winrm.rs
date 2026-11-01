//! SS-12, MO-05, MO-13 over WinRM, end to end: Remotely's own client against the fake WinRM server on 127.0.0.1,
//! with Windows' own SSPI signing in with NTLM (and sealing every message over HTTP), and Basic over HTTPS with a
//! certificate made at run time. The PowerShell console pane, the dashboard's Windows guest metrics, a Windows host's
//! facts and service checks on Windows services. No packet leaves 127.0.0.1; no real Windows host is reached.
//! Kerberos ("my Windows sign-in") can only be tried by hand against a domain host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::Setup;
use remotely_core::adapters::net_tools::TrustVerdict;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::checks::{CheckInput, CheckSpec, CheckStatus, RunResult};
use remotely_core::domain::Environment;
use remotely_core::fakes::clock::{FakeClock, FakeZone};
use remotely_core::fakes::{FakeNetworkTools, FakeVmware, FakeWinrm, Tamper, WinrmTestServer};
use remotely_core::host_details::CollectedBy;
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::history::HistoryRange;
use remotely_core::metrics::{GuestState, MetricSource};
use remotely_core::sessions::kinds::{WinrmCertificate, WinrmOptions, WinrmSignIn, WinrmTransport};
use remotely_core::sessions::{SessionAuth, SessionInput, SessionKind};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::toolbox::ProbeTarget;
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::Core;
use time::OffsetDateTime;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(20);
const SIZE: PtySize = PtySize { cols: 100, rows: 30 };

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn trusted() -> TrustVerdict {
    TrustVerdict {
        trusted: true,
        problems: Vec::new(),
        built: Vec::new(),
    }
}

/// A core with the app's vault and the fake network tools (whose trust check says what the test sets).
async fn core(tools: Arc<FakeNetworkTools>) -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_network_tools(tools)
        .build()
        .await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 3,
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

fn options(transport: WinrmTransport, sign_in: WinrmSignIn, certificate: WinrmCertificate) -> WinrmOptions {
    WinrmOptions {
        transport,
        sign_in,
        certificate,
    }
}

fn input(name: &str, port: u16, password_id: Option<remotely_core::vault::SecretId>, o: WinrmOptions) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: SessionKind::Winrm(o),
    }
}

/// A WinRM session to `server` signing in as alice with `password` saved in the vault.
async fn session(core: &Core, server: &WinrmTestServer, password: &str, o: WinrmOptions) -> Uuid {
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "win login",
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    core.sessions
        .create(&core.ctx(), input("win01", server.port(), Some(secret), o))
        .await
        .unwrap()
        .id
}

/// A pane under test: everything it printed so far, and its events.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    unread: Vec<u8>,
    seen: String,
}

impl Pane {
    fn new(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            unread: Vec::new(),
            seen: String::new(),
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
                    self.seen.push_str(&text[..upto]);
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

    async fn type_text(&self, core: &Core, text: &str) {
        core.terminals.write(self.id, text.as_bytes().to_vec()).await;
    }
}

// ---- The PowerShell console ------------------------------------------------------------------------------

#[tokio::test]
async fn a_powershell_console_over_https_signs_in_with_basic_and_draws_its_prompt() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &password)
        .await
        .unwrap();
    let tools = Arc::new(FakeNetworkTools::new().with_verdict(trusted()));
    let core = core(tools).await;
    let o = options(WinrmTransport::Https, WinrmSignIn::Basic, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;

    let mut pane = Pane::open(&core, id).await;
    pane.expect_status(|s| *s == TerminalStatus::Connected).await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    pane.type_text(&core, "hostname\r").await;
    let shown = pane.expect_output("WIN01").await;
    assert!(
        shown.contains("hostname\r\n"),
        "what was typed is shown here: {shown:?}"
    );
    pane.expect_output("PS C:\\Users\\alice> ").await;
    // A statement that reads stdin gets the next line.
    pane.type_text(&core, "Read-Host 'Name'\r").await;
    pane.expect_output("Name: ").await;
    pane.type_text(&core, "bob\r").await;
    pane.expect_output("bob").await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    // The folder shows in the prompt.
    pane.type_text(&core, "Set-Location C:\\Temp\r").await;
    pane.expect_output("PS C:\\Temp> ").await;
    // An open statement is held until it closes, then sent whole.
    pane.type_text(&core, "if ($true) {\r").await;
    pane.expect_output(">> ").await;
    pane.type_text(&core, "'inside'\r}\r").await;
    pane.expect_output("PS C:\\Temp> ").await;
    assert!(!pane.seen.contains(&password), "the password never shows");

    pane.type_text(&core, "exit 3\r").await;
    let ended = pane.expect_status(|s| matches!(s, TerminalStatus::Ended { .. })).await;
    assert_eq!(ended, TerminalStatus::Ended { exit_status: Some(3) });

    let stats = server.stats();
    assert!(
        stats
            .commands
            .iter()
            .any(|c| c == "powershell.exe -NoLogo -NoProfile -Command - 2>&1"),
        "{:?}",
        stats.commands
    );
    // Each statement went as one line: its lines as typed, quoted, then the prompt marker.
    assert!(
        stats
            .stdin
            .iter()
            .any(|l| l
                .starts_with("try { . ([scriptblock]::Create('if ($true) {' + \"`n\" + '''inside''' + \"`n\" + '}'))")),
        "{:?}",
        stats.stdin
    );
    let audit = core.store.recent_audit(&core.ctx(), 50).await.unwrap();
    let opened = audit
        .iter()
        .find(|e| e.action == "Opened a PowerShell console to 'win01'")
        .expect("opening the console is audited");
    let detail = opened.detail.clone().unwrap_or_default();
    assert!(detail.contains("WinRM, HTTPS"), "{detail}");
    assert!(!detail.contains(&password));
}

#[tokio::test]
async fn ntlm_over_http_seals_every_message_with_windows_own_ntlm() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let o = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;

    let mut pane = Pane::open(&core, id).await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    pane.type_text(&core, "Get-Date\r").await;
    pane.expect_output("November 1, 2026").await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    let stats = server.stats();
    assert!(stats.sign_ins >= 1, "{stats:?}");
    assert_eq!(stats.plain_refused, 0, "nothing went in clear text");
    assert_eq!(stats.refused_sign_ins, 0);

    // A reconnect starts a new PowerShell and says so.
    core.terminals.reconnect(pane.id).await;
    pane.expect_output("A new PowerShell started").await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    core.terminals.close(pane.id).await;
    timeout(WAIT, async {
        while server.open_shells() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("closing the pane deletes its shells");

    // A wrong password is refused by the host's NTLM check.
    server.set_password("rotated-elsewhere");
    let mut refused = Pane::open(&core, id).await;
    let status = refused
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert_eq!(code, "auth_failed");
    assert_eq!(server.stats().refused_sign_ins, 1);
}

#[tokio::test]
async fn a_certificate_windows_doesnt_trust_is_refused_or_trusted_by_its_fingerprint() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &password)
        .await
        .unwrap();
    // The fake's trust check trusts nothing.
    let core = core(Arc::new(FakeNetworkTools::new())).await;

    // Windows' trust only: refused before anything is sent.
    let strict = session(
        &core,
        &server,
        &password,
        options(WinrmTransport::Https, WinrmSignIn::Basic, WinrmCertificate::Windows),
    )
    .await;
    let mut pane = Pane::open(&core, strict).await;
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, message } = status else {
        unreachable!()
    };
    assert_eq!(code, "certificate_not_trusted", "{message}");
    assert_eq!(server.stats().sign_ins, 0, "no password went to an untrusted host");
    core.terminals.close(pane.id).await;

    // By its fingerprint: asked like an SSH host key, then trusted for this host and port.
    let mut by_print = core.sessions.get(&core.ctx(), strict).await.unwrap().input();
    by_print.kind = SessionKind::Winrm(options(
        WinrmTransport::Https,
        WinrmSignIn::Basic,
        WinrmCertificate::Fingerprint,
    ));
    core.sessions.update(&core.ctx(), strict, by_print).await.unwrap();
    let mut pane = Pane::open(&core, strict).await;
    let key = pane
        .expect_event(|e| match e {
            TerminalEvent::HostKeyUnknown { key, .. } => Some(key.clone()),
            _ => None,
        })
        .await;
    assert_eq!(key.key_type, "tls-certificate");
    assert_eq!(Some(key.fingerprint.clone()), server.fingerprint());
    core.terminals.answer_host_key(pane.id, true).unwrap();
    pane.expect_output("PS C:\\Users\\alice> ").await;
    let known = core.known_hosts.list(&core.ctx()).await.unwrap();
    assert!(known
        .iter()
        .any(|k| k.key_type == "tls-certificate" && k.port == server.port()));
    core.terminals.close(pane.id).await;

    // Another certificate for the same host and port blocks, like a changed host key.
    for k in known {
        core.known_hosts.remove(&core.ctx(), k.id).await.unwrap();
    }
    let other = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "tls-certificate".into(),
        fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    core.known_hosts.trust(&core.ctx(), &other, None).await.unwrap();
    let mut pane = Pane::open(&core, strict).await;
    let status = pane
        .expect_status(|s| matches!(s, TerminalStatus::Disconnected { .. }))
        .await;
    let TerminalStatus::Disconnected { code, .. } = status else {
        unreachable!()
    };
    assert_eq!(code, "certificate_changed");
}

#[tokio::test]
async fn ntlm_over_https_binds_its_sign_in_to_the_tls_channel() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new().with_verdict(trusted()))).await;
    let o = options(WinrmTransport::Https, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    let mut pane = Pane::open(&core, id).await;
    pane.expect_output("PS C:\\Users\\alice> ").await;
    let stats = server.stats();
    // The fake checks the AUTHENTICATE message's channel binding against its own certificate (RFC 5929's
    // tls-server-end-point), as a host with Extended Protection does: Windows' NTLM got the same hash from Remotely.
    assert!(stats.sign_ins >= 1, "{stats:?}");
    assert_eq!(stats.bad_bindings, 0, "{stats:?}");
    assert_eq!(stats.refused_sign_ins, 0, "{stats:?}");
    core.terminals.close(pane.id).await;
}

/// The next status that says the pane lost (or never had) its connection: its reason.
async fn lost_reason(pane: &mut Pane) -> String {
    pane.expect_event(|e| match e {
        TerminalEvent::Status {
            status: TerminalStatus::Reconnecting { reason, .. },
        } => Some(reason.clone()),
        TerminalEvent::Status {
            status: TerminalStatus::Disconnected { message, .. },
        } => Some(message.clone()),
        _ => None,
    })
    .await
}

#[tokio::test]
async fn an_answer_in_clear_text_or_forged_over_http_is_refused() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let o = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    for (tamper, says) in [(Tamper::Plain, "clear text"), (Tamper::Forged, "")] {
        server.set_tamper(Tamper::None);
        let mut pane = Pane::open(&core, id).await;
        pane.expect_output("PS C:\\Users\\alice> ").await;
        server.set_tamper(tamper);
        pane.type_text(&core, "Get-Date\r").await;
        let reason = lost_reason(&mut pane).await;
        assert!(reason.contains(says), "{tamper:?}: {reason}");
        while let Ok(chunk) = pane.output.try_recv() {
            pane.unread.extend_from_slice(&chunk);
        }
        let shown = String::from_utf8_lossy(&pane.unread).into_owned();
        assert!(
            !shown.contains("November 1, 2026"),
            "{tamper:?}: nothing of the answer shows: {shown:?}"
        );
        core.terminals.close(pane.id).await;
    }
}

#[tokio::test]
async fn the_windows_sign_in_never_sends_ntlm_even_to_a_host_that_only_takes_it() {
    let password = new_password();
    // The fake takes only NTLM, as a workgroup host would.
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let mut mine = input(
        "win05",
        server.port(),
        None,
        options(WinrmTransport::Http, WinrmSignIn::Windows, WinrmCertificate::Windows),
    );
    // A name, which Kerberos needs; it resolves to 127.0.0.1 alone (no packet leaves this PC).
    mine.host = "localhost".into();
    mine.username = None;
    let id = core.sessions.create(&core.ctx(), mine).await.unwrap().id;
    let mut pane = Pane::open(&core, id).await;
    let reason = lost_reason(&mut pane).await;
    let stats = server.stats();
    assert_eq!(
        stats.ntlm_messages, 0,
        "nothing derived from this PC's Windows password went to the host: {reason}"
    );
    assert_eq!(stats.sign_ins, 0, "{reason}");
    core.terminals.close(pane.id).await;
}

// ---- Sessions ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_winrm_session_keeps_its_password_and_never_sends_basic_over_http() {
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let secret = core
        .vault
        .add(&core.ctx(), SecretKind::Password, "win login", SecretString::new("pw"))
        .await
        .unwrap()
        .id;
    let ntlm = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let saved = core
        .sessions
        .create(&core.ctx(), input("win01", 5985, Some(secret), ntlm))
        .await
        .unwrap();
    assert_eq!(
        saved.auth,
        SessionAuth::Password {
            password_id: Some(secret)
        },
        "the password stays (it is WinRM's login)"
    );
    let spec = core.store.winrm_spec(&core.ctx(), saved.id).await.unwrap().unwrap();
    assert_eq!(spec.address(), "alice@127.0.0.1:5985");

    let basic_http = options(WinrmTransport::Http, WinrmSignIn::Basic, WinrmCertificate::Windows);
    let refused = core
        .sessions
        .create(&core.ctx(), input("win02", 5985, Some(secret), basic_http))
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("HTTPS"), "{refused}");

    let mut keyed = input("win03", 5986, None, WinrmOptions::default());
    keyed.auth = SessionAuth::Agent;
    assert!(core.sessions.create(&core.ctx(), keyed).await.is_err());

    // The Windows sign-in is Kerberos only, which needs the host's name: an IP address is refused.
    let windows = options(WinrmTransport::Https, WinrmSignIn::Windows, WinrmCertificate::Windows);
    let by_ip = core
        .sessions
        .create(&core.ctx(), input("win04", 5986, Some(secret), windows))
        .await
        .unwrap_err();
    assert!(by_ip.to_string().contains("Kerberos"), "{by_ip}");
    let mut named = input("win04", 5986, Some(secret), windows);
    named.host = "win04.example.com".into();
    let mine = core.sessions.create(&core.ctx(), named).await.unwrap();
    assert_eq!(mine.auth, SessionAuth::Password { password_id: None });
    assert_eq!(mine.username, None, "the Windows sign-in is this PC's user");

    // MO-14's Linux reads refuse it before anything signs in (nothing listens on its port).
    let admin = core.host_details.admin(&core.ctx(), saved.id).await.unwrap_err();
    assert!(admin.to_string().contains("Linux"), "{admin}");
    let updates = core.host_details.updates(&core.ctx(), saved.id).await.unwrap_err();
    assert!(updates.to_string().contains("Linux"), "{updates}");

    // SSH-only features still refuse it.
    assert_eq!(
        core.store.session_spec(&core.ctx(), saved.id).await.unwrap_err().code(),
        "wrong_session_kind"
    );
}

// ---- Guest metrics, facts and service checks -------------------------------------------------------------

#[tokio::test]
async fn a_watched_windows_host_gives_guest_metrics_and_its_facts_on_one_kept_powershell() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let o = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();

    // The first round signs in and reads; the second makes rates.
    core.metrics.collect_once().await;
    core.metrics.collect_once().await;
    let sample = timeout(WAIT, async {
        loop {
            if let Some(sample) = core.metrics.hub().latest(MetricSource::Guest, &id.to_string()) {
                if sample.cpu_pct.is_some() {
                    return sample;
                }
            }
            core.metrics.collect_once().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("a guest sample with rates");
    assert!((sample.cpu_pct.unwrap() - 25.0).abs() < 0.01, "{sample:?}");
    assert_eq!(sample.mem_total_bytes, Some(8 * 1024 * 1024 * 1024));
    assert_eq!(sample.mounts.len(), 2);
    assert!(sample.disk_read_bps.is_some() && sample.net_rx_bps.is_some());
    assert_eq!(sample.load1, None);

    let stats = server.stats();
    let runners = stats
        .commands
        .iter()
        .filter(|c| c.as_str() == "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -")
        .count();
    assert!(stats.metrics_reads >= 2);
    // One kept PowerShell for every round; the facts' run (MO-13) is one more, which ends.
    assert!(runners <= 2, "{:?}", stats.commands);
    assert_eq!(stats.plain_refused, 0);

    // MO-13: the dashboard read the host's facts on its kept connection.
    let specs = timeout(WAIT, async {
        loop {
            if let Some(specs) = core.host_details.session_specs(&core.ctx(), id).await.unwrap() {
                return specs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("facts stored");
    assert_eq!(specs.collected_by, CollectedBy::Dashboard);
    assert_eq!(specs.specs.os.name.as_deref(), Some("Windows Server 2022 Datacenter"));
    let windows = specs.specs.windows.clone().unwrap();
    assert_eq!(windows.build.as_deref(), Some("20348.2340"));
    assert_eq!(specs.specs.adapters[0].mac.as_deref(), Some("00:50:56:ab:cd:ef"));
    assert_eq!(specs.specs.listening.len(), 4);
    // A Refresh uses the same kept connection; MO-14's Linux reads say what they are for.
    let refreshed = core.host_details.refresh_session(&core.ctx(), id).await.unwrap();
    assert_eq!(refreshed.collected_by, CollectedBy::Refresh);
    let admin = core.host_details.admin(&core.ctx(), id).await.unwrap_err();
    assert!(admin.to_string().contains("Linux"), "{admin}");

    // FD-02: another workspace is shown: the kept connection and its PowerShell go.
    let other = core
        .workspaces
        .create(WorkspaceInput {
            name: "Globex".into(),
            color: None,
        })
        .await
        .unwrap();
    core.switch_workspace(other.id).await.unwrap();
    timeout(WAIT, async {
        while server.open_shells() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("a workspace switch closes Windows hosts' kept connections");
}

#[tokio::test]
async fn a_refused_password_parks_a_watched_windows_host_until_the_session_changes() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let o = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    server.set_password("rotated-elsewhere");
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    let state = timeout(WAIT, async {
        loop {
            core.metrics.collect_once().await;
            if let Some(status) = core.metrics.guest().statuses().get(&id) {
                if status.state != GuestState::Connecting {
                    return status.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.state, GuestState::LoginFailed, "{state:?}");
    assert!(state.parked);
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    assert_eq!(
        server.stats().refused_sign_ins,
        1,
        "parked: no new sign-in, so no lockout"
    );
}

#[tokio::test]
async fn a_wrong_basic_password_parks_the_dashboard_and_service_checks() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new().with_verdict(trusted()))).await;
    let clock = Arc::new(FakeClock::new(OffsetDateTime::now_utc(), FakeZone::central_europe()));
    core.checks.set_clock(clock.clone());
    let o = options(WinrmTransport::Https, WinrmSignIn::Basic, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    server.set_password("rotated-elsewhere");

    // The dashboard: refused once, then parked.
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    let state = timeout(WAIT, async {
        loop {
            core.metrics.collect_once().await;
            if let Some(status) = core.metrics.guest().statuses().get(&id) {
                if status.state != GuestState::Connecting {
                    return status.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.state, GuestState::LoginFailed, "{state:?}");
    assert!(state.parked);
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    assert_eq!(server.stats().refused_sign_ins, 1, "parked: no new sign-in");

    // A service check on the same session: parked too (one login key), so it signs in no more.
    let check = core
        .checks
        .create(CheckInput {
            name: "Spooler".into(),
            target: ProbeTarget::Session { session_id: id },
            spec: CheckSpec::Service { unit: "Spooler".into() },
            interval_secs: 60,
            timeout_secs: 10,
            failures_before_down: 1,
            paused: false,
        })
        .await
        .unwrap()
        .id;
    for _ in 0..3 {
        core.checks.run_due().await.unwrap();
        clock.advance(time::Duration::minutes(1));
    }
    let row = core
        .checks
        .overview(HistoryRange::Hour)
        .await
        .unwrap()
        .rows
        .into_iter()
        .find(|r| r.check.id == check)
        .unwrap();
    assert_eq!(row.status, CheckStatus::Unknown, "{:?}", row.last);
    assert_eq!(server.stats().refused_sign_ins, 1, "no lockout from the checks either");
}

#[tokio::test]
async fn service_checks_read_windows_services_on_one_kept_sign_in() {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new().with_verdict(trusted()))).await;
    let clock = Arc::new(FakeClock::new(OffsetDateTime::now_utc(), FakeZone::central_europe()));
    core.checks.set_clock(clock.clone());
    let o = options(WinrmTransport::Https, WinrmSignIn::Basic, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    let on = |name: &str| CheckInput {
        name: name.into(),
        target: ProbeTarget::Session { session_id: id },
        spec: CheckSpec::Service { unit: name.into() },
        interval_secs: 60,
        timeout_secs: 10,
        failures_before_down: 1,
        paused: false,
    };
    let spooler = core.checks.create(on("Spooler")).await.unwrap().id;
    let sql = core.checks.create(on("MSSQL$SQLEXPRESS")).await.unwrap().id;
    let gone = core.checks.create(on("NoSuchService")).await.unwrap().id;
    assert!(core.checks.create(on("Spool*")).await.is_err(), "no wildcards");
    for _ in 0..2 {
        core.checks.run_due().await.unwrap();
        clock.advance(time::Duration::minutes(1));
    }
    let row = |check: Uuid| {
        let core = &core;
        async move {
            core.checks
                .overview(HistoryRange::Hour)
                .await
                .unwrap()
                .rows
                .into_iter()
                .find(|r| r.check.id == check)
                .unwrap()
        }
    };
    let up = row(spooler).await;
    assert_eq!(up.last.as_ref().unwrap().result, RunResult::Up, "{:?}", up.last);
    assert_eq!(up.last.unwrap().detail, "Spooler is Running");
    let down = row(sql).await;
    assert_eq!(down.last.unwrap().result, RunResult::Down);
    // A service the host doesn't have is down, so the check-down alert fires.
    let missing = row(gone).await;
    let last = missing.last.unwrap();
    assert_eq!(last.result, RunResult::Down, "{last:?}");
    assert!(last.detail.contains("missing"), "{last:?}");
    assert_eq!(server.stats().sign_ins, 1, "one sign-in for six runs");
    assert_eq!(
        server
            .stats()
            .commands
            .iter()
            .filter(|c| c.contains("-NonInteractive"))
            .count(),
        1,
        "one kept PowerShell"
    );

    // A vault lock closes the kept connection.
    core.vault.lock(&core.ctx()).await.unwrap();
    timeout(WAIT, async {
        while server.open_shells() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("a vault lock closes the checks' kept WinRM connection");
}

/// Every text an xlsx holds: its members' XML.
fn xlsx_text(path: &std::path::Path) -> String {
    use std::io::Read;
    let bytes = std::fs::read(path).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut all = String::new();
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).unwrap();
        let mut text = String::new();
        let _ = file.read_to_string(&mut text);
        all.push_str(&text);
    }
    all
}

/// F6 (FD-05, BX-12): a Windows host in the inventory to Excel, read again on a sign-in of Remotely's own through the
/// login guard, and in the Ansible inventory as a `winrm` host.
#[tokio::test]
async fn the_inventory_reads_a_windows_host_again_and_a_refused_one_is_parked() {
    use remotely_core::reports::{AnsibleRequest, InventoryOptions, InventoryRequest, ReadControl};

    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpNtlm, "alice", &password)
        .await
        .unwrap();
    let core = core(Arc::new(FakeNetworkTools::new())).await;
    let o = options(WinrmTransport::Http, WinrmSignIn::Ntlm, WinrmCertificate::Windows);
    let id = session(&core, &server, &password, o).await;
    let temp = std::env::temp_dir().join(format!("remotely-winrm-inventory-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&temp).unwrap();
    let request = InventoryRequest {
        options: InventoryOptions {
            read_again: true,
            updates: true,
            packages: true,
        },
        utc_offset_minutes: 0,
    };

    let path = temp.join("inventory.xlsx");
    let report = core
        .reports
        .export_inventory(&core.ctx(), &path, request, "Remotely test", &ReadControl::default())
        .await
        .unwrap();
    let read = report.read.clone().unwrap();
    assert_eq!((read.asked, read.read), (1, 1), "{read:?}");
    assert!(read.problems.is_empty(), "{read:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("read from Linux hosts only, so 1 Windows host has none")),
        "{:?}",
        report.notes
    );
    // The host's facts reach the sheet: kind, OS, build, adapter MAC and its listening ports.
    let book = xlsx_text(&path);
    for fact in [
        "WinRM",
        "Windows Server 2022 Datacenter",
        "20348.2340",
        "00:50:56:ab:cd:ef",
        "tcp 5985",
        "Read now",
    ] {
        assert!(book.contains(fact), "{fact} is in the workbook");
    }
    assert!(!book.contains(&password));
    // Stored as a Refresh stores them, and the PowerShell ran only the facts' read (no Linux script).
    let specs = core.host_details.session_specs(&core.ctx(), id).await.unwrap().unwrap();
    assert_eq!(specs.collected_by, CollectedBy::Refresh);
    assert!(
        server
            .stats()
            .stdin
            .iter()
            .all(|line| !line.contains("dpkg-query") && !line.contains("rpm -qa")),
        "no Linux read went to Windows"
    );

    // BX-12: the same host in the Ansible inventory, with nothing picked.
    let preview = core
        .reports
        .ansible_preview(&core.ctx(), &AnsibleRequest::default())
        .await
        .unwrap();
    assert_eq!(preview.hosts, 1, "{}", preview.text);
    assert!(
        preview.text.contains("ansible_connection: \"winrm\""),
        "{}",
        preview.text
    );
    assert!(
        preview.text.contains("ansible_winrm_scheme: \"http\""),
        "{}",
        preview.text
    );
    assert!(
        preview.text.contains("ansible_winrm_transport: \"ntlm\""),
        "{}",
        preview.text
    );
    assert!(!preview.text.contains(&password) && !preview.text.contains("ignore"));

    // A refused password parks the host: the exports after it sign in no more, so no lockout.
    server.set_password("rotated-elsewhere");
    for n in 0..3 {
        let path = temp.join(format!("again-{n}.xlsx"));
        let report = core
            .reports
            .export_inventory(&core.ctx(), &path, request, "Remotely test", &ReadControl::default())
            .await
            .unwrap();
        let read = report.read.unwrap();
        assert_eq!(read.read, 0, "{read:?}");
        assert_eq!(read.problems.len(), 1, "{read:?}");
        let book = xlsx_text(&path);
        assert!(book.contains("Windows Server 2022 Datacenter"), "the stored facts stay");
    }
    assert_eq!(server.stats().refused_sign_ins, 1, "parked after the first refusal");
    let _ = std::fs::remove_dir_all(temp);
}
