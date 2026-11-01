//! FD-09 toolbox, end to end: ping, trace route, DNS and port checks on `FakeNetworkTools`; the certificate viewer
//! against a TLS server on 127.0.0.1 with a certificate made at run time (rcgen); port and certificate checks of a
//! session behind a jump host through the test SSH server; Wake-on-LAN through the bus. No packet leaves 127.0.0.1:
//! the fake sends nothing, and the real probes only reach loopback.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{temp_folder, wait_finished, Setup};
use remotely_core::adapters::net_tools::{DnsFailure, Echo, RecordType, SystemNetworkTools, TrustVerdict};
use remotely_core::command_bus::{Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::net_tools::FakePort;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeNetwork, FakeNetworkTools, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::toolbox::ports::PortState;
use remotely_core::toolbox::{
    CertRequest, DnsRequest, PingRequest, PortRequest, ProbeProgress, ProbeTarget, TraceRequest, WakeDestination,
    WakeSpec,
};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn address(host: &str) -> ProbeTarget {
    ProbeTarget::Address { host: host.into() }
}

fn session_input(name: &str, host: &str, port: u16, jump: Option<Uuid>, environment: Environment) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password { password_id: None },
        jump_session_id: jump,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

/// Collects what a run reports as it goes.
#[derive(Default, Clone)]
struct Seen(Arc<Mutex<Vec<ProbeProgress>>>);

impl Seen {
    fn sink(&self) -> impl Fn(ProbeProgress) + Send + Sync + '_ {
        move |p| self.0.lock().unwrap().push(p)
    }
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

async fn core_with(tools: Arc<FakeNetworkTools>, network: FakeNetwork) -> Core {
    Setup::new(FakeVmware::default())
        .with_network(Arc::new(network))
        .with_network_tools(tools)
        .build()
        .await
}

#[tokio::test]
async fn a_ping_reports_each_reply_and_the_totals() {
    let tools = Arc::new(FakeNetworkTools::new().with_route("192.0.2.10", &[Some("198.51.100.1")]));
    let core = core_with(
        Arc::clone(&tools),
        FakeNetwork::default().with_name("web01.example.com", "192.0.2.10"),
    )
    .await;
    let seen = Seen::default();
    let summary = core
        .toolbox
        .ping(
            &core.ctx(),
            &PingRequest {
                target: address("web01.example.com"),
                count: 2,
                interval_ms: 1000,
                size: 64,
                timeout_ms: 500,
            },
            &CancellationToken::new(),
            &seen.sink(),
        )
        .await
        .unwrap();
    assert_eq!(summary.address.to_string(), "192.0.2.10");
    assert_eq!((summary.sent, summary.received), (2, 2));
    assert_eq!(summary.loss_percent, 0.0);
    assert_eq!(seen.len(), 2, "each reply as it came");
    let sent = tools.echoes();
    assert_eq!(sent.len(), 2);
    assert!(sent
        .iter()
        .all(|e| e.size == 64 && e.timeout == Duration::from_millis(500)));
}

#[tokio::test]
async fn a_cancelled_ping_stops_and_says_so() {
    let tools = Arc::new(FakeNetworkTools::new().with_silent("192.0.2.20"));
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let cancel = CancellationToken::new();
    let stopper = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        stopper.cancel();
    });
    let summary = core
        .toolbox
        .ping(
            &core.ctx(),
            &PingRequest {
                target: address("192.0.2.20"),
                count: 100,
                interval_ms: 1000,
                size: 32,
                timeout_ms: 100,
            },
            &cancel,
            &|_| {},
        )
        .await
        .unwrap();
    assert!(summary.cancelled);
    assert!(summary.sent < 100);
    assert_eq!(summary.received, 0);
    assert_eq!(summary.loss_percent, 100.0);
}

#[tokio::test]
async fn a_trace_lists_each_hop_until_the_host_answers() {
    let tools =
        Arc::new(FakeNetworkTools::new().with_route("192.0.2.30", &[Some("198.51.100.1"), None, Some("203.0.113.9")]));
    let network = FakeNetwork::default().with_name("edge.example.net", "198.51.100.1");
    let core = core_with(Arc::clone(&tools), network).await;
    let seen = Seen::default();
    let summary = core
        .toolbox
        .trace(
            &core.ctx(),
            &TraceRequest {
                target: address("192.0.2.30"),
                max_hops: 30,
                timeout_ms: 200,
                resolve_names: true,
            },
            &CancellationToken::new(),
            &seen.sink(),
        )
        .await
        .unwrap();
    assert!(summary.reached);
    assert_eq!(summary.hops.len(), 4);
    assert_eq!(summary.hops[0].address.unwrap().to_string(), "198.51.100.1");
    assert_eq!(summary.hops[0].hostname.as_deref(), Some("edge.example.net"));
    assert_eq!(summary.hops[1].address, None, "a router that doesn't answer");
    assert_eq!(summary.hops[1].rtts_ms, [None, None, None]);
    assert!(summary.hops[3].reached);
    assert_eq!(seen.len(), 4);
    // Three requests per hop, with the TTL rising.
    let ttls: Vec<u8> = tools.echoes().iter().map(|e| e.ttl).collect();
    assert_eq!(ttls, [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4]);
}

#[tokio::test]
async fn a_vm_is_probed_at_its_guest_ip() {
    let tools = Arc::new(FakeNetworkTools::new());
    let vmware = FakeVmware::with_running([common::vmx("web01")]).with_ip(&common::vmx("web01"), "192.0.2.41");
    let core = Setup::new(vmware)
        .with_network_tools(Arc::clone(&tools) as _)
        .build()
        .await;
    let summary = core
        .toolbox
        .ping(
            &core.ctx(),
            &PingRequest {
                target: ProbeTarget::Vm {
                    vm_key: common::vmx("web01"),
                },
                count: 1,
                interval_ms: 1000,
                size: 32,
                timeout_ms: 200,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap();
    assert_eq!(summary.address.to_string(), "192.0.2.41");
    assert_eq!(summary.label, "web01");
}

#[tokio::test]
async fn a_session_behind_a_jump_host_is_not_pinged_or_traced() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let bastion = core
        .sessions
        .create(
            &core.ctx(),
            session_input("bastion", "192.0.2.1", 22, None, Environment::Lab),
        )
        .await
        .unwrap();
    let db = core
        .sessions
        .create(
            &core.ctx(),
            session_input("db01", "db01.test", 22, Some(bastion.id), Environment::Lab),
        )
        .await
        .unwrap();
    let target = ProbeTarget::Session { session_id: db.id };
    let ping = core
        .toolbox
        .ping(
            &core.ctx(),
            &PingRequest {
                target: target.clone(),
                count: 1,
                interval_ms: 1000,
                size: 32,
                timeout_ms: 200,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(ping.contains("behind the jump host 'bastion'"), "{ping}");
    let trace = core
        .toolbox
        .trace(
            &core.ctx(),
            &TraceRequest {
                target,
                max_hops: 30,
                timeout_ms: 200,
                resolve_names: false,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(trace.contains("trace the route to"), "{trace}");
    assert!(tools.echoes().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn dns_lookups_give_records_or_say_why_not() {
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_records(
                "example.com",
                RecordType::Mx,
                &[("example.com", 300, "10 mail.example.com")],
            )
            .with_records(
                "10.2.0.192.in-addr.arpa",
                RecordType::Ptr,
                &[("10.2.0.192.in-addr.arpa", 60, "web01.example.com")],
            )
            .with_dns_failure("empty.example.com", RecordType::Txt, DnsFailure::NoRecords)
            .with_adapter("Ethernet", "192.0.2.5", 24, &["192.0.2.53"]),
    );
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let mx = core
        .toolbox
        .dns(
            &DnsRequest {
                name: "example.com".into(),
                record_type: RecordType::Mx,
                server: None,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(mx.records[0].data, "10 mail.example.com");
    assert_eq!(mx.records[0].ttl, 300);
    assert_eq!(
        serde_json::to_value(&mx.server).unwrap(),
        serde_json::json!({ "kind": "windows", "servers": ["192.0.2.53"] })
    );
    let ptr = core
        .toolbox
        .dns(
            &DnsRequest {
                name: "192.0.2.10".into(),
                record_type: RecordType::Ptr,
                server: Some("198.51.100.53".into()),
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(ptr.query_name, "10.2.0.192.in-addr.arpa");
    assert_eq!(ptr.records[0].data, "web01.example.com");
    assert_eq!(
        tools.dns_queries().last().unwrap().server.unwrap().to_string(),
        "198.51.100.53"
    );
    let empty = core
        .toolbox
        .dns(
            &DnsRequest {
                name: "empty.example.com".into(),
                record_type: RecordType::Txt,
                server: None,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(empty.failure, Some(DnsFailure::NoRecords));
    let missing = core
        .toolbox
        .dns(
            &DnsRequest {
                name: "nope.example.com".into(),
                record_type: RecordType::A,
                server: None,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(missing.failure, Some(DnsFailure::NoSuchName));
    let bad_server = core
        .toolbox
        .dns(
            &DnsRequest {
                name: "example.com".into(),
                record_type: RecordType::A,
                server: Some("dns.example.com".into()),
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(bad_server.contains("isn't an IP address"), "{bad_server}");
}

#[tokio::test]
async fn a_port_check_reports_open_closed_and_silent_ports_with_clean_banners() {
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_port(
                "192.0.2.10",
                22,
                FakePort::Banner(b"SSH-2.0-OpenSSH_9.6\r\n\x1b[31m\xe2\x80\xae".to_vec()),
            )
            .with_port("192.0.2.10", 8443, FakePort::Silent),
    );
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let seen = Seen::default();
    let summary = core
        .toolbox
        .ports(
            &core.ctx(),
            &PortRequest {
                target: address("192.0.2.10"),
                ports: "22, 80, 8443".into(),
                timeout_ms: 300,
                banner: true,
            },
            &CancellationToken::new(),
            &seen.sink(),
        )
        .await
        .unwrap();
    let states: Vec<(u16, PortState)> = summary.results.iter().map(|r| (r.port, r.state)).collect();
    assert_eq!(
        states,
        [
            (22, PortState::Open),
            (80, PortState::Closed),
            (8443, PortState::NoAnswer)
        ]
    );
    assert_eq!(
        summary.results[0].banner.as_deref(),
        Some("SSH-2.0-OpenSSH_9.6 [31m"),
        "control and format characters removed"
    );
    assert_eq!(summary.open, 1);
    assert_eq!(seen.len(), 3);
    let too_many = core
        .toolbox
        .ports(
            &core.ctx(),
            &PortRequest {
                target: address("192.0.2.10"),
                ports: "1-101".into(),
                timeout_ms: 300,
                banner: false,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(too_many.contains("at most 100 ports"), "{too_many}");
    assert_eq!(tools.connects().len(), 3, "the refused run connected to nothing");
}

#[tokio::test]
async fn the_toolbox_reads_while_presenting_with_the_read_only_lock() {
    let tools = Arc::new(FakeNetworkTools::new().with_port("192.0.2.10", 443, FakePort::Banner(Vec::new())));
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let summary = core
        .toolbox
        .ports(
            &core.ctx(),
            &PortRequest {
                target: address("192.0.2.10"),
                ports: "443".into(),
                timeout_ms: 300,
                banner: false,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap();
    assert_eq!(summary.open, 1);
    // A wake-up is a command: the lock refuses it.
    let refused = core
        .bus
        .submit(
            &core.ctx(),
            Command::WakeOnLan {
                targets: vec![TargetRef::App],
                wake: wake_spec("192.0.2.255", 9),
            },
        )
        .await;
    assert!(refused.is_err());
    assert!(tools.sent().is_empty());
}

// ---- Certificates ------------------------------------------------------------------------------------------------

/// A TLS server on 127.0.0.1 with a certificate for `names`, made now. Returns its address and the SNI names it saw.
async fn tls_server(names: &[&str]) -> (SocketAddr, Arc<Mutex<Vec<Option<String>>>>, Vec<u8>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let at = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let names_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&names_seen);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let name = tls.get_ref().1.server_name().map(str::to_owned);
                    seen.lock().unwrap().push(name);
                }
            });
        }
    });
    (at, seen, der)
}

#[tokio::test]
async fn a_servers_certificate_is_read_whatever_its_chain_and_checked_by_name() {
    let (at, sni, _) = tls_server(&["web01.example.com", "192.0.2.10"]).await;
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_port("192.0.2.10", 443, FakePort::Forward(at))
            .with_verdict(TrustVerdict {
                trusted: false,
                problems: vec!["its root isn't one this PC trusts".into()],
                built: Vec::new(),
            }),
    );
    let network = FakeNetwork::default().with_name("web01.example.com", "192.0.2.10");
    let core = core_with(Arc::clone(&tools), network).await;
    let report = core
        .toolbox
        .certificate(
            &core.ctx(),
            &CertRequest {
                target: address("web01.example.com"),
                port: 443,
                server_name: None,
                timeout_ms: 5000,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(report.source, "web01.example.com (web01.example.com:443)");
    assert_eq!(report.address.as_deref(), Some("192.0.2.10"));
    assert_eq!(report.chain.len(), 1);
    assert_eq!(report.chain[0].subject, "CN=web01.example.com");
    assert_eq!(report.name_matches, Some(true));
    assert!(!report.trusted);
    assert_eq!(report.trust_problems, ["its root isn't one this PC trusts"]);
    assert!(report.days_left.unwrap() > 300);
    assert!(report.protocol.as_deref().is_some_and(|p| p.starts_with("TLS 1.")));
    // The server notes the name once its side of the handshake is done, which may be after the client's.
    let seen_names = |count: usize| {
        let sni = Arc::clone(&sni);
        async move {
            for _ in 0..100 {
                if sni.lock().unwrap().len() >= count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            sni.lock().unwrap().clone()
        }
    };
    assert_eq!(seen_names(1).await, [Some("web01.example.com".to_owned())]);
    assert_eq!(tools.checked().len(), 1);

    // Another name: sent as SNI, and it doesn't match.
    let other = core
        .toolbox
        .certificate(
            &core.ctx(),
            &CertRequest {
                target: address("192.0.2.10"),
                port: 443,
                server_name: Some("db01.example.com".into()),
                timeout_ms: 5000,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(other.name_matches, Some(false));
    assert_eq!(
        seen_names(2).await.last().cloned().flatten().as_deref(),
        Some("db01.example.com")
    );
}

// Windows' own chain check, offline: a self-signed certificate made now is not trusted.
#[tokio::test]
async fn windows_does_not_trust_a_self_signed_certificate() {
    let (at, _, _) = tls_server(&["localhost"]).await;
    let core = Setup::new(FakeVmware::default())
        .with_network_tools(Arc::new(SystemNetworkTools))
        .with_network(Arc::new(FakeNetwork::default().with_name("localhost", "127.0.0.1")))
        .build()
        .await;
    let report = core
        .toolbox
        .certificate(
            &core.ctx(),
            &CertRequest {
                target: address("127.0.0.1"),
                port: at.port(),
                server_name: Some("localhost".into()),
                timeout_ms: 5000,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!report.trusted);
    assert!(!report.trust_problems.is_empty());
    assert_eq!(report.name_matches, Some(true));
}

#[tokio::test]
async fn a_certificate_file_is_read_and_a_device_path_refused() {
    use base64::Engine;
    let (_, _, der) = tls_server(&["files.example.com"]).await;
    let folder = temp_folder("toolbox-cert");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&der)
    );
    let path = folder.join("files.pem");
    std::fs::write(&path, pem).unwrap();
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let report = core.toolbox.certificate_file(&path).await.unwrap();
    assert_eq!(report.source, "files.pem");
    assert_eq!(report.chain[0].subject, "CN=files.example.com");
    assert_eq!(report.name_matches, None);
    assert_eq!(
        tools.checked(),
        [(1, remotely_core::adapters::net_tools::TrustUse::Any)]
    );
    let refused = core
        .toolbox
        .certificate_file(std::path::Path::new("NUL"))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("names a Windows device"), "{refused}");
    std::fs::remove_dir_all(folder).ok();
}

// ---- Jump hosts (SS-07) ------------------------------------------------------------------------------------------

#[tokio::test]
async fn ports_and_certificates_behind_a_jump_host_go_through_it() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let bastion = TestSshServer::start().await.with_password("alice", &password);
    let open = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let open_port = open.local_addr().unwrap().port();
    let closed_port = {
        let gone = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        gone.local_addr().unwrap().port()
    };
    let (tls_at, _, _) = tls_server(&["db01.test"]).await;
    // The jump host reaches `db01.test` (any port) as the TLS server.
    bastion.set_route("db01.test", tls_at.port());

    let tools = Arc::new(FakeNetworkTools::new());
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .with_network_tools(Arc::clone(&tools) as _)
        .build()
        .await;
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "bastion",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let mut jump = session_input("bastion", "127.0.0.1", bastion.port(), None, Environment::Lab);
    jump.auth = SessionAuth::Password {
        password_id: Some(secret),
    };
    let jump = core.sessions.create(&core.ctx(), jump).await.unwrap();
    core.known_hosts
        .trust(
            &core.ctx(),
            &HostKey {
                host: "127.0.0.1".into(),
                port: bastion.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: bastion.host_key_fingerprint(),
            },
            None,
        )
        .await
        .unwrap();
    let local = core
        .sessions
        .create(
            &core.ctx(),
            session_input("local", "127.0.0.1", 22, Some(jump.id), Environment::Lab),
        )
        .await
        .unwrap();
    let ports = core
        .toolbox
        .ports(
            &core.ctx(),
            &PortRequest {
                target: ProbeTarget::Session { session_id: local.id },
                ports: format!("{open_port}, {closed_port}"),
                timeout_ms: 5000,
                banner: false,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap();
    assert_eq!(ports.via.as_deref(), Some("bastion"));
    assert_eq!(ports.address, None, "the jump host resolves the name itself");
    assert_eq!(ports.results[0].state, PortState::Open);
    assert_eq!(ports.results[1].state, PortState::Closed);
    assert!(ports.results[1]
        .detail
        .as_deref()
        .unwrap()
        .contains("the jump host 'bastion'"));
    assert!(tools.connects().is_empty(), "nothing connected from this PC");
    assert!(bastion
        .log()
        .iter()
        .any(|line| line == &format!("direct-tcpip 127.0.0.1:{open_port}")));

    let db = core
        .sessions
        .create(
            &core.ctx(),
            session_input("db01", "db01.test", 22, Some(jump.id), Environment::Lab),
        )
        .await
        .unwrap();
    let report = core
        .toolbox
        .certificate(
            &core.ctx(),
            &CertRequest {
                target: ProbeTarget::Session { session_id: db.id },
                port: 443,
                server_name: None,
                timeout_ms: 5000,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(report.via.as_deref(), Some("bastion"));
    assert_eq!(report.chain[0].subject, "CN=db01.test");
    assert_eq!(report.name_matches, Some(true));
    // One login to the jump host for both checks: the toolbox kept its connection.
    assert_eq!(bastion.connections(), 1);
    drop(open);
    core.toolbox.close_all().await;
}

#[tokio::test]
async fn a_jump_host_whose_login_is_refused_is_parked() {
    let right = format!("pw-{}", Uuid::new_v4().simple());
    let wrong = format!("pw-{}", Uuid::new_v4().simple());
    let bastion = TestSshServer::start().await.with_password("alice", &right);
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    let secret = core
        .vault
        .add(&core.ctx(), SecretKind::Password, "bastion", SecretString::new(&wrong))
        .await
        .unwrap()
        .id;
    let mut jump = session_input("bastion", "127.0.0.1", bastion.port(), None, Environment::Lab);
    jump.auth = SessionAuth::Password {
        password_id: Some(secret),
    };
    let jump = core.sessions.create(&core.ctx(), jump).await.unwrap();
    core.known_hosts
        .trust(
            &core.ctx(),
            &HostKey {
                host: "127.0.0.1".into(),
                port: bastion.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: bastion.host_key_fingerprint(),
            },
            None,
        )
        .await
        .unwrap();
    let behind = core
        .sessions
        .create(
            &core.ctx(),
            session_input("web", "web.test", 22, Some(jump.id), Environment::Lab),
        )
        .await
        .unwrap();
    let request = PortRequest {
        target: ProbeTarget::Session { session_id: behind.id },
        ports: "443".into(),
        timeout_ms: 2000,
        banner: false,
    };
    let first = core
        .toolbox
        .ports(&core.ctx(), &request, &CancellationToken::new(), &|_| {})
        .await
        .unwrap_err()
        .to_string();
    assert!(first.contains("won't log in again on its own"), "{first}");
    let logins = bastion.connections();
    let second = core
        .toolbox
        .ports(&core.ctx(), &request, &CancellationToken::new(), &|_| {})
        .await
        .unwrap_err()
        .to_string();
    assert!(second.contains("won't log in again on its own"), "{second}");
    assert_eq!(bastion.connections(), logins, "a parked jump host isn't tried again");
}

// ---- Wake-on-LAN -------------------------------------------------------------------------------------------------

fn wake_spec(address: &str, port: u16) -> WakeSpec {
    WakeSpec {
        mac: "00-0C-29-AB-CD-EF".into(),
        destination: WakeDestination::Address {
            address: address.parse().unwrap(),
        },
        port,
    }
}

#[tokio::test]
async fn a_wake_up_is_low_audited_and_sends_one_magic_packet() {
    let tools = Arc::new(FakeNetworkTools::new().with_adapter("Ethernet", "192.0.2.5", 24, &[]));
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(
            &core.ctx(),
            Command::WakeOnLan {
                targets: vec![TargetRef::App],
                wake: WakeSpec {
                    destination: WakeDestination::Adapter {
                        address: "192.0.2.5".parse().unwrap(),
                    },
                    ..wake_spec("192.0.2.255", 9)
                },
            },
        )
        .await
        .unwrap()
    else {
        panic!("Low runs at once");
    };
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
    let sent = tools.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to.to_string(), "192.0.2.255:9");
    assert_eq!(sent[0].from.unwrap().to_string(), "192.0.2.5");
    assert!(sent[0].broadcast);
    assert_eq!(sent[0].payload.len(), 102);
    assert_eq!(&sent[0].payload[6..12], &[0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef]);
    let audit = core.store.recent_audit(&core.ctx(), 20).await.unwrap();
    assert!(audit.iter().any(|e| e.action.contains("Wake up 00:0c:29:ab:cd:ef")));
    assert!(audit.iter().any(|e| e.targets_json.contains("MAC 00:0c:29:ab:cd:ef")));
}

#[tokio::test]
async fn a_prod_sessions_wake_up_asks_first() {
    let tools = Arc::new(FakeNetworkTools::new());
    let core = core_with(Arc::clone(&tools), FakeNetwork::default()).await;
    let nas = core
        .sessions
        .create(
            &core.ctx(),
            session_input("nas01", "192.0.2.60", 22, None, Environment::Prod),
        )
        .await
        .unwrap();
    let outcome = core
        .bus
        .submit(
            &core.ctx(),
            Command::WakeOnLan {
                targets: vec![TargetRef::Session { session_id: nas.id }],
                wake: wake_spec("192.0.2.255", 9),
            },
        )
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("Prod asks");
    };
    assert_eq!(request.tier, remotely_core::policy::Tier::Medium);
    assert!(tools.sent().is_empty());
}

// The real socket, to a listener on 127.0.0.1: never a broadcast in a test.
#[tokio::test]
async fn the_magic_packet_reaches_a_listener_on_this_pc() {
    let listener = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let core = Setup::new(FakeVmware::default())
        .with_network_tools(Arc::new(SystemNetworkTools))
        .build()
        .await;
    let mut events = core.jobs.subscribe();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(
            &core.ctx(),
            Command::WakeOnLan {
                targets: vec![TargetRef::App],
                wake: wake_spec("127.0.0.1", port),
            },
        )
        .await
        .unwrap()
    else {
        panic!("Low runs at once");
    };
    let mut buf = [0u8; 200];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), listener.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 102);
    assert_eq!(&buf[..6], &[0xff; 6]);
    assert_eq!(wait_finished(&mut events, job_id).await, JobStatus::Succeeded);
}

#[tokio::test]
async fn a_vms_macs_are_offered_for_its_wake_up() {
    let vmx = common::vmx("nas01");
    let vmware = FakeVmware::default().in_library(&vmx, None).with_vmx_text(
        &vmx,
        "displayName = \"nas01\"\nethernet0.present = \"TRUE\"\nethernet0.addressType = \"static\"\nethernet0.address = \"00:50:56:00:00:01\"\n",
    );
    let tools = Arc::new(FakeNetworkTools::new().with_adapter("Ethernet", "192.0.2.5", 24, &[]));
    let core = Setup::new(vmware)
        .with_network_tools(Arc::clone(&tools) as _)
        .build()
        .await;
    let (adapters, macs) = core
        .toolbox
        .wake_options(&core.ctx(), Some(&TargetRef::Vm { vmx_path: vmx.clone() }))
        .await
        .unwrap();
    assert_eq!(adapters.len(), 1);
    assert_eq!(adapters[0].broadcast.to_string(), "192.0.2.255");
    assert_eq!(macs.len(), 1, "{macs:?}");
    assert_eq!(macs[0].mac, "00:50:56:00:00:01");
    assert!(macs[0].source.contains("ethernet0"), "{}", macs[0].source);
}

#[tokio::test]
async fn the_real_ping_reaches_this_pc() {
    let core = Setup::new(FakeVmware::default())
        .with_network_tools(Arc::new(SystemNetworkTools))
        .build()
        .await;
    let summary = core
        .toolbox
        .ping(
            &core.ctx(),
            &PingRequest {
                target: address("127.0.0.1"),
                count: 1,
                interval_ms: 1000,
                size: 32,
                timeout_ms: 2000,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap();
    assert_eq!(summary.received, 1);
    assert!(matches!(summary.replies[0].echo, Echo::Reply { .. }));
}

// ---- Review fixes ------------------------------------------------------------------------------------------------

/// A bastion test server with a saved, trusted session, and a session behind it at 127.0.0.1 (which the bastion
/// reaches), on the real russh adapter with the app's vault.
async fn jump_lab() -> (Core, TestSshServer, Uuid, Uuid) {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let bastion = TestSshServer::start().await.with_password("alice", &password);
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .with_network_tools(Arc::new(FakeNetworkTools::new()))
        .build()
        .await;
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "bastion",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let mut jump = session_input("bastion", "127.0.0.1", bastion.port(), None, Environment::Lab);
    jump.auth = SessionAuth::Password {
        password_id: Some(secret),
    };
    let jump = core.sessions.create(&core.ctx(), jump).await.unwrap();
    core.known_hosts
        .trust(
            &core.ctx(),
            &HostKey {
                host: "127.0.0.1".into(),
                port: bastion.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: bastion.host_key_fingerprint(),
            },
            None,
        )
        .await
        .unwrap();
    let behind = core
        .sessions
        .create(
            &core.ctx(),
            session_input("local", "127.0.0.1", 22, Some(jump.id), Environment::Lab),
        )
        .await
        .unwrap();
    (core, bastion, jump.id, behind.id)
}

async fn check_port(core: &Core, session_id: Uuid, port: u16) -> remotely_core::toolbox::PortSummary {
    core.toolbox
        .ports(
            &core.ctx(),
            &PortRequest {
                target: ProbeTarget::Session { session_id },
                ports: port.to_string(),
                timeout_ms: 5000,
                banner: false,
            },
            &CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap()
}

// Review: a terminal open to the jump host lends its connection, and its wrapper must pass the channel through.
#[tokio::test]
async fn checks_behind_a_jump_host_go_through_an_open_terminal_to_it() {
    use remotely_core::adapters::remote::{AgentSource, PtySize};
    use remotely_core::terminal::TerminalTuning;
    let (core, bastion, jump, behind) = jump_lab().await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        ..TerminalTuning::default()
    });
    let _terminal = core
        .terminals
        .open(&core.ctx(), jump, PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while core.terminals.commands_for(jump).is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the terminal connects");
    assert_eq!(bastion.connections(), 1, "the terminal's");

    let open = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = open.local_addr().unwrap().port();
    let summary = check_port(&core, behind, port).await;
    assert_eq!(summary.via.as_deref(), Some("bastion"));
    assert_eq!(summary.results[0].state, PortState::Open, "{:?}", summary.results[0]);
    assert_eq!(
        bastion.connections(),
        1,
        "no login of its own: the terminal's connection"
    );
    assert_eq!(core.toolbox.kept_jump_connections(), 0);
    core.terminals.close_all().await;
}

// Review: a kept connection to a jump host closes once idle, by itself, so QL-04 checks that host again.
#[tokio::test]
async fn a_kept_jump_host_connection_closes_when_idle_without_another_check() {
    let (core, bastion, _jump, behind) = jump_lab().await;
    core.toolbox.set_jump_idle(Duration::from_millis(200));
    let open = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = open.local_addr().unwrap().port();
    assert_eq!(check_port(&core, behind, port).await.results[0].state, PortState::Open);
    assert_eq!(core.toolbox.kept_jump_connections(), 1);
    assert_eq!(bastion.connections(), 1);
    tokio::time::timeout(Duration::from_secs(5), async {
        while core.toolbox.kept_jump_connections() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the sweep closes it, with no check to start it");
    // The next check logs in again.
    assert_eq!(check_port(&core, behind, port).await.results[0].state, PortState::Open);
    assert_eq!(bastion.connections(), 2);
}

// Review (for F2): a certificate after the leaf that can't be read is noted; the leaf's report still stands. FD-03:
// the names the report shows are listed for the presentation masker.
#[tokio::test]
async fn an_unreadable_certificate_after_the_leaf_is_noted_and_the_rest_is_shown() {
    use base64::Engine;
    let (_, _, der) = tls_server(&["files.example.com", "intranet"]).await;
    let folder = temp_folder("toolbox-chain");
    let block = |bytes: &[u8]| {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    };
    let path = folder.join("chain.pem");
    std::fs::write(&path, format!("{}{}", block(&der), block(b"not a certificate"))).unwrap();
    let core = core_with(Arc::new(FakeNetworkTools::new()), FakeNetwork::default()).await;
    let report = core.toolbox.certificate_file(&path).await.unwrap();
    assert_eq!(report.chain.len(), 1);
    assert_eq!(report.chain[0].subject, "CN=files.example.com");
    assert_eq!(report.unreadable.len(), 1);
    assert!(
        report.unreadable[0].starts_with("the 2nd certificate sent"),
        "{:?}",
        report.unreadable
    );
    assert_eq!(report.hosts, ["files.example.com", "intranet"]);
    std::fs::remove_dir_all(folder).ok();
}

#[tokio::test]
async fn a_server_report_names_its_host_for_the_masker() {
    let (at, _, _) = tls_server(&["intranet"]).await;
    let tools = Arc::new(FakeNetworkTools::new().with_port("192.0.2.10", 443, FakePort::Forward(at)));
    let core = core_with(tools, FakeNetwork::default().with_name("intranet", "192.0.2.10")).await;
    let report = core
        .toolbox
        .certificate(
            &core.ctx(),
            &CertRequest {
                target: address("intranet"),
                port: 443,
                server_name: None,
                timeout_ms: 5000,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(report.host.as_deref(), Some("intranet"));
    assert_eq!(report.hosts, ["intranet"]);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["host"], "intranet");
    assert_eq!(json["serverName"], "intranet");
}
