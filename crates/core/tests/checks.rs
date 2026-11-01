//! MO-08 health checks, end to end: edits audited and locked; runs on a fake clock (nothing sleeps) with
//! `FakeNetworkTools`, HTTP and TLS servers on 127.0.0.1 with certificates made at run time (rcgen), and the test SSH
//! server for service checks and checks behind a jump host; the history, its prune, MO-07's alerts on checks, and
//! FD-07's export and import. No packet leaves 127.0.0.1.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, Setup};
use remotely_core::adapters::net_tools::{DnsFailure, RecordType, TrustVerdict};
use remotely_core::alerts::{AlertMetric, AlertQuery, AlertTargetKind, Resolution};
use remotely_core::checks::{CheckEvent, CheckInput, CheckSpec, CheckStatus, RunResult};
use remotely_core::domain::Environment;
use remotely_core::fakes::clock::{FakeClock, FakeZone};
use remotely_core::fakes::net_tools::FakePort;
use remotely_core::fakes::ssh_server::host::HostFixture;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeNetwork, FakeNetworkTools, FakeVmware};
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::history::HistoryRange;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::toolbox::ProbeTarget;
use remotely_core::transfer::{ExportRequest, ItemAction, TransferCommit};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

fn address(host: &str) -> ProbeTarget {
    ProbeTarget::Address { host: host.into() }
}

fn check(name: &str, target: ProbeTarget, spec: CheckSpec) -> CheckInput {
    CheckInput {
        name: name.into(),
        target,
        spec,
        interval_secs: 60,
        timeout_secs: 5,
        failures_before_down: 2,
        paused: false,
    }
}

fn http(path: &str) -> CheckSpec {
    CheckSpec::Http {
        https: false,
        port: None,
        path: path.into(),
        status_min: 200,
        status_max: 299,
        body_contains: None,
        follow_redirects: true,
        allow_invalid_cert: false,
    }
}

fn session_input(name: &str, host: &str, port: u16, jump: Option<Uuid>) -> SessionInput {
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
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

/// A core on fake network tools with the checks on a fake clock at the real time now.
async fn lab(tools: Arc<FakeNetworkTools>, network: FakeNetwork) -> (Core, Arc<FakeClock>) {
    let core = Setup::new(FakeVmware::default())
        .with_network(Arc::new(network))
        .with_network_tools(tools)
        .build()
        .await;
    let clock = Arc::new(FakeClock::new(OffsetDateTime::now_utc(), FakeZone::central_europe()));
    core.checks.set_clock(clock.clone());
    (core, clock)
}

fn now_ms(clock: &FakeClock) -> i64 {
    use remotely_core::schedules::Clock;
    i64::try_from(clock.now().unix_timestamp_nanos() / 1_000_000).unwrap()
}

async fn row(core: &Core, id: Uuid) -> remotely_core::checks::CheckRow {
    core.checks
        .overview(HistoryRange::Hour)
        .await
        .unwrap()
        .rows
        .into_iter()
        .find(|r| r.check.id == id)
        .unwrap()
}

// ---- Edits -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn checks_are_checked_audited_and_refused_by_the_read_only_lock() {
    let (core, _clock) = lab(Arc::new(FakeNetworkTools::new()), FakeNetwork::default()).await;
    let made = core
        .checks
        .create(check("ssh", address("192.0.2.10"), CheckSpec::Tcp { port: 22 }))
        .await
        .unwrap();
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "check_changed");
    assert_eq!(audit[0].action, "Added a health check");
    assert!(audit[0]
        .detail
        .as_deref()
        .unwrap()
        .contains("TCP port 22 on 192.0.2.10"));

    // A service check reads a session's host; a ping can't go through a jump host; a VM must be here.
    let refused = core
        .checks
        .create(check(
            "nginx",
            address("192.0.2.10"),
            CheckSpec::Service { unit: "nginx".into() },
        ))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("session"), "{refused}");
    let bastion = core
        .sessions
        .create(&core.ctx(), session_input("bastion", "192.0.2.1", 22, None))
        .await
        .unwrap();
    let behind = core
        .sessions
        .create(&core.ctx(), session_input("db01", "db01.test", 22, Some(bastion.id)))
        .await
        .unwrap();
    let refused = core
        .checks
        .create(check(
            "ping db01",
            ProbeTarget::Session { session_id: behind.id },
            CheckSpec::Ping,
        ))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("jump host 'bastion'"), "{refused}");
    assert!(core
        .checks
        .create(check(
            "vm",
            ProbeTarget::Vm {
                vm_key: r"C:\VMs\gone\gone.vmx".into()
            },
            CheckSpec::Ping
        ))
        .await
        .is_err());

    // While presenting with the lock, edits are refused; runs (reads) go on.
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    assert!(core
        .checks
        .create(check("web", address("192.0.2.11"), CheckSpec::Ping))
        .await
        .is_err());
    assert!(core.checks.set_paused(made.id, true).await.is_err());
    assert!(core.checks.delete(made.id).await.is_err());
    assert_eq!(core.checks.run_due().await.unwrap(), 1, "a run only reads");
    core.presentation
        .set(Presentation {
            enabled: false,
            read_only: false,
        })
        .await
        .unwrap();

    core.checks.set_paused(made.id, true).await.unwrap();
    assert_eq!(row(&core, made.id).await.status, CheckStatus::Paused);
    core.checks.delete(made.id).await.unwrap();
    let audit = core.store.recent_audit(&core.ctx(), 2).await.unwrap();
    assert_eq!(audit[0].action, "Deleted a health check");
    assert_eq!(audit[1].action, "Paused a health check");
    assert!(core.checks.list().await.unwrap().is_empty());
}

// ---- Runs, history and alerts ------------------------------------------------------------------------------------

#[tokio::test]
async fn failed_runs_make_a_check_failing_then_down_and_fire_the_built_in_alert() {
    let tools = Arc::new(FakeNetworkTools::new().with_port("192.0.2.10", 443, FakePort::Banner(Vec::new())));
    let (core, clock) = lab(Arc::clone(&tools), FakeNetwork::default()).await;
    let mut events = core.checks.subscribe();
    let id = core
        .checks
        .create(check("web", address("192.0.2.10"), CheckSpec::Tcp { port: 443 }))
        .await
        .unwrap()
        .id;
    assert_eq!(row(&core, id).await.status, CheckStatus::Pending);
    assert_eq!(core.checks.run_due().await.unwrap(), 1);
    assert_eq!(core.checks.run_due().await.unwrap(), 0, "not due again for a minute");
    let up = row(&core, id).await;
    assert_eq!(up.status, CheckStatus::Up);
    assert!(up.last.as_ref().unwrap().detail.starts_with("port 443 open"));

    // The port closes: failing after one run, down after two.
    tools.set_port("192.0.2.10", 443, FakePort::Refused);
    clock.advance(time::Duration::minutes(1));
    core.checks.run_due().await.unwrap();
    assert_eq!(row(&core, id).await.status, CheckStatus::Failing);
    assert_eq!(core.checks.summary().failing, 1);
    clock.advance(time::Duration::minutes(1));
    core.checks.run_due().await.unwrap();
    let down = row(&core, id).await;
    assert_eq!(down.status, CheckStatus::Down);
    assert_eq!(down.failures, 2);
    assert_eq!(core.checks.summary().down, 1);
    let mut saw_down = false;
    while let Ok(event) = events.try_recv() {
        if let CheckEvent::Result { status, .. } = event {
            saw_down |= status == CheckStatus::Down;
        }
    }
    assert!(saw_down, "the window hears of it");

    // MO-07's built-in rule fires on the next metrics round.
    let t = now_ms(&clock);
    core.metrics.collect_once_at(t).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    let alert = list
        .alerts
        .iter()
        .find(|a| a.metric == AlertMetric::CheckDown)
        .expect("a check-down alert");
    assert_eq!(alert.target.kind, AlertTargetKind::Check);
    assert_eq!(alert.target.key, id.to_string());
    assert!(
        alert.message.contains("closed (connection refused)"),
        "{}",
        alert.message
    );

    // Up again: the alert resolves once a minute of rounds has seen it clear.
    tools.set_port("192.0.2.10", 443, FakePort::Banner(Vec::new()));
    clock.advance(time::Duration::minutes(1));
    core.checks.run_due().await.unwrap();
    assert_eq!(row(&core, id).await.status, CheckStatus::Up);
    core.metrics.collect_once_at(t + 5_000).await;
    core.metrics.collect_once_at(t + 70_000).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    let alert = list.alerts.iter().find(|a| a.metric == AlertMetric::CheckDown).unwrap();
    assert_eq!(alert.resolution, Some(Resolution::Cleared));

    // The history: four runs, newest first; uptime over the hour is 2 of 4.
    let history = core.checks.history(id, HistoryRange::Hour).await.unwrap();
    let results: Vec<RunResult> = history.results.iter().map(|r| r.result).collect();
    assert_eq!(
        results,
        [RunResult::Up, RunResult::Down, RunResult::Down, RunResult::Up]
    );
    assert_eq!(history.row.uptime, Some(50.0));
    assert!(!history.row.spark.is_empty());
}

#[tokio::test]
async fn a_restart_picks_up_where_the_history_left_off_and_old_results_are_pruned() {
    let tools = Arc::new(FakeNetworkTools::new());
    let (core, clock) = lab(Arc::clone(&tools), FakeNetwork::default()).await;
    let id = core
        .checks
        .create(check("web", address("192.0.2.10"), CheckSpec::Tcp { port: 443 }))
        .await
        .unwrap()
        .id;
    // Ten days ago, then twice now: refused each time.
    clock.set(OffsetDateTime::now_utc() - time::Duration::days(10));
    core.checks.run_due().await.unwrap();
    clock.set(OffsetDateTime::now_utc());
    core.checks.run_due().await.unwrap();
    clock.advance(time::Duration::minutes(1));
    core.checks.run_due().await.unwrap();
    assert_eq!(row(&core, id).await.status, CheckStatus::Down);

    // Another core on the same checks (a restart) reads the state from the history.
    core.checks.leave().await;
    assert_eq!(row(&core, id).await.status, CheckStatus::Down, "from the history");
    assert_eq!(
        row(&core, id).await.failures,
        2,
        "the last runs in a row, from the history"
    );

    // MO-06's prune (7 days by default) removes the old run, audited with the history's.
    let report = core.history.prune().await.unwrap();
    assert_eq!(report.removed.check_results, 1);
    let results = core.checks.history(id, HistoryRange::Week).await.unwrap().results;
    assert_eq!(results.len(), 2);
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "history_pruned");
    assert!(audit[0].detail.as_deref().unwrap().contains("1 health check result"));
}

#[tokio::test]
async fn dns_and_ping_checks_read_from_this_pc() {
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_records(
                "web01.example.com",
                RecordType::A,
                &[("web01.example.com", 300, "192.0.2.10")],
            )
            .with_dns_failure("gone.example.com", RecordType::A, DnsFailure::NoSuchName),
    );
    let (core, _clock) = lab(Arc::clone(&tools), FakeNetwork::default()).await;
    let dns = |expect: Option<&str>| CheckSpec::Dns {
        record_type: RecordType::A,
        server: None,
        expect: expect.map(str::to_owned),
    };
    let ok = core
        .checks
        .create(check("dns", address("web01.example.com"), dns(Some("192.0.2.10"))))
        .await
        .unwrap();
    let moved = core
        .checks
        .create(check(
            "dns moved",
            address("web01.example.com"),
            dns(Some("192.0.2.99")),
        ))
        .await
        .unwrap();
    let gone = core
        .checks
        .create(check("dns gone", address("gone.example.com"), dns(None)))
        .await
        .unwrap();
    let ping = core
        .checks
        .create(check("ping", address("192.0.2.10"), CheckSpec::Ping))
        .await
        .unwrap();
    let silent = core
        .checks
        .create(check("ping silent", address("192.0.2.12"), CheckSpec::Ping))
        .await
        .unwrap();
    tools.set_silent("192.0.2.12", true);
    assert_eq!(core.checks.run_due().await.unwrap(), 5);
    let last = |r: remotely_core::checks::CheckRow| r.last.unwrap();
    let ok = last(row(&core, ok.id).await);
    assert_eq!(ok.result, RunResult::Up);
    assert_eq!(ok.detail, "resolves to 192.0.2.10");
    let moved = last(row(&core, moved.id).await);
    assert_eq!(moved.result, RunResult::Down);
    assert_eq!(moved.detail, "resolves to 192.0.2.10, not 192.0.2.99");
    assert_eq!(last(row(&core, gone.id).await).detail, "no such name");
    assert_eq!(last(row(&core, ping.id).await).result, RunResult::Up);
    let silent = last(row(&core, silent.id).await);
    assert_eq!(silent.result, RunResult::Down);
    assert!(silent.detail.contains("no reply"), "{}", silent.detail);
}

// ---- HTTP --------------------------------------------------------------------------------------------------------

/// An HTTP/1.1 server on 127.0.0.1 answering by path, some answers hostile.
async fn http_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let path = read_path(&mut stream).await;
                answer(&mut stream, &path).await;
            });
        }
    });
    at
}

async fn read_path<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    text.split_whitespace().nth(1).unwrap_or("/").to_owned()
}

async fn answer<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, path: &str) {
    let simple = |status: &str, extra: &str, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    };
    match path {
        "/ok" => {
            let _ = stream
                .write_all(simple("200 OK", "", "all good: ready").as_bytes())
                .await;
        }
        "/down" => {
            let _ = stream
                .write_all(simple("503 Service Unavailable", "", "").as_bytes())
                .await;
        }
        "/move" => {
            let _ = stream
                .write_all(simple("302 Found", "Location: /ok\r\n", "").as_bytes())
                .await;
        }
        "/away" => {
            let _ = stream
                .write_all(simple("301 Moved", "Location: http://other.test/ok\r\n", "").as_bytes())
                .await;
        }
        "/loop" => {
            let _ = stream
                .write_all(simple("302 Found", "Location: /loop\r\n", "").as_bytes())
                .await;
        }
        "/file" => {
            let _ = stream
                .write_all(simple("302 Found", "Location: file:///etc/passwd\r\n", "").as_bytes())
                .await;
        }
        // 2 MB of filler, then the text: past what the check reads.
        "/huge" => {
            let head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            if stream.write_all(head.as_bytes()).await.is_ok() {
                let chunk = vec![b'x'; 64 * 1024];
                for _ in 0..32 {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                let _ = stream.write_all(b"ready").await;
            }
        }
        // Headers without end.
        "/headers" => {
            if stream.write_all(b"HTTP/1.1 200 OK\r\n").await.is_ok() {
                for i in 0..100_000 {
                    if stream
                        .write_all(format!("X-Filler-{i}: aaaaaaaaaaaaaaaa\r\n").as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        // Never answers.
        "/silent" => tokio::time::sleep(Duration::from_secs(30)).await,
        _ => {
            let _ = stream.write_all(simple("404 Not Found", "", "").as_bytes()).await;
        }
    }
}

#[tokio::test]
async fn http_checks_read_the_status_body_and_redirects_and_stay_bounded() {
    let server = http_server().await;
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_port("192.0.2.20", 80, FakePort::Forward(server))
            .with_port("192.0.2.21", 80, FakePort::Forward(server)),
    );
    let network = FakeNetwork::default()
        .with_name("web.test", "192.0.2.20")
        .with_name("other.test", "192.0.2.21");
    let (core, _clock) = lab(Arc::clone(&tools), network).await;
    let with_text = |path: &str, text: &str| {
        let mut spec = http(path);
        if let CheckSpec::Http { body_contains, .. } = &mut spec {
            *body_contains = Some(text.into());
        }
        spec
    };
    let cases = [
        ("ok", http("/ok"), RunResult::Up, "HTTP 200 in"),
        ("text", with_text("/ok", "ready"), RunResult::Up, "HTTP 200 in"),
        (
            "no text",
            with_text("/ok", "broken"),
            RunResult::Down,
            "doesn't hold the text",
        ),
        ("down", http("/down"), RunResult::Down, "HTTP 503 (expected 200-299)"),
        ("moved", http("/move"), RunResult::Up, "HTTP 200 after 1 redirect"),
        ("away", http("/away"), RunResult::Up, "HTTP 200 after 1 redirect"),
        ("loop", http("/loop"), RunResult::Down, "more than 5 redirects"),
        ("file", http("/file"), RunResult::Down, "doesn't follow"),
        (
            "huge",
            with_text("/huge", "ready"),
            RunResult::Down,
            "its first 256 KB read",
        ),
        ("headers", http("/headers"), RunResult::Down, "HTTP failed"),
        ("silent", http("/silent"), RunResult::Down, "no answer in time"),
        ("missing", http("/missing"), RunResult::Down, "HTTP 404"),
    ];
    let mut ids = Vec::new();
    for (name, spec, _, _) in &cases {
        let mut input = check(name, address("web.test"), spec.clone());
        input.timeout_secs = 3;
        ids.push(core.checks.create(input).await.unwrap().id);
    }
    // Not following redirects: the redirect's own status answers.
    let mut not_followed = http("/move");
    if let CheckSpec::Http {
        follow_redirects,
        status_min,
        status_max,
        ..
    } = &mut not_followed
    {
        *follow_redirects = false;
        *status_min = 300;
        *status_max = 399;
    }
    let plain = core
        .checks
        .create(check("redirect only", address("web.test"), not_followed))
        .await
        .unwrap()
        .id;
    assert_eq!(core.checks.run_due().await.unwrap(), cases.len() + 1);
    for ((name, _, result, detail), id) in cases.iter().zip(&ids) {
        let last = row(&core, *id).await.last.unwrap();
        assert_eq!(last.result, *result, "{name}: {}", last.detail);
        assert!(last.detail.contains(detail), "{name}: {}", last.detail);
    }
    let last = row(&core, plain).await.last.unwrap();
    assert_eq!(last.result, RunResult::Up, "{}", last.detail);
    assert!(last.detail.starts_with("HTTP 302 in"), "{}", last.detail);
    // Every connection went to a test address: nothing left 127.0.0.1.
    assert!(tools
        .connects()
        .iter()
        .all(|a| a.ip().to_string().starts_with("192.0.2.")));
}

// ---- TLS -----------------------------------------------------------------------------------------------------------

/// An HTTPS server on 127.0.0.1 with a certificate for `names`, made now, valid for `days`.
async fn https_server(names: &[&str], days: i64) -> SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
    params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(days) + time::Duration::hours(12);
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let path = read_path(&mut tls).await;
                    answer(&mut tls, &path).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    at
}

fn trusted() -> TrustVerdict {
    TrustVerdict {
        trusted: true,
        problems: Vec::new(),
        built: Vec::new(),
    }
}

#[tokio::test]
async fn https_and_certificate_checks_use_windows_trust_and_the_name_and_warn_before_expiry() {
    let server = https_server(&["web.test"], 10).await;
    let tools = Arc::new(
        FakeNetworkTools::new()
            .with_port("192.0.2.30", 443, FakePort::Forward(server))
            .with_verdict(trusted()),
    );
    let network = FakeNetwork::default()
        .with_name("web.test", "192.0.2.30")
        .with_name("alias.test", "192.0.2.30");
    let (core, clock) = lab(Arc::clone(&tools), network).await;
    let https = |allow: bool| {
        let mut spec = http("/ok");
        if let CheckSpec::Http {
            https,
            allow_invalid_cert,
            ..
        } = &mut spec
        {
            *https = true;
            *allow_invalid_cert = allow;
        }
        spec
    };
    let site = core
        .checks
        .create(check("site", address("web.test"), https(false)))
        .await
        .unwrap()
        .id;
    let alias = core
        .checks
        .create(check("alias", address("alias.test"), https(false)))
        .await
        .unwrap()
        .id;
    let alias_allowed = core
        .checks
        .create(check("alias allowed", address("alias.test"), https(true)))
        .await
        .unwrap()
        .id;
    let cert = core
        .checks
        .create(check(
            "cert",
            address("web.test"),
            CheckSpec::Certificate {
                port: 443,
                server_name: None,
                allow_untrusted: false,
            },
        ))
        .await
        .unwrap()
        .id;
    core.checks.run_due().await.unwrap();
    let core_ref = &core;
    let last = |id| async move { row(core_ref, id).await.last.unwrap() };
    assert_eq!(last(site).await.result, RunResult::Up, "{}", last(site).await.detail);
    let wrong_name = last(alias).await;
    assert_eq!(wrong_name.result, RunResult::Down);
    assert!(
        wrong_name.detail.contains("doesn't name alias.test"),
        "{}",
        wrong_name.detail
    );
    assert_eq!(last(alias_allowed).await.result, RunResult::Up);
    let cert_run = last(cert).await;
    assert_eq!(cert_run.result, RunResult::Up, "{}", cert_run.detail);
    assert_eq!(cert_run.cert_days, Some(10));
    assert_eq!(cert_run.detail, "valid for 10 more days");

    // MO-07: the built-in rule warns under 14 days.
    core.metrics.collect_once_at(now_ms(&clock)).await;
    let list = core.alerts.list(AlertQuery::default()).await.unwrap();
    let expiring = list
        .alerts
        .iter()
        .find(|a| a.metric == AlertMetric::CertExpiring)
        .expect("an expiring alert");
    assert_eq!(expiring.target.name, "cert");
    assert_eq!(expiring.message, "The certificate expires in 10 days, under 14 days");

    // Windows stops trusting it: the HTTPS and certificate checks fail, unless they allow it.
    tools.set_verdict(TrustVerdict {
        trusted: false,
        problems: vec!["its root isn't one this PC trusts".into()],
        built: Vec::new(),
    });
    clock.advance(time::Duration::minutes(1));
    core.checks.run_due().await.unwrap();
    let untrusted = last(site).await;
    assert_eq!(untrusted.result, RunResult::Down);
    assert!(
        untrusted.detail.contains("isn't trusted: its root"),
        "{}",
        untrusted.detail
    );
    assert_eq!(last(cert).await.result, RunResult::Down);
    assert_eq!(last(cert).await.cert_days, Some(10), "days left are known either way");
}

// ---- SSH: service checks and jump hosts ----------------------------------------------------------------------

/// A test SSH server with host facts, its saved and trusted session on the app's vault, and a core on the real russh
/// adapter.
async fn ssh_lab(tools: Arc<FakeNetworkTools>) -> (Core, Arc<FakeClock>, TestSshServer, Uuid) {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_host_facts(HostFixture::ubuntu());
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .with_network_tools(tools)
        .build()
        .await;
    let clock = Arc::new(FakeClock::new(OffsetDateTime::now_utc(), FakeZone::central_europe()));
    core.checks.set_clock(clock.clone());
    let secret = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "server",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let mut input = session_input("app01", "127.0.0.1", server.port(), None);
    input.auth = SessionAuth::Password {
        password_id: Some(secret),
    };
    let session = core.sessions.create(&core.ctx(), input).await.unwrap();
    core.known_hosts
        .trust(
            &core.ctx(),
            &HostKey {
                host: "127.0.0.1".into(),
                port: server.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: server.host_key_fingerprint(),
            },
            None,
        )
        .await
        .unwrap();
    (core, clock, server, session.id)
}

#[tokio::test]
async fn service_checks_read_systemd_on_one_held_login_and_let_it_go() {
    let (core, clock, server, session) = ssh_lab(Arc::new(FakeNetworkTools::new())).await;
    core.toolbox.set_jump_idle(Duration::from_millis(200));
    let on = |unit: &str| {
        check(
            unit,
            ProbeTarget::Session { session_id: session },
            CheckSpec::Service { unit: unit.into() },
        )
    };
    let nginx = core.checks.create(on("nginx")).await.unwrap().id;
    let cups = core.checks.create(on("cups.service")).await.unwrap().id;
    assert!(core.checks.create(on("nginx; reboot")).await.is_err());
    for _ in 0..3 {
        core.checks.run_due().await.unwrap();
        clock.advance(time::Duration::minutes(1));
        // Longer than the idle time: the hold keeps the connection until the next run.
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let nginx_last = row(&core, nginx).await.last.unwrap();
    assert_eq!(nginx_last.result, RunResult::Up, "{}", nginx_last.detail);
    assert_eq!(nginx_last.detail, "nginx is active");
    let cups_last = row(&core, cups).await.last.unwrap();
    assert_eq!(cups_last.result, RunResult::Down);
    assert_eq!(cups_last.detail, "cups.service is inactive");
    assert_eq!(server.connections(), 1, "one login for six runs");
    assert_eq!(core.toolbox.kept_jump_connections(), 1);

    // Paused and deleted, nothing holds it: it closes once idle.
    core.checks.set_paused(nginx, true).await.unwrap();
    core.checks.delete(cups).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while core.toolbox.kept_jump_connections() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the kept connection closes");

    // A locked vault makes the run unknown, not down.
    core.checks.set_paused(nginx, false).await.unwrap();
    core.vault.lock(&core.ctx()).await.unwrap();
    core.checks.run_due().await.unwrap();
    let locked = row(&core, nginx).await;
    assert_eq!(locked.status, CheckStatus::Unknown, "{:?}", locked.last);
    assert!(locked.last.unwrap().detail.contains("couldn't check"));
}

#[tokio::test]
async fn a_check_behind_a_jump_host_logs_in_to_it_once() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let (core, clock, bastion, jump) = ssh_lab(Arc::new(FakeNetworkTools::new())).await;
    let behind = core
        .sessions
        .create(&core.ctx(), session_input("local", "127.0.0.1", 22, Some(jump)))
        .await
        .unwrap();
    let id = core
        .checks
        .create(check(
            "behind",
            ProbeTarget::Session { session_id: behind.id },
            CheckSpec::Tcp { port },
        ))
        .await
        .unwrap()
        .id;
    for _ in 0..4 {
        core.checks.run_due().await.unwrap();
        clock.advance(time::Duration::minutes(1));
    }
    let last = row(&core, id).await.last.unwrap();
    assert_eq!(last.result, RunResult::Up, "{}", last.detail);
    assert_eq!(bastion.connections(), 1, "four runs, one login to the jump host");
}

// ---- FD-07 ---------------------------------------------------------------------------------------------------------

const PASSPHRASE: &str = "correct horse battery staple 42";

async fn export(core: &Core, dir: &Path) -> PathBuf {
    let path = dir.join(format!("export-{}.remotely", Uuid::new_v4().simple()));
    let report = core
        .transfer
        .export(
            &core.ctx(),
            &path,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: false,
                vault_password: None,
            },
            &core.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    assert_eq!(report.checks, core.checks.list().await.unwrap().len());
    path
}

#[tokio::test]
async fn definitions_travel_in_an_export_with_their_sessions() {
    let dir = temp_folder("checks-transfer");
    let (from, _) = lab(Arc::new(FakeNetworkTools::new()), FakeNetwork::default()).await;
    let web = from
        .sessions
        .create(&from.ctx(), session_input("web01", "web01.example.com", 22, None))
        .await
        .unwrap();
    from.checks
        .create(check(
            "ssh",
            ProbeTarget::Session { session_id: web.id },
            CheckSpec::Tcp { port: 22 },
        ))
        .await
        .unwrap();
    let mut paused = check(
        "dns",
        address("web01.example.com"),
        CheckSpec::Dns {
            record_type: RecordType::A,
            server: None,
            expect: None,
        },
    );
    paused.paused = true;
    from.checks.create(paused).await.unwrap();
    from.checks.run_due().await.unwrap();
    let path = export(&from, &dir).await;

    let (to, _) = lab(Arc::new(FakeNetworkTools::new()), FakeNetwork::default()).await;
    let preview = to
        .transfer
        .open(&to.ctx(), &path, SecretString::new(PASSPHRASE), &to.vault)
        .await
        .unwrap();
    assert_eq!(preview.checks.len(), 2);
    let ssh = preview.checks.iter().find(|c| c.name == "ssh").unwrap();
    assert!(ssh.detail.contains("TCP port 22 on web01"), "{}", ssh.detail);
    let report = to
        .transfer
        .commit(
            &to.ctx(),
            TransferCommit {
                preview_id: preview.id,
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![],
                groups: vec![],
                checks: vec![],
                catalog: Default::default(),
                folder_defaults: vec![],
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
            },
            &to.sessions,
            &to.vault,
            &to.known_hosts,
            &to.snippets,
        )
        .await
        .unwrap();
    assert_eq!(report.checks.added, 2, "{:?}", report.problems);
    let here = to.checks.list().await.unwrap();
    let ssh = here.iter().find(|c| c.name == "ssh").unwrap();
    let web_here = to.store.list_sessions(&to.ctx()).await.unwrap();
    assert_eq!(
        ssh.target,
        ProbeTarget::Session {
            session_id: web_here[0].id
        },
        "on the session it became here"
    );
    assert!(here.iter().find(|c| c.name == "dns").unwrap().paused);
    assert!(
        to.checks
            .history(ssh.id, HistoryRange::Day)
            .await
            .unwrap()
            .results
            .is_empty(),
        "results stay on the PC they ran on"
    );

    // The same file again: both are here already.
    let again = to
        .transfer
        .open(&to.ctx(), &path, SecretString::new(PASSPHRASE), &to.vault)
        .await
        .unwrap();
    assert!(
        again.checks.iter().all(|c| c.default_action == ItemAction::Skip),
        "{:?}",
        again.checks
    );
    let _ = std::fs::remove_dir_all(dir);
}
