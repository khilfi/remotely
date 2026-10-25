//! SS-10: a password typed with MultiExec at a sudo prompt passes straight through and is never kept:
//! not in any log line the core or russh writes (captured at TRACE level), not in the database (jobs,
//! audit log, anything else), not in the terminals' output. In a file of its own because the log
//! capture is process-wide.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Setup;
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::multiexec::{InputOutcome, LineMode, MultiExecEvent};
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use sqlx::{Column, Row};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);

struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

async fn database_text(core: &remotely_core::Core) -> String {
    let pool = core.store.pool();
    let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
        .fetch_all(pool)
        .await
        .unwrap();
    let mut out = String::new();
    for table in tables {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM \"{table}\"")))
            .fetch_all(pool)
            .await
            .unwrap();
        for row in &rows {
            for column in row.columns() {
                let i = column.ordinal();
                if let Ok(Some(text)) = row.try_get::<Option<String>, _>(i) {
                    out.push_str(&text);
                } else if let Ok(Some(bytes)) = row.try_get::<Option<Vec<u8>>, _>(i) {
                    out.push_str(&String::from_utf8_lossy(&bytes));
                }
                out.push('\n');
            }
        }
    }
    out
}

/// Reads a pane's output until `needle` shows.
async fn expect(output: &mut tokio::sync::mpsc::Receiver<Vec<u8>>, seen: &mut String, needle: &str) {
    let found = timeout(WAIT, async {
        while !seen.contains(needle) {
            let chunk = output.recv().await.expect("output ended");
            seen.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await;
    assert!(found.is_ok(), "no {needle:?} in {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_typed_with_multiexec_is_never_logged_or_kept() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&logs);
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || Capture(Arc::clone(&writer)))
        .try_init()
        .unwrap();

    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    // SS-04, AP-06: one vault password for several test servers, given once.
    common::vault_password_given(&core).await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        ..TerminalTuning::default()
    });
    let login = new_password();
    let sudo = new_password();
    let login_id = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            "login",
            SecretString::new(login.as_str()),
        )
        .await
        .unwrap()
        .id;
    let mut servers = Vec::new();
    let mut panes = Vec::new();
    for name in ["web01", "web02"] {
        let server = TestSshServer::start()
            .await
            .with_password("alice", &login)
            .with_sudo(SudoMode::Password(sudo.clone()));
        let key = HostKey {
            host: "127.0.0.1".into(),
            port: server.port(),
            key_type: "ssh-ed25519".into(),
            fingerprint: server.host_key_fingerprint(),
        };
        core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
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
                        password_id: Some(login_id),
                    },
                    jump_session_id: None,
                    jump_direct: false,
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
            .id;
        let mut handle = core
            .terminals
            .open(&core.ctx, session, PtySize { cols: 80, rows: 24 })
            .await
            .unwrap();
        timeout(WAIT, async {
            while let Some(event) = handle.events.recv().await {
                if matches!(
                    event,
                    TerminalEvent::Status {
                        status: TerminalStatus::Connected
                    }
                ) {
                    return;
                }
            }
        })
        .await
        .unwrap();
        let mut seen = String::new();
        expect(&mut handle.output, &mut seen, "$ ").await;
        servers.push(server);
        panes.push((handle, seen));
    }
    let ids: Vec<Uuid> = panes.iter().map(|(h, _)| h.id).collect();
    core.multiexec.set_targets(ids.clone()).await.unwrap();
    let mut events = core.multiexec.subscribe();

    let InputOutcome::Held { line_id, .. } = core.multiexec.input(ids[0], b"sudo whoami\r".to_vec()).await.unwrap()
    else {
        panic!("a line is held");
    };
    timeout(WAIT, async {
        loop {
            if let MultiExecEvent::LineDone { line_id: id, .. } = events.recv().await.unwrap() {
                if id == line_id {
                    return;
                }
            }
        }
    })
    .await
    .unwrap();
    for (handle, seen) in &mut panes {
        expect(&mut handle.output, seen, "[sudo] password for alice: ").await;
    }
    // Typed one key at a time, as a person would.
    for byte in sudo.bytes() {
        let outcome = core.multiexec.input(ids[0], vec![byte]).await.unwrap();
        assert!(
            matches!(
                outcome,
                InputOutcome::Typed {
                    mode: LineMode::Password,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
    core.multiexec.input(ids[0], b"\r".to_vec()).await.unwrap();
    for (handle, seen) in &mut panes {
        expect(&mut handle.output, seen, "ok\r\n$ ").await;
        assert!(!seen.contains(&sudo), "{seen}");
    }
    for server in &servers {
        assert!(server.log().contains(&"sudo alice ok".to_owned()), "{:?}", server.log());
        assert!(!server.log().iter().any(|l| l.contains(&sudo)));
    }
    core.multiexec.stop().await.unwrap();

    let database = database_text(&core).await;
    assert!(database.contains("sudo whoami"), "the line itself is journaled");
    assert!(!database.contains(&sudo), "the password is in the database");
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "the capture works");
    assert!(!logs.contains(&sudo), "the password is in a log line");
    assert!(!logs.contains(&login), "the login password is in a log line");
}
