//! BX-07: the sudo password from the vault never leaks. Not into what a host prints, not into errors,
//! job events, the job journal or anything else in the database, the audit log, exports, the SSH
//! server's log, nor any log line the core or russh writes (all captured at TRACE level). In a file
//! of its own because the log capture is process-wide.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::Setup;
use remotely_core::adapters::remote::AgentSource;
use remotely_core::bulk::{ExportFormat, GroupOptions};
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::{ExecTuning, JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::ApprovalStep;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::{SecretKind, SecretString};
use sqlx::{Column, Row};
use uuid::Uuid;

/// Appends every log line to a shared buffer.
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

/// Every text and blob in every table, as text.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sudo_password_never_leaks() {
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
    core.jobs.set_exec_tuning(ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        ..ExecTuning::default()
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
    let sudo_id = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            "sudo",
            SecretString::new(sudo.as_str()),
        )
        .await
        .unwrap()
        .id;

    let modes = [
        ("right", SudoMode::Password(sudo.clone())),
        // A broken sudo that prints what it read: the client must scrub it.
        ("echoes", SudoMode::EchoesPassword(sudo.clone())),
        // NOPASSWD: sudo never reads stdin, so the script must not be able to.
        ("nopasswd", SudoMode::NoPassword),
        ("wrong", SudoMode::Password(new_password())),
    ];
    let mut servers = Vec::new();
    let mut ids = Vec::new();
    for (name, mode) in modes {
        let server = TestSshServer::start()
            .await
            .with_password("alice", &login)
            .with_sudo(mode);
        let key = HostKey {
            host: "127.0.0.1".into(),
            port: server.port(),
            key_type: "ssh-ed25519".into(),
            fingerprint: server.host_key_fingerprint(),
        };
        core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
        let input = SessionInput {
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
        };
        ids.push(core.sessions.create(&core.ctx, input).await.unwrap().id);
        servers.push(server);
    }

    let mut events = core.jobs.subscribe();
    let command = Command::RemoteExec {
        targets: ids.iter().map(|id| TargetRef::Session { session_id: *id }).collect(),
        // `cat` reads stdin, where the password went.
        script: "whoami\ncat\necho done".into(),
        sudo: true,
        sudo_password_id: Some(sudo_id),
        trust_new_host_keys: false,
        timeout_secs: Some(30),
        rollout: Default::default(),
    };
    // Read-only commands, so Low; but SS-04, AP-06: the chosen sudo password goes to these hosts for the first
    // time, so the run asks for a confirm and the vault password. The secret never reaches the approval.
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, command).await.unwrap() else {
        panic!("a sudo password new to these hosts asks for the vault password");
    };
    assert!(
        request.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        request.steps
    );
    assert!(!format!("{request:?}").contains(&sudo));
    let job = core
        .bus
        .approve(
            request.id,
            ApprovalAnswers {
                confirmed: true,
                vault_password: Some(SecretString::new(common::VAULT_PASSWORD)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut seen = Vec::new();
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let event = events.recv().await.unwrap();
            seen.push(serde_json::to_string(&event).unwrap());
            if let JobEvent::Finished { job_id, status, .. } = event {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status, JobStatus::PartiallyFailed);

    // What each host did.
    let opts = GroupOptions::default();
    let results = core.bulk.results(&core.ctx, job, opts).await.unwrap();
    let output = |name: &str| {
        let host = results.hosts.iter().find(|h| h.name == name).unwrap();
        (host.clone(), host.target_key.clone())
    };
    let mut everything = vec![serde_json::to_string(&results).unwrap()];
    for name in ["right", "echoes", "nopasswd"] {
        let (host, key) = output(name);
        assert_eq!(host.status, "succeeded", "{name}: {:?}", host.error);
        let out = core.bulk.host_output(&core.ctx, job, &key).await.unwrap();
        let expected = if name == "echoes" {
            "[redacted]\nroot\ndone\n"
        } else {
            "root\ndone\n"
        };
        assert_eq!(out.stdout, expected, "{name}");
        assert_eq!(out.stderr, "", "{name}: sudo's prompt is removed");
        everything.push(serde_json::to_string(&out).unwrap());
    }
    let (wrong, _) = output("wrong");
    assert_eq!(wrong.error_code.as_deref(), Some("sudo_password_refused"));

    // Everywhere the password could have gone.
    for format in [ExportFormat::Csv, ExportFormat::Json, ExportFormat::Html] {
        everything.push(core.bulk.render(&core.ctx, job, format, opts).await.unwrap().0);
    }
    for group in &results.groups {
        for other in &results.groups {
            let diff = core
                .bulk
                .diff(&core.ctx, job, &group.sample, &other.sample, opts)
                .await
                .unwrap();
            everything.push(serde_json::to_string(&diff).unwrap());
        }
    }
    everything.extend(seen);
    everything.push(database_text(&core).await);
    for entry in core.store.recent_audit(&core.ctx, 500).await.unwrap() {
        everything.push(serde_json::to_string(&entry).unwrap());
    }
    for server in &servers {
        everything.extend(server.log());
    }
    let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    assert!(logged.len() > 1000, "the log capture works ({} bytes)", logged.len());
    everything.push(logged);

    for (i, text) in everything.iter().enumerate() {
        assert!(!text.contains(&sudo), "the sudo password leaked into item {i}");
        assert!(!text.contains(&login), "the login password leaked into item {i}");
    }
    // Sudo's prompt marker is not left in anything stored either.
    assert!(!database_text(&core).await.contains("remotely-sudo-"));
}
