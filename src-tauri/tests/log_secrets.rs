//! QL-15, CLAUDE.md rule 7: the app's log file never holds a secret. A run that uses a login password and a
//! sudo password from the vault (a terminal logging in, a bulk sudo run, one host refusing the password), a UI crash
//! and a crash report that both carry a password, all logged at TRACE through the same daily file writer the app
//! uses. Then every file in the logs folder is read. Against the local test SSH server only. In a file of its own
//! because the log subscriber is process-wide.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use remotely_core::adapters::containers::cli::CliEngines;
use remotely_core::adapters::remote::{AgentSource, PtySize, RusshAdapter};
use remotely_core::command_bus::{Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::{FakeHostCounters, FakeKeyProtector, FakeNetwork, FakeUpdater, FakeVirtualBox, FakeVmware};
use remotely_core::jobs::{ExecTuning, JobEvent, JobLimits, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::Store;
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::vault::{LocalVault, SecretKind, SecretString, Vault, VaultOptions};
use remotely_core::{Adapters, Core};
use remotely_lib::diagnostics::{self, CrashReport};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn everything_in(dir: &Path) -> String {
    let mut text = String::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        text.push_str(&String::from_utf8_lossy(&std::fs::read(&path).unwrap()));
        text.push('\n');
    }
    text
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_log_file_never_holds_a_secret() {
    let dir = std::env::temp_dir().join(format!("remotely-logs-{}", Uuid::new_v4()));
    let logs = dir.join(diagnostics::LOG_FOLDER);
    let appender = diagnostics::file_appender(&logs).unwrap();
    tracing_subscriber::registry()
        .with(EnvFilter::new("trace"))
        .with(fmt::layer().with_ansi(false).with_writer(appender))
        .try_init()
        .unwrap();

    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let master = new_password();
    let vault = LocalVault::open(
        store.clone(),
        ctx,
        Arc::new(FakeKeyProtector::new()),
        VaultOptions::insecure_fast(),
    )
    .await
    .unwrap();
    vault
        .setup(&ctx, SecretString::new(master.as_str()), true)
        .await
        .unwrap();
    let adapters = Adapters {
        vmware: Arc::new(FakeVmware::default()),
        virtualbox: Arc::new(FakeVirtualBox::new()),
        remote: Arc::new(RusshAdapter::new()),
        vault: Arc::new(vault),
        host_counters: Arc::new(FakeHostCounters::default()),
        updater: Arc::new(FakeUpdater::default()),
        network: Arc::new(FakeNetwork::default()),
        containers: Arc::new(CliEngines::without_this_pc()),
    };
    let core = Core::assemble(store, ctx, adapters, JobLimits::default())
        .await
        .unwrap();
    let no_agent = AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4()));
    core.jobs.set_exec_tuning(ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: no_agent.clone(),
        ..ExecTuning::default()
    });
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        agent: no_agent,
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
    let mut servers = Vec::new();
    let mut sessions = Vec::new();
    for (name, mode) in [
        ("right", SudoMode::Password(sudo.clone())),
        ("echoes", SudoMode::EchoesPassword(sudo.clone())),
        ("wrong", SudoMode::Password(new_password())),
    ] {
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
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: Environment::Lab,
            color: None,
            tags: vec![],
            vm_id: None,
        };
        sessions.push(core.sessions.create(&core.ctx, input).await.unwrap().id);
        servers.push(server);
    }

    // A terminal logs in with the vault's login password.
    let mut pane = core
        .terminals
        .open(&core.ctx, sessions[0], PtySize { cols: 80, rows: 24 })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(event) = pane.events.recv().await {
            if let TerminalEvent::Status {
                status: TerminalStatus::Connected,
            } = event
            {
                break;
            }
        }
    })
    .await
    .expect("the terminal connected");

    // A bulk run with sudo on every host; one refuses the password, one prints what it read.
    let mut events = core.jobs.subscribe();
    let command = Command::RemoteExec {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: "whoami\ncat\necho done".into(),
        sudo: true,
        sudo_password_id: Some(sudo_id),
        trust_new_host_keys: false,
        timeout_secs: Some(30),
    };
    let SubmitOutcome::Queued { job_id: job, .. } = core.bus.submit(&core.ctx, command).await.unwrap() else {
        panic!("whoami, cat and echo only read");
    };
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let JobEvent::Finished { job_id, status, .. } = events.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(status, JobStatus::PartiallyFailed, "one host refused the password");

    // A UI crash and a panic whose messages carry secrets by mistake.
    diagnostics::ui_error(
        "Terminal".into(),
        format!("sudo failed: password={sudo}"),
        Some(format!("at Pane (token: {login})")),
    );
    CrashReport::new(
        &format!("could not log in with --password {login}"),
        "x.rs:1:1".into(),
        "0: main".into(),
    )
    .write(&logs)
    .unwrap();
    core.shutdown().await;
    drop(servers);

    let text = everything_in(&logs);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(text.contains("the UI crashed"), "the UI error is logged");
    assert!(text.contains("panicked"), "the crash report is there");
    assert!(text.len() > 1_000, "the run was logged: {} bytes", text.len());
    for (what, secret) in [
        ("login password", &login),
        ("sudo password", &sudo),
        ("master password", &master),
    ] {
        assert!(!text.contains(secret.as_str()), "the {what} is in the logs folder");
    }
}
