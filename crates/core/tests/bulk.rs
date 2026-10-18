//! Bulk execution (BX-01 to BX-07), end to end: the command bus, the policy engine, the job runner and
//! the real russh adapter against SSH servers on 127.0.0.1 (`fakes::ssh_server`), with passwords
//! made at run time and the app's own vault (fake DPAPI). Target picking and the parallel limit use
//! the fake remote adapter. No real host is contacted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{vm, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::AgentSource;
use remotely_core::bulk::{ExportFormat, GroupKind, GroupOptions, TargetPicks};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeRemote, FakeVmware};
use remotely_core::inventory::VmFilter;
use remotely_core::jobs::{ExecTuning, JobEvent, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(30);

/// A password nobody wrote down: made at run time, so none is committed.
fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn tuning() -> ExecTuning {
    ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        ..ExecTuning::default()
    }
}

async fn ssh_core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.jobs.set_exec_tuning(tuning());
    core
}

fn session_input(name: &str, port: u16, auth: SessionAuth) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        auth,
        jump_session_id: None,
        startup_command: None,
        environment: Environment::Lab,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

async fn add_password(core: &Core, label: &str, password: &str) -> remotely_core::vault::SecretId {
    core.vault
        .add(&core.ctx, SecretKind::Password, label, SecretString::new(password))
        .await
        .unwrap()
        .id
}

async fn trust(core: &Core, server: &TestSshServer) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
}

/// A session on `server` that logs in as alice with `password` (saved in the vault), its key trusted.
async fn host(core: &Core, server: &TestSshServer, name: &str, password: remotely_core::vault::SecretId) -> Uuid {
    trust(core, server).await;
    core.sessions
        .create(
            &core.ctx,
            session_input(
                name,
                server.port(),
                SessionAuth::Password {
                    password_id: Some(password),
                },
            ),
        )
        .await
        .unwrap()
        .id
}

fn exec(script: &str, sessions: &[Uuid]) -> Command {
    Command::RemoteExec {
        targets: sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: script.into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    }
}

fn with_sudo(command: Command, password: Option<remotely_core::vault::SecretId>) -> Command {
    match command {
        Command::RemoteExec {
            targets,
            script,
            trust_new_host_keys,
            timeout_secs,
            ..
        } => Command::RemoteExec {
            targets,
            script,
            sudo: true,
            sudo_password_id: password,
            trust_new_host_keys,
            timeout_secs,
        },
        other => other,
    }
}

/// Every answer the request asks for, right.
fn answers(request: &ApprovalRequest) -> ApprovalAnswers {
    let mut a = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => a.typed_target_count = Some(*expected),
            ApprovalStep::Reason => a.reason = Some("CHG-1234".into()),
            ApprovalStep::VaultReauth => a.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            _ => {}
        }
    }
    a
}

/// Submits, approving whatever it needs. Returns the job id.
async fn run(core: &Core, command: Command) -> Uuid {
    match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => {
            let answers = answers(&request);
            core.bus.approve(request.id, answers).await.unwrap()
        }
    }
}

async fn finished(rx: &mut Receiver<JobEvent>, job: Uuid) -> JobStatus {
    tokio::time::timeout(WAIT, async {
        loop {
            if let JobEvent::Finished { job_id, status } = rx.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .expect("job finished in time")
}

// ---- BX-02: a command or script on many hosts --------------------------------------------------

#[tokio::test]
async fn a_script_runs_on_each_host_with_its_output_exit_code_and_duration() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let a = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_hostname("web01");
    let b = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_hostname("web02");
    let ids = [host(&core, &a, "web01", pw).await, host(&core, &b, "web02", pw).await];
    let mut events = core.jobs.subscribe();

    let job = run(&core, exec("hostname\necho to stderr >&2\nexit 3", &ids)).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);

    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.counts.failed, 2);
    assert_eq!(results.groups.len(), 2, "two hostnames, two outputs");
    for host in &results.hosts {
        assert_eq!(host.status, "failed");
        assert_eq!(host.exit_code, Some(3));
        assert_eq!(host.error.as_deref(), Some("exit code 3"));
        assert!(host.duration_ms.is_some());
    }
    let web01 = results.hosts.iter().find(|h| h.name == "web01").unwrap();
    let out = core.bulk.host_output(&core.ctx, job, &web01.target_key).await.unwrap();
    assert_eq!(out.stdout, "web01\n");
    assert_eq!(out.stderr, "to stderr\n");
    assert!(!out.truncated);
    // The whole script went in one exec request, and no password ever reached the server's log.
    let log = a.log();
    assert!(
        log.iter().any(|l| l == "exec hostname\necho to stderr >&2\nexit 3"),
        "{log:?}"
    );
    assert!(!log.iter().any(|l| l.contains(&password)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_hosts_show_grouped_results_within_five_seconds_of_the_slowest() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "fleet", &password).await;
    let mut servers = Vec::new();
    let mut ids = Vec::new();
    for i in 0..50 {
        let release = if i == 7 || i == 31 {
            "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n"
        } else {
            "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n"
        };
        let mut server = TestSshServer::start()
            .await
            .with_password("alice", &password)
            .with_file("/etc/os-release", release);
        if i == 42 {
            server = server.with_exec_delay(Duration::from_millis(1500));
        }
        ids.push(host(&core, &server, &format!("web{i:02}"), pw).await);
        servers.push(server);
    }
    let mut events = core.jobs.subscribe();

    let started = Instant::now();
    let SubmitOutcome::Queued { job_id, .. } = core
        .bus
        .submit(&core.ctx, exec("cat /etc/os-release", &ids))
        .await
        .unwrap()
    else {
        panic!("a read-only command is Low, even on 50 hosts");
    };
    assert_eq!(finished(&mut events, job_id).await, JobStatus::Succeeded);
    let results = core
        .bulk
        .results(&core.ctx, job_id, GroupOptions::default())
        .await
        .unwrap();
    let grouped = Instant::now();

    // PRD success measure: grouped results within 5 seconds of the slowest host finishing.
    let slowest = servers.iter().filter_map(TestSshServer::last_exit).max().unwrap();
    assert_eq!(servers[42].last_exit(), Some(slowest), "the slow host finished last");
    let after_slowest = grouped.duration_since(slowest);
    assert!(
        after_slowest < Duration::from_secs(5),
        "grouped results came {after_slowest:?} after the slowest host finished"
    );
    eprintln!(
        "50 hosts: whole run {:?}, grouped results {:?} after the slowest host",
        started.elapsed(),
        after_slowest
    );

    assert_eq!(results.headline, "48 hosts same, 2 differ");
    assert_eq!(results.counts.succeeded, 50);
    assert_eq!(results.groups.len(), 2);
    let [big, small] = &results.groups[..] else {
        unreachable!()
    };
    assert_eq!((big.hosts.len(), small.hosts.len()), (48, 2));
    assert_eq!((big.label.as_str(), small.label.as_str()), ("A", "B"));
    assert!(big.stdout.as_deref().unwrap().contains("22.04"));
    assert!(small.stdout.as_deref().unwrap().contains("24.04"));
    let names: Vec<&str> = small
        .hosts
        .iter()
        .map(|k| results.hosts.iter().find(|h| &h.target_key == k).unwrap().name.as_str())
        .collect();
    assert_eq!(names, ["web07", "web31"]);

    // BX-03: the diff between the two groups shows the one line that differs.
    let diff = core
        .bulk
        .diff(&core.ctx, job_id, &big.sample, &small.sample, GroupOptions::default())
        .await
        .unwrap();
    let changed: Vec<(String, &str)> = diff
        .stdout
        .iter()
        .filter(|l| l.kind != remotely_core::bulk::DiffKind::Same)
        .map(|l| (format!("{:?}", l.kind), l.text.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("Removed".to_owned(), "VERSION_ID=\"22.04\""),
            ("Added".to_owned(), "VERSION_ID=\"24.04\"")
        ]
    );
}

#[tokio::test]
async fn big_outputs_are_capped_but_still_grouped_by_the_whole_output() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let a = TestSshServer::start().await.with_password("alice", &password);
    let b = TestSshServer::start().await.with_password("alice", &password);
    let ids = [host(&core, &a, "a", pw).await, host(&core, &b, "b", pw).await];
    let mut events = core.jobs.subscribe();

    let job = run(&core, exec("seq 100000", &ids)).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);

    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.groups.len(), 1, "same output, though only part of it is stored");
    let full: usize = (1..=100_000).map(|i: u32| i.to_string().len() + 1).sum();
    let host = &results.hosts[0];
    assert!(host.truncated);
    assert_eq!(host.stdout_bytes, Some(full as i64));
    let out = core.bulk.host_output(&core.ctx, job, &host.target_key).await.unwrap();
    assert!(out.stdout.len() < 70 * 1024, "{} bytes stored", out.stdout.len());
    assert!(out.stdout.starts_with("1\n2\n3\n"));
    assert!(out.stdout.ends_with("99999\n100000\n"));
    assert!(out.stdout.contains("Remotely cut"));
}

#[tokio::test]
async fn trailing_whitespace_can_be_ignored_when_grouping() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let a = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file("/etc/motd", "hello\n");
    let b = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file("/etc/motd", "hello   \n\n");
    let ids = [host(&core, &a, "a", pw).await, host(&core, &b, "b", pw).await];
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("cat /etc/motd", &ids)).await;
    finished(&mut events, job).await;

    let exact = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(exact.groups.len(), 2);
    let loose = GroupOptions {
        ignore_trailing_whitespace: true,
    };
    let grouped = core.bulk.results(&core.ctx, job, loose).await.unwrap();
    assert_eq!(grouped.groups.len(), 1);
    assert_eq!(grouped.headline, "All 2 hosts the same");
}

#[tokio::test]
async fn failures_name_their_cause_per_host_and_group_by_it() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let wrong = add_password(&core, "old", &new_password()).await;
    let ok = TestSshServer::start().await.with_password("alice", &password);
    let refused = TestSshServer::start().await.with_password("alice", &password);
    let ok_id = host(&core, &ok, "ok", pw).await;
    let refused_id = host(&core, &refused, "bad login", wrong).await;
    // A port nothing listens on.
    let closed = TestSshServer::start().await;
    let closed_port = closed.port();
    drop(closed);
    let gone = core
        .sessions
        .create(
            &core.ctx,
            session_input("gone", closed_port, SessionAuth::Password { password_id: Some(pw) }),
        )
        .await
        .unwrap()
        .id;
    let mut events = core.jobs.subscribe();

    let job = run(&core, exec("uptime", &[ok_id, refused_id, gone])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::PartiallyFailed);
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    let code = |name: &str| {
        results
            .hosts
            .iter()
            .find(|h| h.name == name)
            .and_then(|h| h.error_code.clone())
    };
    assert_eq!(code("bad login").as_deref(), Some("auth_failed"));
    assert_eq!(code("gone").as_deref(), Some("ssh"));
    assert_eq!(code("ok"), None);
    let errors: Vec<_> = results.groups.iter().filter(|g| g.kind == GroupKind::Error).collect();
    assert_eq!(errors.len(), 2);
    assert!(results.headline.contains("differ"), "{}", results.headline);
}

#[tokio::test]
async fn each_host_has_the_runs_time_limit() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let slow = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_exec_delay(Duration::from_secs(10));
    let id = host(&core, &slow, "slow", pw).await;
    let mut events = core.jobs.subscribe();
    let mut command = exec("uptime", &[id]);
    if let Command::RemoteExec { timeout_secs, .. } = &mut command {
        *timeout_secs = Some(1);
    }
    let started = Instant::now();
    let job = run(&core, command).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);
    assert!(started.elapsed() < Duration::from_secs(8));
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.hosts[0].error_code.as_deref(), Some("timeout"));
    assert_eq!(
        results.hosts[0].error.as_deref(),
        Some("the command timed out after 1s")
    );
}

#[tokio::test]
async fn bad_scripts_and_time_limits_are_refused_before_anything_runs() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let target = [Uuid::new_v4()];
    for (script, timeout) in [
        ("   ", None),
        ("a\0b", None),
        ("uptime", Some(0)),
        ("uptime", Some(90_000)),
    ] {
        let mut command = exec(script, &target);
        if let Command::RemoteExec { timeout_secs, .. } = &mut command {
            *timeout_secs = timeout;
        }
        let err = core.bus.submit(&core.ctx, command).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{script:?} {timeout:?}");
    }
    let huge = "x".repeat(65 * 1024);
    let err = core.bus.submit(&core.ctx, exec(&huge, &target)).await.unwrap_err();
    assert_eq!(err.code(), "invalid_input");
}

// ---- SS-05 for bulk runs: host keys ------------------------------------------------------------

#[tokio::test]
async fn unknown_host_keys_fail_unless_the_run_trusts_them_and_changed_keys_always_block() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let server = TestSshServer::start().await.with_password("alice", &password);
    let id = core
        .sessions
        .create(
            &core.ctx,
            session_input(
                "new box",
                server.port(),
                SessionAuth::Password { password_id: Some(pw) },
            ),
        )
        .await
        .unwrap()
        .id;
    let mut events = core.jobs.subscribe();

    let job = run(&core, exec("uptime", &[id])).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.hosts[0].error_code.as_deref(), Some("host_key_unknown"));
    assert!(core.known_hosts.list(&core.ctx).await.unwrap().is_empty());

    let mut trusting = exec("uptime", &[id]);
    if let Command::RemoteExec {
        trust_new_host_keys, ..
    } = &mut trusting
    {
        *trust_new_host_keys = true;
    }
    let job = run(&core, trusting.clone()).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    let known = core.known_hosts.list(&core.ctx).await.unwrap();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].fingerprint, server.host_key_fingerprint());
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "host_key_trusted"));

    // A new key for the same host blocks, even for a run that trusts new keys.
    server.rotate_host_key();
    let job = run(&core, trusting).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.hosts[0].error_code.as_deref(), Some("host_key_changed"));
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "host_key_changed"));
}

// ---- BX-04: cancel and retry -------------------------------------------------------------------

#[tokio::test]
async fn cancelling_stops_hosts_in_flight_and_those_not_started() {
    let core = ssh_core().await;
    core.set_bulk_parallel_limit(1).await.unwrap();
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let mut servers = Vec::new();
    let mut ids = Vec::new();
    for i in 0..3 {
        let server = TestSshServer::start()
            .await
            .with_password("alice", &password)
            .with_exec_delay(Duration::from_secs(20));
        ids.push(host(&core, &server, &format!("slow{i}"), pw).await);
        servers.push(server);
    }
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("uptime", &ids)).await;
    // Wait until the first host is running its command.
    tokio::time::timeout(WAIT, async {
        loop {
            if let JobEvent::TargetStarted { job_id, .. } = events.recv().await.unwrap() {
                if job_id == job {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    assert!(core.jobs.cancel(job));
    assert_eq!(finished(&mut events, job).await, JobStatus::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cancel did not wait for the host"
    );

    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.counts.cancelled, 3);
    let in_flight: Vec<_> = results
        .hosts
        .iter()
        .filter(|h| h.error_code.as_deref() == Some("cancelled_remote"))
        .collect();
    assert_eq!(in_flight.len(), 1, "one host was running when it was cancelled");
    assert!(results.groups.is_empty());
    let audit = core.store.recent_audit(&core.ctx, 20).await.unwrap();
    let end = audit.iter().find(|e| e.event == "job_finished").unwrap();
    assert!(end.detail.as_deref().unwrap().contains("the host may still finish it"));
}

#[tokio::test]
async fn retrying_reruns_only_the_failed_hosts_as_a_new_linked_job() {
    let core = ssh_core().await;
    let password = new_password();
    let pw = add_password(&core, "lab", &password).await;
    let good = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_file("/etc/app.conf", "ok\n");
    let bad = TestSshServer::start().await.with_password("alice", &password);
    let ids = [host(&core, &good, "good", pw).await, host(&core, &bad, "bad", pw).await];
    let mut events = core.jobs.subscribe();
    let first = run(&core, exec("cat /etc/app.conf", &ids)).await;
    assert_eq!(finished(&mut events, first).await, JobStatus::PartiallyFailed);

    let SubmitOutcome::Queued { job_id: retry, .. } = core.bus.retry_failed(&core.ctx, first).await.unwrap() else {
        panic!("a read-only command on one host is Low");
    };
    assert_eq!(finished(&mut events, retry).await, JobStatus::Failed);
    let results = core
        .bulk
        .results(&core.ctx, retry, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.hosts.len(), 1);
    assert_eq!(results.hosts[0].name, "bad");
    assert_eq!(results.job.retry_of.as_deref(), Some(first.to_string().as_str()));
    assert_eq!(
        bad.log().iter().filter(|l| l.starts_with("exec ")).count(),
        2,
        "the failed host ran it twice"
    );
    assert_eq!(
        good.log().iter().filter(|l| l.starts_with("exec ")).count(),
        1,
        "the host that worked was left alone"
    );
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    let started = audit
        .iter()
        .find(|e| e.event == "job_started" && e.job_id.as_deref() == Some(retry.to_string().as_str()))
        .unwrap();
    assert!(started.detail.as_deref().unwrap().contains(&first.to_string()));

    // Nothing left to retry in a job where everything worked.
    let fine = run(&core, exec("cat /etc/app.conf", &ids[..1])).await;
    finished(&mut events, fine).await;
    let err = core.bus.retry_failed(&core.ctx, fine).await.unwrap_err();
    assert_eq!(err.code(), "invalid_input");
}

// ---- BX-07: sudo with the password from the vault ----------------------------------------------

#[tokio::test]
async fn sudo_takes_the_login_password_or_a_chosen_one_and_reports_a_wrong_one_per_host() {
    let core = ssh_core().await;
    let login = new_password();
    let sudo_pw = new_password();
    let login_id = add_password(&core, "login", &login).await;
    let sudo_id = add_password(&core, "sudo", &sudo_pw).await;
    // Sudo wants the login password here.
    let same = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(remotely_core::fakes::ssh_server::SudoMode::Password(login.clone()));
    // And another password here.
    let other = TestSshServer::start()
        .await
        .with_password("alice", &login)
        .with_sudo(remotely_core::fakes::ssh_server::SudoMode::Password(sudo_pw.clone()));
    let same_id = host(&core, &same, "same", login_id).await;
    let other_id = host(&core, &other, "other", login_id).await;
    let mut events = core.jobs.subscribe();

    // Each session's login password: right on one host, refused on the other.
    let job = run(&core, with_sudo(exec("whoami", &[same_id, other_id]), None)).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::PartiallyFailed);
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    let same_host = results.hosts.iter().find(|h| h.name == "same").unwrap();
    let out = core
        .bulk
        .host_output(&core.ctx, job, &same_host.target_key)
        .await
        .unwrap();
    assert_eq!(out.stdout, "root\n");
    assert_eq!(out.stderr, "", "sudo's prompt is not part of the output");
    let other_host = results.hosts.iter().find(|h| h.name == "other").unwrap();
    assert_eq!(other_host.error_code.as_deref(), Some("sudo_password_refused"));
    assert_eq!(
        other_host.error.as_deref(),
        Some("sudo refused the password from the vault")
    );

    // A password chosen from the vault for the run.
    let job = run(&core, with_sudo(exec("whoami", &[other_id]), Some(sudo_id))).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    assert!(other.log().iter().any(|l| l == "sudo ok"));
    // The command line asks sudo to read stdin; the password never travels in it.
    let exec_line = other
        .log()
        .into_iter()
        .find(|l| l.starts_with("exec sudo -S -p "))
        .unwrap();
    assert!(!exec_line.contains(&sudo_pw) && !exec_line.contains(&login));
}

#[tokio::test]
async fn sudo_without_a_password_to_give_fails_that_host_with_what_to_do() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let key_session = core
        .sessions
        .create(
            &core.ctx,
            SessionInput {
                host: "db01.example.com".into(),
                ..session_input("db01", 22, SessionAuth::Agent)
            },
        )
        .await
        .unwrap()
        .id;
    let mut events = core.jobs.subscribe();
    let job = run(&core, with_sudo(exec("whoami", &[key_session]), None)).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Failed);
    let results = core
        .bulk
        .results(&core.ctx, job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.hosts[0].error_code.as_deref(), Some("no_sudo_password"));
    assert!(results.hosts[0]
        .error
        .as_deref()
        .unwrap()
        .contains("Choose a sudo password"));

    // A chosen sudo password must be a password in the vault.
    let key = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Passphrase,
            "a passphrase",
            SecretString::new("not-a-password"),
        )
        .await
        .unwrap()
        .id;
    let err = core
        .bus
        .submit(&core.ctx, with_sudo(exec("whoami", &[key_session]), Some(key)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
}

// ---- BX-06: dangerous commands -----------------------------------------------------------------

#[tokio::test]
async fn the_editor_and_the_approval_dialog_name_the_dangerous_rule_that_matched() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let s = core
        .sessions
        .create(&core.ctx, session_input("web01", 22, SessionAuth::Agent))
        .await
        .unwrap()
        .id;
    let command = exec("cd /srv/app\nrm -rf ./cache\nsystemctl restart app", &[s]);

    let preview = core.bus.preview(&core.ctx, &command).await.unwrap();
    assert_eq!(preview.tier, Tier::High);
    assert_eq!(preview.dangerous.len(), 1);
    assert_eq!(preview.dangerous[0].rule, "rm -r / rm -rf");
    assert_eq!(preview.dangerous[0].text, "rm -rf ./cache");
    assert_eq!(preview.dangerous[0].line, 2);
    // A preview queues and audits nothing.
    assert!(core
        .store
        .recent_audit(&core.ctx, 10)
        .await
        .unwrap()
        .iter()
        .all(|e| e.event != "approval_requested"));

    // Still typing, no target yet: the rule shows all the same.
    let early = core
        .bus
        .preview(&core.ctx, &exec("shutdown -h now", &[]))
        .await
        .unwrap();
    assert_eq!(early.dangerous[0].rule, "shutdown / reboot");

    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx, command).await.unwrap() else {
        panic!("a dangerous command needs approval");
    };
    let details = request.exec.as_ref().unwrap();
    assert_eq!(details.script, "cd /srv/app\nrm -rf ./cache\nsystemctl restart app");
    assert_eq!(details.dangerous[0].rule, "rm -r / rm -rf");
    assert!(request
        .reasons
        .iter()
        .any(|r| r.contains("flagged dangerous: rm -r / rm -rf")));
    core.bus.cancel_approval(request.id).await.unwrap();
}

// ---- BX-01: targets ----------------------------------------------------------------------------

async fn lab_core(remote: FakeRemote) -> Core {
    let fake = FakeVmware::default()
        .in_library(&vmx("web"), Some("web"))
        .in_library(&vmx("db"), Some("db"))
        .in_library(&vmx("win"), Some("win"));
    let mut setup = Setup::new(fake);
    setup.remote = Arc::new(remote);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    core
}

async fn vm_id(core: &Core, name: &str) -> String {
    core.store.find_vm(&core.ctx, &vmx(name)).await.unwrap().unwrap().id
}

#[tokio::test]
async fn targets_come_from_sessions_vms_with_a_linked_session_tags_and_saved_filters() {
    let core = lab_core(FakeRemote::default()).await;
    let ctx = &core.ctx;
    let web_vm = vm_id(&core, "web").await;
    let web = core
        .sessions
        .create(
            ctx,
            SessionInput {
                host: "web.example.com".into(),
                vm_id: Some(web_vm.clone()),
                tags: vec!["frontend".into()],
                ..session_input("web (alice)", 22, SessionAuth::Agent)
            },
        )
        .await
        .unwrap();
    let plain = core
        .sessions
        .create(
            ctx,
            SessionInput {
                host: "bastion.example.org".into(),
                ..session_input("bastion", 22, SessionAuth::Agent)
            },
        )
        .await
        .unwrap();
    core.store.tag_vms(ctx, &[vmx("db")], "backend").await.unwrap();
    let filter = core
        .store
        .save_filter(
            ctx,
            "web and win",
            &VmFilter {
                text: "w".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let picks = TargetPicks {
        session_ids: vec![plain.id],
        vm_paths: vec![vmx("web")],
        tags: vec!["frontend".into(), "backend".into()],
        filter_ids: vec![filter.id.clone()],
    };
    let resolved = core.bulk.resolve(ctx, &picks).await.unwrap();
    let names: Vec<&str> = resolved.hosts.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["bastion", "web (alice)"], "each session once, by name");
    let web_host = &resolved.hosts[1];
    assert_eq!(web_host.vm_name.as_deref(), Some("web"));
    assert_eq!(web_host.address, "alice@web.example.com:22");
    assert_eq!(web_host.via, ["VM 'web'", "tag 'frontend'", "filter 'web and win'"]);
    // db (by tag) and win (by the filter) have no linked session.
    let without: Vec<&str> = resolved.vms_without_session.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(without, ["db", "win"]);
    assert_eq!(resolved.vms_without_session[0].via, ["tag 'backend'"]);

    // Nothing picked, nothing to run.
    let empty = core.bulk.resolve(ctx, &TargetPicks::default()).await.unwrap();
    assert!(empty.hosts.is_empty() && empty.vms_without_session.is_empty());
    assert_eq!(web.vm_id.as_deref(), Some(web_vm.as_str()));
}

#[tokio::test]
async fn a_session_counts_as_prod_or_protected_when_its_vm_is() {
    let core = lab_core(FakeRemote::default()).await;
    let ctx = &core.ctx;
    let web_vm = vm_id(&core, "web").await;
    let session = core
        .sessions
        .create(
            ctx,
            SessionInput {
                host: "web.example.com".into(),
                vm_id: Some(web_vm),
                ..session_input("web", 22, SessionAuth::Agent)
            },
        )
        .await
        .unwrap()
        .id;
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("uptime", &[session])).await;
    assert_eq!(
        finished(&mut events, job).await,
        JobStatus::Succeeded,
        "Lab, read-only: Low"
    );

    core.inventory
        .set_environment(ctx, &[vmx("web")], Environment::Prod)
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(ctx, exec("uptime", &[session])).await.unwrap()
    else {
        panic!("the VM is Prod, so the session is too");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.targets[0].environment, Environment::Prod);
    core.bus.cancel_approval(request.id).await.unwrap();
    let resolved = core
        .bulk
        .resolve(
            ctx,
            &TargetPicks {
                session_ids: vec![session],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.hosts[0].environment, Environment::Prod);

    // AP-04: a protected VM keeps commands off its session too.
    let job = run(
        &core,
        Command::VmProtect {
            targets: vec![vm("web")],
            protected: true,
        },
    )
    .await;
    finished(&mut events, job).await;
    let err = core.bus.submit(ctx, exec("uptime", &[session])).await.unwrap_err();
    assert_eq!(err.code(), "all_targets_protected");
}

#[tokio::test]
async fn linking_a_session_to_a_vm_is_checked_and_audited() {
    let core = lab_core(FakeRemote::default()).await;
    let ctx = &core.ctx;
    let err = core
        .sessions
        .create(
            ctx,
            SessionInput {
                vm_id: Some("no-such-vm".into()),
                ..session_input("x", 22, SessionAuth::Agent)
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");

    let s = core
        .sessions
        .create(ctx, session_input("web", 22, SessionAuth::Agent))
        .await
        .unwrap();
    let mut input = SessionInput {
        name: s.name.clone(),
        folder_id: None,
        host: s.host.clone(),
        port: s.port,
        username: s.username.clone(),
        auth: s.auth.clone(),
        jump_session_id: None,
        startup_command: None,
        environment: s.environment,
        color: None,
        tags: vec![],
        vm_id: Some(vm_id(&core, "web").await),
    };
    let linked = core.sessions.update(ctx, s.id, input.clone()).await.unwrap();
    assert!(linked.vm_id.is_some());
    let audit = core.store.recent_audit(ctx, 5).await.unwrap();
    assert_eq!(audit[0].detail.as_deref(), Some("VM: none -> 'web'"));
    input.vm_id = None;
    core.sessions.update(ctx, s.id, input).await.unwrap();
    let audit = core.store.recent_audit(ctx, 5).await.unwrap();
    assert_eq!(audit[0].detail.as_deref(), Some("VM: 'web' -> none"));
}

// ---- BX-02: the parallel limit -----------------------------------------------------------------

#[tokio::test]
async fn hosts_run_ten_at_a_time_by_default_and_the_limit_is_a_setting() {
    let mut remote = FakeRemote::default();
    for i in 0..24 {
        remote = remote.with_delay(&format!("h{i}.example.com"), Duration::from_millis(80));
    }
    let remote = Arc::new(remote);
    let mut setup = Setup::new(FakeVmware::default());
    setup.remote = remote.clone();
    let core = setup.build().await;
    assert_eq!(core.bulk_parallel_limit(), 10);
    let mut ids = Vec::new();
    for i in 0..24 {
        let input = SessionInput {
            host: format!("h{i}.example.com"),
            ..session_input(&format!("h{i}"), 22, SessionAuth::Agent)
        };
        ids.push(core.sessions.create(&core.ctx, input).await.unwrap().id);
    }
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("uptime", &ids)).await;
    assert_eq!(finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(remote.max_in_flight(), 10);

    for bad in [0, 51] {
        assert_eq!(
            core.set_bulk_parallel_limit(bad).await.unwrap_err().code(),
            "invalid_setting"
        );
    }
    core.set_bulk_parallel_limit(3).await.unwrap();
    assert_eq!(core.bulk_parallel_limit(), 3);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].action, "Set the hosts a bulk run reaches at once");
}

// ---- BX-05: exports ----------------------------------------------------------------------------

#[tokio::test]
async fn exports_hold_every_host_in_csv_json_and_html_without_secrets() {
    let remote = FakeRemote::default()
        .with_output("a.example.com", "db_password=hunter2-from-config\nok\n")
        .with_output("b.example.com", "<script>alert(1)</script>\n")
        .with_exit_code("b.example.com", 1);
    let mut setup = Setup::new(FakeVmware::default());
    setup.remote = Arc::new(remote);
    let core = setup.build().await;
    let mut ids = Vec::new();
    for name in ["a", "b"] {
        let input = SessionInput {
            host: format!("{name}.example.com"),
            ..session_input(name, 22, SessionAuth::Agent)
        };
        ids.push(core.sessions.create(&core.ctx, input).await.unwrap().id);
    }
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("deploy --token tok-123 && cat app.conf", &ids)).await;
    finished(&mut events, job).await;

    let opts = GroupOptions::default();
    let (csv, redacted, hosts) = core.bulk.render(&core.ctx, job, ExportFormat::Csv, opts).await.unwrap();
    assert_eq!(hosts, 2);
    assert!(redacted >= 1);
    assert!(csv.starts_with("\u{FEFF}host,group,status,exit_code,duration_ms,stdout,stderr,output_truncated,error\r\n"));
    assert!(csv.contains("db_password=[redacted]"));
    assert!(!csv.contains("hunter2-from-config"));

    let (json, _, _) = core
        .bulk
        .render(&core.ctx, job, ExportFormat::Json, opts)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(value["groups"].as_array().unwrap().len(), 2);
    assert_eq!(value["command"]["script"], "deploy --token [redacted] && cat app.conf");
    assert!(!json.contains("tok-123") && !json.contains("hunter2-from-config"));

    let (html, _, _) = core
        .bulk
        .render(&core.ctx, job, ExportFormat::Html, opts)
        .await
        .unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>"));
    assert!(!html.contains("tok-123") && !html.contains("hunter2-from-config"));

    let dir = common::temp_folder("bulk-export");
    let path = dir.join("run.html");
    let export = core
        .bulk
        .export(&core.ctx, job, ExportFormat::Html, opts, &path)
        .await
        .unwrap();
    assert_eq!(export.hosts, 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), html);
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "job_exported");
    assert_eq!(audit[0].action, "Exported a bulk run's results to HTML");
    assert_eq!(audit[0].detail.as_deref(), Some("2 hosts to run.html"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn recent_runs_list_only_remote_commands() {
    let core = lab_core(FakeRemote::default()).await;
    let s = core
        .sessions
        .create(&core.ctx, session_input("web", 22, SessionAuth::Agent))
        .await
        .unwrap()
        .id;
    let mut events = core.jobs.subscribe();
    let job = run(&core, exec("uptime", &[s])).await;
    finished(&mut events, job).await;
    let protect = run(
        &core,
        Command::VmProtect {
            targets: vec![vm("db")],
            protected: true,
        },
    )
    .await;
    finished(&mut events, protect).await;
    let runs = core.bulk.recent(&core.ctx, 10).await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].id, job.to_string());
    assert_eq!(runs[0].summary, "Run `uptime` on 1 host");
}
