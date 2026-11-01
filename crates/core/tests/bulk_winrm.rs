//! BX-13 Windows in bulk, end to end: Compare hosts on WinRM hosts (alone and with SSH hosts, each rated by its own
//! rules), its results, retry and certificate rule; Type in all tabs on PowerShell tabs (a line held and rated as a
//! PowerShell statement, a statement left open sent whole, a running statement's input passing through, recording
//! and one notice per line); MultiExec groups of WinRM sessions; and support bundles from Windows hosts.
//!
//! WinRM goes to `fakes::WinrmTestServer` (HTTPS with Basic and a run-time certificate) and SSH to
//! `fakes::ssh_server::TestSshServer`, both on 127.0.0.1 with passwords made at run time. No packet leaves 127.0.0.1;
//! no real Windows host is reached; zips go to the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::net_tools::TrustVerdict;
use remotely_core::adapters::remote::{AgentSource, PtySize, ScriptKind};
use remotely_core::bulk::{GroupOptions, TargetPicks};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeNetworkTools, FakeVmware, FakeWinrm, WinrmTestServer};
use remotely_core::jobs::{ExecTuning, JobStatus};
use remotely_core::known_hosts::HostKey;
use remotely_core::multiexec_groups::GroupInput;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::kinds::{WinrmCertificate, WinrmOptions, WinrmSignIn, WinrmTransport};
use remotely_core::sessions::{SessionAuth, SessionInput, SessionKind};
use remotely_core::support_bundle::{BundleRequest, PresetId};
use remotely_core::terminal::multiexec::{InputOutcome, LineMode, MultiExecEvent};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use serde_json::Value;
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(30);
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

fn untrusted() -> TrustVerdict {
    TrustVerdict {
        trusted: false,
        problems: vec!["the certificate chain ends in a root Windows doesn't trust".into()],
        built: Vec::new(),
    }
}

async fn core_with(tools: Arc<FakeNetworkTools>) -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .with_network_tools(tools)
        .build()
        .await;
    core.jobs.set_exec_tuning(ExecTuning {
        connect_timeout: Duration::from_secs(5),
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        ..ExecTuning::default()
    });
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

async fn core() -> Core {
    core_with(Arc::new(FakeNetworkTools::new().with_verdict(trusted()))).await
}

async fn password_item(core: &Core, label: &str, password: &str) -> remotely_core::vault::SecretId {
    core.vault
        .add(&core.ctx(), SecretKind::Password, label, SecretString::new(password))
        .await
        .unwrap()
        .id
}

fn input(name: &str, port: u16, password_id: remotely_core::vault::SecretId, kind: SessionKind) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: "127.0.0.1".into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password {
            password_id: Some(password_id),
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
        kind,
    }
}

fn winrm(certificate: WinrmCertificate) -> SessionKind {
    SessionKind::Winrm(WinrmOptions {
        transport: WinrmTransport::Https,
        sign_in: WinrmSignIn::Basic,
        certificate,
    })
}

/// A Windows host: the fake WinRM server over HTTPS with Basic, and a session to it.
async fn windows(core: &Core, name: &str) -> (WinrmTestServer, Uuid) {
    windows_with(core, name, WinrmCertificate::Windows).await
}

async fn windows_with(core: &Core, name: &str, certificate: WinrmCertificate) -> (WinrmTestServer, Uuid) {
    let password = new_password();
    let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &password)
        .await
        .unwrap();
    let secret = password_item(core, &format!("{name} login"), &password).await;
    let id = core
        .sessions
        .create(&core.ctx(), input(name, server.port(), secret, winrm(certificate)))
        .await
        .unwrap()
        .id;
    (server, id)
}

/// A Linux host: the SSH test server, its key trusted, and a session to it.
async fn linux(core: &Core, name: &str) -> (TestSshServer, Uuid) {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
    let secret = password_item(core, &format!("{name} login"), &password).await;
    let id = core
        .sessions
        .create(&core.ctx(), input(name, server.port(), secret, SessionKind::Ssh))
        .await
        .unwrap()
        .id;
    (server, id)
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
        timeout_secs: Some(60),
        rollout: Default::default(),
    }
}

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

/// Submits a command, approving it if it asks; the job's id.
async fn run(core: &Core, command: Command) -> Uuid {
    match core.bus.submit(&core.ctx(), command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => core.bus.approve(request.id, answers(&request)).await.unwrap(),
    }
}

async fn finished(core: &Core, job: Uuid) -> JobStatus {
    timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap()
}

// ---- Compare hosts on WinRM hosts ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compare_hosts_runs_powershell_on_a_winrm_host_rated_by_the_powershell_rules() {
    let core = core().await;
    let (server, win01) = windows(&core, "win01").await;
    let ctx = core.ctx();

    // Compare hosts takes WinRM sessions; the key push doesn't.
    let picks = TargetPicks {
        session_ids: vec![win01],
        winrm: true,
        ..TargetPicks::default()
    };
    let resolved = core.bulk.resolve(&ctx, &picks).await.unwrap();
    assert_eq!(resolved.hosts.len(), 1);
    assert_eq!(resolved.hosts[0].script_kind, ScriptKind::PowerShell);
    let ssh_only = core
        .bulk
        .resolve(
            &ctx,
            &TargetPicks {
                winrm: false,
                ..picks.clone()
            },
        )
        .await
        .unwrap();
    assert!(ssh_only.hosts.is_empty());
    assert!(
        ssh_only.notes.iter().any(|n| n.contains("this works over SSH only")),
        "{:?}",
        ssh_only.notes
    );

    // A read by the PowerShell rules is Low and runs at once.
    let preview = core
        .bus
        .preview(&ctx, &exec("hostname; Get-Date", &[win01]))
        .await
        .unwrap();
    assert_eq!(
        (preview.action, preview.tier),
        (ActionKind::ExecReadOnly, Tier::Low),
        "{:?}",
        preview.reasons
    );
    assert!(preview.reasons.iter().any(|r| r == "rated by the PowerShell rules"));
    let job = run(&core, exec("hostname", &[win01])).await;
    assert_eq!(finished(&core, job).await, JobStatus::Succeeded);
    let results = core.bulk.results(&ctx, job, GroupOptions::default()).await.unwrap();
    assert_eq!(results.groups.len(), 1);
    assert!(results.groups[0].ok);
    assert!(
        results.groups[0]
            .stdout
            .as_deref()
            .unwrap_or_default()
            .contains("WIN01"),
        "{:?}",
        results.groups[0]
    );
    assert!(
        server.stats().commands.iter().any(|c| c.contains("-Command -")),
        "a PowerShell of its own ran it: {:?}",
        server.stats().commands
    );

    // A dangerous one asks for the full approval and says why.
    let preview = core
        .bus
        .preview(&ctx, &exec("Restart-Computer -Force", &[win01]))
        .await
        .unwrap();
    assert_eq!(preview.tier, Tier::High);
    assert!(preview
        .dangerous
        .iter()
        .any(|d| d.rule == "Stop-Computer / Restart-Computer"));
    let SubmitOutcome::NeedsApproval { request } =
        core.bus.submit(&ctx, exec("rm -r C:\\Data", &[win01])).await.unwrap()
    else {
        panic!("a dangerous PowerShell command asks first");
    };
    let details = request.exec.as_ref().unwrap();
    assert_eq!(details.languages, [ScriptKind::PowerShell]);
    assert!(details
        .dangerous
        .iter()
        .any(|d| d.rule == "Remove-Item -Recurse / rd /s"));
    core.bus.cancel_approval(request.id).await.unwrap();

    // sudo is a Linux host's.
    let mut with_sudo = exec("hostname", &[win01]);
    if let Command::RemoteExec { sudo, .. } = &mut with_sudo {
        *sudo = true;
    }
    let refused = core.bus.submit(&ctx, with_sudo).await.unwrap_err().to_string();
    assert!(refused.contains("sudo is for Linux hosts"), "{refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mixed_selection_rates_each_host_by_its_own_rules_and_groups_their_outputs() {
    let core = core().await;
    let (_win, win01) = windows(&core, "win01").await;
    let (_lin, web01) = linux(&core, "web01").await;
    let ctx = core.ctx();
    let both = [win01, web01];

    // `hostname` reads in both languages: Low, and each host gives its own name.
    let preview = core.bus.preview(&ctx, &exec("hostname", &both)).await.unwrap();
    assert_eq!(preview.tier, Tier::Low, "{:?}", preview.reasons);
    assert!(preview
        .reasons
        .iter()
        .any(|r| r.contains("each target is rated by its own rules")));
    let job = run(&core, exec("hostname", &both)).await;
    finished(&core, job).await;
    let results = core.bulk.results(&ctx, job, GroupOptions::default()).await.unwrap();
    assert_eq!(results.counts.total, 2);
    assert_eq!(results.groups.len(), 2, "two hosts, two outputs: {:?}", results.groups);

    // `Get-Service` reads in PowerShell but is unknown to a shell: a confirm.
    let preview = core.bus.preview(&ctx, &exec("Get-Service", &both)).await.unwrap();
    assert_eq!((preview.action, preview.tier), (ActionKind::ExecOther, Tier::Medium));
    // The shell's dangerous rules still count for the Linux host.
    let preview = core.bus.preview(&ctx, &exec("rm -rf /var/x", &both)).await.unwrap();
    assert_eq!(preview.action, ActionKind::ExecDangerous);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_windows_host_is_retried_and_the_journal_keeps_its_certificate() {
    let tools = Arc::new(FakeNetworkTools::new().with_verdict(untrusted()));
    let core = core_with(tools).await;
    let (server, win01) = windows_with(&core, "win01", WinrmCertificate::Fingerprint).await;
    let ctx = core.ctx();

    // A certificate never seen fails a run that doesn't trust new ones (nobody can be asked).
    let job = run(&core, exec("hostname", &[win01])).await;
    assert_eq!(finished(&core, job).await, JobStatus::Failed);
    let targets = core.store.job_targets(&ctx, job).await.unwrap();
    let error = targets[0].error.clone().unwrap_or_default();
    assert!(error.to_lowercase().contains("certificate"), "{error}");

    // Trusting new ones: it runs, and the journal names the certificate it accepted.
    let mut trusting = exec("Write-Error 'disk full'", &[win01]);
    if let Command::RemoteExec {
        trust_new_host_keys, ..
    } = &mut trusting
    {
        *trust_new_host_keys = true;
    }
    let job = run(&core, trusting).await;
    assert_eq!(
        finished(&core, job).await,
        JobStatus::Failed,
        "Write-Error ends with exit code 1"
    );
    let targets = core.store.job_targets(&ctx, job).await.unwrap();
    let host_key = targets[0].host_key.clone().unwrap_or_default();
    assert!(
        host_key.starts_with("tls-certificate ") && host_key.ends_with(&server.fingerprint().unwrap()),
        "{host_key}"
    );
    // BX-04: the failed host runs again, rated again.
    let retry = match core.bus.retry_failed(&ctx, job, false).await.unwrap() {
        SubmitOutcome::Queued { job_id, tier, .. } => {
            assert_eq!(tier, Tier::Low, "Write-Error only writes to the error stream");
            job_id
        }
        SubmitOutcome::NeedsApproval { request } => panic!("asked for {:?}", request.reasons),
    };
    finished(&core, retry).await;
    assert_eq!(core.store.job_targets(&ctx, retry).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_winrm_sign_in_parks_the_session_so_the_next_run_does_not_try_it_again() {
    // Review C2: the login guard, so one run (or Retry after it) can't keep signing in to a host that refused and lock
    // a domain account. A refused sign-in parks the session; the next run is refused up front, with no new attempt.
    let core = core().await;
    let (server, win01) = windows(&core, "win01").await;
    // The host's password changes under the saved one: every sign-in is now refused.
    server.set_password(&new_password());

    let job = run(&core, exec("Get-Service", &[win01])).await;
    assert_eq!(finished(&core, job).await, JobStatus::Failed);
    let after_first = server.stats().refused_sign_ins;
    assert!(after_first >= 1, "the first run tried to sign in");

    let job = run(&core, exec("Get-Service", &[win01])).await;
    assert_eq!(finished(&core, job).await, JobStatus::Failed);
    assert_eq!(
        server.stats().refused_sign_ins,
        after_first,
        "the session was parked, so the second run signed in again zero times"
    );
    let error = core.store.job_targets(&core.ctx(), job).await.unwrap()[0]
        .error
        .clone()
        .unwrap_or_default();
    assert!(
        error.to_lowercase().contains("refused") || error.to_lowercase().contains("sign"),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosts_that_share_one_wrong_login_make_a_single_refused_sign_in() {
    // Review C2: a run reaches up to JobLimits.remote hosts at once (10 by default), so without a per-account gate a
    // wrong shared domain password would make one refused sign-in per host at the same moment — enough to lock the
    // account at a low lockout threshold. The first host with an account signs in alone; when it is refused, the others
    // sharing the login are skipped, so exactly one refused sign-in reaches the hosts however many share it.
    let core = core().await;
    // One vault item for every host, holding a password none of the hosts actually accepts.
    let shared = password_item(&core, "shared domain login", &new_password()).await;
    let mut servers = Vec::new();
    let mut sessions = Vec::new();
    for name in ["win01", "win02", "win03"] {
        // Each host's real password differs from the shared one, so every sign-in with the shared item is refused.
        let server = WinrmTestServer::start(FakeWinrm::HttpsBasic, "alice", &new_password())
            .await
            .unwrap();
        // The shared item goes to a new host each time, so creating the session confirms with the vault password.
        let id = core
            .sessions
            .create_with(
                &core.ctx(),
                input(name, server.port(), shared, winrm(WinrmCertificate::Windows)),
                Some(&SecretString::new(VAULT_PASSWORD)),
            )
            .await
            .unwrap()
            .id;
        servers.push(server);
        sessions.push(id);
    }

    let job = run(&core, exec("Get-Service", &sessions)).await;
    assert_eq!(finished(&core, job).await, JobStatus::Failed);

    let refused: usize = servers.iter().map(|s| s.stats().refused_sign_ins).sum();
    assert_eq!(
        refused, 1,
        "only the leader tries the shared login; the rest are skipped"
    );

    // Two hosts are skipped by the gate (not simply refused), so no further sign-in reaches them.
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    let skipped = targets
        .iter()
        .filter(|t| t.error.as_deref().is_some_and(|e| e.contains("skipped")))
        .count();
    assert_eq!(skipped, 2, "{targets:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preview_refuses_a_script_over_the_size_cap_before_parsing_it() {
    // Review A5/A8: preview applies the 64 KB script cap before anything parses, so a huge paste can't be rated in a
    // preview (where submit's full validate does not run) and can't drive the recursive parser deep. The script here
    // would be deeply nested casts if parsed; the cap refuses it first.
    let core = core().await;
    let (_server, win01) = windows(&core, "win01").await;
    let huge = "[int]".repeat(20_000);
    assert!(huge.len() > 64 * 1024);
    let refused = core
        .bus
        .preview(&core.ctx(), &exec(&huge, &[win01]))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("at most") && refused.contains("KB"), "{refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_powershell_tab_picks_its_session_for_compare_hosts_only() {
    let core = core().await;
    let ctx = core.ctx();
    let (_server, win01) = windows(&core, "win01").await;
    let handle = core.terminals.open(&ctx, win01, SIZE).await.unwrap();
    let mut pane = Pane::new(handle);
    pane.expect_status(|s| *s == TerminalStatus::Connected).await;
    let picks = TargetPicks {
        terminal_ids: vec![pane.id],
        winrm: true,
        ..TargetPicks::default()
    };
    let resolved = core.bulk.resolve(&ctx, &picks).await.unwrap();
    assert_eq!(resolved.hosts.len(), 1, "{:?}", resolved.notes);
    assert_eq!(resolved.hosts[0].session_id, win01);
    let ssh_only = core
        .bulk
        .resolve(&ctx, &TargetPicks { winrm: false, ..picks })
        .await
        .unwrap();
    assert!(ssh_only.hosts.is_empty());
    assert!(
        ssh_only.notes.iter().any(|n| n.contains("PowerShell tab")),
        "{:?}",
        ssh_only.notes
    );
}

// ---- MultiExec groups ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_holds_winrm_sessions_or_ssh_sessions_never_both() {
    let core = core().await;
    let ctx = core.ctx();
    let (_w1, win01) = windows(&core, "win01").await;
    let (_w2, win02) = windows(&core, "win02").await;
    let (_l, web01) = linux(&core, "web01").await;
    let group = core
        .groups
        .create(
            &ctx,
            GroupInput {
                name: "Windows".into(),
                session_ids: vec![win01, win02],
            },
        )
        .await
        .unwrap();
    assert_eq!(group.members.len(), 2);
    let refused = core
        .groups
        .create(
            &ctx,
            GroupInput {
                name: "Mixed".into(),
                session_ids: vec![win01, web01],
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("not both"), "{refused}");
}

// ---- Type in all tabs on PowerShell tabs -----------------------------------------------------------------

/// A pane under test.
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

    async fn expect(&mut self, needle: &str) -> String {
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
        result.unwrap_or_else(|_| panic!("no {needle:?}; got {:?}", String::from_utf8_lossy(&self.unread)))
    }

    async fn expect_status(&mut self, want: impl Fn(&TerminalStatus) -> bool) {
        timeout(WAIT, async {
            loop {
                if let TerminalEvent::Status { status } = self.events.recv().await.expect("events ended") {
                    if want(&status) {
                        return;
                    }
                }
            }
        })
        .await
        .expect("the status came");
    }
}

/// Two PowerShell tabs at their prompts, picked for Type in all tabs.
struct Fleet {
    core: Core,
    servers: Vec<WinrmTestServer>,
    panes: Vec<Pane>,
}

impl Fleet {
    async fn new(n: usize) -> Self {
        let core = core().await;
        let mut servers = Vec::new();
        let mut panes = Vec::new();
        for i in 0..n {
            let (server, id) = windows(&core, &format!("win{:02}", i + 1)).await;
            let mut pane = Pane::new(core.terminals.open(&core.ctx(), id, SIZE).await.unwrap());
            pane.expect_status(|s| *s == TerminalStatus::Connected).await;
            pane.expect("PS C:\\Users\\alice> ").await;
            servers.push(server);
            panes.push(pane);
        }
        let ids: Vec<Uuid> = panes.iter().map(|p| p.id).collect();
        core.multiexec.set_targets(ids).await.unwrap();
        Self { core, servers, panes }
    }

    async fn type_in(&self, i: usize, keys: &str) -> InputOutcome {
        self.core
            .multiexec
            .input(self.panes[i].id, keys.as_bytes().to_vec())
            .await
            .unwrap()
    }

    /// The statements the host at `i` was sent (the console's statement lines), as typed.
    fn statements(&self, i: usize) -> Vec<String> {
        self.servers[i]
            .stats()
            .stdin
            .iter()
            .filter(|l| l.starts_with("try { . ([scriptblock]::Create("))
            .cloned()
            .collect()
    }
}

fn held(outcome: InputOutcome) -> (Uuid, Tier, Option<Box<ApprovalRequest>>) {
    match outcome {
        InputOutcome::Held {
            line_id, tier, request, ..
        } => (line_id, tier, request),
        other => panic!("Enter was not held: {other:?}"),
    }
}

async fn line_done(events: &mut Receiver<MultiExecEvent>, line: Uuid) -> bool {
    timeout(WAIT, async {
        loop {
            if let MultiExecEvent::LineDone { line_id, sent, .. } = events.recv().await.unwrap() {
                if line_id == line {
                    return sent;
                }
            }
        }
    })
    .await
    .expect("the line finished in time")
}

async fn line_finished(events: &mut Receiver<MultiExecEvent>, line: Uuid) -> usize {
    timeout(WAIT, async {
        loop {
            if let MultiExecEvent::LineFinished { line_id, terminals, .. } = events.recv().await.unwrap() {
                if line_id == line {
                    return terminals;
                }
            }
        }
    })
    .await
    .expect("every tab finished the line in time")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_powershell_line_is_held_rated_as_powershell_and_recorded_in_each_tab() {
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // A read: Low, sent at once to both tabs, recorded, one notice for the line.
    let outcome = fleet.type_in(0, "hostname").await;
    assert!(
        matches!(
            outcome,
            InputOutcome::Typed {
                mode: LineMode::Command,
                ..
            }
        ),
        "{outcome:?}"
    );
    let (line, tier, request) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Low);
    assert!(request.is_none());
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("WIN01").await;
        pane.expect("PS C:\\Users\\alice> ").await;
    }
    assert_eq!(line_finished(&mut events, line).await, 2);
    let recorded = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(recorded.groups.len(), 1, "both tabs said the same");
    assert!(
        recorded.groups[0]
            .stdout
            .as_deref()
            .unwrap_or_default()
            .contains("WIN01"),
        "{:?}",
        recorded.groups[0]
    );

    // A dangerous one needs the full approval; cancelling clears the line everywhere.
    fleet.type_in(0, "Stop-Computer -Force").await;
    let (line, tier, request) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::High);
    let request = request.expect("asked first");
    assert_eq!(request.exec.as_ref().unwrap().languages, [ScriptKind::PowerShell]);
    fleet.core.multiexec.cancel(line).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C").await;
    }
    for i in 0..2 {
        assert!(
            !fleet.statements(i).iter().any(|s| s.contains("Stop-Computer")),
            "the host never got it: {:?}",
            fleet.statements(i)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_left_open_goes_whole_and_is_rated_whole() {
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // Lines that leave the statement open run nothing: they go at once, unrated.
    let outcome = fleet.type_in(0, "if ($true) {\r").await;
    assert!(matches!(outcome, InputOutcome::Typed { .. }), "{outcome:?}");
    for pane in &mut fleet.panes {
        pane.expect(">> ").await;
    }
    assert!(matches!(
        fleet.type_in(0, "  'inside'\r").await,
        InputOutcome::Typed { .. }
    ));
    // The line that closes it sends the whole statement, which is what is rated: a read.
    let (line, tier, _) = held(fleet.type_in(0, "}\r").await);
    assert_eq!(tier, Tier::Low);
    assert!(line_done(&mut events, line).await);
    for i in 0..2 {
        fleet.panes[i].expect("PS C:\\Users\\alice> ").await;
        let sent = fleet.statements(i);
        assert!(
            sent.iter()
                .any(|s| s.contains("Create('if ($true) {' + \"`n\" + '  ''inside''' + \"`n\" + '}')")),
            "{sent:?}"
        );
    }

    // Open again, with a command that changes something inside: the closing line asks first, for the whole of it.
    fleet.type_in(0, "foreach ($s in 'Spooler') {\r").await;
    fleet.type_in(0, "  Restart-Service $s\r").await;
    let (line, tier, request) = held(fleet.type_in(0, "}\r").await);
    assert_eq!(tier, Tier::Medium);
    let script = request.unwrap().exec.unwrap().script;
    assert!(
        script.starts_with("foreach ($s in 'Spooler') {") && script.contains("Restart-Service"),
        "{script}"
    );
    fleet.core.multiexec.cancel(line).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_statements_input_is_rated_unless_at_a_password_prompt_and_mixing_kinds_is_refused() {
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // Read-Host isn't a read by the rules (it waits for input): a confirm.
    fleet.type_in(0, "Read-Host 'Name'").await;
    let (line, tier, request) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Medium);
    fleet
        .core
        .multiexec
        .approve(line, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("Name: ").await;
    }
    // While it runs, a typed line goes to it as input, and PowerShell would run it as the next statement if nothing
    // read it: it is rated first, as a line Remotely can't follow (the tabs aren't at their prompt).
    fleet.type_in(0, "bob").await;
    let (line, tier, request) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Medium);
    let request = request.unwrap();
    assert!(request.exec.as_ref().unwrap().unreliable);
    fleet.core.multiexec.approve(line, answers(&request)).await.unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("bob").await;
        pane.expect("PS C:\\Users\\alice> ").await;
    }

    // At a password prompt the keys pass straight through, never rated or journaled.
    fleet.type_in(0, "Read-Host 'Password'").await;
    let (line, _, request) = held(fleet.type_in(0, "\r").await);
    fleet
        .core
        .multiexec
        .approve(line, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("Password: ").await;
    }
    let jobs = fleet.core.store.recent_jobs(&fleet.core.ctx(), 50).await.unwrap().len();
    let outcome = fleet.type_in(0, "s3cret-value\r").await;
    assert!(
        matches!(outcome, InputOutcome::Typed { mode: LineMode::Password, ref reached, .. } if reached.len() == 2),
        "{outcome:?}"
    );
    for pane in &mut fleet.panes {
        pane.expect("PS C:\\Users\\alice> ").await;
    }
    assert_eq!(
        fleet.core.store.recent_jobs(&fleet.core.ctx(), 50).await.unwrap().len(),
        jobs
    );

    // Output that switches xterm to its alternate screen makes no PowerShell tab a full-screen program: at its prompt,
    // a typed line is still held and rated, never sent straight to a console that would run it.
    fleet.type_in(0, "Enter-AltScreen").await;
    let (line, _, request) = held(fleet.type_in(0, "\r").await);
    fleet
        .core
        .multiexec
        .approve(line, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("PS C:\\Users\\alice> ").await;
    }
    let outcome = fleet.type_in(0, "Restart-Service Spooler").await;
    assert!(
        matches!(
            outcome,
            InputOutcome::Typed {
                mode: LineMode::Command,
                ..
            }
        ),
        "{outcome:?}"
    );
    let (line, tier, _) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Medium);
    fleet.core.multiexec.cancel(line).await.unwrap();

    // An SSH tab and a PowerShell tab can't be typed into at once.
    let (_server, web01) = linux(&fleet.core, "web01").await;
    let mut ssh = Pane::new(fleet.core.terminals.open(&fleet.core.ctx(), web01, SIZE).await.unwrap());
    ssh.expect_status(|s| *s == TerminalStatus::Connected).await;
    let refused = fleet
        .core
        .multiexec
        .set_targets(vec![fleet.panes[0].id, ssh.id])
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("not both at once"), "{refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recalled_history_line_is_refused_not_run_unrated() {
    // Review B1: MultiExec follows the keys, but each console's history is its own. Pressing Up recalls a line the
    // keys didn't carry, so what each console would run is unknown: the line is refused and the consoles cleared,
    // never run unrated.
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // Run a line so it is in each tab's history.
    fleet.type_in(0, "hostname").await;
    let (line, _, _) = held(fleet.type_in(0, "\r").await);
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("PS C:\\Users\\alice> ").await;
    }

    // Up recalls the history line in each console; MultiExec followed an empty line. Enter is refused, not run.
    fleet.type_in(0, "\x1b[A").await;
    let outcome = fleet.type_in(0, "\r").await;
    assert!(matches!(outcome, InputOutcome::Refused { .. }), "{outcome:?}");
    for pane in &mut fleet.panes {
        pane.expect("PS C:\\Users\\alice> ").await;
    }
    // Only the one line it ran reached each host; the recalled line never did.
    for i in 0..2 {
        assert_eq!(
            fleet.statements(i).len(),
            1,
            "only the first run reached the host: {:?}",
            fleet.statements(i)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_that_opens_a_statement_while_one_runs_is_held_not_passed_through() {
    // Review M1 (R1/R6): while a console runs a statement, a typed line is its stdin, which PowerShell runs as the next
    // statement once the running one stops reading. A line that would merely open a statement at a prompt (`$x = @'`, a
    // here-string start) must not be passed through unrated on that ground while running — it is rated and held like
    // any other line, with the raw lines sent since the statement started.
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // A statement that keeps reading, so the consoles are mid-statement, not at their prompt.
    fleet.type_in(0, "Read-Host 'Name'").await;
    let (line, _, request) = held(fleet.type_in(0, "\r").await);
    fleet
        .core
        .multiexec
        .approve(line, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("Name: ").await;
    }

    // `$x = @'` opens a here-string at a prompt (it would go through unrated there). While running it is input to the
    // running statement: `held` panics unless the Enter was held and rated.
    let (opener, _, _) = held(fleet.type_in(0, "$x = @'\r").await);
    fleet.core.multiexec.cancel(opener).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_line_stops_being_straight_through_once_a_console_returns_to_its_prompt() {
    // Review M3 (B5): password mode forwards keys straight through until Enter. If a tab's prompt comes back mid-line
    // (its statement ended), a forwarded line would run there as a statement unrated. Before forwarding each chunk,
    // every target's console is re-checked; when any is back at its prompt, password mode is dropped and the line is
    // rated instead of sent straight through.
    let mut fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    fleet.type_in(0, "Read-Host 'Password'").await;
    let (line, _, request) = held(fleet.type_in(0, "\r").await);
    fleet
        .core
        .multiexec
        .approve(line, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("Password: ").await;
    }

    // A first password key is forwarded while both consoles are at the prompt.
    fleet.type_in(0, "x").await;
    // Tab 1's Read-Host ends from outside Type in all tabs, so its console returns to its prompt.
    fleet.core.terminals.write(fleet.panes[1].id, b"\r".to_vec()).await;
    fleet.panes[1].expect("PS C:\\Users\\alice> ").await;

    // The rest of the "password" line would run as a statement in tab 1. Re-checking every console drops password mode
    // and re-rates, so tab 1 (back at its prompt) is left out and never receives the keys.
    let rest = fleet.type_in(0, "\x15Restart-Computer\r").await;
    if let InputOutcome::Typed { reached, .. } = &rest {
        assert!(
            !reached.contains(&fleet.panes[1].id),
            "tab 1 was left out once its prompt returned: {rest:?}"
        );
    }
    for i in 0..2 {
        assert!(
            !fleet.statements(i).iter().any(|s| s.contains("Restart-Computer")),
            "tab {i} never ran the line as a statement unrated: {:?}",
            fleet.statements(i)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_line_is_not_diverted_by_typing_into_an_unpicked_tab() {
    // Review R5: a tab still in a held line's targets is queued even after it is un-picked, so its console cannot be
    // changed to a different statement and then run under the first line's approval once it is re-picked.
    let fleet = Fleet::new(2).await;
    let mut events = fleet.core.multiexec.subscribe();

    // A line typed into both tabs and held for approval.
    fleet.type_in(0, "Stop-Computer -Force").await;
    let (line, tier, request) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::High);
    let request = request.expect("asked first");

    // Un-pick tab 1, then type a different, dangerous statement into it alone. It is still a target of the held line, so
    // the keys are queued (not written to its console), keeping its console on the rated line.
    fleet.core.multiexec.set_targets(vec![fleet.panes[0].id]).await.unwrap();
    let diverted = fleet.type_in(1, "\x15Restart-Computer -Force\r").await;
    assert!(matches!(diverted, InputOutcome::Queued { .. }), "{diverted:?}");

    // Re-pick tab 1 and approve the first line.
    fleet
        .core
        .multiexec
        .set_targets(vec![fleet.panes[0].id, fleet.panes[1].id])
        .await
        .unwrap();
    fleet.core.multiexec.approve(line, answers(&request)).await.unwrap();
    assert!(line_done(&mut events, line).await);

    // Both tabs ran the approved statement; neither ran the one typed while tab 1 was un-picked.
    for i in 0..2 {
        let sent = fleet.statements(i);
        assert!(
            sent.iter().any(|s| s.contains("Stop-Computer")),
            "tab {i} ran the approved line: {sent:?}"
        );
        assert!(
            !sent.iter().any(|s| s.contains("Restart-Computer")),
            "tab {i} never ran the diverted line under the wrong approval: {sent:?}"
        );
    }
}

// ---- Support bundles from Windows hosts -------------------------------------------------------------------

fn read_zip(path: &Path) -> (BTreeMap<String, Vec<u8>>, Value) {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        files.insert(entry.name().unwrap().to_string(), bytes);
    }
    let manifest = serde_json::from_slice(&files["manifest.json"]).unwrap();
    (files, manifest)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_support_bundle_collects_windows_presets_and_files_beside_a_linux_host() {
    let core = core().await;
    let ctx = core.ctx();
    let (win, win01) = windows(&core, "win01").await;
    let (_lin, web01) = linux(&core, "web01").await;
    win.set_file(r"C:\ProgramData\App\app.conf", b"port=8080\ndb_password = hunter2\n");
    let request = BundleRequest {
        session_ids: vec![win01, web01],
        presets: vec![PresetId::WindowsSystem, PresetId::WindowsNetwork, PresetId::System],
        windows_files: vec![
            r"C:\ProgramData\App\app.conf".into(),
            r"C:\ProgramData\App\missing.log".into(),
        ],
        timeout_secs: Some(60),
        ..BundleRequest::default()
    };
    let preview = core.bundles.preview(&ctx, &request).await.unwrap();
    assert_eq!(preview.tier, Tier::Low, "every preset reads: {:?}", preview.reasons);
    let folder = temp_folder("bundle-windows");
    let output = folder.join("bundle.zip");
    let job = match core.bundles.submit(&ctx, &request, &output).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => panic!("asked for {:?}", request.reasons),
    };
    finished(&core, job).await;
    let (files, manifest) = read_zip(&output);
    let windows_folder = files
        .keys()
        .find(|k| k.contains("get-computerinfo"))
        .map(|k| k.split('/').next().unwrap().to_owned())
        .expect("the Windows host's folder");
    let get = |name: &str| {
        files
            .iter()
            .find(|(k, _)| k.starts_with(&windows_folder) && k.contains(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(|| panic!("no {name} in {:?}", files.keys()))
    };
    assert!(get("get-computerinfo").contains("Windows Server 2022"));
    assert!(get("ipconfig-all").contains("192.0.2.10"));
    // The file came through PowerShell's read, scrubbed like any other.
    let conf = get("app.conf");
    assert!(conf.contains("port=8080") && !conf.contains("hunter2"), "{conf}");
    // The Linux host gave the Linux preset only.
    assert!(!files
        .keys()
        .any(|k| !k.starts_with(&windows_folder) && k.contains("get-computerinfo")));
    assert!(files
        .keys()
        .any(|k| !k.starts_with(&windows_folder) && k.contains("uname-a")));
    assert!(manifest["windowsItems"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    std::fs::remove_dir_all(&folder).ok();
}
