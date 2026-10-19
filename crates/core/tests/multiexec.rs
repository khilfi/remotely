//! Post-MVP P6, SS-10 MultiExec end to end: keys typed into one terminal go to the picked ones only,
//! Enter is held and the line rated by the policy engine (Low sent at once, a confirm, the full
//! approval for a dangerous line, Prod raising the tier, keys Remotely can't follow), cancelling clears
//! the line with Ctrl+C, a password prompt and a full-screen program pass keys straight through with
//! nothing rated, journaled or audited, and what the audit log keeps of a line.
//!
//! SSH goes to `fakes::ssh_server` on 127.0.0.1 (one server per host, passwords made at run time); its
//! toy interactive shell logs each line it runs, and each line Ctrl+C dropped. No real host is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::multiexec::{InputOutcome, LineMode, MultiExecEvent};
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

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
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core
}

/// A pane under test: everything it printed, read as it comes.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    printed: Vec<u8>,
    unread: Vec<u8>,
}

impl Pane {
    async fn expect(&mut self, needle: &str) {
        let found = timeout(WAIT, async {
            loop {
                let text = String::from_utf8_lossy(&self.unread).into_owned();
                if let Some(at) = text.find(needle) {
                    self.unread = text.as_bytes()[at + needle.len()..].to_vec();
                    return;
                }
                tokio::select! {
                    chunk = self.output.recv() => {
                        let chunk = chunk.expect("output ended");
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                    Some(_) = self.events.recv() => {}
                }
            }
        })
        .await;
        assert!(
            found.is_ok(),
            "no {needle:?} in the output; got {:?}",
            String::from_utf8_lossy(&self.unread)
        );
    }

    /// Reads what comes for a moment.
    async fn settle(&mut self) {
        let _ = timeout(Duration::from_millis(300), async {
            loop {
                tokio::select! {
                    Some(chunk) = self.output.recv() => {
                        self.unread.extend_from_slice(&chunk);
                        self.printed.extend_from_slice(&chunk);
                    }
                    Some(_) = self.events.recv() => {}
                }
            }
        })
        .await;
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.printed).into_owned()
    }
}

/// Hosts with a terminal open to each, every one a saved session that logs in from the vault.
struct Fleet {
    core: Core,
    servers: Vec<TestSshServer>,
    sessions: Vec<Uuid>,
    panes: Vec<Pane>,
}

impl Fleet {
    async fn new(count: usize) -> Self {
        Self::build(count, |_, server| server, |_| Environment::Lab).await
    }

    async fn build(
        count: usize,
        server: impl Fn(usize, TestSshServer) -> TestSshServer,
        environment: impl Fn(usize) -> Environment,
    ) -> Self {
        let core = core().await;
        let password = new_password();
        let login = core
            .vault
            .add(
                &core.ctx,
                SecretKind::Password,
                "lab login",
                SecretString::new(password.as_str()),
            )
            .await
            .unwrap()
            .id;
        let mut fleet = Fleet {
            core,
            servers: Vec::new(),
            sessions: Vec::new(),
            panes: Vec::new(),
        };
        for i in 0..count {
            let s = server(i, TestSshServer::start().await.with_password("alice", &password));
            let core = &fleet.core;
            let key = HostKey {
                host: "127.0.0.1".into(),
                port: s.port(),
                key_type: "ssh-ed25519".into(),
                fingerprint: s.host_key_fingerprint(),
            };
            core.known_hosts.trust(&core.ctx, &key, None).await.unwrap();
            let session = core
                .sessions
                .create(
                    &core.ctx,
                    SessionInput {
                        name: format!("web{:02}", i + 1),
                        folder_id: None,
                        host: "127.0.0.1".into(),
                        port: s.port(),
                        username: Some("alice".into()),
                        auth: SessionAuth::Password {
                            password_id: Some(login),
                        },
                        jump_session_id: None,
                        startup_command: None,
                        environment: environment(i),
                        color: None,
                        tags: vec![],
                        vm_id: None,
                    },
                )
                .await
                .unwrap()
                .id;
            let handle = core.terminals.open(&core.ctx, session, SIZE).await.unwrap();
            let mut pane = Pane {
                id: handle.id,
                output: handle.output,
                events: handle.events,
                printed: Vec::new(),
                unread: Vec::new(),
            };
            let connected = timeout(WAIT, async {
                while let Some(event) = pane.events.recv().await {
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
            .await;
            assert!(connected.is_ok(), "web{:02} connected", i + 1);
            pane.expect("Welcome, alice\r\n$ ").await;
            fleet.servers.push(s);
            fleet.sessions.push(session);
            fleet.panes.push(pane);
        }
        fleet
    }

    fn id(&self, i: usize) -> Uuid {
        self.panes[i].id
    }

    async fn pick(&self, which: &[usize]) {
        let ids = which.iter().map(|i| self.id(*i)).collect();
        self.core.multiexec.set_targets(ids).await.unwrap();
    }

    /// Types into pane `i` with MultiExec.
    async fn type_in(&self, i: usize, keys: &str) -> InputOutcome {
        self.core
            .multiexec
            .input(self.id(i), keys.as_bytes().to_vec())
            .await
            .unwrap()
    }

    /// The lines host `i` ran.
    fn ran(&self, i: usize) -> Vec<String> {
        self.servers[i]
            .log()
            .into_iter()
            .filter_map(|l| l.strip_prefix("line ").map(str::to_owned))
            .collect()
    }

    fn log(&self, i: usize) -> Vec<String> {
        self.servers[i].log()
    }

    async fn audit(&self) -> Vec<AuditEntry> {
        self.core.store.recent_audit(&self.core.ctx, 500).await.unwrap()
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

/// The held line, its tier and its approval request (if it needs one).
fn held(outcome: InputOutcome) -> (Uuid, Tier, Option<Box<ApprovalRequest>>, Option<Uuid>) {
    match outcome {
        InputOutcome::Held {
            line_id,
            tier,
            request,
            job_id,
            ..
        } => (line_id, tier, request, job_id),
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

// ---- Broadcasting --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_go_to_the_picked_terminals_only_and_a_read_only_line_runs_at_once() {
    let mut fleet = Fleet::new(3).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let InputOutcome::Typed {
        mode,
        reached,
        left_out,
    } = fleet.type_in(0, "echo hello").await
    else {
        panic!("typed keys go straight out");
    };
    assert_eq!(mode, LineMode::Command);
    assert_eq!(reached, [fleet.id(0), fleet.id(1)]);
    assert!(left_out.is_empty());
    let (line, tier, request, job) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Low);
    assert!(request.is_none() && job.is_some(), "Low: sent without asking");
    assert!(line_done(&mut events, line).await);
    for i in [0, 1] {
        fleet.panes[i].expect("hello\r\n$ ").await;
        assert_eq!(fleet.ran(i), ["echo hello"]);
    }
    fleet.panes[2].settle().await;
    assert!(fleet.ran(2).is_empty(), "web03 was not picked: {:?}", fleet.log(2));
    assert!(!fleet.panes[2].text().contains("hello"));

    // Typing into a terminal that is not picked goes to it alone, as usual.
    let outcome = fleet.type_in(2, "echo alone\r").await;
    assert!(matches!(outcome, InputOutcome::Alone { .. }), "{outcome:?}");
    fleet.panes[2].expect("alone\r\n$ ").await;
    assert_eq!(fleet.ran(2), ["echo alone"]);
    assert_eq!(fleet.ran(0), ["echo hello"]);

    // Enter on an empty line runs nothing, so nothing is rated or audited.
    let jobs = fleet.core.store.recent_jobs(&fleet.core.ctx, 50).await.unwrap().len();
    let outcome = fleet.type_in(0, "\r").await;
    assert!(matches!(outcome, InputOutcome::Typed { .. }), "{outcome:?}");
    fleet.panes[1].expect("\r\n$ ").await;
    assert_eq!(
        fleet.core.store.recent_jobs(&fleet.core.ctx, 50).await.unwrap().len(),
        jobs
    );

    // Off: each terminal gets only its own keys again.
    fleet.core.multiexec.stop().await.unwrap();
    assert!(matches!(
        fleet.type_in(0, "echo solo\r").await,
        InputOutcome::Alone { .. }
    ));
    fleet.panes[0].expect("solo\r\n$ ").await;
    fleet.panes[1].settle().await;
    assert!(!fleet.ran(1).contains(&"echo solo".to_owned()));
}

// ---- Classification on Enter ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_that_may_change_the_hosts_waits_for_a_confirm_and_keys_typed_meanwhile_follow_it() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, tier, request, job) = held(fleet.type_in(1, "touch /tmp/ready\r").await);
    assert_eq!(tier, Tier::Medium);
    assert!(job.is_none());
    let request = request.expect("a confirm");
    assert_eq!(request.action, ActionKind::ExecOther);
    assert_eq!(request.steps, vec![ApprovalStep::Confirm]);
    assert_eq!(request.summary, "MultiExec: run `touch /tmp/ready` in 2 terminals");
    let names: Vec<&str> = request.targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["web01", "web02"], "the dialog shows the targets");
    let exec = request.exec.as_deref().expect("the line, for the dialog");
    assert!(exec.multi_exec && !exec.unreliable);
    assert_eq!(exec.script, "touch /tmp/ready");

    // Held: the terminals show the line, but have not run it.
    for pane in &mut fleet.panes {
        pane.expect("touch /tmp/ready").await;
        pane.settle().await;
    }
    assert!(fleet.ran(0).is_empty() && fleet.ran(1).is_empty());
    // Keys typed now wait for the Enter.
    assert!(matches!(
        fleet.type_in(1, "echo after\r").await,
        InputOutcome::Queued { dropped: false, .. }
    ));

    let answers = answers(&request);
    fleet.core.multiexec.approve(line, answers).await.unwrap();
    assert!(line_done(&mut events, line).await);
    for i in [0, 1] {
        fleet.panes[i].expect("after\r\n$ ").await;
        assert_eq!(fleet.ran(i), ["touch /tmp/ready", "echo after"], "in order");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dangerous_line_needs_the_full_approval_and_cancelling_clears_it_everywhere() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, tier, request, _) = held(fleet.type_in(0, "rm -rf /srv/app\r").await);
    assert_eq!(tier, Tier::High);
    let request = request.unwrap();
    assert_eq!(request.action, ActionKind::ExecDangerous);
    assert!(request.steps.contains(&ApprovalStep::TypeTargetCount { expected: 2 }));
    assert!(request.steps.contains(&ApprovalStep::Reason));
    let exec = request.exec.as_deref().unwrap();
    assert_eq!(exec.dangerous[0].rule, "rm -r / rm -rf");
    // Typed while the dialog is open: dropped with the line.
    assert!(matches!(fleet.type_in(0, "uptime").await, InputOutcome::Queued { .. }));

    fleet.core.multiexec.cancel(line).await.unwrap();
    assert!(!line_done(&mut events, line).await, "cancelled");
    for i in [0, 1] {
        fleet.panes[i].expect("^C\r\n$ ").await;
        assert!(fleet.ran(i).is_empty(), "{:?}", fleet.log(i));
        assert!(
            fleet.log(i).contains(&"interrupt rm -rf /srv/app".to_owned()),
            "{:?}",
            fleet.log(i)
        );
    }
    // The next line starts clean: what was typed during the dialog never reached the shells.
    let (next, tier, _, _) = held(fleet.type_in(0, "echo next\r").await);
    assert_eq!(tier, Tier::Low);
    assert!(line_done(&mut events, next).await);
    for i in [0, 1] {
        fleet.panes[i].expect("next\r\n$ ").await;
        assert_eq!(fleet.ran(i), ["echo next"]);
    }
    let audit = fleet.audit().await;
    let cancelled = audit.iter().find(|e| e.event == "approval_cancelled").unwrap();
    assert_eq!(cancelled.action, "MultiExec: run `rm -rf /srv/app` in 2 terminals");
    assert_eq!(cancelled.tier.as_deref(), Some("high"));
    assert!(!audit
        .iter()
        .any(|e| e.event == "job_started" && e.action.contains("rm -rf")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prod_terminal_raises_the_line_by_one_tier() {
    let mut fleet = Fleet::build(
        2,
        |_, s| s,
        |i| if i == 1 { Environment::Prod } else { Environment::Lab },
    )
    .await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();
    let (line, tier, request, _) = held(fleet.type_in(0, "uptime\r").await);
    assert_eq!(tier, Tier::Medium, "read-only, but web02 is Prod");
    let request = request.unwrap();
    assert!(
        request.reasons.iter().any(|r| r.contains("Prod")),
        "{:?}",
        request.reasons
    );
    let answers = answers(&request);
    fleet.core.multiexec.approve(line, answers).await.unwrap();
    assert!(line_done(&mut events, line).await);
    fleet.panes[1].expect("uptime\r\n").await;
    assert_eq!(fleet.ran(1), ["uptime"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_remotely_cannot_follow_make_the_line_at_least_a_confirm() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;

    // Tab completion: the shell may have completed it to anything.
    let (line, tier, request, _) = held(fleet.type_in(0, "upt\time\r").await);
    assert_eq!(tier, Tier::Medium, "read-only as typed, but not as run");
    let request = request.unwrap();
    assert!(request.exec.as_deref().unwrap().unreliable);
    assert!(
        request.reasons.iter().any(|r| r.contains("can't follow")),
        "{:?}",
        request.reasons
    );
    fleet.core.multiexec.cancel(line).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C\r\n$ ").await;
    }

    // An arrow key (history): Remotely sees only Enter.
    let (line, tier, request, _) = held(fleet.type_in(0, "\x1b[A\r").await);
    assert_eq!(tier, Tier::Medium);
    assert_eq!(request.unwrap().summary, "MultiExec: press Enter in 2 terminals");
    fleet.core.multiexec.cancel(line).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C\r\n$ ").await;
    }

    // Text typed straight into a terminal before its line went to MultiExec.
    fleet.core.multiexec.stop().await.unwrap();
    fleet
        .core
        .terminals
        .write(fleet.id(1), b"rm -rf /tmp/x ".to_vec())
        .await;
    fleet.panes[1].expect("rm -rf /tmp/x ").await;
    fleet.pick(&[0, 1]).await;
    let (line, tier, request, _) = held(fleet.type_in(0, "\r").await);
    assert_eq!(tier, Tier::Medium, "web02's line already held text");
    assert!(request.unwrap().exec.as_deref().unwrap().unreliable);
    fleet.core.multiexec.cancel(line).await.unwrap();
    fleet.panes[1].expect("^C\r\n$ ").await;
    assert!(fleet.ran(1).is_empty(), "{:?}", fleet.log(1));
}

// ---- Pass-through: password prompts and full-screen programs --------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_typed_at_a_prompt_goes_only_to_terminals_at_one_and_is_never_kept() {
    let sudo = new_password();
    let mut fleet = Fleet::build(
        3,
        |i, s| {
            // web03 has passwordless sudo, so it never asks.
            if i == 2 {
                s.with_sudo(SudoMode::NoPassword)
            } else {
                s.with_sudo(SudoMode::Password(sudo.clone()))
            }
        },
        |_| Environment::Lab,
    )
    .await;
    fleet.pick(&[0, 1, 2]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, tier, _, _) = held(fleet.type_in(0, "sudo whoami\r").await);
    assert_eq!(tier, Tier::Low, "whoami only reads, with sudo or not");
    assert!(line_done(&mut events, line).await);
    for i in [0, 1] {
        fleet.panes[i].expect("[sudo] password for alice: ").await;
    }
    fleet.panes[2].expect("ok\r\n$ ").await;

    // web01 shows a password prompt: what is typed now is a password.
    let InputOutcome::Typed {
        mode,
        reached,
        left_out,
    } = fleet.type_in(0, &sudo).await
    else {
        panic!("a password is not held");
    };
    assert_eq!(mode, LineMode::Password);
    assert_eq!(reached, [fleet.id(0), fleet.id(1)]);
    assert_eq!(left_out.len(), 1);
    assert_eq!(left_out[0].terminal_id, fleet.id(2));
    assert_eq!(left_out[0].reason, "not at a password prompt");
    let InputOutcome::Typed { mode, .. } = fleet.type_in(0, "\r").await else {
        panic!("its Enter is not held either");
    };
    assert_eq!(mode, LineMode::Password);
    for i in [0, 1] {
        fleet.panes[i].expect("ok\r\n$ ").await;
        assert!(fleet.log(i).contains(&"sudo alice ok".to_owned()));
    }
    fleet.panes[2].settle().await;

    // The password reached sudo only: not web03's shell, not a job, not the audit log, not the
    // terminals' output.
    for i in 0..3 {
        assert!(!fleet.log(i).iter().any(|l| l.contains(&sudo)), "{:?}", fleet.log(i));
        assert!(!fleet.panes[i].text().contains(&sudo));
    }
    assert_eq!(fleet.ran(2), ["sudo whoami"]);
    let jobs = fleet.core.store.recent_jobs(&fleet.core.ctx, 50).await.unwrap();
    assert_eq!(jobs.len(), 1, "only `sudo whoami` was a job: {jobs:?}");
    for entry in fleet.audit().await {
        assert!(!format!("{entry:?}").contains(&sudo), "{entry:?}");
    }
    let (next, _, _, _) = held(fleet.type_in(0, "echo done\r").await);
    assert!(
        line_done(&mut events, next).await,
        "lines are rated again after the prompt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_for_a_full_screen_program_pass_straight_through_unrated() {
    let mut fleet = Fleet::new(3).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, tier, request, _) = held(fleet.type_in(0, "top\r").await);
    assert_eq!(tier, Tier::Medium);
    let request = request.unwrap();
    fleet.core.multiexec.approve(line, answers(&request)).await.unwrap();
    assert!(line_done(&mut events, line).await);
    for i in [0, 1] {
        fleet.panes[i].expect("Tasks: 99 total\r\n").await;
    }
    // web03 joins with a shell prompt, not in `top`.
    fleet.pick(&[0, 1, 2]).await;
    let status = fleet.core.multiexec.status().await.unwrap();
    assert!(status.targets[0].receives);
    assert_eq!(
        status.targets[0].note.as_deref(),
        Some("a full-screen program is open: keys pass straight through")
    );
    assert!(status.targets[2].receives && status.targets[2].note.is_none());

    let jobs = fleet.core.store.recent_jobs(&fleet.core.ctx, 50).await.unwrap().len();
    let InputOutcome::Typed {
        mode,
        reached,
        left_out,
    } = fleet.type_in(0, "kx\rrm -rf /\r").await
    else {
        panic!("keys for a full-screen program are not held");
    };
    assert_eq!(mode, LineMode::FullScreen);
    assert_eq!(reached, [fleet.id(0), fleet.id(1)]);
    assert_eq!(left_out[0].terminal_id, fleet.id(2));
    assert_eq!(left_out[0].reason, "no full-screen program is open");
    fleet.type_in(0, "q").await;
    for i in [0, 1] {
        fleet.panes[i].expect("\x1b[?1049l$ ").await;
        assert!(
            fleet.log(i).contains(&r#"top keys "kx\rrm -rf /\r""#.to_owned()),
            "{:?}",
            fleet.log(i)
        );
        assert_eq!(fleet.ran(i), ["top"], "nothing typed in top ran in the shell");
    }
    fleet.panes[2].settle().await;
    assert!(fleet.ran(2).is_empty(), "{:?}", fleet.log(2));
    assert_eq!(
        fleet.core.store.recent_jobs(&fleet.core.ctx, 50).await.unwrap().len(),
        jobs
    );
    assert!(!fleet.audit().await.iter().any(|e| e.action.contains("rm -rf")));

    // Back at the prompt, lines are rated again.
    let (_, tier, _, _) = held(fleet.type_in(0, "rm -rf /tmp/old\r").await);
    assert_eq!(tier, Tier::High);
}

// ---- The audit log -------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_line_sent_is_audited_with_the_command_the_sessions_and_the_tier_never_the_output() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, _, _, job) = held(fleet.type_in(0, "whoami\r").await);
    assert!(line_done(&mut events, line).await);
    for pane in &mut fleet.panes {
        pane.expect("alice\r\n$ ").await;
    }
    let (confirm, _, request, _) = held(fleet.type_in(0, "touch /tmp/a\r").await);
    let request = request.unwrap();
    fleet.core.multiexec.approve(confirm, answers(&request)).await.unwrap();
    assert!(line_done(&mut events, confirm).await);

    let audit = fleet.audit().await;
    let started: Vec<&AuditEntry> = audit.iter().filter(|e| e.event == "job_started").collect();
    let finished: Vec<&AuditEntry> = audit.iter().filter(|e| e.event == "job_finished").collect();
    assert_eq!((started.len(), finished.len()), (2, 2), "{audit:?}");
    let job = job.map(|j| j.to_string());
    let low = started
        .iter()
        .find(|e| e.job_id == job)
        .expect("the read-only line's start");
    assert_eq!(low.action, "MultiExec: run `whoami` in 2 terminals");
    assert_eq!(low.tier.as_deref(), Some("low"));
    for session in &fleet.sessions {
        assert!(low.targets_json.contains(&session.to_string()), "{}", low.targets_json);
    }
    for pane in &fleet.panes {
        assert!(low.targets_json.contains(&pane.id.to_string()));
    }
    assert!(low.targets_json.contains("web01") && low.targets_json.contains("web02"));
    let medium = started.iter().find(|e| e.action.contains("touch")).unwrap();
    assert_eq!(medium.tier.as_deref(), Some("medium"));
    assert!(medium.approval_json.as_deref().is_some_and(|a| a.contains("requestId")));
    assert!(audit
        .iter()
        .any(|e| e.event == "approval_granted" && e.action.contains("touch")));
    // The output ("alice") is in no entry's action or detail.
    for entry in audit.iter().filter(|e| e.job_id.is_some()) {
        assert!(!entry.action.contains("alice"), "{entry:?}");
        assert!(
            !entry.detail.as_deref().unwrap_or_default().contains("alice"),
            "{entry:?}"
        );
    }
    assert!(fleet.core.store.verify_audit_chain().await.unwrap().ok);
    // Lines typed into terminals are not Compare runs.
    assert!(fleet.core.bulk.recent(&fleet.core.ctx, 20).await.unwrap().is_empty());
}
