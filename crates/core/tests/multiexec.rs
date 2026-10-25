//! Post-MVP P6, SS-10 MultiExec end to end: keys typed into one terminal go to the picked ones only,
//! Enter is held and the line rated by the policy engine (Low sent at once, a confirm, the full
//! approval for a dangerous line, Prod raising the tier, keys Remotely can't follow), a line run with
//! Ctrl+O is held and rated like one run with Enter, keys that open the line in an editor are refused, a
//! pager is not read-only, the bus sends only the held keys of a rated line, cancelling clears the line
//! with Ctrl+C, a password prompt and a full-screen program pass keys straight through with nothing
//! rated, journaled or audited, and what the audit log keeps of a line.
//!
//! QL-12: each line sent is recorded in each terminal until its prompt comes back, grouped and diffed
//! like a Compare run, with password prompts, full-screen keys and cancelled lines left out, secrets
//! scrubbed, caps kept, and exports audited without their output. QL-07: one notification per line.
//!
//! SSH goes to `fakes::ssh_server` on 127.0.0.1 (one server per host, passwords made at run time); its
//! toy interactive shell logs each line it runs, and each line Ctrl+C dropped. No real host is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::bulk::{render_recorded, DiffKind, ExportFormat, GroupOptions};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command};
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::fakes::FakeVmware;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::folder::{FolderInfo, FolderTracking};
use remotely_core::terminal::multiexec::{InputOutcome, LineMode, MultiExecEvent};
use remotely_core::terminal::record::{CaptureEnd, CaptureState, RecordLimits};
use remotely_core::terminal::shell_user::UserInfo;
use remotely_core::terminal::{NotifyWhen, TerminalEvent, TerminalSettings, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::{Core, CoreError};
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
    /// Events seen while reading the output.
    seen: Vec<TerminalEvent>,
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
                    Some(event) = self.events.recv() => self.seen.push(event),
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
                    Some(event) = self.events.recv() => self.seen.push(event),
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
                        startup_on_reconnect: false,
                        prompt_hook: None,
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
                seen: Vec::new(),
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

// ---- Keys that run the line another way, and keys refused ------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_run_with_ctrl_o_is_held_rated_and_audited_before_it_reaches_the_hosts() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    // The toy shell runs a line on Ctrl+O, as bash and zsh do.
    let outcome = fleet.type_in(0, "touch /tmp/ctrl-o\x0f").await;
    assert!(
        matches!(&outcome, InputOutcome::Held { run_key, .. } if run_key == "Ctrl+O"),
        "the MultiExec bar names the key: {outcome:?}"
    );
    let (line, tier, request, job) = held(outcome);
    assert!(tier >= Tier::Medium, "{tier:?}");
    assert!(job.is_none());
    let request = request.expect("an approval");
    assert_eq!(request.action, ActionKind::ExecOther);
    let summary = "MultiExec: run `touch /tmp/ctrl-o` with Ctrl+O in 2 terminals";
    assert_eq!(request.summary, summary);
    assert!(
        request.warnings.iter().any(|w| w.starts_with("Ctrl+O runs the line")),
        "{:?}",
        request.warnings
    );
    let exec = request.exec.as_deref().expect("the line, for the dialog");
    assert_eq!(exec.run_key.as_deref(), Some("Ctrl+O"), "the dialog presses Ctrl+O");
    // Held: the terminals show the line, but have not run it.
    for pane in &mut fleet.panes {
        pane.expect("touch /tmp/ctrl-o").await;
        pane.settle().await;
    }
    assert!(fleet.ran(0).is_empty() && fleet.ran(1).is_empty(), "{:?}", fleet.log(0));

    fleet.core.multiexec.approve(line, answers(&request)).await.unwrap();
    loop {
        if let MultiExecEvent::LineDone {
            line_id, sent, run_key, ..
        } = events.recv().await.unwrap()
        {
            if line_id == line {
                assert!(sent);
                assert_eq!(run_key, "Ctrl+O", "the MultiExec bar says Ctrl+O went, not Enter");
                break;
            }
        }
    }
    for i in [0, 1] {
        fleet.panes[i].expect("\r\n$ ").await;
        assert_eq!(fleet.ran(i), ["touch /tmp/ctrl-o"]);
    }
    let audit = fleet.audit().await;
    assert!(
        audit.iter().any(|e| e.event == "job_started" && e.action == summary),
        "{audit:?}"
    );

    // bash brings the next history line up after Ctrl+O: the next line is one Remotely can't follow.
    let (next, tier, request, _) = held(fleet.type_in(0, "uptime\r").await);
    assert!(tier >= Tier::Medium, "read-only as typed, but not as run");
    assert!(request.unwrap().exec.as_deref().unwrap().unreliable);
    fleet.core.multiexec.cancel(next).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C\r\n$ ").await;
    }
    assert_eq!(fleet.ran(0), ["touch /tmp/ctrl-o"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_that_open_the_line_in_an_editor_are_refused_and_never_reach_the_hosts() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;

    let InputOutcome::Refused { reason, reached, .. } = fleet.type_in(0, "ls -l\x18\x05").await else {
        panic!("Ctrl+X Ctrl+E is refused");
    };
    assert!(reason.starts_with("Ctrl+X Ctrl+E was not sent"), "{reason}");
    assert_eq!(reached, [fleet.id(0), fleet.id(1)], "the keys before it went");
    // Ctrl+X waits for the key after it, typed apart as well.
    assert!(matches!(fleet.type_in(0, "\x18").await, InputOutcome::Typed { .. }));
    assert!(matches!(fleet.type_in(0, "\x05").await, InputOutcome::Refused { .. }));
    // v after Esc: vi mode's edit-and-execute.
    let InputOutcome::Refused { reason, .. } = fleet.type_in(0, "\x1bv").await else {
        panic!("Esc then v is refused");
    };
    assert!(reason.starts_with("v was not sent"), "{reason}");

    // None of those keys reached a shell: Ctrl+C drops just what was typed before them.
    fleet.type_in(0, "\x03").await;
    for i in [0, 1] {
        fleet.panes[i].expect("^C\r\n$ ").await;
        assert!(
            fleet.log(i).contains(&"interrupt ls -l".to_owned()),
            "{:?}",
            fleet.log(i)
        );
        assert!(fleet.ran(i).is_empty());
    }
    assert!(fleet
        .core
        .store
        .recent_jobs(&fleet.core.ctx, 50)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pager_is_not_read_only_in_multiexec_but_is_in_compare() {
    let mut fleet = Fleet::new(2).await;
    fleet.pick(&[0, 1]).await;

    let (line, tier, request, _) = held(fleet.type_in(0, "less /etc/os-release\r").await);
    assert!(tier >= Tier::Medium, "{tier:?}");
    let request = request.expect("an approval");
    assert_eq!(request.action, ActionKind::ExecOther);
    assert!(
        request.reasons.iter().any(|r| r.contains("less stays open")),
        "{:?}",
        request.reasons
    );
    fleet.core.multiexec.cancel(line).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C\r\n$ ").await;
    }
    assert!(fleet.ran(0).is_empty() && fleet.ran(1).is_empty());

    // Compare runs it without a terminal, so nothing waits for keys.
    let compare = Command::RemoteExec {
        targets: fleet
            .sessions
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect(),
        script: "less /etc/os-release".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    };
    let preview = fleet.core.bus.preview(&fleet.core.ctx, &compare).await.unwrap();
    assert_eq!(preview.action, ActionKind::ExecReadOnly);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bus_refuses_a_line_whose_keys_are_not_what_was_rated() {
    let mut fleet = Fleet::new(2).await;
    let targets: Vec<TargetRef> = (0..2)
        .map(|i| TargetRef::Terminal {
            terminal_id: fleet.id(i),
            session_id: None,
        })
        .collect();
    let crafted = |keys: &str| Command::TerminalLine {
        targets: targets.clone(),
        line: "uptime".into(),
        unreliable: false,
        keys: keys.into(),
    };
    for keys in [
        "\rrm -rf /tmp/x\r",
        "\r\x18\x05",
        "x",
        "\x0frm -rf /tmp/x\r",
        "\x1b\r\r",
    ] {
        let err = fleet.core.bus.submit(&fleet.core.ctx, crafted(keys)).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "{keys:?}: {err:?}");
    }
    // Nor can the UI send one: only MultiExec builds them, from what it held and rated.
    assert!(crafted("\r").check_from_ui().is_err());
    let compare = Command::RemoteExec {
        targets: vec![TargetRef::Session {
            session_id: fleet.sessions[0],
        }],
        script: "uptime".into(),
        sudo: false,
        sudo_password_id: None,
        trust_new_host_keys: false,
        timeout_secs: None,
    };
    assert!(compare.check_from_ui().is_ok());

    for pane in &mut fleet.panes {
        pane.settle().await;
    }
    assert!(fleet.ran(0).is_empty() && fleet.ran(1).is_empty());
    assert!(fleet
        .core
        .store
        .recent_jobs(&fleet.core.ctx, 50)
        .await
        .unwrap()
        .is_empty());
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

// ---- QL-12: recording into Compare ----------------------------------------------------------------

/// What `LineFinished` said about a line.
#[derive(Debug)]
struct Finished {
    terminals: usize,
    after_secs: u64,
    unfinished: usize,
}

/// Waits for a recorded line's one `LineFinished`.
async fn line_finished(events: &mut Receiver<MultiExecEvent>, line: Uuid) -> Finished {
    timeout(WAIT, async {
        loop {
            if let MultiExecEvent::LineFinished {
                line_id,
                terminals,
                after_secs,
                unfinished,
                ..
            } = events.recv().await.unwrap()
            {
                if line_id == line {
                    return Finished {
                        terminals,
                        after_secs,
                        unfinished,
                    };
                }
            }
        }
    })
    .await
    .expect("every terminal finished the line in time")
}

/// Waits until a line went out (its job ended, so the next line is not queued behind it) and every
/// terminal finished recording it, in either order.
async fn line_recorded(events: &mut Receiver<MultiExecEvent>, line: Uuid) -> Finished {
    let mut sent = false;
    let mut finished = None;
    timeout(WAIT, async {
        loop {
            match events.recv().await.unwrap() {
                MultiExecEvent::LineDone { line_id, sent: s, .. } if line_id == line => {
                    assert!(s, "the line was sent");
                    sent = true;
                }
                MultiExecEvent::LineFinished {
                    line_id,
                    terminals,
                    after_secs,
                    unfinished,
                    ..
                } if line_id == line => {
                    finished = Some(Finished {
                        terminals,
                        after_secs,
                        unfinished,
                    });
                }
                _ => {}
            }
            if sent {
                if let Some(finished) = finished.take() {
                    return finished;
                }
            }
        }
    })
    .await
    .expect("the line was sent and recorded in time")
}

/// Types a line into terminal `i` and approves it if it asks: the line's id.
async fn send_line(fleet: &Fleet, i: usize, keys: &str) -> Uuid {
    let (line, _, request, _) = held(fleet.type_in(i, keys).await);
    if let Some(request) = request {
        fleet.core.multiexec.approve(line, answers(&request)).await.unwrap();
    }
    line
}

fn ids(fleet: &Fleet, which: &[usize]) -> Vec<String> {
    which.iter().map(|i| fleet.id(*i).to_string()).collect()
}

fn os_release(version: &str) -> String {
    format!("NAME=\"Ubuntu\"\nVERSION_ID=\"{version}\"\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_line_is_recorded_per_terminal_and_grouped_like_a_compare_run() {
    let fleet = Fleet::build(
        3,
        |i, s| {
            let release = if i == 2 { "24.04" } else { "22.04" };
            s.with_file("/etc/os-release", &os_release(release))
                .with_program("colours", "\x1b[1;32mgreen\x1b[0m  plain\n10%\r100%\n")
                .with_program("report", if i == 0 { "ok   \n" } else { "ok\n" })
        },
        |_| Environment::Lab,
    )
    .await;
    fleet.pick(&[0, 1, 2]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, tier, _, _) = held(fleet.type_in(0, "cat /etc/os-release\r").await);
    assert_eq!(tier, Tier::Low);
    let finished = line_recorded(&mut events, line).await;
    assert_eq!((finished.terminals, finished.unfinished), (3, 0));

    let list = fleet.core.multiexec.recordings();
    assert_eq!(list.lines.len(), 1);
    let recorded = &list.lines[0];
    assert_eq!(recorded.line, "cat /etc/os-release");
    assert_eq!(recorded.tier, Some(Tier::Low));
    assert_eq!((recorded.terminals, recorded.finished, recorded.groups), (3, 3, 2));
    assert_eq!(recorded.headline, "2 hosts same, 1 differ");
    assert!(recorded.duration_ms.is_some() && !recorded.waiting_approval);

    let results = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(results.groups.len(), 2);
    let (a, b) = (&results.groups[0], &results.groups[1]);
    assert_eq!((a.label.as_str(), b.label.as_str()), ("A", "B"));
    assert_eq!(a.hosts, ids(&fleet, &[0, 1]));
    assert_eq!(b.hosts, ids(&fleet, &[2]));
    // The output only: not the command's own line, not the prompt that came back.
    assert_eq!(a.stdout.as_deref(), Some(os_release("22.04").as_str()));
    assert_eq!(b.stdout.as_deref(), Some(os_release("24.04").as_str()));
    let names: Vec<&str> = results.hosts.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["web01", "web02", "web03"]);
    assert!(results.hosts.iter().all(|h| h.status == "succeeded"));
    assert!(results.terminals.iter().all(|t| t.state
        == CaptureState::Done {
            how: CaptureEnd::Prompt
        }));

    // BX-03's diff between the two groups' samples.
    let diff = fleet
        .core
        .multiexec
        .recorded_diff(line, fleet.id(0), fleet.id(2), GroupOptions::default())
        .unwrap();
    let shown: Vec<(DiffKind, &str)> = diff.stdout.iter().map(|l| (l.kind, l.text.as_str())).collect();
    assert_eq!(
        shown,
        [
            (DiffKind::Same, "NAME=\"Ubuntu\""),
            (DiffKind::Removed, "VERSION_ID=\"22.04\""),
            (DiffKind::Added, "VERSION_ID=\"24.04\""),
        ]
    );
    assert_eq!((diff.left.as_str(), diff.right.as_str()), ("web01", "web03"));

    // Escapes are dropped and redrawn lines read as they ended.
    let colours = send_line(&fleet, 1, "colours\r").await;
    line_recorded(&mut events, colours).await;
    let results = fleet.core.multiexec.recorded(colours, GroupOptions::default()).unwrap();
    assert_eq!(results.groups.len(), 1);
    assert_eq!(results.groups[0].stdout.as_deref(), Some("green  plain\n100%\n"));

    // Trailing whitespace makes outputs differ unless it is ignored.
    let report = send_line(&fleet, 0, "report\r").await;
    line_recorded(&mut events, report).await;
    let exact = fleet.core.multiexec.recorded(report, GroupOptions::default()).unwrap();
    assert_eq!(exact.groups.len(), 2);
    let loose = fleet
        .core
        .multiexec
        .recorded(
            report,
            GroupOptions {
                ignore_trailing_whitespace: true,
            },
        )
        .unwrap();
    assert_eq!(loose.groups.len(), 1);
    assert_eq!(loose.headline, "All 3 hosts the same");
    assert!(loose.ignore_trailing_whitespace);

    // Newest first.
    let lines: Vec<String> = fleet
        .core
        .multiexec
        .recordings()
        .lines
        .into_iter()
        .map(|l| l.line)
        .collect();
    assert_eq!(lines, ["report", "colours", "cat /etc/os-release"]);

    // Turning MultiExec off drops them.
    fleet.core.multiexec.stop().await.unwrap();
    assert!(fleet.core.multiexec.recordings().lines.is_empty());
    assert!(fleet.core.multiexec.recorded(line, GroupOptions::default()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_terminal_fills_in_when_its_prompt_comes_back() {
    let mut fleet = Fleet::build(
        3,
        |i, s| {
            let s = s.with_hostname(&format!("web{:02}.example.com", i + 1));
            if i == 2 {
                s.with_exec_delay(Duration::from_millis(1500))
            } else {
                s
            }
        },
        |_| Environment::Lab,
    )
    .await;
    fleet.pick(&[0, 1, 2]).await;
    let mut events = fleet.core.multiexec.subscribe();
    let mut early = fleet.core.multiexec.subscribe();

    let (line, _, _, _) = held(fleet.type_in(0, "hostname\r").await);
    for i in [0, 1] {
        fleet.panes[i]
            .expect(&format!("web{:02}.example.com\r\n$ ", i + 1))
            .await;
    }
    // Two are done, the slow one still runs. The job presses Enter in each terminal on its own, so the
    // fast two can finish before the slow one's Enter has even reached it (Waiting, "pending"): wait
    // for that Enter too. Its host then holds the answer for 1.5 s; had the test missed that, the
    // assertions below would say so.
    let results = timeout(WAIT, async {
        loop {
            let r = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
            if r.line.finished >= 2 && r.counts.pending == 0 {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("two terminals finished and the slow one got its Enter");
    assert_eq!((results.counts.succeeded, results.counts.running), (2, 1));
    assert_eq!(results.terminals[2].state, CaptureState::Running);
    assert_eq!(results.hosts[2].status, "running");
    assert_eq!(results.hosts[2].group, None);
    assert_eq!(results.groups.len(), 2);
    assert!(
        results.headline.ends_with("; 1 host still to finish"),
        "{}",
        results.headline
    );
    assert!(results.line.duration_ms.is_none());
    while let Ok(event) = early.try_recv() {
        assert!(
            !matches!(event, MultiExecEvent::LineFinished { .. }),
            "not before every terminal is done"
        );
    }

    let finished = line_recorded(&mut events, line).await;
    assert_eq!(finished.terminals, 3);
    assert!(finished.after_secs >= 1, "{finished:?}");
    let results = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(results.headline, "3 hosts, all different");
    assert_eq!(
        results.groups[2].stdout.as_deref(),
        Some("web03.example.com\n"),
        "{:?}",
        results.groups
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_prompts_full_screen_keys_and_cancelled_lines_are_not_recorded() {
    let sudo = new_password();
    let mut fleet = Fleet::build(
        2,
        |_, s| s.with_sudo(SudoMode::Password(sudo.clone())),
        |_| Environment::Lab,
    )
    .await;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, _, _, _) = held(fleet.type_in(0, "sudo whoami\r").await);
    for pane in &mut fleet.panes {
        pane.expect("[sudo] password for alice: ").await;
    }
    assert!(line_done(&mut events, line).await, "Enter went");
    let waiting = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert!(
        waiting.terminals.iter().all(|t| t.state == CaptureState::Running),
        "at the password prompt, still running"
    );
    let InputOutcome::Typed { mode, .. } = fleet.type_in(0, &format!("{sudo}\r")).await else {
        panic!("a password is not held");
    };
    assert_eq!(mode, LineMode::Password);
    line_finished(&mut events, line).await;
    let results = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(results.groups.len(), 1);
    assert_eq!(
        results.groups[0].stdout.as_deref(),
        Some("[sudo] password for alice: \nok\n")
    );

    // A full-screen program: its screens and the keys sent into it are not recorded.
    let (top, _, request, _) = held(fleet.type_in(0, "top\r").await);
    fleet
        .core
        .multiexec
        .approve(top, answers(&request.unwrap()))
        .await
        .unwrap();
    assert!(line_done(&mut events, top).await);
    for pane in &mut fleet.panes {
        pane.expect("Tasks: 99 total\r\n").await;
    }
    let InputOutcome::Typed { mode, .. } = fleet.type_in(0, "kx").await else {
        panic!("keys for top pass straight through");
    };
    assert_eq!(mode, LineMode::FullScreen);
    fleet.type_in(0, "q").await;
    line_finished(&mut events, top).await;
    let results = fleet.core.multiexec.recorded(top, GroupOptions::default()).unwrap();
    assert!(results.terminals.iter().all(|t| t.full_screen));
    assert_eq!(results.groups[0].stdout.as_deref(), Some(""));
    assert!(results.line.full_screen);

    // A line cancelled before its Enter never ran: it is not kept.
    let (rm, _, _, _) = held(fleet.type_in(0, "rm -rf /srv/x\r").await);
    fleet.core.multiexec.cancel(rm).await.unwrap();
    for pane in &mut fleet.panes {
        pane.expect("^C\r\n$ ").await;
    }
    assert!(fleet.core.multiexec.recorded(rm, GroupOptions::default()).is_err());

    // Only the two lines: no password, no keys for top.
    let list = fleet.core.multiexec.recordings();
    let lines: Vec<&str> = list.lines.iter().map(|l| l.line.as_str()).collect();
    assert_eq!(lines, ["top", "sudo whoami"]);
    let everything = format!("{list:?}");
    assert!(!everything.contains(&sudo) && !everything.contains("kx"));
    for run in fleet.core.multiexec.recorded_runs(None).unwrap() {
        assert!(!format!("{run:?}").contains(&sudo));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_password_typed_while_a_line_records_is_scrubbed() {
    let sudo = new_password();
    let mut fleet = Fleet::build(
        2,
        |_, s| s.with_sudo(SudoMode::EchoesPassword(sudo.clone())),
        |_| Environment::Lab,
    )
    .await;
    let core = &fleet.core;
    let secret = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            "lab sudo",
            SecretString::new(sudo.as_str()),
        )
        .await
        .unwrap()
        .id;
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, _, _, _) = held(fleet.type_in(0, "sudo whoami\r").await);
    for pane in &mut fleet.panes {
        pane.expect("[sudo] password for alice: ").await;
    }
    for i in [0, 1] {
        fleet
            .core
            .terminals
            .type_secret(&fleet.core.ctx, fleet.id(i), secret, false, None)
            .await
            .unwrap();
    }
    // This toy sudo prints it back, so the terminal shows it.
    for pane in &mut fleet.panes {
        pane.expect(&format!("ok {sudo}\r\n$ ")).await;
    }
    line_recorded(&mut events, line).await;
    let results = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(results.groups.len(), 1);
    assert_eq!(
        results.groups[0].stdout.as_deref(),
        Some("[sudo] password for alice: \nok [redacted]\n")
    );
    let runs = fleet.core.multiexec.recorded_runs(None).unwrap();
    for format in [ExportFormat::Html, ExportFormat::Csv, ExportFormat::Json] {
        let (text, _, _) = render_recorded(&runs, format, GroupOptions::default()).unwrap();
        assert!(!text.contains(&sudo), "{format:?}");
        assert!(text.contains("ok [redacted]"), "{format:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recordings_keep_to_their_caps_and_say_when_one_was_hit() {
    let fleet = Fleet::new(2).await;
    fleet.core.multiexec.set_record_limits(RecordLimits {
        max_lines: 2,
        max_output: 64,
        max_session_bytes: 1024 * 1024,
        line_time: Duration::from_millis(1500),
    });
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let mut last = None;
    for _ in 0..3 {
        let line = send_line(&fleet, 0, "seq 100\r").await;
        line_recorded(&mut events, line).await;
        last = Some(line);
    }
    let list = fleet.core.multiexec.recordings();
    assert_eq!(list.lines.len(), 2, "the session keeps its newest lines");
    assert_eq!(list.dropped, 1);
    assert_eq!(list.limits.max_lines, 2);
    assert!(list.lines[0].truncated);
    let results = fleet
        .core
        .multiexec
        .recorded(last.unwrap(), GroupOptions::default())
        .unwrap();
    assert_eq!(results.groups.len(), 1, "cut outputs still group by their whole text");
    let group = &results.groups[0];
    assert!(group.truncated);
    let text = group.stdout.as_deref().unwrap();
    assert!(text.starts_with("1\n2\n") && text.ends_with("99\n100\n"), "{text}");
    assert!(text.contains("Remotely cut"), "{text}");
    assert!(results.terminals.iter().all(|t| t.truncated && t.output_bytes == 292));

    // The time limit: recording stops, the command goes on.
    let sleep = send_line(&fleet, 0, "sleep 5\r").await;
    let finished = line_recorded(&mut events, sleep).await;
    assert_eq!(finished.unfinished, 2);
    let results = fleet.core.multiexec.recorded(sleep, GroupOptions::default()).unwrap();
    assert!(results.terminals.iter().all(|t| t.state == CaptureState::TimedOut));
    assert_eq!(results.groups.len(), 1);
    assert_eq!(results.groups[0].error_code.as_deref(), Some("time_limit"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recorded_lines_export_with_groups_and_diffs_and_the_audit_keeps_what_and_where_only() {
    let fleet = Fleet::build(
        3,
        |i, s| s.with_file("/etc/os-release", &os_release(if i == 2 { "24.04" } else { "22.04" })),
        |_| Environment::Lab,
    )
    .await;
    fleet.pick(&[0, 1, 2]).await;
    let mut events = fleet.core.multiexec.subscribe();
    let (release, _, _, _) = held(fleet.type_in(0, "cat /etc/os-release\r").await);
    line_recorded(&mut events, release).await;
    let (who, _, _, _) = held(fleet.type_in(0, "whoami\r").await);
    line_recorded(&mut events, who).await;

    let core = &fleet.core;
    let runs = core.multiexec.recorded_runs(None).unwrap();
    let lines: Vec<&str> = runs.iter().map(|r| r.line.as_str()).collect();
    assert_eq!(lines, ["cat /etc/os-release", "whoami"], "oldest first");
    let mut files = Vec::new();
    for format in [ExportFormat::Html, ExportFormat::Csv, ExportFormat::Json] {
        let path = std::env::temp_dir().join(format!(
            "remotely-test-{}.{}",
            Uuid::new_v4().simple(),
            format.extension()
        ));
        let done = core
            .bulk
            .export_recorded(&core.ctx, &runs, format, GroupOptions::default(), &path)
            .await
            .unwrap();
        assert_eq!((done.lines, done.outputs, done.redacted), (2, 6, 0));
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        files.push(path.file_name().unwrap().to_string_lossy().into_owned());
        assert!(
            text.contains("cat /etc/os-release") && text.contains("whoami"),
            "{format:?}"
        );
        assert!(text.contains("24.04") && text.contains("web03"), "{format:?}");
        match format {
            ExportFormat::Html => {
                assert!(text.contains("Diff from group A"));
                assert!(text.contains("<div class=\"removed\">- VERSION_ID=&quot;22.04&quot;</div>"));
                assert!(text.contains("<div class=\"added\">+ VERSION_ID=&quot;24.04&quot;</div>"));
                assert!(!text.contains("<script"));
            }
            ExportFormat::Csv => {
                let header = text.lines().next().unwrap();
                assert!(header.ends_with("output_truncated,error,diff_from_group_a"), "{header}");
                assert!(text.contains("+ VERSION_ID=\"\"24.04\"\""), "{text}");
            }
            ExportFormat::Json => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                let groups = &value["lines"][0]["groups"];
                assert_eq!(groups.as_array().unwrap().len(), 2);
                assert!(groups[0]["diffFromA"].is_null());
                assert_eq!(groups[1]["diffFromA"][2]["kind"], "added");
                assert_eq!(groups[1]["terminals"][0], "web03");
                assert_eq!(value["lines"][1]["headline"], "All 3 hosts the same");
            }
        }
    }
    // One line on its own.
    assert_eq!(core.multiexec.recorded_runs(Some(who)).unwrap().len(), 1);

    let audit = fleet.audit().await;
    let exports: Vec<&AuditEntry> = audit.iter().filter(|e| e.event == "multiexec_exported").collect();
    assert_eq!(exports.len(), 3);
    for (entry, file) in exports.iter().rev().zip(&files) {
        let detail = entry.detail.as_deref().unwrap();
        assert_eq!(detail, format!("2 lines from 3 terminals to {file}"));
    }
    // Outputs never reach the audit log.
    for entry in &audit {
        let text = format!("{entry:?}");
        assert!(!text.contains("22.04") && !text.contains("VERSION_ID"), "{entry:?}");
    }
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

// ---- QL-07: one notification per MultiExec line -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multiexec_line_notifies_once_for_all_its_terminals_never_per_terminal() {
    let mut fleet = Fleet::new(3).await;
    // "Any command that finishes while I'm away": every command reports, whatever its length.
    fleet.core.terminals.apply_settings(&TerminalSettings {
        notify_when: NotifyWhen::Any,
        ..TerminalSettings::default()
    });
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let (line, _, _, _) = held(fleet.type_in(0, "echo hi\r").await);
    let finished = line_recorded(&mut events, line).await;
    assert_eq!(finished.terminals, 2);
    for i in [0, 1] {
        fleet.panes[i].expect("hi\r\n$ ").await;
        fleet.panes[i].settle().await;
        assert!(
            !fleet.panes[i]
                .seen
                .iter()
                .any(|e| matches!(e, TerminalEvent::CommandFinished { .. })),
            "web{:02} did not notify on its own: {:?}",
            i + 1,
            fleet.panes[i].seen
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, MultiExecEvent::LineFinished { line_id, .. } if line_id == line),
            "one LineFinished per line"
        );
    }

    // Typed into a terminal MultiExec doesn't send to: it notifies as before, short or not.
    assert!(matches!(
        fleet.type_in(2, "echo solo\r").await,
        InputOutcome::Alone { .. }
    ));
    fleet.panes[2].expect("solo\r\n$ ").await;
    fleet.panes[2].settle().await;
    assert!(fleet.panes[2]
        .seen
        .iter()
        .any(|e| matches!(e, TerminalEvent::CommandFinished { .. })));
}

// ---- QL-12 with QL-09: shells with the prompt hook ------------------------------------------------

/// Waits until `check` holds for terminal `i`'s folder info (the prompt hook's reports).
async fn until_folder(fleet: &Fleet, i: usize, what: &str, check: impl Fn(&FolderInfo) -> bool) {
    let ok = timeout(WAIT, async {
        loop {
            if fleet.core.terminals.folder(fleet.id(i)).is_some_and(|f| check(&f)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        ok.is_ok(),
        "web{:02}: {what}; folder info {:?}",
        i + 1,
        fleet.core.terminals.folder(fleet.id(i))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hooked_shell_records_without_its_reports_and_still_notices_a_switched_user() {
    let fleet = Fleet::build(
        2,
        |_, s| s.with_login_shell("bash").with_hostname("web.example.com"),
        |_| Environment::Lab,
    )
    .await;
    // Each shell's prompt hook is set up: OSC 7 and the user report come before every prompt.
    for i in 0..2 {
        until_folder(&fleet, i, "the hook reports", |f| {
            f.tracking == FolderTracking::Following
        })
        .await;
    }
    fleet.pick(&[0, 1]).await;
    let mut events = fleet.core.multiexec.subscribe();

    let line = send_line(&fleet, 0, "hostname\r").await;
    line_recorded(&mut events, line).await;
    let results = fleet.core.multiexec.recorded(line, GroupOptions::default()).unwrap();
    assert_eq!(results.groups.len(), 1);
    assert_eq!(
        results.groups[0].stdout.as_deref(),
        Some("web.example.com\n"),
        "no folder report, user report or hook marker"
    );
    // MultiExec's line is a command like any other to QL-09: alice's shell, still reporting.
    for i in 0..2 {
        until_folder(&fleet, i, "the login user, reporting", |f| {
            f.user == UserInfo::connected("alice")
        })
        .await;
    }

    // `su bob` through MultiExec: its recording ends at bob's prompt, and QL-09 notices the switch.
    let su = send_line(&fleet, 0, "su bob\r").await;
    line_recorded(&mut events, su).await;
    let results = fleet.core.multiexec.recorded(su, GroupOptions::default()).unwrap();
    assert!(results.terminals.iter().all(|t| t.state
        == CaptureState::Done {
            how: CaptureEnd::Prompt
        }));
    assert_eq!(results.groups[0].stdout.as_deref(), Some(""));
    for i in 0..2 {
        until_folder(&fleet, i, "the switch noticed", |f| {
            f.user.stopped && f.user.shell.as_ref().is_some_and(|s| s.username == "bob")
        })
        .await;
        assert_eq!(
            fleet
                .core
                .terminals
                .folder(fleet.id(i))
                .unwrap()
                .user
                .username
                .as_deref(),
            Some("alice"),
            "transfers still run as alice"
        );
    }

    // Back to alice's shell: the hook reports again, and the line was recorded like any other.
    let exit = send_line(&fleet, 0, "exit\r").await;
    line_recorded(&mut events, exit).await;
    for i in 0..2 {
        until_folder(&fleet, i, "reporting again", |f| !f.user.stopped).await;
    }
    // What was recorded (each line, and each terminal's output) holds no hook report: not its marker
    // in any form (the escape sequence, the text of one, the hook's own printf), no folder report and
    // no escape. Only those texts: the runs' timestamps and ids can read "7777" by chance.
    let runs = fleet.core.multiexec.recorded_runs(None).unwrap();
    assert_eq!(runs.len(), 3);
    let recorded: Vec<&str> = runs
        .iter()
        .flat_map(|run| {
            let outputs = run.targets.iter().flat_map(|t| [&t.output, &t.stderr, &t.error]);
            std::iter::once(run.line.as_str()).chain(outputs.filter_map(|text| text.as_deref()))
        })
        .collect();
    for leak in ["7777;", "remotely-", "file://", "\u{1b}"] {
        assert!(
            !recorded.iter().any(|text| text.contains(leak)),
            "{leak:?} in {recorded:?}"
        );
    }
}
