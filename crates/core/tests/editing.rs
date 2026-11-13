//! SS-14, SS-08 (0.8.0 G4): editing a host's files, end to end with the real russh adapter against
//! `fakes::ssh_server::TestSshServer` on 127.0.0.1 (its SFTP temp folder, its toy shell and sudo, and its fake
//! terminal editors), and `fakes::FakeLocalEditors` for the editor on this PC (no real editor ever starts).
//!
//! * "Edit in the terminal": a command on the bus at its tiers, a new tab whose channel is an exec with a PTY running
//!   `/bin/sh` with the path passed byte for byte, the host's editors found once, the session's editor setting, and
//!   `sudoedit` as root with root browsing's password given once and never shown.
//! * "Edit on this PC": one approval for the editing session, a private copy with the Mark of the Web, each save
//!   uploaded once the host's copy is checked (overwrite, save beside it or compare when it changed), and the end:
//!   Stop editing, a vault lock, the terminal closing, a workspace switch; leftovers deleted at the next start.
//!
//! No real host is contacted; test data uses alice and files made at run time in the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer, DEFAULT_SFTP_SERVER};
use remotely_core::fakes::{FakeLocalEditors, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::edit_local::{EditAnswer, EditInfo, EditState, EditTuning};
use remotely_core::terminal::folder::FolderTracking;
use remotely_core::terminal::root_files::RootRequest;
use remotely_core::terminal::{PaneKind, TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretId, SecretKind, SecretString, UnlockMethod};
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::Core;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(20);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn tuning() -> TerminalTuning {
    TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    }
}

fn password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

/// A terminal to the test server, logged in with a password from the vault: the core, the terminal and its session.
async fn pane(server: &TestSshServer, password: &str, environment: Environment) -> (Core, Uuid, Uuid) {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
    let login = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "alice login",
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    let session = core
        .sessions
        .create(&core.ctx(), web01("127.0.0.1", server.port(), login, environment))
        .await
        .unwrap()
        .id;
    let handle = core.terminals.open(&core.ctx(), session, SIZE).await.unwrap();
    let id = handle.id;
    drain(&core, handle).await;
    (core, id, session)
}

/// The session `pane` saves: alice on `host`, logging in with the vault's `login`.
fn web01(host: &str, port: u16, login: SecretId, environment: Environment) -> SessionInput {
    SessionInput {
        name: "web01".into(),
        folder_id: None,
        host: host.into(),
        port,
        username: Some("alice".into()),
        auth: SessionAuth::Password {
            password_id: Some(login),
        },
        jump_session_id: None,
        jump_direct: false,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment,
        color: None,
        tags: vec![],
        vm_id: None,
        kind: Default::default(),
    }
}

/// Waits until the terminal is connected; keeps draining it after.
async fn drain(core: &Core, handle: TerminalHandle) {
    let TerminalHandle {
        id,
        mut output,
        mut events,
    } = handle;
    timeout(WAIT, async {
        loop {
            if core
                .terminals
                .folder(id)
                .is_some_and(|f| f.tracking != FolderTracking::Waiting)
            {
                break;
            }
            tokio::select! {
                _ = output.recv() => {}
                _ = events.recv() => {}
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    })
    .await
    .expect("the terminal connected");
    tokio::spawn(async move {
        loop {
            tokio::select! {
                out = output.recv() => if out.is_none() { break },
                ev = events.recv() => if ev.is_none() { break },
            }
        }
    });
}

/// Approves a request with what its steps ask for.
async fn approve(core: &Core, request: &ApprovalRequest) -> Uuid {
    let mut answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("editing a config".into()),
            ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            _ => {}
        }
    }
    core.bus.approve(request.id, answers).await.unwrap()
}

/// The job of an outcome: queued (Low), or approved first; the tier and the request it was asked with.
async fn job_of(core: &Core, outcome: SubmitOutcome) -> (Uuid, Tier, Option<ApprovalRequest>) {
    match outcome {
        SubmitOutcome::Queued { job_id, tier, .. } => (job_id, tier, None),
        SubmitOutcome::NeedsApproval { request } => (approve(core, &request).await, request.tier, Some(request)),
    }
}

/// What a tab shows until `wanted` shows (its output as text), and the status events it sent.
struct Tab {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    seen: String,
    statuses: Vec<TerminalStatus>,
}

impl Tab {
    fn of(handle: TerminalHandle) -> Self {
        Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            seen: String::new(),
            statuses: Vec::new(),
        }
    }

    /// Waits for the tab's Ended status (it comes right after the notice saying so).
    async fn until_ended(&mut self) {
        let ended = |statuses: &[TerminalStatus]| statuses.iter().any(|s| matches!(s, TerminalStatus::Ended { .. }));
        let found = timeout(WAIT, async {
            while !ended(&self.statuses) {
                tokio::select! {
                    Some(bytes) = self.output.recv() => self.seen.push_str(&String::from_utf8_lossy(&bytes)),
                    Some(event) = self.events.recv() => {
                        if let TerminalEvent::Status { status } = event {
                            self.statuses.push(status);
                        }
                    }
                }
            }
        })
        .await;
        assert!(found.is_ok(), "never ended: {:?}", self.statuses);
    }

    async fn until(&mut self, wanted: &str) -> &str {
        let found = timeout(WAIT, async {
            while !self.seen.contains(wanted) {
                tokio::select! {
                    Some(bytes) = self.output.recv() => self.seen.push_str(&String::from_utf8_lossy(&bytes)),
                    Some(event) = self.events.recv() => {
                        if let TerminalEvent::Status { status } = event {
                            self.statuses.push(status);
                        }
                    }
                }
            }
        })
        .await;
        assert!(found.is_ok(), "never showed {wanted:?}; showed {:?}", self.seen);
        &self.seen
    }
}

/// Opens `path` in a terminal editor through the bus and takes the tab once the job ran.
async fn open_tab(
    core: &Core,
    terminal: Uuid,
    path: &str,
    as_root: bool,
    editor: Option<&str>,
) -> (Tab, Tier, Option<ApprovalRequest>) {
    let outcome = core
        .files
        .open_in_editor(terminal, path.into(), as_root, editor.map(str::to_owned))
        .await
        .unwrap();
    let (job, tier, request) = job_of(core, outcome).await;
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    let handle = core.terminals.take_editor_tab(&core.ctx(), job).unwrap();
    assert!(
        core.terminals.take_editor_tab(&core.ctx(), job).is_err(),
        "the window takes a tab once"
    );
    (Tab::of(handle), tier, request)
}

fn count(log: &[String], line: &str) -> usize {
    log.iter().filter(|l| l.as_str() == line).count()
}

// ---- Edit in the terminal ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_file_opens_in_the_host_s_editor_in_a_tab_of_its_own_with_its_path_byte_for_byte() {
    let pw = password();
    // A name that would end the quotes or run a command in any shell that parsed it.
    let path = "/srv/app/it's $(id) `id`; x.conf";
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file(path, b"listen 80;\n")
        .with_host_editors(&["vi", "nano"]);
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;

    let editors = core.terminals.host_editors(&core.ctx(), t).await.unwrap();
    assert_eq!(editors.found, ["nano", "vi"]);
    assert_eq!(
        editors.uses.as_deref(),
        Some("nano"),
        "the first of nano, micro, vim, vi"
    );
    assert!(editors.chosen.is_none());

    // Low and audited: no question.
    let (mut tab, tier, asked) = open_tab(&core, t, path, false, None).await;
    assert_eq!(tier, Tier::Low);
    assert!(asked.is_none());
    tab.until(&format!("fake nano: {path}")).await;
    tab.until("listen 80;").await;
    let log = server.log();
    assert!(
        log.iter()
            .any(|l| l == &format!("editor nano {path} in /srv/app as alice")),
        "the path reached the editor byte for byte: {log:?}"
    );
    assert!(log.iter().any(|l| l.starts_with("pty xterm-256color")), "{log:?}");
    assert_eq!(count(&log, "editor probe"), 1);
    assert!(
        !log.iter().any(|l| l.contains("uid=")),
        "nothing in the name ran: {log:?}"
    );

    // An editor tab is a tab of its own kind: never in Type in all tabs, never split.
    let info = core.terminals.pane_info(tab.id).unwrap();
    assert_eq!(info.kind, PaneKind::Editor);
    assert!(!info.kind.joins_multiexec());
    assert!(core.terminals.open_like(&core.ctx(), tab.id, SIZE).await.is_err());

    // The editor quits: the tab says so and runs nothing again, Reconnect included.
    core.terminals.write(tab.id, vec![0x18]).await;
    tab.until("The editor closed").await;
    tab.until_ended().await;
    core.terminals.reconnect(tab.id).await;
    core.terminals.write(tab.id, b"\r".to_vec()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server.log().iter().filter(|l| l.starts_with("editor nano")).count(),
        1,
        "the editor runs once"
    );

    // The host's editors were found once: a second file opens without looking again.
    let (mut again, _, _) = open_tab(&core, t, path, false, None).await;
    again.until("fake nano").await;
    assert_eq!(count(&server.log(), "editor probe"), 1);

    let audit = core.store.recent_audit(&core.ctx(), 200).await.unwrap();
    assert!(
        audit.iter().any(|e| e.event == "terminal_opened"
            && e.action.contains("in nano on 'web01'")
            && e.action.contains("it's")),
        "the tab's opening is audited with the file"
    );
    let jobs: Vec<_> = audit
        .iter()
        .filter(|e| e.event == "job_finished" && e.action.starts_with("Edit /srv/app/it's"))
        .collect();
    assert_eq!(jobs.len(), 2, "each opening is a job of its own");
    core.terminals.close_all().await;
}

#[tokio::test]
async fn a_prod_session_or_root_asks_once_and_the_shell_rules_never_rate_the_editor() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_server(Some(DEFAULT_SFTP_SERVER))
        .with_sftp_file("/etc/nginx/nginx.conf", b"worker_processes 1;\n")
        .with_host_editors(&["vim"]);
    let (core, t, _) = pane(&server, &pw, Environment::Prod).await;

    let outcome = core
        .files
        .open_in_editor(t, "/etc/nginx/nginx.conf".into(), false, None)
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("Prod asks");
    };
    assert_eq!(
        (request.action, request.tier),
        (ActionKind::FileEditorOpen, Tier::Medium)
    );
    assert_eq!(request.steps, [ApprovalStep::Confirm]);
    let details = request.file_op.as_ref().unwrap();
    assert_eq!(details.kind, "editInTerminal");
    assert_eq!(
        details.script.as_deref(),
        Some("cd '/etc/nginx' && exec vim '/etc/nginx/nginx.conf'")
    );
    assert!(
        !request.reasons.iter().any(|r| r.contains("shell rules")),
        "{:?}",
        request.reasons
    );
    core.bus.cancel_approval(request.id).await.unwrap();

    // As root on Prod: one tier more for root, one for Prod.
    let err = core
        .files
        .open_in_editor(t, "/etc/nginx/nginx.conf".into(), true, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not browsing as root"), "{err}");
    core.terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    let outcome = core
        .files
        .open_in_editor(t, "/etc/nginx/nginx.conf".into(), true, None)
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("root on Prod asks");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(request.file_op.as_ref().unwrap().as_root);
    core.bus.cancel_approval(request.id).await.unwrap();
    core.terminals.close_all().await;
}

#[tokio::test]
async fn sudoedit_gets_root_browsing_s_password_once_and_the_tab_never_shows_it() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_server(Some(DEFAULT_SFTP_SERVER))
        .with_sftp_file("/etc/nginx/nginx.conf", b"worker_processes 1;\n")
        .with_host_editors(&["vim", "emacs"]);
    let (core, t, session) = pane(&server, &pw, Environment::Lab).await;
    core.terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();

    let (mut tab, tier, asked) = open_tab(&core, t, "/etc/nginx/nginx.conf", true, Some("emacs")).await;
    assert_eq!(tier, Tier::Medium, "as root: one tier higher");
    let asked = asked.unwrap();
    assert_eq!(
        asked.file_op.unwrap().script.as_deref(),
        Some("cd '/etc/nginx' && SUDO_EDITOR='emacs -nw' exec sudoedit -- '/etc/nginx/nginx.conf'")
    );
    let shown = tab.until("worker_processes 1;").await.to_owned();
    assert!(shown.contains("fake emacs -nw: /etc/nginx/nginx.conf"), "{shown}");
    assert!(!shown.contains("remotely-sudo"), "sudo's marker never shows: {shown}");
    assert!(!shown.contains(&pw), "nor the password");
    let log = server.log();
    assert_eq!(count(&log, "sudo alice ok"), 1, "{log:?}");
    assert!(
        log.iter()
            .any(|l| l == "editor emacs -nw /etc/nginx/nginx.conf in /etc/nginx as root"),
        "{log:?}"
    );
    // The password went to sudo once, and nowhere else.
    core.terminals.write(tab.id, b"q".to_vec()).await;
    tab.until("The editor closed").await;
    assert!(
        !server.log().iter().any(|l| l.contains(&pw)),
        "the host's log never holds it"
    );

    // Rule 7: the session changed since root browsing started (another name for the host): a new tab would connect
    // there, so sudo's password doesn't go with it.
    let login = core.sessions.get(&core.ctx(), session).await.unwrap();
    let login = match login.auth {
        SessionAuth::Password { password_id } => password_id.unwrap(),
        other => panic!("{other:?}"),
    };
    core.sessions
        .update_with(
            &core.ctx(),
            session,
            web01("localhost", server.port(), login, Environment::Lab),
            Some(&SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    let outcome = core
        .files
        .open_in_editor(t, "/etc/nginx/nginx.conf".into(), true, None)
        .await
        .unwrap();
    let (job, _, _) = job_of(&core, outcome).await;
    assert_eq!(
        timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap(),
        JobStatus::Failed
    );
    let Err(err) = core.terminals.take_editor_tab(&core.ctx(), job) else {
        panic!("no tab opened");
    };
    assert!(err.to_string().contains("changed since root browsing started"), "{err}");
    assert_eq!(count(&server.log(), "sudo alice ok"), 1, "nothing more went to sudo");
    core.terminals.close_all().await;
}

#[tokio::test]
async fn a_refused_sudoedit_password_closes_the_tab_and_ends_root_browsing() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_server(Some(DEFAULT_SFTP_SERVER))
        .with_sftp_file("/etc/hosts", b"127.0.0.1 localhost\n")
        .with_host_editors(&["nano"]);
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;
    core.terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    let outcome = core
        .files
        .open_in_editor(t, "/etc/hosts".into(), true, None)
        .await
        .unwrap();
    // The host's sudo password changes before the approval.
    server.set_sudo(SudoMode::Password(password()));
    let (job, _, _) = job_of(&core, outcome).await;
    assert_eq!(
        timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap(),
        JobStatus::Succeeded
    );
    let mut tab = Tab::of(core.terminals.take_editor_tab(&core.ctx(), job).unwrap());
    tab.until("sudo refused the password").await;
    timeout(WAIT, async {
        while core.terminals.root_browsing(t).is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("root browsing ended");
    let log = server.log();
    assert_eq!(count(&log, "sudo alice refused"), 1, "tried once, never again: {log:?}");
    assert!(!log.iter().any(|l| l.starts_with("editor nano")), "{log:?}");
    // Audited once root browsing's channels closed.
    timeout(WAIT, async {
        loop {
            let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
            if audit
                .iter()
                .any(|e| e.event == "files_root_stopped" && e.detail.as_deref().is_some_and(|d| d.contains("sudoedit")))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the end of root browsing is audited with why");
    core.terminals.close_all().await;
}

#[tokio::test]
async fn the_session_s_editor_setting_picks_the_editor_and_only_known_ones_are_taken() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/notes.txt", b"hello\n")
        .with_host_editors(&["nano", "vi"]);
    let (core, t, session) = pane(&server, &pw, Environment::Lab).await;

    core.files.set_host_editor(session, Some("vi".into())).await.unwrap();
    let editors = core.terminals.host_editors(&core.ctx(), t).await.unwrap();
    assert_eq!(
        (editors.chosen.as_deref(), editors.uses.as_deref()),
        (Some("vi"), Some("vi"))
    );
    let (mut tab, _, _) = open_tab(&core, t, "/home/alice/notes.txt", false, None).await;
    tab.until("fake vi: /home/alice/notes.txt").await;

    assert!(core.files.set_host_editor(session, Some("bash".into())).await.is_err());
    // A choice the host doesn't have falls back for a double-click; asked for by name, it says so.
    core.files.set_host_editor(session, Some("micro".into())).await.unwrap();
    let editors = core.terminals.host_editors(&core.ctx(), t).await.unwrap();
    assert_eq!(editors.uses.as_deref(), Some("nano"));
    let err = core
        .files
        .open_in_editor(t, "/home/alice/notes.txt".into(), false, Some("micro".into()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no micro"), "{err}");
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.event == "setting_changed" && e.action == "Set the editor files open in on 'web01'"));

    // Folders aren't files; a host with no editor Remotely knows says so.
    let err = core
        .files
        .open_in_editor(t, "/home/alice".into(), false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a file"), "{err}");
    core.terminals.close_all().await;

    let bare = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/notes.txt", b"hello\n");
    let (core, t, _) = pane(&bare, &pw, Environment::Lab).await;
    let err = core
        .files
        .open_in_editor(t, "/home/alice/notes.txt".into(), false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "no_host_editor", "{err}");
    core.terminals.close_all().await;
}

// ---- Edit on this PC ---------------------------------------------------------------------------------------------

/// The core set up to edit on this PC: a fake editor (no program starts), a saved editor path (an empty `Code.exe`
/// made in the temp folder, so the fake opens "VS Code"), the copies' folder in the temp folder, and a short poll.
fn edit_here(core: &Core, poll: Duration) -> (FakeLocalEditors, PathBuf) {
    let editors = FakeLocalEditors::default();
    core.terminals.set_local_editors(std::sync::Arc::new(editors.clone()));
    core.terminals.set_edit_tuning(EditTuning {
        poll,
        limit: Duration::from_secs(600),
    });
    let folder = temp_folder("edits");
    core.terminals.set_edit_folder(&folder).unwrap();
    (editors, folder)
}

async fn use_fake_code(core: &Core) -> PathBuf {
    let program = temp_folder("editor").join("Code.exe");
    std::fs::write(&program, b"").unwrap();
    let in_use = core.set_local_editor_path(Some(program.clone())).await.unwrap();
    assert_eq!(in_use.as_deref(), Some(program.as_path()));
    program
}

async fn until_edit(core: &Core, what: &str, ok: impl Fn(&EditInfo) -> bool) -> EditInfo {
    let found = timeout(WAIT, async {
        loop {
            if let Some(edit) = core.terminals.edits(&core.ctx()).into_iter().find(&ok) {
                return edit;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    match found {
        Ok(edit) => edit,
        Err(_) => panic!("{what}: {:?}", core.terminals.edits(&core.ctx())),
    }
}

async fn until_host(server: &TestSshServer, path: &str, content: &[u8]) {
    let changed = timeout(WAIT, async {
        while server.sftp_file(path).as_deref() != Some(content) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        changed.is_ok(),
        "the host's {path} never became {:?}; it is {:?}",
        String::from_utf8_lossy(content),
        server.sftp_file(path).map(|b| String::from_utf8_lossy(&b).into_owned())
    );
}

/// Saves the copy as an editor would: new bytes, a new time.
fn save(copy: &Path, content: &[u8]) {
    std::fs::write(copy, content).unwrap();
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[tokio::test]
async fn edit_on_this_pc_uploads_each_save_once_the_host_s_copy_is_checked() {
    let pw = password();
    let path = "/srv/app/app.conf";
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file(path, b"port = 80\n");
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;
    let (editors, folder) = edit_here(&core, Duration::from_millis(30));
    let program = use_fake_code(&core).await;

    // One approval for the editing session: each save replaces the file (Medium).
    let outcome = core.files.edit_on_pc(t, path.into(), false).await.unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("editing on this PC replaces the file: it asks");
    };
    assert_eq!(
        (request.action, request.tier),
        (ActionKind::FileEditLocal, Tier::Medium)
    );
    let details = request.file_op.as_ref().unwrap();
    assert!(details.kind == "editOnPc" && details.replace);
    let job = approve(&core, &request).await;
    let edit = until_edit(&core, "the session watches its copy", |e| {
        e.state == EditState::Watching
    })
    .await;
    assert_eq!((edit.id, edit.editor.as_str(), edit.saves), (job, "VS Code", 0));

    // The copy: in a folder of its own only this user opens, with the Mark of the Web, opened in the editor's program.
    let opened = editors.opened();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].program, program);
    let copy = opened[0].files[0].clone();
    assert_eq!(copy.file_name().unwrap(), "app.conf");
    assert!(copy.starts_with(&folder));
    assert_eq!(std::fs::read(&copy).unwrap(), b"port = 80\n");
    #[cfg(windows)]
    {
        // Protected (nothing inherited from above), one entry: this user, full control.
        let acl = remotely_core::private_folder::describe(copy.parent().unwrap()).unwrap();
        assert!(acl.starts_with("D:P") && acl.contains("(A;OICI;FA;;;S-1-"), "{acl}");
        assert_eq!(acl.matches("(A;").count(), 1, "{acl}");
        let mut stream = copy.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        assert!(std::fs::read_to_string(PathBuf::from(stream))
            .unwrap()
            .contains("ZoneId=3"));
    }

    // A save goes up.
    save(&copy, b"port = 81\n");
    until_host(&server, path, b"port = 81\n").await;
    until_edit(&core, "one save", |e| e.saves == 1 && e.state == EditState::Watching).await;
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    let saved = audit
        .iter()
        .find(|e| e.event == "file_changed" && e.action.starts_with("Saved /srv/app/app.conf from this PC"))
        .expect("each save is audited");
    assert_eq!(saved.job_id.as_deref(), Some(job.to_string().as_str()));
    assert!(saved.detail.as_deref().unwrap().contains(&sha(b"port = 81\n")));

    // The host's copy changes meanwhile: the next save waits for an answer.
    std::fs::write(server.sftp_path(path), b"port = 90 # changed on the host\n").unwrap();
    save(&copy, b"port = 82\n");
    until_edit(&core, "a conflict", |e| matches!(e.state, EditState::Conflict { .. })).await;
    assert_eq!(server.sftp_file(path).unwrap(), b"port = 90 # changed on the host\n");

    // Compare: the host's copy beside this PC's, opened as a diff in VS Code.
    core.terminals
        .answer_edit(&core.ctx(), job, Some(EditAnswer::Compare))
        .await
        .unwrap();
    timeout(WAIT, async {
        while editors.opened().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let compared = &editors.opened()[1];
    assert!(compared.diff);
    assert_eq!(compared.files[0], copy);
    assert_eq!(compared.files[1].file_name().unwrap(), "app (on the host).conf");
    assert_eq!(
        std::fs::read(&compared.files[1]).unwrap(),
        b"port = 90 # changed on the host\n"
    );

    // Save beside it: a new file; the host's own copy stays.
    core.terminals
        .answer_edit(&core.ctx(), job, Some(EditAnswer::SaveBeside))
        .await
        .unwrap();
    until_host(&server, "/srv/app/app (edited).conf", b"port = 82\n").await;
    assert_eq!(server.sftp_file(path).unwrap(), b"port = 90 # changed on the host\n");
    until_edit(&core, "watching again", |e| e.state == EditState::Watching).await;

    // The next save asks again; Overwrite replaces the host's copy.
    save(&copy, b"port = 83\n");
    until_edit(&core, "a second conflict", |e| {
        matches!(e.state, EditState::Conflict { .. })
    })
    .await;
    core.terminals
        .answer_edit(&core.ctx(), job, Some(EditAnswer::Overwrite))
        .await
        .unwrap();
    until_host(&server, path, b"port = 83\n").await;

    // Stop editing: the last save goes up first, then the copy is deleted and the job ends.
    save(&copy, b"port = 84\n");
    core.terminals.stop_edit(&core.ctx(), job).await.unwrap();
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(server.sftp_file(path).unwrap(), b"port = 84\n");
    assert!(!copy.parent().unwrap().exists(), "the copy is deleted");
    assert!(core.terminals.edits(&core.ctx()).is_empty());
    let audit = core.store.recent_audit(&core.ctx(), 200).await.unwrap();
    let ended = audit.iter().find(|e| e.event == "file_edit_ended").unwrap();
    assert!(
        ended.detail.as_deref().unwrap().contains("stopped by the user"),
        "{ended:?}"
    );
    let saves = audit
        .iter()
        .filter(|e| e.event == "file_changed" && e.job_id.as_deref() == Some(job.to_string().as_str()))
        .count();
    assert_eq!(saves, 4, "81, beside it, 83 overwriting, 84");
    assert!(audit
        .iter()
        .any(|e| e.event == "file_edit_opened" && e.detail.as_deref().unwrap().contains(&sha(b"port = 80\n"))));
    core.terminals.close_all().await;
}

async fn start_edit(core: &Core, terminal: Uuid, path: &str) -> Uuid {
    let outcome = core.files.edit_on_pc(terminal, path.into(), false).await.unwrap();
    job_of(core, outcome).await.0
}

#[tokio::test]
async fn editing_ends_without_uploading_when_the_vault_locks_the_terminal_closes_or_the_workspace_changes() {
    let pw = password();
    let path = "/srv/app/app.conf";
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file(path, b"port = 80\n");
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;
    // A slow poll: nothing goes up before the end.
    let (editors, _) = edit_here(&core, Duration::from_secs(30));
    use_fake_code(&core).await;

    let job = start_edit(&core, t, path).await;
    until_edit(&core, "watching", |e| e.id == job).await;
    let copy = editors.opened().last().unwrap().files[0].clone();
    save(&copy, b"port = 99\n");
    core.vault.lock(&core.ctx()).await.unwrap();
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(server.sftp_file(path).unwrap(), b"port = 80\n", "nothing went up");
    assert!(!copy.parent().unwrap().exists());
    let audit = core.store.recent_audit(&core.ctx(), 50).await.unwrap();
    let ended = audit.iter().find(|e| e.event == "file_edit_ended").unwrap();
    let detail = ended.detail.as_deref().unwrap();
    assert!(
        detail.contains("the vault locked") && detail.contains("not uploaded"),
        "{detail}"
    );
    core.vault
        .unlock(
            &core.ctx(),
            UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();

    // The terminal closes: its editing ends at once (the poll is slow).
    let job = start_edit(&core, t, path).await;
    until_edit(&core, "watching", |e| e.id == job).await;
    core.terminals.close(t).await;
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    assert_eq!(status, JobStatus::Succeeded);
    let audit = core.store.recent_audit(&core.ctx(), 50).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.event == "file_edit_ended" && e.detail.as_deref().unwrap().contains("its terminal closed")));
    core.terminals.close_all().await;
}

#[tokio::test]
async fn a_workspace_switch_ends_editing_and_is_not_held_up_by_it() {
    let pw = password();
    let path = "/srv/app/app.conf";
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file(path, b"port = 80\n");
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;
    edit_here(&core, Duration::from_secs(30));
    use_fake_code(&core).await;
    let outcome = core.files.edit_on_pc(t, path.into(), false).await.unwrap();
    let (job, _, _) = job_of(&core, outcome).await;
    let edit = until_edit(&core, "watching", |e| e.id == job).await;
    assert_eq!(edit.state, EditState::Watching);
    let preview = core
        .switch_preview(
            core.workspaces
                .create(WorkspaceInput {
                    name: "Customer B".into(),
                    color: None,
                })
                .await
                .unwrap()
                .id,
        )
        .await
        .unwrap();
    assert_eq!(
        (preview.open_jobs, preview.edits),
        (0, 1),
        "an editing session doesn't hold a switch up"
    );
    let home = core.ctx();
    core.switch_workspace(preview.to.id).await.unwrap();
    assert_eq!(core.store.job_status(job).await.unwrap(), Some(JobStatus::Succeeded));
    let audit = core.store.recent_audit(&home, 50).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.event == "file_edit_ended"
                && e.detail.as_deref().unwrap().contains("another workspace was opened"))
    );
}

#[tokio::test]
async fn leftover_copies_go_at_the_next_start_and_what_can_t_be_edited_is_refused() {
    // What a crash left: gone when the folder is set up again.
    let folder = temp_folder("edits-left");
    std::fs::create_dir_all(folder.join("0123")).unwrap();
    std::fs::write(folder.join("0123").join("hosts"), b"left behind").unwrap();
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/srv/app/app.conf", b"port = 80\n")
        .with_sftp_dir("/srv/app/conf.d");
    let (core, t, _) = pane(&server, &pw, Environment::Lab).await;
    assert_eq!(core.terminals.set_edit_folder(&folder).unwrap(), 1);
    assert!(!folder.join("0123").exists());

    // Never a folder in a Git working tree.
    let repo = temp_folder("edits-repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    assert!(core.terminals.set_edit_folder(&repo.join("editing")).is_err());

    // A folder is not a file; without an editor on this PC nothing is asked.
    let err = core
        .files
        .edit_on_pc(t, "/srv/app/conf.d".into(), false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not a file"), "{err}");
    let gone = temp_folder("editor-gone").join("Code.exe");
    std::fs::write(&gone, b"").unwrap();
    core.set_local_editor_path(Some(gone.clone())).await.unwrap();
    std::fs::remove_file(&gone).unwrap();
    let err = core
        .files
        .edit_on_pc(t, "/srv/app/app.conf".into(), false)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "local_editor_not_found", "{err}");
    // A program that runs what it is given is never the editor.
    assert!(core
        .set_local_editor_path(Some(PathBuf::from(r"C:\Windows\System32\cmd.exe")))
        .await
        .is_err());
    core.terminals.close_all().await;
}
