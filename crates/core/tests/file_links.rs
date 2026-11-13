//! SS-14 (0.8.0 G2): what another user on a host could swap in while Remotely looks and then changes, on the fake
//! remote adapter's in-memory files ([`FakeFiles`] models symbolic links):
//!
//! * permissions and owners are never set through a link, refused when asked and again when a file became one
//!   after the approval;
//! * a folder that became a link before its delete runs loses only the link;
//! * a paused upload whose file became a link starts again, never writing through it;
//! * a folder download stops at its cap of files and folders, before anything is made on this PC;
//! * nothing downloads into Remotely's own data folder;
//! * (G4) a save from an editing session on this PC never goes through a link swapped in on the host, Overwrite
//!   included, while an ordinary replacing write follows a link as the real SFTP adapter does.
//!
//! No real host is contacted; test data uses alice and files made at run time in the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, Setup};
use remotely_core::adapters::remote::{AgentSource, PtySize, RemoteFiles};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome, MAX_UPLOAD_FILES};
use remotely_core::domain::Environment;
use remotely_core::fakes::{FakeFiles, FakeLocalEditors, FakeRemote, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::ApprovalStep;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::edit_local::{EditAnswer, EditInfo, EditState, EditTuning, StopChoice, StopOutcome};
use remotely_core::terminal::file_ops::FileChange;
use remotely_core::terminal::files::{DownloadOptions, Existing, TransferState, UploadStart};
use remotely_core::terminal::folder::FolderTracking;
use remotely_core::terminal::{TerminalHandle, TerminalTuning};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
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

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// A terminal on the fake remote adapter with these files; the terminal's id.
async fn pane(files: &FakeFiles) -> (Core, Uuid) {
    let remote = FakeRemote::default().with_files(files.clone());
    let core = Setup::new(FakeVmware::default())
        .with_remote(Arc::new(remote))
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    let session = core
        .sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "web01.example.com".into(),
                port: 22,
                username: Some("alice".into()),
                auth: SessionAuth::Agent,
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id: None,
                kind: Default::default(),
            },
        )
        .await
        .unwrap()
        .id;
    let handle = core.terminals.open(&core.ctx(), session, SIZE).await.unwrap();
    let id = handle.id;
    drain(&core, handle).await;
    (core, id)
}

/// Waits until the terminal is connected and knows how it follows its folder; keeps draining it after.
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

/// Approves a request with what its steps ask for; waits for the job.
async fn approve(core: &Core, request: &ApprovalRequest) -> JobStatus {
    let mut answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    for step in &request.steps {
        match step {
            ApprovalStep::TypeTargetCount { expected } => answers.typed_target_count = Some(*expected),
            ApprovalStep::Reason => answers.reason = Some("tidying up".into()),
            _ => {}
        }
    }
    let job = core.bus.approve(request.id, answers).await.unwrap();
    timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap()
}

/// The approval a change asks for.
async fn asked(core: &Core, terminal: Uuid, change: FileChange) -> ApprovalRequest {
    match core.files.change(terminal, change, false).await.unwrap() {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("it asks first: {other:?}"),
    }
}

async fn step_errors(core: &Core, request: &ApprovalRequest) -> Vec<String> {
    let jobs = core.store.recent_jobs(&core.ctx(), 20).await.unwrap();
    let job = jobs.iter().find(|j| j.summary == request.summary).expect("the job");
    core.store
        .job_targets(&core.ctx(), Uuid::parse_str(&job.id).unwrap())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|t| t.error)
        .collect()
}

#[tokio::test]
async fn permissions_and_owners_are_never_set_through_a_link() {
    let files = FakeFiles::default()
        .with_file("/etc/shadow", b"root:x:")
        .with_link("/home/alice/x", "/etc/shadow")
        .with_file("/home/alice/y", b"y");
    let (core, t) = pane(&files).await;
    let shadow = files.meta("/etc/shadow").unwrap();

    // Asked on a link: refused before anything is asked.
    for change in [
        FileChange::Mode {
            paths: strings(&["/home/alice/x"]),
            mode: 0o644,
        },
        FileChange::Owner {
            paths: strings(&["/home/alice/x"]),
            uid: None,
            gid: Some(1001),
        },
    ] {
        let err = core.files.change(t, change, false).await.unwrap_err();
        assert!(err.to_string().contains("is a link"), "{err}");
    }

    // A file that became a link after the approval: the step looks first and refuses.
    for change in [
        FileChange::Mode {
            paths: strings(&["/home/alice/y"]),
            mode: 0o666,
        },
        FileChange::Owner {
            paths: strings(&["/home/alice/y"]),
            uid: Some(1001),
            gid: Some(1001),
        },
    ] {
        files.set_file("/home/alice/y", b"y");
        let request = asked(&core, t, change).await;
        files.set_link("/home/alice/y", "/etc/shadow");
        assert_eq!(approve(&core, &request).await, JobStatus::Failed);
        let errors = step_errors(&core, &request).await;
        assert!(errors.iter().any(|e| e.contains("is a link")), "{errors:?}");
        assert_eq!(
            files.meta("/etc/shadow").unwrap(),
            shadow,
            "what it points to is as it was"
        );
        assert_eq!(files.link("/home/alice/y").as_deref(), Some("/etc/shadow"));
    }
}

#[tokio::test]
async fn a_folder_that_became_a_link_before_its_delete_loses_only_the_link() {
    let files = FakeFiles::default()
        .with_dir("/srv/app")
        .with_dir("/srv/app/uploads")
        .with_file("/srv/app/index.html", b"<p>hi</p>")
        .with_file("/srv/app/uploads/a.png", b"png")
        .with_file("/etc/passwd", b"root:x:0:0");
    let (core, t) = pane(&files).await;
    let request = asked(
        &core,
        t,
        FileChange::Delete {
            paths: strings(&["/srv/app"]),
        },
    )
    .await;
    assert!(request.file_op.as_ref().unwrap().recursive);
    // Meanwhile someone puts a link to /etc in its place.
    files.set_link("/srv/app", "/etc");
    assert_eq!(approve(&core, &request).await, JobStatus::Succeeded);
    assert!(files.link("/srv/app").is_none(), "the link is gone");
    assert_eq!(
        files.file("/etc/passwd").unwrap(),
        b"root:x:0:0",
        "what it pointed to stays"
    );
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.event == "file_changed" && e.action.starts_with("Deleted the link /srv/app")),
        "{:#?}",
        audit.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_paused_upload_whose_file_became_a_link_starts_again_and_never_writes_through_it() {
    let files = FakeFiles::default()
        .with_file("/etc/passwd", b"root:x:0:0")
        .with_delay(Duration::from_millis(20));
    let (core, t) = pane(&files).await;
    let body: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    let local = temp_folder("link-up").join("big.bin");
    std::fs::write(&local, &body).unwrap();
    let staged = core.files.stage(vec![local]).unwrap();
    let start = core
        .files
        .upload(t, staged.id, "/home/alice", Existing::Ask)
        .await
        .unwrap();
    let UploadStart::Submitted {
        outcome: SubmitOutcome::Queued { job_id, .. },
    } = start
    else {
        panic!("a new file is Low: {start:?}")
    };
    let find = |core: &Core| {
        core.terminals
            .transfers()
            .into_iter()
            .find(|x| x.job_id == Some(job_id))
    };
    timeout(WAIT, async {
        while find(&core).is_none_or(|x| x.done == 0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let id = find(&core).unwrap().id;
    assert!(core.terminals.pause_transfer(id));
    timeout(WAIT, async {
        while find(&core).unwrap().state != TransferState::Paused {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    files.set_link("/home/alice/big.bin", "/etc/passwd");
    assert!(core.terminals.resume_transfer(id));
    assert_eq!(
        timeout(WAIT, core.jobs.wait(job_id)).await.unwrap().unwrap(),
        JobStatus::Succeeded
    );
    assert_eq!(
        files.file("/etc/passwd").unwrap(),
        b"root:x:0:0",
        "nothing written through the link"
    );
    assert!(files.link("/home/alice/big.bin").is_none());
    assert_eq!(files.file("/home/alice/big.bin").unwrap(), body, "sent again, whole");
}

#[tokio::test]
async fn a_folder_download_stops_at_its_cap_of_files_and_folders() {
    let mut files = FakeFiles::default().with_dir("/srv/tree");
    for n in 0..=MAX_UPLOAD_FILES {
        files = files.with_dir(&format!("/srv/tree/d{n}"));
    }
    let (core, t) = pane(&files).await;
    let dest = temp_folder("cap-down");
    let err = core
        .terminals
        .download_with(
            &core.ctx(),
            t,
            &strings(&["/srv/tree"]),
            &dest,
            DownloadOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("files and folders"), "{err}");
    assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0, "nothing made on this PC");
}

#[tokio::test]
async fn nothing_downloads_into_remotelys_data_folder() {
    let files = FakeFiles::default()
        .with_file("/srv/remotely.db", b"not a database")
        .with_dir("/srv/COM.REMOTELY.DESKTOP")
        .with_file("/srv/COM.REMOTELY.DESKTOP/remotely.db", b"not a database");
    let (core, t) = pane(&files).await;
    let parent = temp_folder("data-down");
    let data = parent.join("com.remotely.desktop");
    std::fs::create_dir_all(&data).unwrap();
    core.protect_folder(&data);
    let replace = DownloadOptions {
        existing: Existing::Replace,
        as_root: false,
    };

    let err = core
        .terminals
        .download_with(&core.ctx(), t, &strings(&["/srv/remotely.db"]), &data, replace)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Remotely's own data folder"), "{err}");
    // A folder of the same name, in any letter case, coming down beside it lands in it: refused too.
    let err = core
        .terminals
        .download_with(
            &core.ctx(),
            t,
            &strings(&["/srv/COM.REMOTELY.DESKTOP"]),
            &parent,
            replace,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Remotely's own data folder"), "{err}");
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0, "nothing landed there");
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

#[tokio::test]
async fn an_edit_on_this_pc_never_saves_through_a_link_swapped_in_on_the_host() {
    let files = FakeFiles::default()
        .with_dir("/srv/shared")
        .with_dir("/home/alice/.ssh")
        .with_file("/srv/shared/app.conf", b"port = 80\n")
        .with_file("/home/alice/.ssh/authorized_keys", b"ssh-ed25519 AAAA alice\n");
    let (core, t) = pane(&files).await;
    let editors = FakeLocalEditors::default();
    core.terminals.set_local_editors(Arc::new(editors.clone()));
    core.terminals.set_edit_tuning(EditTuning {
        poll: Duration::from_millis(30),
        limit: Duration::from_secs(600),
        retry: Duration::from_secs(600),
    });
    core.terminals.set_edit_folder(&temp_folder("link-edits")).unwrap();
    let program = temp_folder("link-editor").join("Code.exe");
    std::fs::write(&program, b"").unwrap();
    core.set_local_editor_path(Some(program)).await.unwrap();
    let SubmitOutcome::NeedsApproval { request } = core
        .files
        .edit_on_pc(t, "/srv/shared/app.conf".into(), false)
        .await
        .unwrap()
    else {
        panic!("each save replaces the file: it asks");
    };
    let answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    until_edit(&core, "watching", |e| e.id == job).await;
    let copy = editors.opened()[0].files[0].clone();

    // Another user who can write the folder changes the file (the next save is a conflict), then puts a link there.
    files.set_file("/srv/shared/app.conf", b"port = 90\n");
    std::fs::write(&copy, b"port = 82\n").unwrap();
    until_edit(&core, "a conflict", |e| matches!(e.state, EditState::Conflict { .. })).await;
    files.set_link("/srv/shared/app.conf", "/home/alice/.ssh/authorized_keys");
    core.terminals
        .answer_edit(&core.ctx(), job, Some(EditAnswer::Overwrite))
        .await
        .unwrap();
    let refused = until_edit(&core, "refused", |e| matches!(e.state, EditState::Failed { .. })).await;
    let EditState::Failed { message } = &refused.state else {
        unreachable!()
    };
    assert!(message.contains("link"), "{message}");
    assert_eq!(refused.saves, 0);
    assert_eq!(
        files.file("/home/alice/.ssh/authorized_keys").unwrap(),
        b"ssh-ed25519 AAAA alice\n",
        "nothing written through the link"
    );
    assert_eq!(
        files.link("/srv/shared/app.conf").as_deref(),
        Some("/home/alice/.ssh/authorized_keys")
    );

    // An ordinary save with a link there now is refused too, before anything is written.
    std::fs::write(&copy, b"port = 83\n").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        files.file("/home/alice/.ssh/authorized_keys").unwrap(),
        b"ssh-ed25519 AAAA alice\n"
    );
    let asked = core.terminals.stop_edit(&core.ctx(), job, None).await.unwrap();
    assert!(matches!(asked, StopOutcome::Unsent { .. }), "{asked:?}");
    core.terminals
        .stop_edit(&core.ctx(), job, Some(StopChoice::Discard))
        .await
        .unwrap();
    timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();

    // Why editing has its own way to replace: an ordinary replacing write follows the link (as SftpFiles does, for
    // the login user), so the file it points to would get the bytes.
    let mut write = RemoteFiles::write(&files, "/srv/shared/app.conf", true).await.unwrap();
    write.write_all(b"ssh-ed25519 BBBB mallory\n").await.unwrap();
    write.finish().await.unwrap();
    assert_eq!(
        files.file("/home/alice/.ssh/authorized_keys").unwrap(),
        b"ssh-ed25519 BBBB mallory\n"
    );
    assert!(files.link("/srv/shared/app.conf").is_some(), "the link stays a link");
    core.terminals.close_all().await;
}
