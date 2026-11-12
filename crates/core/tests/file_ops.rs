//! SS-14 (0.8.0 G2): file operations on a terminal's host, root browsing and the transfer queue, end to end with the
//! real russh adapter against `fakes::ssh_server::TestSshServer` on 127.0.0.1 (its SFTP temp folder, its toy sudo,
//! and its toy `cp`).
//!
//! * File changes go through the command bus with a step per path, at the plan's tiers, and are audited with their
//!   paths; what the window sends is checked, never resolved.
//! * Root browsing starts the host's sftp-server under sudo on an exec channel of the terminal's connection; changes
//!   made through it are one tier higher; a refused password parks it.
//! * The transfer queue: four at a time per host, pause and resume (an upload from the same offset once the host's
//!   file is checked to be what was sent, a download again from the start), what to do with a file that is there,
//!   times kept both ways, folders up and down with what is in them (never Git's data).
//! * What another user on the host could do meanwhile: a paused upload's file written again, a paused download's file
//!   rewritten in place, a vault lock while a root upload waits, a sudo park the Containers page set.
//!
//! No real host is contacted; test data uses alice and files made at run time in the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::error::CoreError;
use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer, DEFAULT_SFTP_SERVER};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::login_guard::{self, ParkReason, ParkScope, Parked};
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::file_ops::FileChange;
use remotely_core::terminal::files::{
    DownloadOptions, DownloadStart, Existing, TransferInfo, TransferState, UploadStart,
};
use remotely_core::terminal::folder::FolderTracking;
use remotely_core::terminal::root_files::RootRequest;
use remotely_core::terminal::{TerminalHandle, TerminalTuning};
use remotely_core::vault::{SecretId, SecretKind, SecretString};
use remotely_core::Core;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(20);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 % 251) as u8).collect()
}

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

/// A terminal to the test server, logged in with a password from the vault; the terminal's id.
async fn pane(server: &TestSshServer, password: &str, environment: Environment) -> (Core, Uuid) {
    let (core, id, _, _) = pane_ids(server, password, environment).await;
    (core, id)
}

/// [`pane`], with the session's id and its login password's vault item too.
async fn pane_ids(server: &TestSshServer, password: &str, environment: Environment) -> (Core, Uuid, Uuid, SecretId) {
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
        .create(
            &core.ctx(),
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port: server.port(),
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
            },
        )
        .await
        .unwrap()
        .id;
    let handle = core.terminals.open(&core.ctx(), session, SIZE).await.unwrap();
    let id = handle.id;
    drain(&core, handle).await;
    (core, id, session, login)
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

fn password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
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
            ApprovalStep::Reason => answers.reason = Some("tidying up".into()),
            ApprovalStep::VaultReauth => answers.vault_password = Some(SecretString::new(VAULT_PASSWORD)),
            _ => {}
        }
    }
    core.bus.approve(request.id, answers).await.unwrap()
}

/// Runs an outcome to its end: queued (Low), or approved first. The tier it ran at too.
async fn run(core: &Core, outcome: SubmitOutcome) -> (JobStatus, Tier, Option<ApprovalRequest>) {
    let (job, tier, request) = match outcome {
        SubmitOutcome::Queued { job_id, tier, .. } => (job_id, tier, None),
        SubmitOutcome::NeedsApproval { request } => (approve(core, &request).await, request.tier, Some(request)),
    };
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    if status != JobStatus::Succeeded {
        // What failed, for the test's output.
        for target in core.store.job_targets(&core.ctx(), job).await.unwrap() {
            eprintln!("{}: {} {:?}", target.target_name, target.status, target.error);
        }
    }
    (status, tier, request)
}

async fn change(
    core: &Core,
    terminal: Uuid,
    change: FileChange,
    as_root: bool,
) -> (JobStatus, Tier, Option<ApprovalRequest>) {
    let outcome = core.files.change(terminal, change, as_root).await.unwrap();
    run(core, outcome).await
}

fn names(server: &TestSshServer, folder: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(server.sftp_path(folder))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

// ---- File changes on the bus -----------------------------------------------------------------------------------

#[tokio::test]
async fn file_changes_run_on_the_host_a_step_per_path_at_their_tiers_and_are_audited() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/www/a.html", b"<p>a</p>")
        .with_sftp_file("/home/alice/www/b.html", b"<p>b</p>")
        .with_sftp_file("/home/alice/old/x.txt", b"x")
        .with_sftp_file("/home/alice/old/sub/y.txt", b"y")
        .with_sftp_dir("/home/alice/empty");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;

    // A new folder and an empty file: Low, no question.
    let new_folder = FileChange::NewFolder {
        folder: "/home/alice/www".into(),
        name: "new".into(),
    };
    let (status, tier, asked) = change(&core, t, new_folder.clone(), false).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert!(asked.is_none());
    assert!(server.sftp_path("/home/alice/www/new").is_dir());
    let err = core.files.change(t, new_folder, false).await.unwrap_err();
    assert_eq!(err.code(), "path_taken", "{err}");
    let (status, _, _) = change(
        &core,
        t,
        FileChange::NewFile {
            folder: "/home/alice/www/new".into(),
            name: "empty.txt".into(),
        },
        false,
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(server.sftp_file("/home/alice/www/new/empty.txt").unwrap(), b"");

    // A rename: Low; over a file it asks first, and replaces it once confirmed.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Rename {
            path: "/home/alice/www/a.html".into(),
            name: "c.html".into(),
            replace: false,
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert_eq!(names(&server, "/home/alice/www"), ["b.html", "c.html", "new"]);
    let over = FileChange::Rename {
        path: "/home/alice/www/b.html".into(),
        name: "c.html".into(),
        replace: false,
    };
    let err = core.files.change(t, over, false).await.unwrap_err();
    assert_eq!(err.code(), "path_taken", "{err}");
    let (status, tier, asked) = change(
        &core,
        t,
        FileChange::Rename {
            path: "/home/alice/www/b.html".into(),
            name: "c.html".into(),
            replace: true,
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(asked.unwrap().action, ActionKind::FileMoveReplace);
    assert_eq!(server.sftp_file("/home/alice/www/c.html").unwrap(), b"<p>b</p>");

    // A move: Low, a step per path.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Move {
            paths: strings(&["/home/alice/www/c.html"]),
            into: "/home/alice/www/new".into(),
            replace: false,
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert_eq!(names(&server, "/home/alice/www/new"), ["c.html", "empty.txt"]);

    // A copy: Medium, `cp -a` on an exec channel, rated by the shell rules too.
    let (status, tier, asked) = change(
        &core,
        t,
        FileChange::Copy {
            paths: strings(&["/home/alice/www/new"]),
            into: "/home/alice".into(),
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    let asked = asked.unwrap();
    assert!(
        asked.reasons.iter().any(|r| r.contains("`cp -a`")),
        "{:?}",
        asked.reasons
    );
    assert_eq!(
        asked.file_op.as_ref().unwrap().script.as_deref(),
        Some("cp -a -- '/home/alice/www/new' '/home/alice/new'")
    );
    assert_eq!(names(&server, "/home/alice/new"), ["c.html", "empty.txt"]);
    assert!(server
        .log()
        .iter()
        .any(|l| l == "cp -a /home/alice/www/new /home/alice/new as alice"));

    // Permissions: Medium.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Mode {
            paths: strings(&["/home/alice/new/c.html"]),
            mode: 0o600,
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(server.sftp_meta("/home/alice/new/c.html").unwrap().0, 0o600);

    // Deleting a file and an empty folder: Medium. A folder with what is in it: High, the full approval.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Delete {
            paths: strings(&["/home/alice/new/empty.txt", "/home/alice/empty"]),
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert!(!server.sftp_path("/home/alice/empty").exists());
    let (status, tier, asked) = change(
        &core,
        t,
        FileChange::Delete {
            paths: strings(&["/home/alice/old"]),
        },
        false,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::High));
    let asked = asked.unwrap();
    assert!(asked.steps.contains(&ApprovalStep::TypeTargetCount { expected: 1 }));
    assert!(asked.file_op.as_ref().unwrap().recursive);
    assert_eq!(
        asked.targets[0].name, "web01: /home/alice/old",
        "a step named by its path"
    );
    assert!(!server.sftp_path("/home/alice/old").exists());
    // Review H2, M9: GNU rm on the host, which never follows a link swapped in, its path passed as octal escapes
    // through /bin/sh, so no login shell reads anything in it.
    let log = server.log();
    assert!(
        log.iter().any(|l| l.starts_with("exec /bin/sh -c 'p0=$(printf ")
            && l.contains("exec rm -rf --one-file-system -- \"$p0\"")),
        "{log:#?}"
    );
    assert!(log.iter().any(|l| l == "rm -rf /home/alice/old as alice"), "{log:#?}");
    assert!(
        log.iter()
            .any(|l| l.starts_with("exec /bin/sh -c 'p0=$(printf ") && l.contains("exec cp -a -- ")),
        "{log:#?}"
    );

    // Audited with the paths, each step on its own.
    let audit = core.store.recent_audit(&core.ctx(), 300).await.unwrap();
    let changed: Vec<&str> = audit
        .iter()
        .filter(|e| e.event == "file_changed")
        .map(|e| e.action.as_str())
        .collect();
    for wanted in [
        "Made the folder /home/alice/www/new on 'web01'",
        "Made the empty file /home/alice/www/new/empty.txt on 'web01'",
        "Renamed /home/alice/www/a.html to /home/alice/www/c.html on 'web01'",
        "Copied /home/alice/www/new to /home/alice/new on 'web01'",
        "Set the permissions of /home/alice/new/c.html to 0600 on 'web01'",
        "Deleted the empty folder /home/alice/empty on 'web01'",
        "Deleted the folder /home/alice/old with everything in it on 'web01'",
    ] {
        assert!(changed.contains(&wanted), "{wanted}: {changed:#?}");
    }
    // The journal keeps a step per path, by its step, never by its path.
    let jobs = core.store.recent_jobs(&core.ctx(), 50).await.unwrap();
    let delete = jobs
        .iter()
        .find(|j| j.summary.starts_with("Delete 2 items"))
        .expect("the delete job");
    let targets = core
        .store
        .job_targets(&core.ctx(), Uuid::parse_str(&delete.id).unwrap())
        .await
        .unwrap();
    assert_eq!(targets.len(), 2);
    assert!(targets.iter().all(|t| t.target_kind == "remote_path"));
    assert!(targets.iter().all(|t| !t.target_key.contains("/home")), "{targets:?}");
}

#[tokio::test]
async fn what_the_window_sends_is_checked_never_resolved() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/a.txt", b"a");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    for bad in [
        FileChange::Delete {
            paths: strings(&["/home/alice/../../etc/passwd"]),
        },
        FileChange::Delete {
            paths: strings(&["home/alice/a.txt"]),
        },
        FileChange::Delete { paths: strings(&["/"]) },
        FileChange::Rename {
            path: "/home/alice/a.txt".into(),
            name: "../b.txt".into(),
            replace: false,
        },
        FileChange::NewFolder {
            folder: "/home/alice".into(),
            name: "x\u{202E}txt.exe".into(),
        },
        FileChange::Move {
            paths: strings(&["/home/alice"]),
            into: "/home/alice/sub".into(),
            replace: false,
        },
        // A top-level folder with what is in it.
        FileChange::Delete {
            paths: strings(&["/home"]),
        },
    ] {
        let err = core.files.change(t, bad.clone(), false).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "{bad:?}: {err}");
    }
    assert_eq!(server.sftp_file("/home/alice/a.txt").unwrap(), b"a", "nothing changed");
    assert!(!server
        .log()
        .iter()
        .any(|l| l.starts_with("sftp remove") || l.starts_with("sftp rmdir")));
}

#[tokio::test]
async fn a_failed_step_fails_alone_and_a_retry_runs_only_it() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/a.txt", b"a")
        .with_sftp_file("/etc/motd", b"hello");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let outcome = core
        .files
        .change(
            t,
            FileChange::Delete {
                paths: strings(&["/home/alice/a.txt", "/etc/motd"]),
            },
            false,
        )
        .await
        .unwrap();
    let (status, _, _) = run(&core, outcome).await;
    assert_eq!(status, JobStatus::PartiallyFailed);
    assert!(server.sftp_file("/home/alice/a.txt").is_none());
    assert!(server.sftp_file("/etc/motd").is_some(), "alice may not delete in /etc");
    let job = core
        .store
        .recent_jobs(&core.ctx(), 10)
        .await
        .unwrap()
        .into_iter()
        .find(|j| j.summary.starts_with("Delete 2 items"))
        .unwrap();
    let outcome = core
        .bus
        .retry_failed(&core.ctx(), Uuid::parse_str(&job.id).unwrap(), false)
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = &outcome else {
        panic!("a delete asks: {outcome:?}");
    };
    assert_eq!(request.targets.len(), 1);
    assert_eq!(request.targets[0].name, "web01: /etc/motd");
}

// ---- Root browsing ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn root_browsing_runs_sftp_under_sudo_and_every_change_through_it_asks_one_tier_more() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_file("/etc/nginx/nginx.conf", b"worker_processes 1;")
        .with_sftp_file("/home/alice/site.conf", b"server {}");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;

    // As the login user, /etc is refused.
    let outcome = core
        .files
        .change(
            t,
            FileChange::NewFolder {
                folder: "/etc".into(),
                name: "remotely".into(),
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(run(&core, outcome).await.0, JobStatus::Failed);
    let err = core.files.change(
        t,
        FileChange::NewFolder {
            folder: "/etc".into(),
            name: "remotely".into(),
        },
        true,
    );
    assert!(err.await.unwrap_err().to_string().contains("not browsing as root"));

    let started = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    assert_eq!(started.server, DEFAULT_SFTP_SERVER);
    assert!(started.with_password);
    assert!(core.terminals.root_browsing(t).is_some());
    let log = server.log();
    assert!(log.iter().any(|l| l == "sudo ok"), "{log:?}");
    assert!(log.iter().any(|l| l == "sftp start as root"));
    assert!(
        !log.iter().any(|l| l.contains(&pw)),
        "the password is never in the host's log of commands"
    );

    // A listing as root says so.
    let listing = core
        .terminals
        .open_folder_as(t, Some("/etc/nginx"), None, true)
        .await
        .unwrap();
    assert!(listing.as_root && listing.root_available);
    assert!(listing.entries.iter().any(|e| e.name == "nginx.conf"));

    // A new folder as root: Low becomes Medium; it is root's.
    let (status, tier, asked) = change(
        &core,
        t,
        FileChange::NewFolder {
            folder: "/etc".into(),
            name: "remotely".into(),
        },
        true,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    let asked = asked.unwrap();
    assert!(
        asked.reasons.iter().any(|r| r == "as root (sudo): low -> medium"),
        "{:?}",
        asked.reasons
    );
    assert!(asked.file_op.as_ref().unwrap().as_root);
    assert!(asked.summary.ends_with(", as root"));
    let (_, uid, gid) = server.sftp_meta("/etc/remotely").unwrap();
    assert_eq!((uid, gid), (0, 0));

    // An owner change as root: Medium becomes High.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Owner {
            paths: strings(&["/etc/remotely"]),
            uid: Some(33),
            gid: Some(33),
        },
        true,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::High));
    let (_, uid, gid) = server.sftp_meta("/etc/remotely").unwrap();
    assert_eq!((uid, gid), (33, 33));
    // Set on the path itself, never through a link: OpenSSH's lsetstat, which the host offers.
    assert!(
        server.log().iter().any(|l| l == "sftp lsetstat /etc/remotely"),
        "{:?}",
        server.log()
    );

    // A copy as root runs cp -a under sudo.
    let (status, tier, _) = change(
        &core,
        t,
        FileChange::Copy {
            paths: strings(&["/home/alice/site.conf"]),
            into: "/etc/nginx".into(),
        },
        true,
    )
    .await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::High));
    assert_eq!(server.sftp_file("/etc/nginx/site.conf").unwrap(), b"server {}");
    assert!(server
        .log()
        .iter()
        .any(|l| l == "cp -a /home/alice/site.conf /etc/nginx/site.conf as root"));

    // An upload as root: Low becomes Medium.
    let local = temp_folder("root-up").join("extra.conf");
    std::fs::write(&local, b"gzip on;").unwrap();
    let staged = core.files.stage(vec![local]).unwrap();
    let start = core
        .files
        .upload_as(t, staged.id, "/etc/nginx", Existing::Ask, true)
        .await
        .unwrap();
    let UploadStart::Submitted { outcome } = start else {
        panic!("{start:?}")
    };
    let (status, tier, _) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(server.sftp_file("/etc/nginx/extra.conf").unwrap(), b"gzip on;");

    // Stopped: as root is refused again, and both ends are audited.
    assert!(core.terminals.stop_root(&core.ctx(), t).await.unwrap());
    assert!(core
        .terminals
        .open_folder_as(t, Some("/etc"), None, true)
        .await
        .is_err());
    let audit = core.store.recent_audit(&core.ctx(), 300).await.unwrap();
    for event in ["files_root_started", "files_root_stopped"] {
        assert!(audit.iter().any(|e| e.event == event), "{event}");
    }
    assert!(audit
        .iter()
        .any(|e| e.event == "file_uploaded" && e.action.ends_with(", as root")));
}

#[tokio::test]
async fn a_refused_sudo_password_parks_root_browsing_until_asked_to_retry() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password("another password".into()));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let refused = |log: &[String]| log.iter().filter(|l| *l == "sudo refused").count();

    let err = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "login_parked", "{err}");
    assert_eq!(refused(&server.log()), 1, "one try, then the channel closes");
    // Parked: no second try on the host.
    let err = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "login_parked");
    assert_eq!(refused(&server.log()), 1);
    // Asked to retry, it tries once more.
    let retry = RootRequest {
        retry: true,
        ..RootRequest::default()
    };
    assert!(core.terminals.browse_as_root(&core.ctx(), t, retry).await.is_err());
    assert_eq!(refused(&server.log()), 2);
    assert!(core
        .store
        .recent_audit(&core.ctx(), 50)
        .await
        .unwrap()
        .iter()
        .any(|e| e.event == "files_root_refused"));
}

#[tokio::test]
async fn a_new_sudo_password_asks_for_the_vault_password_and_nopasswd_gets_none() {
    let pw = password();
    let sudo_pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(sudo_pw.clone()));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let ctx = core.ctx();
    let sudo_id = core
        .vault
        .add(&ctx, SecretKind::Password, "web01 sudo", SecretString::new(&sudo_pw))
        .await
        .unwrap()
        .id;
    // Locked and unlocked since: no longer new, and no vault password given lately.
    core.vault.lock(&ctx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    core.vault
        .unlock(
            &ctx,
            remotely_core::vault::UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    // Rule 7: a vault password going somewhere it doesn't go yet asks for the vault password first.
    let ask = || RootRequest {
        sudo_password_id: Some(sudo_id),
        ..RootRequest::default()
    };
    let err = core.terminals.browse_as_root(&ctx, t, ask()).await.unwrap_err();
    assert_eq!(err.code(), "reauth_required", "{err}");
    assert!(
        !server.log().iter().any(|l| l.starts_with("sudo ")),
        "nothing went to the host"
    );
    let given = RootRequest {
        vault_password: Some(SecretString::new(VAULT_PASSWORD)),
        ..ask()
    };
    core.terminals.browse_as_root(&ctx, t, given).await.unwrap();
    core.terminals.stop_root(&ctx, t).await.unwrap();
    // Given once, it may go there again.
    core.vault.lock(&ctx).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    core.vault
        .unlock(
            &ctx,
            remotely_core::vault::UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    core.terminals.browse_as_root(&ctx, t, ask()).await.unwrap();
    let audit = core.store.recent_audit(&ctx, 100).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "vault_secret_allowed"));

    // NOPASSWD: sudo never asks, so nothing goes on its stdin.
    let quiet = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::NoPassword);
    let (core, t) = pane(&quiet, &pw, Environment::Lab).await;
    let started = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    assert!(!started.with_password);
    assert!(!quiet.log().iter().any(|l| l.starts_with("sudo ")));
}

#[tokio::test]
async fn a_host_without_an_sftp_server_or_sudo_says_so() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_server(None);
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let err = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no sftp-server was found"), "{err}");

    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Missing);
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let err = core
        .terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("sudo did not start"), "{err}");
}

#[tokio::test]
async fn root_browsing_ends_when_the_vault_locks() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    core.terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    core.terminals.forget_logins();
    assert!(core.terminals.root_browsing(t).is_none());
}

// ---- The transfer queue ----------------------------------------------------------------------------------------

/// Every transfer's state as it changes, for counting what ran at once.
fn watch_running(core: &Core) -> tokio::task::JoinHandle<usize> {
    let mut events = core.terminals.subscribe_transfers();
    tokio::spawn(async move {
        let mut states: HashMap<Uuid, TransferState> = HashMap::new();
        let mut peak = 0;
        while let Ok(Ok(info)) = timeout(Duration::from_secs(3), events.recv()).await {
            states.insert(info.id, info.state);
            let running = states.values().filter(|s| **s == TransferState::Running).count();
            peak = peak.max(running);
        }
        peak
    })
}

async fn wait_done(core: &Core, ids: &[Uuid]) -> Vec<TransferInfo> {
    timeout(WAIT, async {
        loop {
            let all = core.terminals.transfers();
            let mine: Vec<TransferInfo> = all.into_iter().filter(|t| ids.contains(&t.id)).collect();
            if mine.len() == ids.len()
                && mine.iter().all(|t| {
                    matches!(
                        t.state,
                        TransferState::Done | TransferState::Failed | TransferState::Cancelled
                    )
                })
            {
                return mine;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the transfers ended")
}

#[tokio::test]
async fn four_transfers_run_at_a_time_per_host() {
    let pw = password();
    let mut server = TestSshServer::start().await.with_password("alice", &pw);
    let body = content(1024 * 1024);
    for n in 0..7 {
        server = server.with_sftp_file(&format!("/home/alice/f{n}.bin"), &body);
    }
    let server = server.with_sftp_delay(Duration::from_millis(15));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let peak = watch_running(&core);
    let paths: Vec<String> = (0..7).map(|n| format!("/home/alice/f{n}.bin")).collect();
    let dest = temp_folder("four");
    let queued = core.terminals.download(&core.ctx(), t, &paths, &dest).await.unwrap();
    let ids: Vec<Uuid> = queued.iter().map(|q| q.id).collect();
    let done = wait_done(&core, &ids).await;
    assert!(done.iter().all(|d| d.state == TransferState::Done), "{done:?}");
    assert!(done.iter().all(|d| d.sha256.as_deref() == Some(sha(&body).as_str())));
    assert_eq!(peak.await.unwrap(), 4, "four at a time, never more");
}

#[tokio::test]
async fn a_paused_download_comes_down_again_once_it_goes_on() {
    let pw = password();
    let body = content(3 * 1024 * 1024);
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/big.bin", &body)
        .with_sftp_delay(Duration::from_millis(20));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let dest = temp_folder("pause-down");
    let queued = core
        .terminals
        .download(&core.ctx(), t, &strings(&["/home/alice/big.bin"]), &dest)
        .await
        .unwrap();
    let id = queued[0].id;
    let find = |core: &Core| core.terminals.transfers().into_iter().find(|x| x.id == id).unwrap();
    timeout(WAIT, async {
        while find(&core).done == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(core.terminals.pause_transfer(id));
    timeout(WAIT, async {
        while find(&core).state != TransferState::Paused {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let at = find(&core).done;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(find(&core).done, at, "nothing moves while paused");
    assert!(at < body.len() as u64);
    assert!(core.terminals.resume_transfer(id));
    let done = wait_done(&core, &[id]).await;
    assert_eq!(done[0].state, TransferState::Done, "{:?}", done[0].message);
    assert_eq!(done[0].sha256.as_deref(), Some(sha(&body).as_str()));
    assert_eq!(std::fs::read(dest.join("big.bin")).unwrap(), body);
    let opened = server
        .log()
        .iter()
        .filter(|l| *l == "sftp open /home/alice/big.bin")
        .count();
    assert_eq!(opened, 2, "read again, from the start, after the pause");
}

#[tokio::test]
async fn a_paused_upload_goes_on_from_where_it_stopped() {
    let pw = password();
    let body = content(3 * 1024 * 1024);
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_delay(Duration::from_millis(20));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let local = temp_folder("pause-up").join("big.bin");
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
    let at = find(&core).unwrap().done;
    assert!(core.terminals.resume_transfer(id));
    assert_eq!(
        timeout(WAIT, core.jobs.wait(job_id)).await.unwrap().unwrap(),
        JobStatus::Succeeded
    );
    assert!(at > 0 && at < body.len() as u64);
    assert_eq!(server.sftp_file("/home/alice/big.bin").unwrap(), body);
    let reopened = server
        .log()
        .iter()
        .filter(|l| *l == "sftp open /home/alice/big.bin for writing")
        .count();
    assert_eq!(reopened, 2, "written on from its offset after the pause");
}

/// Sets a local file's modification time.
fn touch(path: &Path, at: SystemTime) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

fn secs(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::test]
async fn an_upload_asks_replaces_if_newer_skips_or_keeps_both() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/app.conf", b"old");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let local = temp_folder("existing-up").join("app.conf");
    std::fs::write(&local, b"new").unwrap();
    let up = |existing| {
        let staged = core.files.stage(vec![local.clone()]).unwrap();
        let core = &core;
        async move { core.files.upload(t, staged.id, "/home/alice", existing).await.unwrap() }
    };

    let UploadStart::Conflicts { existing, .. } = up(Existing::Ask).await else {
        panic!("asks first")
    };
    assert_eq!(existing, ["app.conf"]);
    assert!(matches!(up(Existing::Skip).await, UploadStart::Nothing));
    // Older than the host's: left alone.
    touch(&local, UNIX_EPOCH + Duration::from_secs(1_000_000_000));
    assert!(matches!(up(Existing::ReplaceIfNewer).await, UploadStart::Nothing));
    // Kept beside it with a number.
    let UploadStart::Submitted { outcome } = up(Existing::KeepBoth).await else {
        panic!()
    };
    assert_eq!(run(&core, outcome).await.0, JobStatus::Succeeded);
    assert_eq!(server.sftp_file("/home/alice/app (1).conf").unwrap(), b"new");
    assert_eq!(server.sftp_file("/home/alice/app.conf").unwrap(), b"old");
    // Newer than the host's: replaced, which asks.
    touch(&local, SystemTime::now() + Duration::from_secs(86_400));
    let UploadStart::Submitted { outcome } = up(Existing::ReplaceIfNewer).await else {
        panic!()
    };
    let (status, tier, _) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(server.sftp_file("/home/alice/app.conf").unwrap(), b"new");
}

#[tokio::test]
async fn a_download_asks_replaces_skips_or_keeps_both_and_keeps_the_mark_of_the_web() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/report.txt", b"from the host");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let dest = temp_folder("existing-down");
    std::fs::write(dest.join("report.txt"), b"mine").unwrap();
    let down = |existing| {
        let core = &core;
        let dest = dest.clone();
        async move {
            core.terminals
                .download_with(
                    &core.ctx(),
                    t,
                    &strings(&["/home/alice/report.txt"]),
                    &dest,
                    DownloadOptions {
                        existing,
                        as_root: false,
                    },
                )
                .await
                .unwrap()
        }
    };
    let DownloadStart::Conflicts { existing, .. } = down(Existing::Ask).await else {
        panic!("asks first")
    };
    assert_eq!(existing, ["report.txt"]);
    let DownloadStart::Queued { transfers, skipped, .. } = down(Existing::Skip).await else {
        panic!()
    };
    assert!(transfers.is_empty() && skipped == 1);
    let DownloadStart::Queued { transfers, .. } = down(Existing::KeepBoth).await else {
        panic!()
    };
    wait_done(&core, &[transfers[0].id]).await;
    assert_eq!(std::fs::read(dest.join("report (1).txt")).unwrap(), b"from the host");
    let DownloadStart::Queued { transfers, .. } = down(Existing::Replace).await else {
        panic!()
    };
    assert!(transfers[0].replace);
    let done = wait_done(&core, &[transfers[0].id]).await;
    assert_eq!(done[0].state, TransferState::Done, "{:?}", done[0].message);
    assert_eq!(std::fs::read(dest.join("report.txt")).unwrap(), b"from the host");
    // A8: a replaced file is marked as from the internet like any download.
    let mut stream = dest.join("report.txt").into_os_string();
    stream.push(":Zone.Identifier");
    assert!(std::fs::read_to_string(stream).unwrap().contains("ZoneId=3"));
    let left: HashSet<String> = std::fs::read_dir(&dest)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        left,
        HashSet::from(["report.txt".into(), "report (1).txt".into()]),
        "no partial file left"
    );
}

#[tokio::test]
async fn modification_times_are_kept_both_ways() {
    let pw = password();
    let server = TestSshServer::start().await.with_password("alice", &pw);
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let local = temp_folder("times").join("dated.txt");
    std::fs::write(&local, b"2020").unwrap();
    let then = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    touch(&local, then);
    let staged = core.files.stage(vec![local]).unwrap();
    let UploadStart::Submitted { outcome } = core
        .files
        .upload(t, staged.id, "/home/alice", Existing::Ask)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(run(&core, outcome).await.0, JobStatus::Succeeded);
    let host = std::fs::metadata(server.sftp_path("/home/alice/dated.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(secs(host), secs(then), "the host's copy keeps this PC's time");

    let dest = temp_folder("times-down");
    let queued = core
        .terminals
        .download(&core.ctx(), t, &strings(&["/home/alice/dated.txt"]), &dest)
        .await
        .unwrap();
    wait_done(&core, &[queued[0].id]).await;
    let here = std::fs::metadata(dest.join("dated.txt")).unwrap().modified().unwrap();
    assert_eq!(secs(here), secs(then), "and the download the host's");
}

#[tokio::test]
async fn folders_go_up_and_come_down_with_what_is_in_them() {
    let pw = password();
    let server = TestSshServer::start().await.with_password("alice", &pw);
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let root = temp_folder("folder-up").join("site");
    std::fs::create_dir_all(root.join("css")).unwrap();
    std::fs::create_dir_all(root.join("empty")).unwrap();
    std::fs::write(root.join("index.html"), b"<p>hi</p>").unwrap();
    std::fs::write(root.join("css/main.css"), b"p{}").unwrap();
    let staged = core.files.stage(vec![root]).unwrap();
    assert_eq!(staged.count, 2);
    assert!(staged.files[0].folder);
    let UploadStart::Submitted { outcome } = core
        .files
        .upload(t, staged.id, "/home/alice", Existing::Ask)
        .await
        .unwrap()
    else {
        panic!()
    };
    let (status, tier, _) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert_eq!(names(&server, "/home/alice/site"), ["css", "empty", "index.html"]);
    assert_eq!(server.sftp_file("/home/alice/site/css/main.css").unwrap(), b"p{}");
    let jobs = core.store.recent_jobs(&core.ctx(), 5).await.unwrap();
    assert!(
        jobs.iter()
            .any(|j| j.summary == "Upload the folder 'site' with 2 files (12 B) to /home/alice"),
        "{:?}",
        jobs.iter().map(|j| &j.summary).collect::<Vec<_>>()
    );

    let dest = temp_folder("folder-down");
    let DownloadStart::Queued { transfers, .. } = core
        .terminals
        .download_with(
            &core.ctx(),
            t,
            &strings(&["/home/alice/site"]),
            &dest,
            DownloadOptions {
                existing: Existing::Ask,
                as_root: false,
            },
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let ids: Vec<Uuid> = transfers.iter().map(|x| x.id).collect();
    let done = wait_done(&core, &ids).await;
    assert!(done.iter().all(|d| d.state == TransferState::Done), "{done:?}");
    assert_eq!(std::fs::read(dest.join("site/css/main.css")).unwrap(), b"p{}");
    assert_eq!(std::fs::read(dest.join("site/index.html")).unwrap(), b"<p>hi</p>");
    assert!(dest.join("site/empty").is_dir(), "an empty folder comes down too");
}

// ---- What others on the host do meanwhile ----------------------------------------------------------------------

/// The transfer `id`, as the panel shows it.
fn transfer(core: &Core, id: Uuid) -> TransferInfo {
    core.terminals.transfers().into_iter().find(|x| x.id == id).unwrap()
}

/// Waits until the job's transfer has sent something, pauses it, and waits until it shows as paused; its id.
async fn pause_job_transfer(core: &Core, job_id: Uuid) -> Uuid {
    let find = |core: &Core| {
        core.terminals
            .transfers()
            .into_iter()
            .find(|x| x.job_id == Some(job_id))
    };
    timeout(WAIT, async {
        while find(core).is_none_or(|x| x.done == 0) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let id = find(core).unwrap().id;
    assert!(core.terminals.pause_transfer(id));
    timeout(WAIT, async {
        while transfer(core, id).state != TransferState::Paused {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    id
}

/// Writes `content` over a file of the test server's folder and puts its modification time back, as someone on the
/// host could: the same size and time as before, other bytes.
fn rewrite_in_place(path: &Path, content: &[u8]) {
    let before = std::fs::metadata(path).unwrap().modified().unwrap();
    std::fs::write(path, content).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(before)
        .unwrap();
}

#[tokio::test]
async fn a_paused_upload_whose_file_was_written_again_on_the_host_starts_again() {
    let pw = password();
    let body = content(3 * 1024 * 1024);
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_delay(Duration::from_millis(20));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let local = temp_folder("swap-up").join("big.bin");
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
    let id = pause_job_transfer(&core, job_id).await;
    // While paused, the part on the host is written again: as many bytes, the same time, other content.
    let host = server.sftp_path("/home/alice/big.bin");
    let size = std::fs::metadata(&host).unwrap().len() as usize;
    assert!(size > 0 && size < body.len());
    rewrite_in_place(&host, &vec![0xAA; size]);
    assert!(core.terminals.resume_transfer(id));
    assert_eq!(
        timeout(WAIT, core.jobs.wait(job_id)).await.unwrap().unwrap(),
        JobStatus::Succeeded
    );
    assert_eq!(
        server.sftp_file("/home/alice/big.bin").unwrap(),
        body,
        "what is on the host is what was sent, all of it"
    );
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    let uploaded = audit.iter().find(|e| e.event == "file_uploaded").unwrap();
    let detail = uploaded.detail.as_deref().unwrap();
    assert!(
        detail.contains(&format!("{} bytes sent, SHA-256 {}", body.len(), sha(&body))),
        "{detail}"
    );
}

#[tokio::test]
async fn a_paused_download_of_a_file_rewritten_in_place_comes_down_as_it_is_now() {
    let pw = password();
    let old = content(3 * 1024 * 1024);
    let new: Vec<u8> = old.iter().map(|b| b ^ 0x5A).collect();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/big.bin", &old)
        .with_sftp_delay(Duration::from_millis(20));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let dest = temp_folder("rewrite-down");
    let queued = core
        .terminals
        .download(&core.ctx(), t, &strings(&["/home/alice/big.bin"]), &dest)
        .await
        .unwrap();
    let id = queued[0].id;
    timeout(WAIT, async {
        while transfer(&core, id).done == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(core.terminals.pause_transfer(id));
    timeout(WAIT, async {
        while transfer(&core, id).state != TransferState::Paused {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // The same size and time: nothing SFTP says tells the two apart.
    rewrite_in_place(&server.sftp_path("/home/alice/big.bin"), &new);
    assert!(core.terminals.resume_transfer(id));
    let done = wait_done(&core, &[id]).await;
    assert_eq!(done[0].state, TransferState::Done, "{:?}", done[0].message);
    let saved = std::fs::read(dest.join("big.bin")).unwrap();
    assert!(saved == new, "the new file whole, never part of each");
    assert_eq!(done[0].sha256.as_deref(), Some(sha(&new).as_str()));
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    let downloaded = audit.iter().find(|e| e.event == "file_downloaded").unwrap();
    assert!(downloaded.detail.as_deref().unwrap().contains(&sha(&new)));
}

#[tokio::test]
async fn a_vault_lock_ends_root_browsing_and_its_paused_upload_writes_nothing_more() {
    let pw = password();
    let body = content(3 * 1024 * 1024);
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password(pw.clone()))
        .with_sftp_file("/etc/nginx/nginx.conf", b"worker_processes 1;")
        .with_sftp_delay(Duration::from_millis(20));
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    core.terminals
        .browse_as_root(&core.ctx(), t, RootRequest::default())
        .await
        .unwrap();
    let local = temp_folder("root-lock").join("site.conf");
    std::fs::write(&local, &body).unwrap();
    let staged = core.files.stage(vec![local]).unwrap();
    let UploadStart::Submitted { outcome } = core
        .files
        .upload_as(t, staged.id, "/etc/nginx", Existing::Ask, true)
        .await
        .unwrap()
    else {
        panic!("submitted")
    };
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("as root, an upload asks")
    };
    let job_id = approve(&core, &request).await;
    let id = pause_job_transfer(&core, job_id).await;
    let starts = |log: &[String]| log.iter().filter(|l| *l == "sftp start as root").count();
    let started = starts(&server.log());

    core.terminals.forget_logins();
    assert!(core.terminals.root_browsing(t).is_none());
    // Going on is no longer possible: it was cancelled with root browsing.
    core.terminals.resume_transfer(id);
    timeout(WAIT, core.jobs.wait(job_id)).await.unwrap().unwrap();
    let ended = transfer(&core, id);
    assert_eq!(ended.state, TransferState::Cancelled, "{:?}", ended.message);
    assert!(
        server.sftp_file("/etc/nginx/site.conf").is_none(),
        "the part it made is deleted, nothing more is written"
    );
    assert_eq!(starts(&server.log()), started, "no root channel opened again");
    // Its end is audited with why.
    timeout(WAIT, async {
        loop {
            let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
            if audit
                .iter()
                .any(|e| e.event == "files_root_stopped" && e.detail.as_deref() == Some("the vault locked"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("files_root_stopped, the vault locked");
}

#[tokio::test]
async fn git_data_never_comes_down_and_a_git_folder_picked_is_refused() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/proj/src/main.rs", b"fn main() {}")
        .with_sftp_file("/home/alice/proj/.git/config", b"[core]\n\tfsmonitor = calc.exe\n")
        .with_sftp_file("/home/alice/proj/.git/hooks/post-checkout", b"#!/bin/sh\n")
        .with_sftp_file("/home/alice/proj/sub/.git", b"gitdir: /home/alice/elsewhere\n");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let dest = temp_folder("git-down");
    let started = core
        .terminals
        .download_with(
            &core.ctx(),
            t,
            &strings(&["/home/alice/proj"]),
            &dest,
            DownloadOptions::default(),
        )
        .await
        .unwrap();
    let DownloadStart::Queued {
        transfers, left_out, ..
    } = started
    else {
        panic!("{started:?}")
    };
    assert_eq!(left_out, 2, "the .git folder and the .git file, counted");
    let ids: Vec<Uuid> = transfers.iter().map(|x| x.id).collect();
    let done = wait_done(&core, &ids).await;
    assert!(done.iter().all(|d| d.state == TransferState::Done));
    assert!(dest.join("proj").join("src").join("main.rs").is_file());
    assert!(!dest.join("proj").join(".git").exists());
    assert!(!dest.join("proj").join("sub").join(".git").exists());

    let err = core
        .terminals
        .download_with(
            &core.ctx(),
            t,
            &strings(&["/home/alice/proj/.git"]),
            &dest,
            DownloadOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Git's own data"), "{err}");
}

#[tokio::test]
async fn keep_both_never_takes_a_name_another_file_of_the_upload_has() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/a.txt", b"there");
    let (core, t) = pane(&server, &pw, Environment::Lab).await;
    let folder = temp_folder("keep-both");
    std::fs::write(folder.join("a.txt"), b"new").unwrap();
    std::fs::write(folder.join("a (1).txt"), b"other").unwrap();
    let staged = core
        .files
        .stage(vec![folder.join("a.txt"), folder.join("a (1).txt")])
        .unwrap();
    let start = core
        .files
        .upload(t, staged.id, "/home/alice", Existing::KeepBoth)
        .await
        .unwrap();
    let UploadStart::Submitted { outcome } = start else {
        panic!("{start:?}")
    };
    assert_eq!(run(&core, outcome).await.0, JobStatus::Succeeded);
    assert_eq!(server.sftp_file("/home/alice/a.txt").unwrap(), b"there");
    assert_eq!(server.sftp_file("/home/alice/a (1).txt").unwrap(), b"other");
    assert_eq!(server.sftp_file("/home/alice/a (2).txt").unwrap(), b"new");
}

#[tokio::test]
async fn a_sudo_park_is_one_per_password_shared_with_the_containers_page() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sudo(SudoMode::Password("another password".into()));
    let (core, t, session, login) = pane_ids(&server, &pw, Environment::Lab).await;
    let ctx = core.ctx();
    let spec = core.store.session_spec(&ctx, session).await.unwrap().unwrap();
    let key = login_guard::sudo_key(&spec);
    let refused = |log: &[String]| log.iter().filter(|l| *l == "sudo refused").count();
    let parked = || Parked {
        reason: ParkReason::SudoRefused,
        message: "sudo refused".into(),
    };

    // The Containers page parked this session's sudo with its login password: root browsing doesn't try it either.
    let login_scope = ParkScope::Sudo { secret: Some(login) };
    core.login_guard.park(session, login_scope, &key, parked());
    let err = core
        .terminals
        .browse_as_root(&ctx, t, RootRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "login_parked", "{err}");
    assert_eq!(refused(&server.log()), 0, "nothing tried on the host");

    // Another sudo password, parked for the Containers page, and the session's logins: a retry here lifts neither.
    let other = core
        .vault
        .add(&ctx, SecretKind::Password, "other sudo", SecretString::new("x"))
        .await
        .unwrap()
        .id;
    let other_scope = ParkScope::Sudo { secret: Some(other) };
    core.login_guard.park(session, other_scope, &key, parked());
    let login_key = login_guard::login_key(&spec);
    core.login_guard.park(session, ParkScope::Login, &login_key, parked());
    let retry = RootRequest {
        retry: true,
        ..RootRequest::default()
    };
    let err = core.terminals.browse_as_root(&ctx, t, retry).await.unwrap_err();
    assert_eq!(err.code(), "login_parked", "refused again, and parked again: {err}");
    assert_eq!(refused(&server.log()), 1, "one try");
    assert!(core.login_guard.parked(session, login_scope, &key).is_some());
    assert!(core.login_guard.parked(session, other_scope, &key).is_some());
    assert!(core.login_guard.parked(session, ParkScope::Login, &login_key).is_some());
}
