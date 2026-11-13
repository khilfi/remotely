//! SS-14, BX-10 (0.8.0 G3): the Files page's core, end to end with the real russh adapter against
//! `fakes::ssh_server::TestSshServer` on 127.0.0.1 (its SFTP temp folder, its toy `find` and `sha256sum`).
//!
//! * Find, the text preview and SHA-256 checksums are reads on the terminal's own connection; a hostile pattern or
//!   folder reaches the host only as printf escapes.
//! * Bookmarks per session: audited, refused by the read-only lock, into the trash with their session and back.
//! * The local pane names files by listing; compare and sync both ways: to the host one upload job (uploads Low,
//!   replacements Medium, deletes only when chosen and High), to this PC downloads that replace older files.
//! * BX-10: a push to many hosts (Medium, High from 5 hosts) with each host's SHA-256 checked, a fetch of the same
//!   file from each (Low; a Prod host's Medium) grouped by what they hold.
//!
//! No real host is contacted; test data uses alice and files made at run time in the system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::remote::{AgentSource, EntryKind, PtySize};
use remotely_core::bulk::{GroupOptions, TargetPicks};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::local_files::LocalAsk;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::file_reads::FindRequest;
use remotely_core::terminal::files::{DownloadStart, TransferInfo, TransferState};
use remotely_core::terminal::folder::FolderTracking;
use remotely_core::terminal::sync::{CompareRequest, RowState, Side, SyncDirection, SyncRequest, SyncStart};
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

fn password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
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

/// A core trusting the test server, with alice's login password in the vault.
async fn core_for(server: &TestSshServer, password: &str) -> (Core, SecretId) {
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
    (core, login)
}

/// A saved session to the test server.
async fn session(core: &Core, server: &TestSshServer, login: SecretId, name: &str, environment: Environment) -> Uuid {
    core.sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: name.into(),
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
        .id
}

/// A terminal to the test server: the core, the terminal's id and its session's.
async fn pane(server: &TestSshServer, password: &str) -> (Core, Uuid, Uuid) {
    let (core, login) = core_for(server, password).await;
    let session = session(&core, server, login, "web01", Environment::Lab).await;
    let handle = core.terminals.open(&core.ctx(), session, SIZE).await.unwrap();
    let id = handle.id;
    drain(&core, handle).await;
    (core, id, session)
}

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

/// Runs an outcome to its end; its job, status, tier and approval request (if it asked).
async fn run(core: &Core, outcome: SubmitOutcome) -> (Uuid, JobStatus, Tier, Option<ApprovalRequest>) {
    let (job, tier, request) = match outcome {
        SubmitOutcome::Queued { job_id, tier, .. } => (job_id, tier, None),
        SubmitOutcome::NeedsApproval { request } => (approve(core, &request).await, request.tier, Some(request)),
    };
    let status = timeout(WAIT, core.jobs.wait(job)).await.unwrap().unwrap();
    if status != JobStatus::Succeeded {
        for target in core.store.job_targets(&core.ctx(), job).await.unwrap() {
            eprintln!("{}: {} {:?}", target.target_name, target.status, target.error);
        }
    }
    (job, status, tier, request)
}

async fn wait_done(core: &Core, ids: &[Uuid]) -> Vec<TransferInfo> {
    timeout(WAIT, async {
        loop {
            let mine: Vec<TransferInfo> = core
                .terminals
                .transfers()
                .into_iter()
                .filter(|t| ids.contains(&t.id))
                .collect();
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

fn list_here(core: &Core, folder: &Path) -> remotely_core::local_files::LocalListing {
    core.local_files
        .list(
            LocalAsk::Typed {
                path: folder.display().to_string(),
            },
            folder,
            folder,
        )
        .unwrap()
}

// ---- Find, preview, checksums ----------------------------------------------------------------------------------

#[tokio::test]
async fn find_preview_and_checksums_read_the_host_without_the_bus() {
    let pw = password();
    let conf = b"port = 80\n\x1b[31mred\n";
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/etc/app.conf", conf)
        .with_sftp_file("/home/alice/etc/conf.d/a.conf", b"a")
        .with_sftp_file("/home/alice/etc/readme.txt", b"r")
        .with_sftp_file("/home/alice/bin/tool", b"\x7fELF\0\0\x01");
    let (core, t, _) = pane(&server, &pw).await;
    let jobs_before = core.store.recent_audit(&core.ctx(), 500).await.unwrap().len();

    let find = |pattern: &str, ignore_case: bool| FindRequest {
        folder: "/home/alice/etc".into(),
        pattern: pattern.into(),
        ignore_case,
        as_root: false,
    };
    let found = core.terminals.find(t, find("*.conf", false)).await.unwrap();
    let paths: Vec<&str> = found.hits.iter().map(|h| h.path.as_str()).collect();
    assert_eq!(paths, vec!["/home/alice/etc/app.conf", "/home/alice/etc/conf.d/a.conf"]);
    assert_eq!(found.hits[0].kind, Some(EntryKind::File));
    assert_eq!(found.hits[0].size, Some(conf.len() as u64));
    assert!(!found.timed_out && !found.more && !found.paths_only);
    let any_case = core.terminals.find(t, find("*.CONF", true)).await.unwrap();
    assert_eq!(any_case.hits.len(), 2);
    assert!(core
        .terminals
        .find(t, find("*.CONF", false))
        .await
        .unwrap()
        .hits
        .is_empty());
    // A pattern that would be a command line elsewhere is a name to look for here.
    let hostile = core.terminals.find(t, find("x'; rm -rf ~ #", false)).await.unwrap();
    assert!(hostile.hits.is_empty());
    assert!(server.sftp_file("/home/alice/etc/app.conf").is_some(), "nothing ran");
    for bad in ["etc/*.conf", "a\nb"] {
        assert!(core.terminals.find(t, find(bad, false)).await.is_err(), "{bad:?}");
    }
    let mut outside = find("*", false);
    outside.folder = "/home/alice/../root".into();
    assert!(core.terminals.find(t, outside).await.is_err());

    let preview = core
        .terminals
        .preview(t, "/home/alice/etc/app.conf", false)
        .await
        .unwrap();
    assert_eq!(preview.text.as_deref(), Some("port = 80\n\u{241B}[31mred\n"));
    assert_eq!(preview.marked, 1);
    assert!(!preview.truncated);
    let binary = core.terminals.preview(t, "/home/alice/bin/tool", false).await.unwrap();
    assert!(binary.text.is_none(), "a NUL byte is binary");
    assert!(
        core.terminals.preview(t, "/home/alice/etc", false).await.is_err(),
        "a folder has no preview"
    );

    let sum = core
        .terminals
        .checksum(t, "/home/alice/etc/app.conf", false)
        .await
        .unwrap();
    assert_eq!(sum.sha256, sha(conf));
    assert_eq!(sum.by, "host", "the host's own sha256sum");
    assert!(core.terminals.checksum(t, "/home/alice/nope", false).await.is_err());

    // Reads: nothing on the bus, nothing audited.
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 500).await.unwrap().len(),
        jobs_before
    );
}

// ---- Bookmarks -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn bookmarks_are_audited_locked_and_go_to_the_trash_with_their_session() {
    let pw = password();
    let server = TestSshServer::start().await.with_password("alice", &pw);
    let (core, login) = core_for(&server, &pw).await;
    let ctx = core.ctx();
    let web = session(&core, &server, login, "web01", Environment::Lab).await;

    let etc = core.bookmarks.add(&ctx, web, "", "/etc/nginx").await.unwrap();
    assert_eq!(etc.name, "nginx");
    let logs = core.bookmarks.add(&ctx, web, "Logs", "/var/log").await.unwrap();
    let err = core.bookmarks.add(&ctx, web, "again", "/etc/nginx").await.unwrap_err();
    assert!(err.to_string().contains("bookmarked already"), "{err}");
    for bad in ["etc", "/etc/../root", "/etc/a\u{202E}b"] {
        assert!(core.bookmarks.add(&ctx, web, "", bad).await.is_err(), "{bad}");
    }
    assert!(
        core.bookmarks.add(&ctx, Uuid::new_v4(), "", "/srv").await.is_err(),
        "no such session"
    );
    core.bookmarks.rename(&ctx, logs.id, "System logs").await.unwrap();
    let names: Vec<String> = core
        .bookmarks
        .list(&ctx, web)
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, vec!["nginx", "System logs"]);
    let audited: Vec<_> = core
        .store
        .recent_audit(&ctx, 500)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "file_bookmark_changed")
        .collect();
    assert_eq!(audited.len(), 3, "two added, one renamed");
    assert!(audited.iter().all(|e| e.targets_json.contains(&web.to_string())));

    // FD-03: the read-only lock refuses edits; reading goes on.
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let refused = core.bookmarks.add(&ctx, web, "", "/srv").await.unwrap_err();
    assert_eq!(refused.code(), "read_only_lock", "{refused}");
    assert_eq!(
        core.bookmarks.remove(&ctx, etc.id).await.unwrap_err().code(),
        "read_only_lock"
    );
    assert_eq!(core.bookmarks.list(&ctx, web).await.unwrap().len(), 2);
    core.presentation.set(Presentation::default()).await.unwrap();

    // QL-27: deleting the session takes its bookmarks into the trash; restoring brings them back.
    core.sessions.delete(&ctx, web).await.unwrap();
    assert!(core.bookmarks.all(&ctx).await.unwrap().is_empty());
    let entry = core
        .trash
        .list(&ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.item_id == web.to_string())
        .unwrap();
    assert!(entry.detail.contains("2 bookmarks"), "{}", entry.detail);
    core.trash.restore(&ctx, entry.id, None).await.unwrap();
    let back = core.bookmarks.list(&ctx, web).await.unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back[1].path, "/var/log");
}

// ---- Local pane, compare and sync ------------------------------------------------------------------------------

#[tokio::test]
async fn the_local_pane_uploads_and_downloads_by_listing() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/srv/remote.txt", b"from the host");
    let (core, t, _) = pane(&server, &pw).await;
    let here = temp_folder("files-page-local");
    std::fs::write(here.join("site.conf"), b"server {}").unwrap();
    let listing = list_here(&core, &here);
    // A name the listing didn't find is refused; one it did is staged and uploaded through the bus.
    assert!(core.local_files.paths_of(listing.id, &["..\\x".into()]).is_err());
    let paths = core.local_files.paths_of(listing.id, &["site.conf".into()]).unwrap();
    let staged = core.files.stage(paths).unwrap();
    let start = core
        .files
        .upload(
            t,
            staged.id,
            "/home/alice/srv",
            remotely_core::terminal::files::Existing::Ask,
        )
        .await
        .unwrap();
    let remotely_core::terminal::files::UploadStart::Submitted { outcome } = start else {
        panic!("submitted")
    };
    let (_, status, tier, _) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert_eq!(server.sftp_file("/home/alice/srv/site.conf").unwrap(), b"server {}");
    // A download into the listing's folder.
    let dest = core.local_files.folder_of(listing.id).unwrap();
    let start = core
        .files
        .download(
            t,
            &["/home/alice/srv/remote.txt".into()],
            remotely_core::terminal::files::DownloadDest::Folder(dest),
            remotely_core::terminal::files::DownloadOptions::default(),
        )
        .await
        .unwrap();
    let DownloadStart::Queued { transfers, .. } = start else {
        panic!("queued")
    };
    wait_done(&core, &transfers.iter().map(|t| t.id).collect::<Vec<_>>()).await;
    assert_eq!(std::fs::read(here.join("remote.txt")).unwrap(), b"from the host");
    std::fs::remove_dir_all(&here).unwrap();
}

#[tokio::test]
async fn compare_then_sync_to_the_host_rates_uploads_replacements_and_deletes() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/www/same.html", b"same")
        .with_sftp_file("/home/alice/www/old.html", b"old")
        .with_sftp_file("/home/alice/www/extra.html", b"only on the host")
        .with_sftp_file("/home/alice/www/gone/x.txt", b"x")
        .with_sftp_file("/home/alice/www/.git/HEAD", b"ref");
    let (core, t, _) = pane(&server, &pw).await;
    let here = temp_folder("files-page-sync");
    std::fs::write(here.join("same.html"), b"same").unwrap();
    std::fs::write(here.join("old.html"), b"new and longer").unwrap();
    std::fs::create_dir_all(here.join("css")).unwrap();
    std::fs::write(here.join("css/main.css"), b"p{}").unwrap();
    std::fs::create_dir_all(here.join(".git")).unwrap();
    std::fs::write(here.join(".git/HEAD"), b"ref").unwrap();
    let listing = list_here(&core, &here);

    let compare = |contents: bool| CompareRequest {
        terminal_id: t,
        listing: listing.id,
        host_folder: "/home/alice/www".into(),
        contents,
        as_root: false,
    };
    let compared = core.sync.compare(compare(true)).await.unwrap();
    let state = |path: &str| compared.rows.iter().find(|r| r.path == path).map(|r| r.state);
    assert_eq!(state("same.html"), None, "the same file isn't listed (only counted)");
    assert_eq!(compared.counts.same, 1);
    assert_eq!(state("old.html"), Some(RowState::Differs));
    let old = compared.rows.iter().find(|r| r.path == "old.html").unwrap();
    assert_eq!(old.larger, Some(Side::Here));
    assert_eq!(state("css"), Some(RowState::OnlyHere));
    assert_eq!(state("css/main.css"), Some(RowState::OnlyHere));
    assert_eq!(state("extra.html"), Some(RowState::OnlyThere));
    assert_eq!(state("gone"), Some(RowState::OnlyThere));
    assert!(
        compared.rows.iter().all(|r| !r.path.starts_with(".git")),
        "Git's data stays out"
    );
    assert_eq!(compared.left_out, 2, ".git on both sides");

    // Without deletes: uploads and a replacement, one confirm (the replacement is Medium).
    let picks: Vec<String> = compared.rows.iter().map(|r| r.path.clone()).collect();
    let start = core
        .sync
        .sync(SyncRequest {
            comparison: compared.id,
            direction: SyncDirection::ToHost,
            paths: picks.clone(),
            delete: false,
        })
        .await
        .unwrap();
    let SyncStart::Submitted { outcome } = start else {
        panic!("submitted")
    };
    let (_, status, tier, asked) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(asked.unwrap().action, ActionKind::FileReplace);
    assert_eq!(server.sftp_file("/home/alice/www/old.html").unwrap(), b"new and longer");
    assert_eq!(server.sftp_file("/home/alice/www/css/main.css").unwrap(), b"p{}");
    assert!(
        server.sftp_file("/home/alice/www/extra.html").is_some(),
        "nothing deleted unasked"
    );

    // With deletes: High, and what only the host had is gone (the folder with what is in it).
    let compared = core.sync.compare(compare(false)).await.unwrap();
    let picks: Vec<String> = compared.rows.iter().map(|r| r.path.clone()).collect();
    assert_eq!(compared.counts.only_there, 3, "extra.html, gone, gone/x.txt");
    let start = core
        .sync
        .sync(SyncRequest {
            comparison: compared.id,
            direction: SyncDirection::ToHost,
            paths: picks,
            delete: true,
        })
        .await
        .unwrap();
    let SyncStart::Submitted { outcome } = start else {
        panic!("submitted")
    };
    let (job, status, tier, asked) = run(&core, outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::High));
    let asked = asked.unwrap();
    assert_eq!(asked.action, ActionKind::FileSyncDelete);
    assert_eq!(asked.upload.as_ref().unwrap().delete, vec!["extra.html", "gone"]);
    assert!(server.sftp_file("/home/alice/www/extra.html").is_none());
    assert!(!server.sftp_path("/home/alice/www/gone").exists());
    assert!(
        server.sftp_file("/home/alice/www/.git/HEAD").is_some(),
        "Git's data is left alone"
    );
    let deleted: Vec<_> = core
        .store
        .recent_audit(&core.ctx(), 500)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "file_changed" && e.job_id.as_deref() == Some(&job.to_string()))
        .collect();
    assert_eq!(deleted.len(), 2, "each delete audited");

    // A path that isn't a row of the comparison is refused.
    let err = core
        .sync
        .sync(SyncRequest {
            comparison: compared.id,
            direction: SyncDirection::ToHost,
            paths: vec!["../etc/passwd".into()],
            delete: true,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not part of that comparison"), "{err}");
    std::fs::remove_dir_all(&here).unwrap();
}

#[tokio::test]
async fn a_sync_to_this_pc_downloads_and_never_deletes_here() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/conf/app.conf", b"from the host, longer")
        .with_sftp_file("/home/alice/conf/sub/new.conf", b"new");
    let (core, t, _) = pane(&server, &pw).await;
    let here = temp_folder("files-page-pull");
    std::fs::write(here.join("app.conf"), b"short").unwrap();
    std::fs::write(here.join("mine.txt"), b"only here").unwrap();
    let listing = list_here(&core, &here);
    let compared = core
        .sync
        .compare(CompareRequest {
            terminal_id: t,
            listing: listing.id,
            host_folder: "/home/alice/conf".into(),
            contents: false,
            as_root: false,
        })
        .await
        .unwrap();
    let picks: Vec<String> = compared.rows.iter().map(|r| r.path.clone()).collect();
    let start = core
        .sync
        .sync(SyncRequest {
            comparison: compared.id,
            direction: SyncDirection::ToPc,
            paths: picks,
            delete: true,
        })
        .await
        .unwrap();
    let SyncStart::Downloads {
        start: DownloadStart::Queued { transfers, .. },
    } = start
    else {
        panic!("downloads queued")
    };
    let done = wait_done(&core, &transfers.iter().map(|t| t.id).collect::<Vec<_>>()).await;
    assert!(done.iter().all(|t| t.state == TransferState::Done), "{done:?}");
    assert_eq!(std::fs::read(here.join("app.conf")).unwrap(), b"from the host, longer");
    assert_eq!(std::fs::read(here.join("sub").join("new.conf")).unwrap(), b"new");
    assert_eq!(
        std::fs::read(here.join("mine.txt")).unwrap(),
        b"only here",
        "nothing here is deleted"
    );
    std::fs::remove_dir_all(&here).unwrap();
}

// ---- BX-10: many hosts -----------------------------------------------------------------------------------------

#[tokio::test]
async fn pushing_to_many_hosts_checks_each_copy_and_is_high_from_five() {
    let pw = password();
    // Five hosts of their own, each with the folder.
    let mut servers = Vec::new();
    for _ in 0..5 {
        servers.push(
            TestSshServer::start()
                .await
                .with_password("alice", &pw)
                .with_sftp_dir("/home/alice/app"),
        );
    }
    let (core, login) = core_for(&servers[0], &pw).await;
    let mut hosts = Vec::new();
    for (n, server) in servers.iter().enumerate() {
        let key = HostKey {
            host: "127.0.0.1".into(),
            port: server.port(),
            key_type: "ssh-ed25519".into(),
            fingerprint: server.host_key_fingerprint(),
        };
        core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
        // AP-06: a vault password goes to one new place without asking, so each host has its own item.
        let login = if n == 0 {
            login
        } else {
            core.vault
                .add(
                    &core.ctx(),
                    SecretKind::Password,
                    &format!("alice login {n}"),
                    SecretString::new(&pw),
                )
                .await
                .unwrap()
                .id
        };
        hosts.push(session(&core, server, login, &format!("web0{}", n + 1), Environment::Lab).await);
    }
    let server = &servers[0];
    let here = temp_folder("files-page-push");
    let body = b"listen 8080\n";
    std::fs::write(here.join("app.conf"), body).unwrap();
    let paths = vec![here.join("app.conf")];

    // Two hosts: Medium, one confirm.
    let picks = TargetPicks {
        session_ids: hosts[..2].to_vec(),
        ..Default::default()
    };
    let started = core
        .bulk_files
        .push(&picks, paths.clone(), "/home/alice/app", false, false)
        .await
        .unwrap();
    assert_eq!(started.resolved.hosts.len(), 2);
    let (job, status, tier, asked) = run(&core, started.outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(asked.unwrap().action, ActionKind::FilePush);
    assert_eq!(server.sftp_file("/home/alice/app/app.conf").unwrap(), body);
    let results = core
        .bulk
        .results(&core.ctx(), job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(
        results.groups.len(),
        1,
        "both hosts got the same bytes: {:?}",
        results.groups
    );
    let out = results.groups[0].stdout.clone().unwrap();
    assert!(
        out.contains(&sha(body)) && out.contains("the host's copy matches"),
        "{out}"
    );

    assert!(
        servers[2].sftp_file("/home/alice/app/app.conf").is_none(),
        "only the picked hosts"
    );

    // Five hosts: the bulk tier. The first two have the file now, so without replacing they fail alike, and the
    // results show two groups: the hosts that got it, and those that had one.
    let picks = TargetPicks {
        session_ids: hosts.clone(),
        ..Default::default()
    };
    let started = core
        .bulk_files
        .push(&picks, paths.clone(), "/home/alice/app", false, false)
        .await
        .unwrap();
    let (job, status, tier, asked) = run(&core, started.outcome).await;
    assert_eq!(tier, Tier::High);
    assert!(asked.unwrap().reasons.iter().any(|r| r.contains("5 or more hosts")));
    assert_eq!(status, JobStatus::PartiallyFailed);
    let results = core
        .bulk
        .results(&core.ctx(), job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.groups.len(), 2, "{:?}", results.groups);
    assert_eq!(results.groups[0].hosts.len(), 3);
    // With replacing, every host gets the same bytes again.
    let started = core
        .bulk_files
        .push(&picks, paths.clone(), "/home/alice/app", true, false)
        .await
        .unwrap();
    let (_, status, _, _) = run(&core, started.outcome).await;
    assert_eq!(status, JobStatus::Succeeded);
    for s in &servers {
        assert_eq!(s.sftp_file("/home/alice/app/app.conf").unwrap(), body);
    }

    // A push never names a folder, and the bus never takes one from the window.
    std::fs::create_dir_all(here.join("dir")).unwrap();
    assert!(core
        .bulk_files
        .push(&picks, vec![here.join("dir")], "/home/alice/app", false, false)
        .await
        .is_err());
    std::fs::remove_dir_all(&here).unwrap();
}

#[tokio::test]
async fn fetching_from_many_hosts_saves_each_file_and_groups_by_content() {
    let pw = password();
    let server = TestSshServer::start()
        .await
        .with_password("alice", &pw)
        .with_sftp_file("/home/alice/etc/motd", b"Welcome\n");
    let (core, login) = core_for(&server, &pw).await;
    let web01 = session(&core, &server, login, "web01", Environment::Lab).await;
    let web02 = session(&core, &server, login, "web02", Environment::Prod).await;
    let here = temp_folder("files-page-fetch");

    let picks = TargetPicks {
        session_ids: vec![web01],
        ..Default::default()
    };
    let started = core
        .bulk_files
        .fetch(&picks, "/home/alice/etc/motd", &here, false)
        .await
        .unwrap();
    let (_, status, tier, asked) = run(&core, started.outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Low));
    assert!(asked.is_none(), "a fetch from a Lab host runs without asking");

    // A Prod host makes it Medium; both hosts' files land in folders of their own, grouped as one.
    let picks = TargetPicks {
        session_ids: vec![web01, web02],
        ..Default::default()
    };
    let started = core
        .bulk_files
        .fetch(&picks, "/home/alice/etc/motd", &here, false)
        .await
        .unwrap();
    let (job, status, tier, asked) = run(&core, started.outcome).await;
    assert_eq!((status, tier), (JobStatus::Succeeded, Tier::Medium));
    assert_eq!(asked.unwrap().action, ActionKind::FileFetch);
    assert_eq!(
        std::fs::read(here.join("web01").join("motd (1)")).unwrap(),
        b"Welcome\n"
    );
    assert_eq!(std::fs::read(here.join("web02").join("motd")).unwrap(), b"Welcome\n");
    let results = core
        .bulk
        .results(&core.ctx(), job, GroupOptions::default())
        .await
        .unwrap();
    assert_eq!(results.groups.len(), 1);
    let out = results.groups[0].stdout.clone().unwrap();
    assert!(out.starts_with(&format!("SHA-256 {}", sha(b"Welcome\n"))), "{out}");
    assert!(out.contains("Welcome"), "the text is the output, for the diff: {out}");
    let audited = core
        .store
        .recent_audit(&core.ctx(), 500)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "file_downloaded")
        .count();
    assert_eq!(audited, 3, "every fetched file is an audited download");
    // A missing file fails that host; a folder of a Git working tree is refused before anything runs.
    let started = core
        .bulk_files
        .fetch(&picks, "/home/alice/etc/nope", &here, false)
        .await
        .unwrap();
    let (_, status, _, _) = run(&core, started.outcome).await;
    assert_eq!(status, JobStatus::Failed);
    std::fs::create_dir_all(here.join("repo/.git")).unwrap();
    assert!(core
        .bulk_files
        .fetch(&picks, "/home/alice/etc/motd", &here.join("repo"), false)
        .await
        .is_err());
    std::fs::remove_dir_all(&here).unwrap();
}
