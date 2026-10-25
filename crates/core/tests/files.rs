//! Post-MVP P7, SS-08: file transfer in the terminal, end to end.
//!
//! * With the fake remote adapter and its in-memory files: uploads through the command bus (tiers,
//!   the overwrite question, Prod), protected folders, cancel, retry, downloads and their audit.
//! * With the real russh adapter against `fakes::ssh_server` on 127.0.0.1: SFTP on the terminal's own
//!   connection (no second login), a host without SFTP, and the invisible OSC 7 prompt hook for bash.
//! * QL-09: the drawer after a folder it can't open (Up, typed paths, Home, Back), the user transfers
//!   run as, the hook's user report staying invisible, and a shell that stops reporting after `su`.
//!
//! No real host is contacted; test data uses alice, example.com names and files made at run time in the
//! system temp folder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, Setup};
use remotely_core::adapters::remote::{AgentSource, EntryKind, PtySize};
use remotely_core::command_bus::{ApprovalAnswers, SubmitOutcome};
use remotely_core::domain::Environment;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeFiles, FakeRemote, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::known_hosts::HostKey;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::AuditEntry;
use remotely_core::terminal::files::{Existing, Retried, TransferInfo, TransferState, UploadStart};
use remotely_core::terminal::folder::FolderTracking;
use remotely_core::terminal::shell_user::{ShellUser, UserInfo, UserSource};
use remotely_core::terminal::{TerminalEvent, TerminalHandle, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn tuning() -> TerminalTuning {
    TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 5,
        keepalive_interval: None,
        keepalive_max: 2,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    }
}

async fn audit(core: &Core) -> Vec<AuditEntry> {
    core.store.recent_audit(&core.ctx, 300).await.unwrap()
}

/// A local file with this content, in a fresh temp folder.
fn local_file(name: &str, content: &[u8]) -> PathBuf {
    let path = temp_folder("upload").join(name);
    std::fs::write(&path, content).unwrap();
    path
}

/// Bytes that are not all alike, so a mixed-up chunk would show.
fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

// ---- With the fake remote adapter ------------------------------------------------------------------

struct Fake {
    core: Core,
    files: FakeFiles,
}

async fn fake(files: FakeFiles, environment: Environment) -> (Fake, Uuid) {
    let remote = FakeRemote::default().with_files(files.clone());
    let core = Setup::new(FakeVmware::default())
        .with_remote(Arc::new(remote))
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    let session = core
        .sessions
        .create(
            &core.ctx,
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "web01.example.com".into(),
                port: 22,
                username: Some("alice".into()),
                auth: SessionAuth::Agent,
                jump_session_id: None,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id;
    let handle = core.terminals.open(&core.ctx, session, SIZE).await.unwrap();
    let id = handle.id;
    wait_ready(&core, handle).await;
    (Fake { core, files }, id)
}

/// Waits until the terminal is connected and knows how it follows its folder; keeps draining it.
async fn wait_ready(core: &Core, handle: TerminalHandle) {
    let TerminalHandle {
        id,
        mut output,
        mut events,
    } = handle;
    timeout(WAIT, async {
        loop {
            match core.terminals.folder(id) {
                Some(folder) if folder.tracking != FolderTracking::Waiting => break,
                _ => {}
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

impl Fake {
    async fn start(&self, terminal: Uuid, path: &Path, folder: &str, existing: Existing) -> UploadStart {
        let staged = self.core.files.stage(vec![path.to_owned()]).unwrap();
        self.core
            .files
            .upload(terminal, staged.id, folder, existing)
            .await
            .unwrap()
    }

    /// Submits the upload and waits for its job (approving a confirm when asked).
    async fn upload(&self, terminal: Uuid, path: &Path, folder: &str, existing: Existing) -> JobStatus {
        let start = self.start(terminal, path, folder, existing).await;
        self.finish(start).await
    }

    async fn finish(&self, start: UploadStart) -> JobStatus {
        let UploadStart::Submitted { outcome } = start else {
            panic!("not submitted: {start:?}");
        };
        let job = match outcome {
            SubmitOutcome::Queued { job_id, .. } => job_id,
            SubmitOutcome::NeedsApproval { request } => self
                .core
                .bus
                .approve(
                    request.id,
                    ApprovalAnswers {
                        confirmed: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        };
        timeout(WAIT, self.core.jobs.wait(job)).await.unwrap().unwrap()
    }

    fn transfer(&self, name: &str) -> TransferInfo {
        self.core
            .terminals
            .transfers()
            .into_iter()
            .rev()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("no transfer of {name}"))
    }

    async fn wait_transfer(&self, id: Uuid) -> TransferInfo {
        timeout(WAIT, async {
            loop {
                let found = self
                    .core
                    .terminals
                    .transfers()
                    .into_iter()
                    .find(|t| t.id == id)
                    .unwrap();
                if !matches!(found.state, TransferState::Queued | TransferState::Running) {
                    return found;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the transfer finished")
    }
}

#[tokio::test]
async fn a_new_file_uploads_without_asking_and_is_audited_with_its_hash() {
    let (t, terminal) = fake(FakeFiles::default(), Environment::Lab).await;
    let body = content(600 * 1024);
    let path = local_file("site.tar.gz", &body);
    let start = t.start(terminal, &path, "/srv", Existing::Ask).await;
    let UploadStart::Submitted {
        outcome: SubmitOutcome::Queued { tier, summary, .. },
    } = &start
    else {
        panic!("a new file is Low: {start:?}");
    };
    assert_eq!(*tier, Tier::Low);
    assert_eq!(summary, "Upload 'site.tar.gz' (614 KB) to /srv");
    assert_eq!(t.finish(start).await, JobStatus::Succeeded);
    assert_eq!(t.files.file("/srv/site.tar.gz").unwrap(), body);

    let transfer = t.transfer("site.tar.gz");
    assert_eq!(transfer.state, TransferState::Done);
    assert_eq!(transfer.done, body.len() as u64);
    assert_eq!(transfer.sha256.as_deref(), Some(sha(&body).as_str()));
    assert_eq!(transfer.remote_path, "/srv/site.tar.gz");
    assert!(!transfer.replace);

    let entries = audit(&t.core).await;
    let uploaded = entries.iter().find(|e| e.event == "file_uploaded").expect("audited");
    assert_eq!(uploaded.action, "Uploaded 'site.tar.gz' to /srv on 'web01'");
    let detail = uploaded.detail.as_deref().unwrap();
    assert!(detail.contains(&format!("{} bytes", body.len())), "{detail}");
    assert!(detail.contains(&sha(&body)), "{detail}");
    assert!(detail.contains("/srv/site.tar.gz"), "{detail}");
    assert_eq!(uploaded.tier.as_deref(), Some("low"));
    let finished = entries.iter().find(|e| e.event == "job_finished").unwrap();
    assert!(
        finished
            .detail
            .as_deref()
            .unwrap()
            .contains("uploaded to /srv: site.tar.gz"),
        "{finished:?}"
    );
}

#[tokio::test]
async fn a_file_that_is_there_is_replaced_only_after_asking() {
    let files = FakeFiles::default().with_file("/srv/index.html", b"old page");
    let (t, terminal) = fake(files, Environment::Lab).await;
    let path = local_file("index.html", b"new page");

    // Asked first: nothing is submitted.
    let start = t.start(terminal, &path, "/srv", Existing::Ask).await;
    let UploadStart::Conflicts { existing, folder } = start else {
        panic!("no question: {start:?}");
    };
    assert_eq!(existing, ["index.html"]);
    assert_eq!(folder, "/srv");
    assert_eq!(t.files.file("/srv/index.html").unwrap(), b"old page");

    // Skipping the only file leaves nothing to do.
    let start = t.start(terminal, &path, "/srv", Existing::Skip).await;
    assert!(matches!(start, UploadStart::Nothing), "{start:?}");

    // Replacing needs the approval dialog's confirm, which shows the file it replaces.
    let start = t.start(terminal, &path, "/srv", Existing::Replace).await;
    let UploadStart::Submitted {
        outcome: SubmitOutcome::NeedsApproval { request },
    } = &start
    else {
        panic!("replacing asks: {start:?}");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.steps, vec![ApprovalStep::Confirm]);
    let upload = request.upload.as_ref().unwrap();
    assert_eq!(upload.folder, "/srv");
    assert!(upload.files[0].replace);
    assert!(
        request.summary.ends_with("replacing the file there"),
        "{}",
        request.summary
    );
    assert_eq!(t.finish(start).await, JobStatus::Succeeded);
    assert_eq!(t.files.file("/srv/index.html").unwrap(), b"new page");
    assert!(t.transfer("index.html").replace);
    let entries = audit(&t.core).await;
    let uploaded = entries.iter().find(|e| e.event == "file_uploaded").unwrap();
    assert!(uploaded
        .detail
        .as_deref()
        .unwrap()
        .ends_with("replacing the file there"));
}

#[tokio::test]
async fn a_prod_terminal_raises_an_upload_one_tier() {
    let files = FakeFiles::default().with_file("/srv/app.conf", b"old");
    let (t, terminal) = fake(files, Environment::Prod).await;
    let new = local_file("new.conf", b"x=1");
    let start = t.start(terminal, &new, "/srv", Existing::Ask).await;
    let UploadStart::Submitted {
        outcome: SubmitOutcome::NeedsApproval { request },
    } = &start
    else {
        panic!("Prod asks: {start:?}");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert!(
        request.reasons.iter().any(|r| r.contains("Prod")),
        "{:?}",
        request.reasons
    );
    assert_eq!(t.finish(start).await, JobStatus::Succeeded);

    let replace = local_file("app.conf", b"x=2");
    let start = t.start(terminal, &replace, "/srv", Existing::Replace).await;
    let UploadStart::Submitted {
        outcome: SubmitOutcome::NeedsApproval { request },
    } = start
    else {
        panic!("replacing on Prod asks");
    };
    assert_eq!(request.tier, Tier::High);
    assert!(request.steps.contains(&ApprovalStep::Reason));
    t.core.bus.cancel_approval(request.id).await.unwrap();
    assert_eq!(t.files.file("/srv/app.conf").unwrap(), b"old");
}

#[tokio::test]
async fn a_protected_folder_fails_with_a_clear_message_and_leaves_nothing() {
    let (t, terminal) = fake(FakeFiles::default(), Environment::Lab).await;
    let path = local_file("hosts", b"192.0.2.10 web01.example.com\n");
    assert_eq!(
        t.upload(terminal, &path, "/etc", Existing::Ask).await,
        JobStatus::Failed
    );
    let transfer = t.transfer("hosts");
    assert_eq!(transfer.state, TransferState::Failed);
    let message = transfer.message.unwrap();
    assert!(message.contains("alice can't write to /etc/hosts"), "{message}");
    assert!(t.files.file("/etc/hosts").is_none());
    assert!(!audit(&t.core).await.iter().any(|e| e.event == "file_uploaded"));
}

#[tokio::test]
async fn an_upload_can_be_cancelled_part_way_and_leaves_no_partial_file() {
    let files = FakeFiles::default().with_delay(Duration::from_millis(40));
    let (t, terminal) = fake(files, Environment::Lab).await;
    let path = local_file("big.iso", &content(4 * 1024 * 1024));
    let start = t.start(terminal, &path, "/tmp", Existing::Ask).await;
    let core = &t.core;
    // Cancel once some of it went up.
    let id = timeout(WAIT, async {
        loop {
            if let Some(found) = core.terminals.transfers().into_iter().find(|x| x.name == "big.iso") {
                if found.done > 0 {
                    return found.id;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the upload started");
    assert!(core.terminals.cancel_transfer(id));
    let status = t.finish(start).await;
    assert_eq!(status, JobStatus::Succeeded, "cancelling a file is not a failure");
    let transfer = t.wait_transfer(id).await;
    assert_eq!(transfer.state, TransferState::Cancelled);
    assert!(transfer.message.unwrap().contains("nothing was left"));
    assert!(t.files.file("/tmp/big.iso").is_none(), "the partial file was deleted");
    assert!(!core.terminals.cancel_transfer(id), "nothing left to cancel");
}

#[tokio::test]
async fn a_failed_upload_can_be_retried() {
    let (t, terminal) = fake(FakeFiles::default(), Environment::Lab).await;
    let body = content(900 * 1024);
    let path = local_file("backup.sql", &body);
    t.files.fail_next_write_after(300 * 1024);
    assert_eq!(
        t.upload(terminal, &path, "/srv", Existing::Ask).await,
        JobStatus::Failed
    );
    let failed = t.transfer("backup.sql");
    assert_eq!(failed.state, TransferState::Failed);
    assert!(
        t.files.file("/srv/backup.sql").is_none(),
        "the half-written file was deleted"
    );

    let Retried::Upload { start } = t.core.files.retry(failed.id).await.unwrap() else {
        panic!("an upload is retried as an upload");
    };
    assert_eq!(t.finish(start).await, JobStatus::Succeeded);
    assert_eq!(t.files.file("/srv/backup.sql").unwrap(), body);
    let again = t.transfer("backup.sql");
    assert_ne!(again.id, failed.id);
    assert_eq!(again.state, TransferState::Done);
}

#[tokio::test]
async fn downloads_are_audited_and_never_overwrite_a_file_here() {
    let body = content(300 * 1024);
    let files = FakeFiles::default().with_file("/home/alice/report.pdf", &body);
    let (t, terminal) = fake(files, Environment::Lab).await;
    let dest = temp_folder("download");
    std::fs::write(dest.join("report.pdf"), b"mine").unwrap();

    // Relative to the folder (the home folder: this shell does not report one).
    let queued = t
        .core
        .terminals
        .download(&t.core.ctx, terminal, &["report.pdf".into()], &dest)
        .await
        .unwrap();
    assert_eq!(queued[0].remote_path, "/home/alice/report.pdf");
    let done = t.wait_transfer(queued[0].id).await;
    assert_eq!(done.state, TransferState::Done);
    assert_eq!(done.sha256.as_deref(), Some(sha(&body).as_str()));
    let saved = PathBuf::from(done.local_path.clone().unwrap());
    assert_eq!(saved, dest.join("report (1).pdf"));
    assert_eq!(std::fs::read(&saved).unwrap(), body);
    assert_eq!(std::fs::read(dest.join("report.pdf")).unwrap(), b"mine");
    assert_eq!(t.core.files.saved_at(done.id), Some(saved.clone()));
    // A8: marked as from the internet, as a browser marks a download, with no host name in the mark.
    #[cfg(windows)]
    {
        assert_eq!(
            zone_identifier(&saved).as_deref(),
            Some("[ZoneTransfer]\r\nZoneId=3\r\n")
        );
        assert_eq!(done.message, None, "marked, so nothing to say");
        assert_eq!(
            zone_identifier(&dest.join("report.pdf")),
            None,
            "the file that was here is left alone"
        );
    }

    let entries = audit(&t.core).await;
    let entry = entries.iter().find(|e| e.event == "file_downloaded").expect("audited");
    assert_eq!(entry.action, "Downloaded 'report.pdf' from 'web01'");
    let detail = entry.detail.as_deref().unwrap();
    assert!(detail.contains("/home/alice/report.pdf"), "{detail}");
    assert!(detail.contains(&sha(&body)), "{detail}");
    assert!(detail.contains(&saved.display().to_string()), "{detail}");
    assert!(detail.contains(&format!("{} bytes", body.len())), "{detail}");

    // A folder is not downloaded, and a missing file says so.
    let err = t
        .core
        .terminals
        .download(&t.core.ctx, terminal, &["/srv".into()], &dest)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("is a folder"), "{err}");
    let err = t
        .core
        .terminals
        .download(&t.core.ctx, terminal, &["nope.txt".into()], &dest)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "not_found");

    // Retried, it goes to the same folder again.
    let Retried::Download { transfers } = t.core.files.retry(done.id).await.unwrap() else {
        panic!("a download is retried as a download");
    };
    let again = t.wait_transfer(transfers[0].id).await;
    assert_eq!(PathBuf::from(again.local_path.unwrap()), dest.join("report (2).pdf"));
    std::fs::remove_dir_all(&dest).unwrap();
}

/// A8: the Mark of the Web a download got: its `Zone.Identifier` stream, if any.
#[cfg(windows)]
fn zone_identifier(path: &Path) -> Option<String> {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::read_to_string(PathBuf::from(stream)).ok()
}

#[tokio::test]
async fn a_name_that_hides_its_real_extension_is_saved_plainly_and_marked() {
    // U+202E RIGHT-TO-LEFT OVERRIDE shows this as "invoiceexe.pdf"; a zero-width space and a BOM
    // hide in the other.
    let files = FakeFiles::default()
        .with_file("/home/alice/invoice\u{202E}fdp.exe", b"MZ")
        .with_file("/home/alice/notes\u{200B}\u{FEFF}.txt", b"hi");
    let (t, terminal) = fake(files, Environment::Lab).await;
    let dest = temp_folder("download-names");
    let queued = t
        .core
        .terminals
        .download(
            &t.core.ctx,
            terminal,
            &["invoice\u{202E}fdp.exe".into(), "notes\u{200B}\u{FEFF}.txt".into()],
            &dest,
        )
        .await
        .unwrap();
    let first = t.wait_transfer(queued[0].id).await;
    let second = t.wait_transfer(queued[1].id).await;
    assert_eq!(first.state, TransferState::Done);
    assert_eq!(PathBuf::from(first.local_path.unwrap()), dest.join("invoice_fdp.exe"));
    assert_eq!(PathBuf::from(second.local_path.unwrap()), dest.join("notes__.txt"));
    assert_eq!(std::fs::read(dest.join("invoice_fdp.exe")).unwrap(), b"MZ");
    #[cfg(windows)]
    assert_eq!(
        zone_identifier(&dest.join("invoice_fdp.exe")).as_deref(),
        Some("[ZoneTransfer]\r\nZoneId=3\r\n")
    );
    std::fs::remove_dir_all(&dest).unwrap();
}

#[tokio::test]
async fn the_drawer_lists_the_home_folder_when_the_shell_does_not_report_one() {
    let files = FakeFiles::default()
        .with_dir("/home/alice/logs")
        .with_file("/home/alice/notes.txt", b"hello");
    let (t, terminal) = fake(files, Environment::Lab).await;
    let folder = t.core.terminals.folder(terminal).unwrap();
    assert_eq!(folder.tracking, FolderTracking::Unsupported);
    assert_eq!(folder.path, None);
    let listing = t.core.terminals.list_folder(terminal, None).await.unwrap();
    assert_eq!(listing.path, "/home/alice");
    assert_eq!(listing.parent.as_deref(), Some("/home"));
    let names: Vec<(&str, EntryKind)> = listing.entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(names, [("logs", EntryKind::Folder), ("notes.txt", EntryKind::File)]);
    let up = t.core.terminals.list_folder(terminal, Some("..")).await.unwrap();
    assert_eq!(up.path, "/home");
    let (path, entry) = t
        .core
        .terminals
        .look_up(terminal, "~/notes.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(path, "/home/alice/notes.txt");
    assert_eq!(entry.size, 5);
    assert!(t.core.terminals.look_up(terminal, "missing").await.unwrap().is_none());
}

#[tokio::test]
async fn folders_and_two_files_of_one_name_are_not_staged() {
    let (t, _) = fake(FakeFiles::default(), Environment::Lab).await;
    let folder = temp_folder("stage");
    let err = t.core.files.stage(vec![folder.clone()]).unwrap_err();
    assert!(err.to_string().contains("is a folder"), "{err}");
    let a = local_file("same.txt", b"a");
    let b = local_file("same.txt", b"b");
    let err = t.core.files.stage(vec![a, b]).unwrap_err();
    assert!(err.to_string().contains("Two files are named 'same.txt'"), "{err}");
}

// ---- With the real russh adapter and the test SSH server ---------------------------------------------

async fn ssh_core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(tuning());
    core
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

async fn ssh_session(core: &Core, server: &TestSshServer, password: &str, startup: Option<&str>) -> Uuid {
    let login = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            "alice login",
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    core.sessions
        .create(
            &core.ctx,
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
                startup_command: startup.map(str::to_owned),
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id
}

/// A pane under test: everything it printed, and every event.
struct Pane {
    id: Uuid,
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    events: tokio::sync::mpsc::Receiver<TerminalEvent>,
    printed: Vec<u8>,
    seen: Vec<TerminalEvent>,
}

impl Pane {
    async fn open(core: &Core, session: Uuid) -> Self {
        let handle = core.terminals.open(&core.ctx, session, SIZE).await.unwrap();
        let mut pane = Self {
            id: handle.id,
            output: handle.output,
            events: handle.events,
            printed: Vec::new(),
            seen: Vec::new(),
        };
        pane.until(|p| {
            p.seen
                .iter()
                .any(|e| matches!(e, TerminalEvent::Status { status } if *status == TerminalStatus::Connected))
        })
        .await;
        pane
    }

    /// Reads output and events until `done` says so.
    async fn until(&mut self, mut done: impl FnMut(&Self) -> bool) {
        let ok = timeout(WAIT, async {
            while !done(self) {
                tokio::select! {
                    Some(chunk) = self.output.recv() => self.printed.extend_from_slice(&chunk),
                    Some(event) = self.events.recv() => self.seen.push(event),
                }
            }
        })
        .await;
        assert!(
            ok.is_ok(),
            "timed out; printed {:?}, events {:?}",
            self.text(),
            self.seen
        );
    }

    /// Keeps reading for a while.
    async fn settle(&mut self, how_long: Duration) {
        let _ = timeout(how_long, async {
            loop {
                tokio::select! {
                    Some(chunk) = self.output.recv() => self.printed.extend_from_slice(&chunk),
                    Some(event) = self.events.recv() => self.seen.push(event),
                }
            }
        })
        .await;
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.printed).into_owned()
    }

    fn folder(&self) -> Option<(Option<String>, FolderTracking)> {
        self.seen.iter().rev().find_map(|e| match e {
            TerminalEvent::Folder { folder } => Some((folder.path.clone(), folder.tracking)),
            _ => None,
        })
    }

    /// QL-09: who transfers and the shell run as, as last reported.
    fn user(&self) -> Option<UserInfo> {
        self.seen.iter().rev().find_map(|e| match e {
            TerminalEvent::Folder { folder } => Some(folder.user.clone()),
            _ => None,
        })
    }

    /// What the terminal shows: the output without escape sequences (OSC strings included).
    fn visible(&self) -> String {
        visible_text(&self.printed)
    }
}

/// Output as a terminal draws it, roughly: CSI and OSC/DCS sequences dropped.
fn visible_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            Some(']' | 'P' | '_' | '^' | 'X') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[tokio::test]
async fn sftp_runs_on_the_terminals_own_connection() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let body = content(700 * 1024);
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_sftp_file("/home/alice/data.csv", &body);
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let mut pane = Pane::open(&core, session).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t != FolderTracking::Waiting))
        .await;
    assert_eq!(
        pane.folder().unwrap().1,
        FolderTracking::Unsupported,
        "the toy is not bash"
    );

    let listing = core.terminals.list_folder(pane.id, None).await.unwrap();
    assert_eq!(listing.path, "/home/alice");
    assert!(listing
        .entries
        .iter()
        .any(|e| e.name == "data.csv" && e.size == body.len() as u64));

    // Down...
    let dest = temp_folder("sftp-down");
    let queued = core
        .terminals
        .download(&core.ctx, pane.id, &["data.csv".into()], &dest)
        .await
        .unwrap();
    let done = timeout(WAIT, async {
        loop {
            let t = core
                .terminals
                .transfers()
                .into_iter()
                .find(|t| t.id == queued[0].id)
                .unwrap();
            if t.state != TransferState::Queued && t.state != TransferState::Running {
                return t;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(done.state, TransferState::Done, "{:?}", done.message);
    assert_eq!(std::fs::read(dest.join("data.csv")).unwrap(), body);

    // ...and up, through the bus.
    let up = local_file("upload.bin", &body[..100_000]);
    let staged = core.files.stage(vec![up]).unwrap();
    let start = core
        .files
        .upload(pane.id, staged.id, "/srv", Existing::Ask)
        .await
        .unwrap();
    let UploadStart::Submitted {
        outcome: SubmitOutcome::Queued { job_id, .. },
    } = start
    else {
        panic!("{start:?}");
    };
    assert_eq!(core.jobs.wait(job_id).await.unwrap(), JobStatus::Succeeded);
    assert_eq!(server.sftp_file("/srv/upload.bin").unwrap(), &body[..100_000]);

    // A protected folder: the host's refusal, with what to do instead.
    let staged = core.files.stage(vec![local_file("motd", b"hi")]).unwrap();
    let UploadStart::Submitted {
        outcome: SubmitOutcome::Queued { job_id, .. },
    } = core
        .files
        .upload(pane.id, staged.id, "/etc", Existing::Ask)
        .await
        .unwrap()
    else {
        panic!("a new file is Low");
    };
    assert_eq!(core.jobs.wait(job_id).await.unwrap(), JobStatus::Failed);
    let failed = core
        .terminals
        .transfers()
        .into_iter()
        .find(|t| t.name == "motd")
        .unwrap();
    let message = failed.message.unwrap();
    assert!(message.contains("alice can't write to /etc/motd"), "{message}");
    assert!(message.contains("never uses sudo"), "{message}");

    assert_eq!(server.connections(), 1, "no second login for SFTP");
    let log = server.log();
    assert_eq!(
        log.iter().filter(|l| l.starts_with("password alice")).count(),
        1,
        "{log:?}"
    );
    assert!(log.contains(&"subsystem sftp".to_owned()), "{log:?}");
    std::fs::remove_dir_all(&dest).unwrap();
}

#[tokio::test]
async fn a_host_without_sftp_says_so() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .without_sftp();
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let pane = Pane::open(&core, session).await;
    let err = core.terminals.list_folder(pane.id, None).await.unwrap_err();
    assert_eq!(err.code(), "sftp");
    assert!(err.to_string().contains("no SFTP server"), "{err}");
}

#[tokio::test]
async fn bash_reports_its_folder_through_a_hook_nobody_sees() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_login_shell("bash")
        .with_sftp_dir("/srv/www")
        .with_sftp_file("/srv/www/index.html", b"<h1>hi</h1>");
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let log_file = temp_folder("hook-log").join("web01.log");
    let mut pane = Pane::open(&core, session).await;
    core.terminals.start_log(&core.ctx, pane.id, &log_file).await.unwrap();
    pane.until(|p| p.folder().is_some_and(|(_, t)| t == FolderTracking::Following))
        .await;
    assert_eq!(pane.folder().unwrap().0.as_deref(), Some("/home/alice"));

    // The user's own command: the folder follows.
    core.terminals.write(pane.id, b"cd /srv/www\r".to_vec()).await;
    pane.until(|p| p.folder().is_some_and(|(path, _)| path.as_deref() == Some("/srv/www")))
        .await;
    let listing = core.terminals.list_folder(pane.id, None).await.unwrap();
    assert_eq!(listing.path, "/srv/www");
    assert_eq!(listing.entries[0].name, "index.html");
    // A file name from the output resolves from there.
    let (path, _) = core.terminals.look_up(pane.id, "index.html").await.unwrap().unwrap();
    assert_eq!(path, "/srv/www/index.html");
    pane.settle(Duration::from_millis(200)).await;

    // The hook never showed: not in the terminal, its log, or what MultiExec sees of the line. Its
    // marker never reached the terminal; the user report (QL-09) does, as an OSC that draws nothing.
    let text = pane.text();
    assert!(!text.contains("__remotely"), "{text:?}");
    assert_eq!(
        text.matches("\x1b]7777;").count(),
        text.matches("\x1b]7777;remotely-user=alice\x07").count(),
        "only user reports, never the marker: {text:?}"
    );
    assert!(!pane.visible().contains("remotely"), "{:?}", pane.visible());
    let info = core.terminals.pane_info(pane.id).unwrap();
    assert_eq!(info.screen.line, "$ ");
    assert!(!info.dirty);
    assert!(
        !pane
            .seen
            .iter()
            .any(|e| matches!(e, TerminalEvent::CommandFinished { .. })),
        "the hook is no command run"
    );
    // The old prompt was erased before the new one was drawn over it.
    assert!(
        text.contains(
            "Welcome, alice\r\n$ \r\x1b[2K\x1b]7;file://test-host/home/alice\x1b\\\x1b]7777;remotely-user=alice\x07$ "
        ),
        "{text:?}"
    );
    core.terminals.stop_log(&core.ctx, pane.id).await.unwrap();
    let logged = std::fs::read_to_string(&log_file).unwrap();
    assert!(!logged.contains("__remotely"), "{logged}");
    assert!(!logged.contains("remotely-user"), "{logged}");
    assert!(logged.contains("cd /srv/www"), "{logged}");
    let log = server.log();
    assert_eq!(log.iter().filter(|l| *l == "line [prompt hook]").count(), 1, "{log:?}");
    std::fs::remove_dir_all(log_file.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn the_startup_command_waits_for_the_hook() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_login_shell("zsh")
        .with_sftp_dir("/var/log");
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, Some("cd /var/log")).await;
    let mut pane = Pane::open(&core, session).await;
    pane.until(|p| p.folder().is_some_and(|(path, _)| path.as_deref() == Some("/var/log")))
        .await;
    let lines: Vec<String> = server.log().into_iter().filter(|l| l.starts_with("line ")).collect();
    assert_eq!(lines, ["line [prompt hook]", "line cd /var/log"]);
    assert!(!pane.text().contains("__remotely"));
}

#[tokio::test]
async fn keys_typed_before_the_first_prompt_settles_mean_no_hook() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_login_shell("bash");
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let mut pane = Pane::open(&core, session).await;
    // Typed at once, before the shell's output paused.
    core.terminals.write(pane.id, b"whoami\r".to_vec()).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t != FolderTracking::Waiting))
        .await;
    assert_eq!(pane.folder().unwrap().1, FolderTracking::Missed);
    pane.settle(Duration::from_millis(600)).await;
    assert!(!server.log().iter().any(|l| l == "line [prompt hook]"));
    // The drawer starts at home then.
    let listing = core.terminals.list_folder(pane.id, None).await.unwrap();
    assert_eq!(listing.path, "/home/alice");
}

// ---- QL-09: the drawer after errors, and who transfers run as --------------------------------------

/// A bash login on a host where /home/bob/.app is bob's alone, so alice (the login) can't open it.
async fn bob_host() -> (TestSshServer, Core, Pane) {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_login_shell("bash")
        .with_sftp_file("/home/alice/logs/app.log", b"started\n")
        .with_sftp_file("/home/bob/notes.txt", b"bob's notes\n")
        .with_unreadable("/home/bob/.app")
        .with_sftp_file("/home/bob/.app/conf/app.ini", b"[app]\n");
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let mut pane = Pane::open(&core, session).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t == FolderTracking::Following))
        .await;
    (server, core, pane)
}

#[tokio::test]
async fn a_folder_the_login_cant_open_leaves_the_drawer_working() {
    let (_server, core, mut pane) = bob_host().await;
    let terminals = &core.terminals;
    let home = terminals.open_folder(pane.id, None, None).await.unwrap();
    assert_eq!(home.path, "/home/alice");
    assert_eq!(home.back, None, "nothing opened before");

    // The shell goes where alice can't look, and the drawer follows it there.
    terminals.write(pane.id, b"cd /home/bob/.app\r".to_vec()).await;
    pane.until(|p| {
        p.folder()
            .is_some_and(|(path, _)| path.as_deref() == Some("/home/bob/.app"))
    })
    .await;
    let denied = terminals.open_folder(pane.id, None, None).await.unwrap();
    assert_eq!(
        denied.path, "/home/bob/.app",
        "the path box shows the folder that failed"
    );
    assert_eq!(denied.parent.as_deref(), Some("/home/bob"), "Up goes somewhere");
    assert!(denied.entries.is_empty());
    let error = denied.error.unwrap();
    assert_eq!(error.code, "permission_denied");
    assert!(
        error.message.contains("alice can't open the folder /home/bob/.app"),
        "{}",
        error.message
    );
    assert_eq!(
        denied.back.as_deref(),
        Some("/home/alice"),
        "Back: the last folder that opened"
    );
    // Refresh: the same answer, still readable.
    let again = terminals.open_folder(pane.id, None, None).await.unwrap();
    assert_eq!(again.error.unwrap().code, "permission_denied");

    // Up.
    let up = terminals.open_folder(pane.id, Some("/home/bob"), None).await.unwrap();
    assert!(up.error.is_none(), "{:?}", up.error);
    let names: Vec<&str> = up.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, [".app", "notes.txt"]);
    assert_eq!(up.back.as_deref(), Some("/home/alice"));

    // Typed paths go on from the folder shown, even the one that failed.
    let typed = terminals
        .open_folder(pane.id, Some("../../alice/logs"), Some("/home/bob/.app"))
        .await
        .unwrap();
    assert_eq!(typed.path, "/home/alice/logs");
    assert_eq!(typed.entries[0].name, "app.log");
    let parent = terminals
        .open_folder(pane.id, Some(".."), Some("/home/bob/.app"))
        .await
        .unwrap();
    assert_eq!(parent.path, "/home/bob");
    // Home.
    let home_again = terminals
        .open_folder(pane.id, Some("~"), Some("/home/bob/.app"))
        .await
        .unwrap();
    assert_eq!(home_again.path, "/home/alice");
    // A folder inside the denied one fails the same way, with its own path.
    let inside = terminals
        .open_folder(pane.id, Some("conf"), Some("/home/bob/.app"))
        .await
        .unwrap();
    assert_eq!(inside.path, "/home/bob/.app/conf");
    assert_eq!(inside.error.unwrap().code, "permission_denied");
    assert_eq!(inside.back.as_deref(), Some("/home/alice"));

    // Back, through what opened: /home/alice, /home/bob, /home/alice/logs, /home/bob, /home/alice.
    let back = terminals.folder_back(pane.id, "/home/bob/.app/conf").await.unwrap();
    assert_eq!(back.path, "/home/alice", "from a failed folder: the last that opened");
    assert_eq!(back.back.as_deref(), Some("/home/bob"));
    let back = terminals.folder_back(pane.id, "/home/alice").await.unwrap();
    assert_eq!(back.path, "/home/bob");
    let back = terminals.folder_back(pane.id, "/home/bob").await.unwrap();
    assert_eq!(back.path, "/home/alice/logs");
    let back = terminals.folder_back(pane.id, "/home/alice/logs").await.unwrap();
    assert_eq!(back.path, "/home/bob");
    let back = terminals.folder_back(pane.id, "/home/bob").await.unwrap();
    assert_eq!(back.path, "/home/alice");
    assert_eq!(back.back, None);
    let err = terminals.folder_back(pane.id, "/home/alice").await.unwrap_err();
    assert!(err.to_string().contains("no folder to go back to"), "{err}");
}

#[tokio::test]
async fn the_drawer_says_who_transfers_run_as_and_notices_a_switched_shell() {
    let (_server, core, mut pane) = bob_host().await;
    let log_file = temp_folder("user-log").join("web01.log");
    core.terminals.start_log(&core.ctx, pane.id, &log_file).await.unwrap();
    pane.settle(Duration::from_millis(1000)).await;
    assert_eq!(pane.user(), Some(UserInfo::connected("alice")));

    // `su bob`: a shell without the hook. Its prompt names bob, and no report comes.
    core.terminals.write(pane.id, b"su bob\r".to_vec()).await;
    pane.until(|p| p.user().is_some_and(|u| u.stopped)).await;
    let user = pane.user().unwrap();
    assert_eq!(user.username.as_deref(), Some("alice"), "transfers still run as alice");
    assert_eq!(
        user.shell,
        Some(ShellUser {
            username: "bob".into(),
            seen_in: UserSource::Prompt
        })
    );
    // The drawer keeps alice's view: the last folder the hook reported.
    assert_eq!(pane.folder().unwrap().0.as_deref(), Some("/home/alice"));
    assert_eq!(core.terminals.folder(pane.id).unwrap().user, user);

    // Back to alice's shell: the hook reports again.
    core.terminals.write(pane.id, b"exit\r".to_vec()).await;
    pane.until(|p| p.user().is_some_and(|u| !u.stopped)).await;
    assert_eq!(pane.user(), Some(UserInfo::connected("alice")));

    // `su -`: root, in its own home.
    core.terminals.write(pane.id, b"su -\r".to_vec()).await;
    pane.until(|p| p.user().is_some_and(|u| u.stopped)).await;
    assert_eq!(pane.user().unwrap().shell.unwrap().username, "root");

    // The user report never showed: not on screen, in the log, or on MultiExec's line.
    pane.settle(Duration::from_millis(200)).await;
    let visible = pane.visible();
    assert!(!visible.contains("remotely"), "{visible:?}");
    assert!(visible.contains("bob@test-host:/home/alice$ "), "{visible:?}");
    assert!(visible.contains("root@test-host:~# "), "{visible:?}");
    assert_eq!(
        core.terminals.pane_info(pane.id).unwrap().screen.line,
        "root@test-host:~# "
    );
    core.terminals.stop_log(&core.ctx, pane.id).await.unwrap();
    let logged = std::fs::read_to_string(&log_file).unwrap();
    assert!(!logged.contains("remotely"), "{logged}");
    assert!(logged.contains("su bob"), "{logged}");
    std::fs::remove_dir_all(log_file.parent().unwrap()).unwrap();
}

/// Without the hook (a shell that is not bash or zsh), the prompt is all there is to go on.
#[tokio::test]
async fn without_the_hook_the_drawer_goes_by_the_prompt() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = ssh_core().await;
    trust(&core, &server).await;
    let session = ssh_session(&core, &server, &password, None).await;
    let mut pane = Pane::open(&core, session).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t == FolderTracking::Unsupported))
        .await;
    assert_eq!(pane.user(), Some(UserInfo::connected("alice")));
    core.terminals.write(pane.id, b"su bob\r".to_vec()).await;
    pane.until(|p| p.user().is_some_and(|u| u.shell.is_some())).await;
    let user = pane.user().unwrap();
    assert!(!user.stopped, "only a hook can stop reporting");
    assert_eq!(user.shell.unwrap().username, "bob");
    core.terminals.write(pane.id, b"exit\r".to_vec()).await;
    // The toy's own prompt names nobody, so nothing says bob any more.
    pane.until(|p| p.user().is_some_and(|u| u.shell.is_none())).await;
}

/// A bash session on `server` with its environment and its own prompt hook choice (SS-08).
async fn hook_session(
    core: &Core,
    server: &TestSshServer,
    password: &str,
    name: &str,
    environment: Environment,
    prompt_hook: Option<bool>,
) -> Uuid {
    let login = core
        .vault
        .add(
            &core.ctx,
            SecretKind::Password,
            &format!("{name} login"),
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    core.sessions
        .create(
            &core.ctx,
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
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook,
                environment,
                color: None,
                tags: vec![],
                vm_id: None,
            },
        )
        .await
        .unwrap()
        .id
}

async fn hook_audits(core: &Core) -> usize {
    core.store
        .recent_audit(&core.ctx, 200)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "folder_hook_installed")
        .count()
}

/// SS-08: the hook is off for a Prod session unless the session turns it on, and Settings can turn it
/// off everywhere. Off, nothing is typed and the drawer starts in the home folder. On, it is audited
/// once per connection.
#[tokio::test]
async fn the_prompt_hook_is_off_for_prod_unless_the_session_says_and_audited_once_when_typed() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_login_shell("bash");
    let core = ssh_core().await;
    trust(&core, &server).await;
    let typed = |server: &TestSshServer| server.log().iter().filter(|l| *l == "line [prompt hook]").count();

    // Prod, following Settings: off.
    let prod = hook_session(&core, &server, &password, "prod01", Environment::Prod, None).await;
    let mut pane = Pane::open(&core, prod).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t != FolderTracking::Waiting))
        .await;
    assert_eq!(pane.folder().unwrap().1, FolderTracking::Off);
    pane.settle(Duration::from_millis(600)).await;
    assert_eq!(typed(&server), 0);
    assert_eq!(hook_audits(&core).await, 0);
    let listing = core.terminals.list_folder(pane.id, None).await.unwrap();
    assert_eq!(listing.path, "/home/alice", "the drawer starts at home");
    core.terminals.close(pane.id).await;

    // Prod, but the session turns it on: typed once, audited once.
    let opted = hook_session(&core, &server, &password, "prod02", Environment::Prod, Some(true)).await;
    let mut pane = Pane::open(&core, opted).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t == FolderTracking::Following))
        .await;
    assert_eq!(typed(&server), 1);
    assert_eq!(hook_audits(&core).await, 1);
    let entry = core
        .store
        .recent_audit(&core.ctx, 50)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "folder_hook_installed")
        .unwrap();
    assert!(entry.action.contains("'prod02'"), "{entry:?}");
    core.terminals.close(pane.id).await;

    // Settings turn it off everywhere; a lab session that follows Settings gets none.
    let mut settings = core.terminal_settings().await.unwrap();
    settings.prompt_hook = false;
    core.set_terminal_settings(settings).await.unwrap();
    let lab = hook_session(&core, &server, &password, "lab01", Environment::Lab, None).await;
    let mut pane = Pane::open(&core, lab).await;
    pane.until(|p| p.folder().is_some_and(|(_, t)| t != FolderTracking::Waiting))
        .await;
    assert_eq!(pane.folder().unwrap().1, FolderTracking::Off);
    pane.settle(Duration::from_millis(600)).await;
    assert_eq!(typed(&server), 1, "no new hook");
    assert_eq!(hook_audits(&core).await, 1);
}
