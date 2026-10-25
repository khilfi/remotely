//! VM-25 the Log and Timeline tabs end to end with the fakes: log files made at run time in the system temp folder
//! (a capped tail, following what was added, a replaced log, a burst skipped to its tail, names outside the listing
//! refused), and the timeline from the audit log and the job journal, newest first, a page at a time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};

use common::{temp_folder, wait_finished, Setup};
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::command_bus::{Command, PowerOp, SubmitOutcome};
use remotely_core::domain::{Environment, PowerState, TargetRef};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::vm_insight::logs::{DEFAULT_TAIL_BYTES, MAX_CHUNK_BYTES};
use remotely_core::Core;

const LAB: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `n` numbered log lines of about 100 bytes each.
fn lines(from: usize, n: usize) -> String {
    (from..from + n)
        .map(|i| format!("2026-10-25T10:00:00.000Z In(05) vmx - line {i:07} {}\n", "x".repeat(50)))
        .collect()
}

fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

/// A Workstation VM whose folder is a fresh temp folder with three logs and a file that isn't one.
async fn workstation_vm() -> (Core, Folder, String) {
    let folder = Folder(temp_folder("r4-logs"));
    let vmx = folder.0.join("web.vmx").display().to_string();
    std::fs::write(&vmx, "displayName = \"web\"\n").unwrap();
    std::fs::write(folder.0.join("vmware.log"), lines(0, 6000)).unwrap();
    std::fs::write(folder.0.join("vmware-0.log"), lines(0, 10)).unwrap();
    std::fs::write(folder.0.join("vmware-1.log"), lines(0, 5)).unwrap();
    std::fs::write(folder.0.join("notes.log.txt"), "not a log").unwrap();
    let fake = FakeVmware::with_running([vmx.clone()])
        .in_library(&vmx, Some("web"))
        .with_vmx(
            &vmx,
            VmxInfo {
                display_name: Some("web".into()),
                ..Default::default()
            },
        );
    let core = Setup::new(fake).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    (core, folder, vmx)
}

#[tokio::test]
async fn a_workstation_vms_logs_are_listed_current_first() {
    let (core, folder, vmx) = workstation_vm().await;
    let listing = core.insight.logs(&vmx).await.unwrap();
    assert_eq!(listing.folder.as_deref(), Some(folder.0.display().to_string().as_str()));
    let names: Vec<&str> = listing.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["vmware.log", "vmware-0.log", "vmware-1.log"]);
    assert!(listing.files[0].current && !listing.files[1].current);
    assert!(listing.files[0].modified.is_some());
    assert_eq!(listing.problem, None);
}

#[tokio::test]
async fn the_tail_is_capped_and_following_reads_only_what_was_added() {
    let (core, folder, vmx) = workstation_vm().await;
    let log = folder.0.join("vmware.log");
    let size = std::fs::metadata(&log).unwrap().len();
    assert!(size > DEFAULT_TAIL_BYTES, "the log is larger than a tail");

    let tail = core.insight.read_log(&vmx, "vmware.log", None, None).await.unwrap();
    assert!(tail.text.len() as u64 <= DEFAULT_TAIL_BYTES);
    assert!(tail.truncated_before && !tail.reset);
    assert!(
        tail.text.starts_with("2026-10-25T10:00:00.000Z"),
        "starts at a whole line"
    );
    assert!(tail.text.ends_with(&format!("line 0005999 {}\n", "x".repeat(50))));
    assert_eq!(tail.end, size);

    // Nothing new: an empty read that ends where it started.
    let same = core
        .insight
        .read_log(&vmx, "vmware.log", Some(tail.end), None)
        .await
        .unwrap();
    assert_eq!((same.text.as_str(), same.end), ("", size));

    // Two lines and half of a third: the two whole ones.
    append(&log, &lines(6000, 2));
    append(&log, "2026-10-25T10:00:01.000Z In(05) vmx - half a li");
    let more = core
        .insight
        .read_log(&vmx, "vmware.log", Some(same.end), None)
        .await
        .unwrap();
    assert_eq!(more.text.lines().count(), 2);
    assert!(more.text.contains("line 0006001"));
    assert!(!more.truncated_before || more.start == same.end);
    append(&log, "ne\n");
    let rest = core
        .insight
        .read_log(&vmx, "vmware.log", Some(more.end), None)
        .await
        .unwrap();
    assert_eq!(rest.text, "2026-10-25T10:00:01.000Z In(05) vmx - half a line\n");

    // A burst larger than a follow read skips to the tail and says how much it left out.
    append(&log, &lines(7000, (MAX_CHUNK_BYTES / 80) as usize + 2000));
    let burst = core
        .insight
        .read_log(&vmx, "vmware.log", Some(rest.end), None)
        .await
        .unwrap();
    assert!(burst.skipped > 0, "{}", burst.skipped);
    assert!(burst.text.len() as u64 <= DEFAULT_TAIL_BYTES);

    // The VM started again: Workstation replaced the log with a short new one.
    std::fs::write(&log, lines(0, 3)).unwrap();
    let reset = core
        .insight
        .read_log(&vmx, "vmware.log", Some(burst.end), None)
        .await
        .unwrap();
    assert!(reset.reset);
    assert_eq!(reset.text.lines().count(), 3);
}

#[tokio::test]
async fn only_the_vms_own_log_names_can_be_read() {
    let (core, _folder, vmx) = workstation_vm().await;
    for name in [
        "notes.log.txt",
        r"..\other\vmware.log",
        "../vmware.log",
        "web.vmx",
        "VBox.log",
    ] {
        let err = core.insight.read_log(&vmx, name, None, None).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{name}: {err}");
    }
    let old = core.insight.read_log(&vmx, "vmware-1.log", None, None).await.unwrap();
    assert_eq!(old.text.lines().count(), 5);
    assert!(!old.truncated_before);
    let gone = core
        .insight
        .read_log(&vmx, "vmware-7.log", None, None)
        .await
        .unwrap_err();
    assert!(gone.to_string().contains("not there"), "{gone}");
}

#[tokio::test]
async fn a_virtualbox_vms_logs_are_in_its_log_folder() {
    let folder = Folder(temp_folder("r4-vbox-logs"));
    let vbox_file = folder.0.join("lab01.vbox");
    std::fs::create_dir_all(folder.0.join("Logs")).unwrap();
    std::fs::write(folder.0.join("Logs").join("VBox.log"), lines(0, 20)).unwrap();
    std::fs::write(folder.0.join("Logs").join("VBox.log.1"), lines(0, 4)).unwrap();
    std::fs::write(folder.0.join("Logs").join("VBoxHardening.log"), "hardening").unwrap();
    let vbox = FakeVirtualBox::new()
        .with_vm(LAB, "lab01", PowerState::Running)
        .with_info(LAB, |vm| vm.config_file = Some(vbox_file.clone()));
    let core = Setup::new(FakeVmware::default()).with_virtualbox(vbox).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let listing = core.insight.logs(LAB).await.unwrap();
    let names: Vec<&str> = listing.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["VBox.log", "VBox.log.1"]);
    let chunk = core.insight.read_log(LAB, "VBox.log", None, None).await.unwrap();
    assert_eq!(chunk.text.lines().count(), 20);
}

#[tokio::test]
async fn a_vm_without_logs_yet_says_so() {
    let folder = Folder(temp_folder("r4-nologs"));
    let vmx = folder.0.join("new.vmx").display().to_string();
    let core = Setup::new(FakeVmware::default().in_library(&vmx, Some("new")))
        .build()
        .await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let listing = core.insight.logs(&vmx).await.unwrap();
    assert!(listing.files.is_empty());
    assert!(listing.problem.unwrap().contains("No log files yet"));
}

#[tokio::test]
async fn the_timeline_lists_what_remotely_did_to_the_vm_newest_first_in_pages() {
    let web = common::vmx("web");
    let db = common::vmx("db");
    let fake = FakeVmware::default()
        .in_library(&web, Some("web"))
        .in_library(&db, Some("db"));
    let core = Setup::new(fake).build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    let mut rx = core.jobs.subscribe();
    let start = |key: &str| Command::VmPower {
        targets: vec![TargetRef::Vm { vmx_path: key.into() }],
        op: PowerOp::Start { gui: false },
    };
    for command in [start(&web), start(&db)] {
        let SubmitOutcome::Queued { job_id, .. } = core.bus.submit(&core.ctx, command).await.unwrap() else {
            panic!("starting is Low");
        };
        wait_finished(&mut rx, job_id).await;
    }
    core.inventory
        .set_environment(&core.ctx, std::slice::from_ref(&web), Environment::Lab)
        .await
        .unwrap();

    let page = core.insight.timeline(&web, None, None).await.unwrap();
    let events: Vec<&str> = page.entries.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(events, ["vm_label_changed", "job_finished", "job_started"]);
    assert!(page.entries.windows(2).all(|w| w[0].seq > w[1].seq), "newest first");
    let finished = &page.entries[1];
    let outcome = finished.outcome.as_ref().expect("the VM's own row of the job");
    assert_eq!(outcome.status, "succeeded");
    assert!(finished.action.starts_with("Start"));
    assert_eq!(page.next_before, None);
    // db's job is not in web's timeline.
    assert_eq!(core.insight.timeline(&db, None, None).await.unwrap().entries.len(), 2);

    // Pages of two.
    let first = core.insight.timeline(&web, None, Some(2)).await.unwrap();
    assert_eq!(first.entries.len(), 2);
    let next = core.insight.timeline(&web, first.next_before, Some(2)).await.unwrap();
    assert_eq!(next.entries.len(), 1);
    assert_eq!(next.entries[0].event, "job_started");
    assert!(core
        .insight
        .timeline(r"C:\VMs\nope\nope.vmx", None, None)
        .await
        .is_err());
}
