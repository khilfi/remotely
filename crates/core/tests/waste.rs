//! VM-16, VM-14 the waste finder end to end with the fakes: idle VMs from the dashboard's history on disk, suspended
//! VMs and their saved state, long snapshot chains, and folders no known VM uses, with VM folders made at run time in
//! the system temp folder. Open folder takes only folders the report or a known VM names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{temp_folder, Setup};
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::domain::PowerState;
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::metrics::history::{now_ms, HistorySource, MinuteRow, MINUTE_MS};
use remotely_core::waste::{OrphanKind, WasteOptions};
use remotely_core::Core;
use time::OffsetDateTime;

const SAVED: &str = "9d1e2f3a-0000-4000-8000-0000000000cc";

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Folder {
    fn file(&self, rel: &str, bytes: usize) -> String {
        let mut path = self.0.clone();
        for part in rel.split('/') {
            path.push(part);
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'x'; bytes]).unwrap();
        path.display().to_string()
    }
}

fn minutes(key: &str, days: i64, cpu: f64) -> Vec<MinuteRow> {
    let now = now_ms().div_euclid(MINUTE_MS);
    (now - days * 24 * 60..now)
        .map(|minute| MinuteRow {
            source: HistorySource::Host,
            key: key.to_owned(),
            minute,
            samples: 12,
            cpu_avg: Some(cpu),
            cpu_min: Some(cpu),
            cpu_max: Some(cpu),
            mem_avg: None,
            mem_max: None,
            mem_total: None,
            swap_avg: None,
            swap_total: None,
            read_avg: None,
            write_avg: None,
            rx_avg: None,
            tx_avg: None,
            load_avg: None,
            load_max: None,
            disk_used_max: None,
        })
        .collect()
}

struct Lab {
    core: Core,
    root: Folder,
    vms: Folder,
    quiet: String,
    busy: String,
    sleeping: String,
    chained: String,
}

/// In a temp root (a scanned folder): `quiet` and `busy` running, `sleeping` suspended with its state files,
/// `chained` off with five snapshots and delta disks, a folder of an old VM no library lists, and loose disks.
/// A VirtualBox VM `saved` in its own temp folder, suspended.
async fn lab() -> Lab {
    let root = Folder(temp_folder("r4-waste"));
    let vms = Folder(temp_folder("r4-waste-vbox"));
    let quiet = root.file("quiet/quiet.vmx", 10);
    let busy = root.file("busy/busy.vmx", 10);
    let sleeping = root.file("sleeping/sleeping.vmx", 10);
    root.file("sleeping/sleeping-6f1a.vmss", 3_000);
    root.file("sleeping/sleeping-6f1a.vmem", 40_000);
    root.file("sleeping/sleeping-Snapshot1.vmem", 9);
    let chained = root.file("chained/chained.vmx", 10);
    root.file("chained/chained.vmdk", 1_000);
    for n in 1..=5 {
        root.file(&format!("chained/chained-00000{n}.vmdk"), 2_000);
        root.file(&format!("chained/chained-Snapshot{n}.vmsn"), 100);
    }
    root.file("old-vm/old-vm.vmx", 10);
    root.file("old-vm/old-vm.vmdk", 50_000);
    root.file("spare-disks/data.vdi", 7_000);
    let vbox_file = vms.file("saved/saved.vbox", 100);
    vms.file("saved/Snapshots/saved.sav", 60_000);
    vms.file("saved/Logs/VBox.log", 10);

    let running = |_path: &str, name: &str| VmxInfo {
        display_name: Some(name.into()),
        ..Default::default()
    };
    let at = OffsetDateTime::now_utc() - time::Duration::days(40);
    let mut fake = FakeVmware::with_running([quiet.clone(), busy.clone()])
        .in_folder(&root.0.display().to_string(), &quiet)
        .in_folder(&root.0.display().to_string(), &busy)
        .in_folder(&root.0.display().to_string(), &sleeping)
        .in_folder(&root.0.display().to_string(), &chained)
        .with_vmx(&quiet, running(&quiet, "quiet"))
        .with_vmx(&busy, running(&busy, "busy"))
        .with_vmx(
            &sleeping,
            VmxInfo {
                display_name: Some("sleeping".into()),
                suspended: true,
                ..Default::default()
            },
        )
        .with_vmx(&chained, running(&chained, "chained"))
        // A share as Workstation's default VM folder: refused, never opened.
        .with_default_vm_folder(r"\\server\vms");
    for n in 1..=5 {
        fake = fake.with_snapshot(&chained, &format!("step {n}"), at + time::Duration::days(n));
    }
    let vbox = FakeVirtualBox::new()
        .with_vm(SAVED, "saved", PowerState::Suspended)
        .with_info(SAVED, |vm| vm.config_file = Some(PathBuf::from(&vbox_file)));
    let core = Setup::new(fake).with_virtualbox(vbox).build().await;
    core.set_scan_folders(vec![root.0.clone()]).await.unwrap();
    core.inventory.refresh(&core.ctx).await.unwrap();
    core.store
        .write_history(&core.ctx, &minutes(&quiet, 3, 0.3))
        .await
        .unwrap();
    core.store
        .write_history(&core.ctx, &minutes(&busy, 3, 25.0))
        .await
        .unwrap();
    Lab {
        core,
        root,
        vms,
        quiet,
        busy,
        sleeping,
        chained,
    }
}

#[tokio::test]
async fn the_report_finds_idle_suspended_chained_and_unknown() {
    let lab = lab().await;
    let report = lab.core.waste.report(WasteOptions::default()).await.unwrap();

    let idle: Vec<&str> = report.idle.iter().map(|i| i.vm.name.as_str()).collect();
    assert_eq!(idle, ["quiet"], "busy used a quarter of the CPU");
    assert!(report.idle[0].verdict.covered_hours >= 70);
    assert_eq!(report.idle[0].vm.vmx_path, lab.quiet);
    assert!(!report.idle.iter().any(|i| i.vm.vmx_path == lab.busy));

    let sleeping = report.suspended.iter().find(|s| s.vm.vmx_path == lab.sleeping).unwrap();
    assert_eq!(
        sleeping.state_bytes,
        Some(43_000),
        "the snapshot's .vmem is not the suspend state"
    );
    assert!(sleeping.since.is_some());
    assert_eq!(sleeping.folder_bytes, Some(43_019));
    let saved = report.suspended.iter().find(|s| s.vm.name == "saved").unwrap();
    assert_eq!(saved.state_bytes, Some(60_000));
    assert_eq!(report.suspended[0].vm.name, "saved", "largest state first");

    assert_eq!(report.chains.len(), 1);
    let chain = &report.chains[0];
    assert_eq!(chain.vm.vmx_path, lab.chained);
    assert_eq!((chain.snapshots, chain.depth), (5, 5));
    assert_eq!(chain.snapshot_bytes, Some(5 * 2_100));
    assert!(chain.why.iter().any(|w| w == "5 snapshots deep"));
    assert!(chain.oldest.is_some());

    let kinds: Vec<(String, OrphanKind)> = report
        .orphans
        .iter()
        .map(|o| {
            (
                PathBuf::from(&o.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                o.kind,
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("old-vm".to_owned(), OrphanKind::WorkstationVm),
            ("spare-disks".to_owned(), OrphanKind::Disks)
        ]
    );
    assert_eq!(report.orphans[0].bytes, 50_010);
    assert_eq!(report.searched, [lab.root.0.display().to_string()]);
    assert_eq!(report.skipped.len(), 1);
    assert!(report.skipped[0].reason.contains("network share"));
    let _ = &lab.vms;
}

#[tokio::test]
async fn a_deeper_limit_or_shorter_history_changes_what_counts() {
    let lab = lab().await;
    let report = lab
        .core
        .waste
        .report(WasteOptions {
            idle_days: 7,
            chain_depth: 6,
            chain_gb: 1,
        })
        .await
        .unwrap();
    assert!(report.chains.is_empty(), "5 deep and 10 KB is under the limits");
    assert_eq!(report.idle_days, 7);
    assert!(
        report.idle.is_empty(),
        "three days of history can't show seven idle days"
    );

    lab.core
        .history
        .set_retention(remotely_core::metrics::history::HistoryRetention::Day1)
        .await
        .unwrap();
    let short = lab.core.waste.report(WasteOptions::default()).await.unwrap();
    assert_eq!(short.idle_days, 1);
    assert!(short.notes.iter().any(|n| n.contains("1 day")), "{:?}", short.notes);
}

#[tokio::test]
async fn open_folder_takes_only_folders_the_report_or_a_known_vm_names() {
    let lab = lab().await;
    let waste = &lab.core.waste;
    let old = lab.root.0.join("old-vm").display().to_string();
    assert!(
        waste.folder_to_open(Some(&old), None).await.is_err(),
        "not reported yet"
    );
    waste.report(WasteOptions::default()).await.unwrap();
    assert_eq!(
        waste.folder_to_open(Some(&old), None).await.unwrap(),
        PathBuf::from(&old)
    );
    let elsewhere = std::env::temp_dir().display().to_string();
    assert!(waste.folder_to_open(Some(&elsewhere), None).await.is_err());
    assert!(waste.folder_to_open(Some(r"\\server\vms"), None).await.is_err());
    let by_vm = waste.folder_to_open(None, Some(&lab.chained)).await.unwrap();
    assert_eq!(by_vm, lab.root.0.join("chained"));
    assert!(waste.folder_to_open(None, None).await.is_err());
}
