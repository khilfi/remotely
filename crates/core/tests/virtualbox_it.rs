//! VM-18: opt-in test against the real Oracle VirtualBox install (CLAUDE.md "Development safety").
//!
//! Runs only with `REMOTELY_IT=1`, and only reads: `VBoxManage list vms` and `list runningvms`, then
//! for VMs whose name starts with `it-` only, `showvminfo --machinereadable`, `snapshot list
//! --machinereadable`, the .vbox file's snapshot times, the Guest Additions' guest properties, and the
//! counters of each running `it-` VM's process (MO-01). It never starts, stops or changes a VM. It
//! prints counts, not VM names, UUIDs or paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use remotely_core::adapters::host_counters::{HostCounters, WindowsCounters};
use remotely_core::adapters::virtualbox::{self, VboxListedVm, VirtualBoxAdapter};
use remotely_core::domain::PowerState;

fn enabled() -> bool {
    let on = std::env::var("REMOTELY_IT").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set REMOTELY_IT=1 to run against the real VirtualBox install");
    }
    on
}

/// The adapter for this PC, and its `it-` VMs. `None` when VirtualBox is not installed.
async fn it_vms() -> Option<(Box<dyn VirtualBoxAdapter>, Vec<VboxListedVm>)> {
    let path = virtualbox::locate_vboxmanage(None)?;
    eprintln!("VBoxManage found");
    let vbox: Box<dyn VirtualBoxAdapter> = Box::new(virtualbox::VBoxManageCli::new(path));
    let all = vbox.list_vms().await.unwrap();
    let it: Vec<VboxListedVm> = all.into_iter().filter(|vm| vm.name.starts_with("it-")).collect();
    eprintln!("{} it- VM(s)", it.len());
    Some((vbox, it))
}

/// What `showvminfo` says about each `it-` VM: a UUID, a known state, a size, a settings file, and
/// for a running one, when it started.
#[tokio::test]
async fn showvminfo_describes_every_it_vm() {
    if !enabled() {
        return;
    }
    let Some((vbox, vms)) = it_vms().await else {
        eprintln!("skipped: VirtualBox is not installed");
        return;
    };
    let running = vbox.list_running().await.unwrap();
    for vm in &vms {
        let info = vbox.vm_info(&vm.uuid).await.unwrap();
        assert_eq!(info.uuid, vm.uuid);
        assert_ne!(info.power_state(), PowerState::Unknown, "an unknown VMState");
        assert!(info.memory_mb.is_some() && info.cpus.is_some());
        assert!(
            info.config_file.as_ref().is_some_and(|f| f.is_file()),
            "the .vbox file is readable"
        );
        assert_eq!(
            info.power_state().is_on(),
            running.contains(&vm.uuid),
            "list runningvms agrees"
        );
        if info.power_state().is_on() {
            assert!(info.running_since().is_some(), "VMStateChangeTime parsed");
            if info.tools_state() == Some(remotely_core::adapters::vmware::ToolsState::Running) {
                let props = vbox.guest_properties(&vm.uuid).await.unwrap();
                let ip = virtualbox::guest_ip(&props, &info.nics);
                let os = virtualbox::guest_os_name(&props);
                eprintln!("a guest reports an IP: {}, an OS: {}", ip.is_some(), os.is_some());
            }
        }
    }
}

/// VM-04: the tree read from `showvminfo` (with times from the .vbox) holds the same snapshots as
/// `snapshot list --machinereadable`.
#[tokio::test]
async fn the_snapshot_tree_matches_vboxmanage_snapshot_list() {
    if !enabled() {
        return;
    }
    let Some((vbox, vms)) = it_vms().await else {
        return;
    };
    let path = virtualbox::locate_vboxmanage(None).unwrap();
    let mut snapshots = 0;
    for vm in &vms {
        let tree = vbox.snapshots(&vm.uuid).await.unwrap();
        let out = Command::new(&path)
            .args(["snapshot", &vm.uuid, "list", "--machinereadable"])
            .output()
            .unwrap();
        // A VM without snapshots makes `snapshot list` fail ("does not have any snapshots").
        let listed = if out.status.success() {
            virtualbox::snapshot_tree(&virtualbox::parse_machine_readable(&String::from_utf8_lossy(
                &out.stdout,
            )))
        } else {
            Default::default()
        };
        let names = |t: &remotely_core::adapters::vmware::SnapshotTree| {
            let mut n: Vec<(String, Option<String>)> =
                t.snapshots.iter().map(|s| (s.name.clone(), s.id.clone())).collect();
            n.sort();
            n
        };
        assert_eq!(names(&tree), names(&listed), "showvminfo and snapshot list disagree");
        assert_eq!(tree.current_uid.is_some(), listed.current_uid.is_some());
        assert!(
            tree.snapshots.iter().all(|s| s.created_at.is_some()),
            "every snapshot has a time in the .vbox file"
        );
        snapshots += tree.snapshots.len();
    }
    eprintln!("{snapshots} snapshot(s) across {} it- VM(s)", vms.len());
}

/// MO-01: every running `it-` VM has a VirtualBoxVM.exe or VBoxHeadless.exe process whose command
/// line names its UUID. Reads only (process counters).
#[tokio::test]
async fn every_running_it_vm_has_a_process_with_its_uuid() {
    if !enabled() {
        return;
    }
    let Some((vbox, vms)) = it_vms().await else {
        return;
    };
    let running = vbox.list_running().await.unwrap();
    let processes = WindowsCounters::new().vm_processes().await.unwrap();
    let mut seen = 0;
    for vm in vms.iter().filter(|vm| running.contains(&vm.uuid)) {
        assert!(
            processes
                .iter()
                .any(|p| p.vmx_path.as_deref() == Some(vm.uuid.as_str())),
            "a running VM's process names its UUID"
        );
        seen += 1;
    }
    eprintln!("{seen} running it- VM(s) with a process");
}
