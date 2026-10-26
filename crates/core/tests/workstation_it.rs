//! Opt-in test against the real VMware Workstation install (CLAUDE.md "Development safety").
//!
//! Runs only with `REMOTELY_IT=1`, and only reads: Workstation's library, `vmrun list`, for running
//! VMs `checkToolsState` and `getGuestIPAddress`, and each VM's snapshots (`vmrun listSnapshots`, the
//! .vmsd file, the first line of vmware.log), and the counters of each running VM's `vmware-vmx.exe`
//! process (MO-01). It never starts, stops or changes a VM. It prints
//! counts, not VM names or paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::updater::DisabledUpdater;
use remotely_core::adapters::vmware;
use remotely_core::domain::PowerState;
use remotely_core::{Core, CoreConfig};

fn enabled() -> bool {
    let on = std::env::var("REMOTELY_IT").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set REMOTELY_IT=1 to run against the real Workstation install");
    }
    on
}

async fn real_core() -> (Core, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("remotely-it-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let core = Core::init(CoreConfig {
        db_path: dir.join("it.db"),
        vmrun_path: None,
        vboxmanage_path: None,
        account: r"IT\tester".into(),
        display_name: "IT".into(),
        updater: Arc::new(DisabledUpdater),
    })
    .await
    .unwrap();
    (core, dir)
}

/// VM-04: the snapshot manager reads the .vmsd; vmrun only knows names. Both must agree.
#[tokio::test]
async fn the_vmsd_lists_the_same_snapshots_as_vmrun() {
    if !enabled() {
        return;
    }
    let (core, dir) = real_core().await;
    let report = core.inventory.refresh(&core.ctx()).await.unwrap();
    let vmrun = vmware::connect(None);
    let mut snapshots = 0;
    // VM-18: VirtualBox VMs (when it is installed too) are not vmrun's.
    let vmware_vms = report.vms.iter().filter(|vm| vm.hypervisor == Hypervisor::Vmware);
    for vm in vmware_vms.clone() {
        let vmx = Path::new(&vm.vmx_path);
        let mut from_vmrun = vmrun.list_snapshots(vmx).await.unwrap();
        let mut from_vmsd: Vec<String> = vmrun
            .snapshots(vmx)
            .await
            .unwrap()
            .snapshots
            .into_iter()
            .map(|s| s.name)
            .collect();
        from_vmrun.sort();
        from_vmsd.sort();
        assert_eq!(from_vmsd, from_vmrun, "a VM's .vmsd and vmrun disagree");
        snapshots += from_vmsd.len();
        if vm.power_state == PowerState::Running {
            assert!(
                vmrun.running_since(vmx).await.unwrap().is_some(),
                "a running VM has a vmware.log"
            );
        }
    }
    let listed: usize = core
        .snapshots
        .list(&core.ctx(), None)
        .await
        .unwrap()
        .iter()
        .filter(|v| v.hypervisor == Hypervisor::Vmware)
        .map(|v| v.snapshots.len())
        .sum();
    assert_eq!(listed, snapshots);
    eprintln!("snapshots: {snapshots} across {} VM(s)", vmware_vms.count());

    drop(core);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn lists_every_vm_through_the_core() {
    if !enabled() {
        return;
    }
    let (core, dir) = real_core().await;

    assert!(core.vmrun_path().is_some(), "vmrun.exe was not found");
    let report = core.inventory.refresh(&core.ctx()).await.unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let running = report
        .vms
        .iter()
        .filter(|vm| vm.power_state == PowerState::Running)
        .count();
    eprintln!("inventory: {} VM(s), {running} running", report.vms.len());

    drop(core);
    let _ = std::fs::remove_dir_all(&dir);
}

/// MO-01: every VM `vmrun list` says is running has a `vmware-vmx.exe` process whose command line names
/// its .vmx, and two rounds give it a CPU share and a working set. Reads only (process counters).
#[tokio::test]
async fn every_running_vm_has_host_side_metrics() {
    if !enabled() {
        return;
    }
    let (core, dir) = real_core().await;
    let vmrun = vmware::connect(None);
    let running: Vec<String> = vmrun
        .list_running()
        .await
        .unwrap()
        .iter()
        .map(|p| vmware::path_key(p))
        .collect();
    core.metrics.collect_once().await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let cost = core.metrics.collect_once().await;
    for key in &running {
        let sample = core
            .metrics
            .hub()
            .latest(remotely_core::metrics::MetricSource::Host, key)
            .or_else(|| {
                // The hub keys samples by the inventory's (or the command line's) spelling.
                core.metrics.hub().running().unwrap_or_default().iter().find_map(|p| {
                    (vmware::path_key(Path::new(p)) == *key)
                        .then(|| core.metrics.hub().latest(remotely_core::metrics::MetricSource::Host, p))
                        .flatten()
                })
            })
            .expect("a running VM has host-side metrics");
        assert!(sample.host_cpu_pct.is_some(), "a CPU share after two rounds");
        assert!(sample.mem_bytes.unwrap_or(0) > 0, "a working set");
    }
    eprintln!(
        "{} running VMs with host-side metrics; a round took {:.0} ms",
        running.len(),
        cost.round_ms
    );
    drop(core);
    let _ = std::fs::remove_dir_all(dir);
}
