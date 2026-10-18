//! Opt-in test against the real VMware Workstation install (CLAUDE.md "Development safety").
//!
//! Runs only with `REMOTELY_IT=1`, and only reads: Workstation's library, `vmrun list`, and for running
//! VMs `checkToolsState` and `getGuestIPAddress`. It never starts, stops or changes a VM. It prints
//! counts, not VM names or paths.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use remotely_core::adapters::updater::DisabledUpdater;
use remotely_core::domain::PowerState;
use remotely_core::{Core, CoreConfig};

#[tokio::test]
async fn lists_every_vm_through_the_core() {
    if std::env::var("REMOTELY_IT").as_deref() != Ok("1") {
        eprintln!("skipped: set REMOTELY_IT=1 to run against the real Workstation install");
        return;
    }
    let dir = std::env::temp_dir().join(format!("remotely-it-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let core = Core::init(CoreConfig {
        db_path: dir.join("it.db"),
        vmrun_path: None,
        account: r"IT\tester".into(),
        display_name: "IT".into(),
        updater: Arc::new(DisabledUpdater),
    })
    .await
    .unwrap();

    assert!(core.vmrun_path().is_some(), "vmrun.exe was not found");
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
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
