//! VM settings and lifecycle (VM-11, VM-12, VM-15, VM-16, VM-23, VM-24) end to end with the fakes: every
//! change goes through the bus (tier, preview, approval, audit) to the job runner, which edits the fake
//! Workstation's .vmx (with its backup) or makes the fake VirtualBox's VBoxManage calls. No real VM is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{vbox_vm, vm, vmx, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::virtualbox::VboxSettingsExtras;
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::vault::SecretString;
use remotely_core::vm_settings::{
    ConsoleOutcome, Firmware, NicNetwork, VmConfigEdit, VmDeviceOp, VmDiskOp, VmLifecycleOp,
};
use remotely_core::Core;
use uuid::Uuid;

const WEB_VMX: &str = ".encoding = \"UTF-8\"\r\n\
config.version = \"8\"\r\n\
virtualHW.version = \"21\"\r\n\
displayName = \"web\"\r\n\
guestOS = \"ubuntu-64\"\r\n\
numvcpus = \"2\"\r\n\
memsize = \"4096\"\r\n\
scsi0.present = \"TRUE\"\r\n\
scsi0.virtualDev = \"pvscsi\"\r\n\
scsi0:0.present = \"TRUE\"\r\n\
scsi0:0.fileName = \"web.vmdk\"\r\n\
sata0.present = \"TRUE\"\r\n\
sata0:1.present = \"TRUE\"\r\n\
sata0:1.deviceType = \"cdrom-image\"\r\n\
sata0:1.fileName = \"\"\r\n\
ethernet0.present = \"TRUE\"\r\n\
ethernet0.connectionType = \"nat\"\r\n\
ethernet0.virtualDev = \"vmxnet3\"\r\n\
ethernet0.addressType = \"generated\"\r\n\
someVendor.setting = \"kept as it was\"\r\n";

const DB: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";

/// `web` (off, a 40 GB disk) and `app` (off) in Workstation's library.
fn workstation() -> FakeVmware {
    FakeVmware::default()
        .in_library(&vmx("web"), Some("web"))
        .with_vmx_text(&vmx("web"), WEB_VMX)
        .with_disk(r"C:\VMs\web\web.vmdk", 40 * 1024)
        .with_file(r"C:\VMs\web\vmware.log", 70_000)
        .with_file(r"C:\VMs\web\notes.txt", 10)
        .in_library(&vmx("app"), Some("app"))
        .with_vmx_text(&vmx("app"), &WEB_VMX.replace("\"web", "\"app"))
        .with_disk(r"C:\VMs\app\app.vmdk", 20 * 1024)
        .with_file(r"C:\ISOs\ubuntu-24.04.iso", 3_000_000_000)
}

async fn built(setup: Setup) -> Core {
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    core
}

fn asked(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

/// Every step answered; the vault password when the request asks for it.
async fn approve(core: &Core, request: &ApprovalRequest) -> Uuid {
    let vault = request.steps.contains(&ApprovalStep::VaultReauth);
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("R3 test".into()),
        safety_snapshot: None,
        vault_password: vault.then(|| SecretString::new(VAULT_PASSWORD)),
    };
    core.bus.approve(request.id, answers).await.unwrap()
}

/// Submits, approves when asked, and waits for the job's end.
async fn run(core: &Core, command: Command) -> (Uuid, JobStatus) {
    let mut rx = core.jobs.subscribe();
    let job = match core.bus.submit(&core.ctx, command).await.unwrap() {
        SubmitOutcome::Queued { job_id, .. } => job_id,
        SubmitOutcome::NeedsApproval { request } => approve(core, &request).await,
    };
    (job, wait_finished(&mut rx, job).await)
}

async fn last_finished(core: &Core) -> String {
    core.store
        .recent_audit(&core.ctx, 20)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "job_finished")
        .and_then(|e| e.detail)
        .unwrap_or_default()
}

fn resize(vcpus: u32, memory_mb: u32) -> VmConfigEdit {
    VmConfigEdit::Resources {
        vcpus: Some(vcpus),
        cores_per_socket: None,
        memory_mb: Some(memory_mb),
        nested_virtualization: None,
    }
}

// ---- Workstation: the .vmx ---------------------------------------------------------------------

#[tokio::test]
async fn a_resize_edits_the_vmx_keeps_the_rest_and_drops_its_backup() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let command = Command::VmConfig {
        targets: vec![vm("web")],
        edit: resize(4, 8192),
    };
    let request = asked(core.bus.submit(&core.ctx, command.clone()).await.unwrap());
    assert_eq!(request.tier, Tier::Medium);
    let preview = request.vm_change.as_ref().expect("a VM change preview");
    assert_eq!(preview.targets[0].changes, ["vCPUs: 2 → 4", "Memory: 4 GB → 8 GB"]);
    assert_eq!(preview.targets[0].problem, None);
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);

    let text = fake.vmx_text(&vmx("web")).unwrap();
    assert!(
        text.contains("numvcpus = \"4\"\r\n") && text.contains("memsize = \"8192\"\r\n"),
        "{text}"
    );
    assert!(text.contains("someVendor.setting = \"kept as it was\"\r\n"));
    assert_eq!(text.lines().count(), WEB_VMX.lines().count(), "every other line kept");
    assert!(fake.backups().is_empty(), "the backup goes once the change went well");
    let calls = fake.calls();
    let backup = calls.iter().position(|c| c.starts_with("backup")).unwrap();
    let write = calls.iter().position(|c| c.starts_with("write")).unwrap();
    assert!(backup < write, "the backup comes first: {calls:?}");
    assert!(last_finished(&core)
        .await
        .contains("'web': vCPUs: 2 → 4; Memory: 4 GB → 8 GB"));
    // The inventory reads it back.
    let refreshed = core.inventory.refresh(&core.ctx).await.unwrap();
    let web = refreshed.vms.iter().find(|v| v.display_name == "web").unwrap();
    assert_eq!((web.num_vcpus, web.memsize_mb), (Some(4), Some(8192)));
}

#[tokio::test]
async fn a_bulk_resize_is_one_approval_and_a_running_vm_is_refused_with_the_reason() {
    let fake = workstation()
        .in_library(&vmx("live"), Some("live"))
        .with_vmx_text(&vmx("live"), &WEB_VMX.replace("\"web", "\"live"));
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    core.bus
        .submit(
            &core.ctx,
            Command::VmPower {
                targets: vec![vm("live")],
                op: remotely_core::command_bus::PowerOp::Start { gui: false },
            },
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let command = Command::VmConfig {
        targets: vec![vm("web"), vm("app"), vm("live")],
        edit: resize(2, 2048),
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::Medium, "VM-12: one confirm for all of them");
    assert_eq!(request.steps, [ApprovalStep::Confirm]);
    assert!(
        request
            .warnings
            .iter()
            .any(|w| w.starts_with("live: The VM is running")),
        "{:?}",
        request.warnings
    );
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::PartiallyFailed);
    let targets = core.store.job_targets(&core.ctx, job).await.unwrap();
    let live = targets.iter().find(|t| t.target_key == vmx("live")).unwrap();
    assert_eq!(live.error_code.as_deref(), Some("vm_setting_refused"));
    assert!(vmware.vmx_text(&vmx("app")).unwrap().contains("memsize = \"2048\""));
    assert!(
        vmware.vmx_text(&vmx("live")).unwrap().contains("memsize = \"4096\""),
        "untouched"
    );
}

#[tokio::test]
async fn a_failed_write_puts_the_backup_back() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    fake.set_failing_vmx_write(true);
    let (_, status) = run(
        &core,
        Command::VmConfig {
            targets: vec![vm("web")],
            edit: VmConfigEdit::Rename { name: "web02".into() },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Failed);
    assert_eq!(fake.vmx_text(&vmx("web")).unwrap(), WEB_VMX, "as it was");
    assert!(fake.calls().iter().any(|c| c.starts_with("restore")));
    assert!(fake.backups().is_empty(), "put back, then deleted");
}

#[tokio::test]
async fn adapters_firmware_and_shared_folders_on_workstation() {
    let setup = Setup::new(workstation().with_file(r"C:\Shared\data", 0));
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    for edit in [
        VmConfigEdit::AddNic {
            network: NicNetwork::Custom { vnet: "VMnet2".into() },
            model: None,
        },
        VmConfigEdit::Firmware {
            firmware: Firmware::Efi,
            secure_boot: true,
            tpm: None,
        },
        VmConfigEdit::GuestOs {
            os_type: "debian12-64".into(),
        },
    ] {
        let (_, status) = run(
            &core,
            Command::VmConfig {
                targets: vec![vm("web")],
                edit,
            },
        )
        .await;
        assert_eq!(status, JobStatus::Succeeded);
    }
    // A shared folder's path comes from a folder dialog, through the core.
    let outcome = core
        .vm_settings
        .add_shared_folder(&vmx("web"), "data", std::path::Path::new(r"C:\Shared\data"), false)
        .await
        .unwrap();
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &asked(outcome)).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    let text = fake.vmx_text(&vmx("web")).unwrap();
    for line in [
        "ethernet1.vnet = \"VMnet2\"",
        "firmware = \"efi\"",
        "uefi.secureBoot.enabled = \"TRUE\"",
        "guestOS = \"debian12-64\"",
        "sharedFolder0.hostPath = \"C:\\Shared\\data\"",
        "sharedFolder0.writeAccess = \"FALSE\"",
    ] {
        assert!(text.contains(line), "{line} in {text}");
    }
    let specs = core.host_details.vm_specs(&core.ctx, &vmx("web")).await.unwrap();
    let hardware = specs.hardware;
    assert_eq!(hardware.nics.len(), 2);
    assert_eq!(hardware.secure_boot, Some(true));
    assert_eq!(hardware.shared_folders[0].name, "data");
    assert_eq!(hardware.cdroms[0].slot, "sata0:1");
    assert_eq!(
        hardware.controllers.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["sata0", "scsi0"]
    );
}

#[tokio::test]
async fn a_hardware_upgrade_is_high_and_runs_upgradevm() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let command = Command::VmConfig {
        targets: vec![vm("web")],
        edit: VmConfigEdit::UpgradeHardware,
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::High);
    assert!(request.vm_change.as_ref().unwrap().targets[0].changes[0].starts_with("Hardware version: 21 →"));
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    assert!(fake
        .vmx_text(&vmx("web"))
        .unwrap()
        .contains("virtualHW.version = \"22\""));
    assert!(fake.calls().iter().any(|c| c.starts_with("vmrun upgradevm")));
}

#[tokio::test]
async fn a_prod_vms_settings_change_is_high_and_takes_a_safety_snapshot_first() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    core.inventory
        .set_environment(&core.ctx, &[vmx("web")], Environment::Prod)
        .await
        .unwrap();
    let command = Command::VmConfig {
        targets: vec![vm("web")],
        edit: resize(4, 4096),
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::High);
    assert!(request
        .steps
        .contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    let calls = fake.calls();
    let snapshot = calls
        .iter()
        .position(|c| c.starts_with("snapshot take safety"))
        .unwrap();
    let write = calls.iter().position(|c| c.starts_with("write")).unwrap();
    assert!(snapshot < write, "{calls:?}");
}

// ---- Workstation: disks -------------------------------------------------------------------------

#[tokio::test]
async fn disks_are_added_expanded_and_compacted_with_vdiskmanager() {
    let setup = Setup::new(workstation());
    let fake = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let add = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Add {
            size_mb: 20 * 1024,
            thin: true,
            bus: None,
        },
    };
    let (_, status) = run(&core, add).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(fake.disk_size_mb(r"C:\VMs\web\web-1.vmdk"), Some(20 * 1024));
    let text = fake.vmx_text(&vmx("web")).unwrap();
    assert!(
        text.contains("scsi0:1.fileName = \"web-1.vmdk\""),
        "on the boot disk's bus: {text}"
    );
    assert!(fake
        .calls()
        .iter()
        .any(|c| c == r"vdiskmanager -c -s 20480MB -a lsilogic -t 0 C:\VMs\web\web-1.vmdk"));

    let expand = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Expand {
            slot: "scsi0:0".into(),
            size_mb: 60 * 1024,
        },
    };
    let request = asked(core.bus.submit(&core.ctx, expand).await.unwrap());
    assert_eq!(request.tier, Tier::High);
    assert_eq!(
        request.vm_change.as_ref().unwrap().targets[0].changes[0],
        "Disk scsi0:0: 40 GB → 60 GB (it can't be shrunk back; grow the partition in the guest afterwards)"
    );
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    assert_eq!(fake.disk_size_mb(r"C:\VMs\web\web.vmdk"), Some(60 * 1024));

    let shrink = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Expand {
            slot: "scsi0:0".into(),
            size_mb: 10 * 1024,
        },
    };
    let request = asked(core.bus.submit(&core.ctx, shrink).await.unwrap());
    assert!(request.vm_change.as_ref().unwrap().targets[0]
        .problem
        .as_deref()
        .unwrap()
        .contains("can only grow"));
    core.bus.cancel_approval(request.id).await.unwrap();

    let (_, status) = run(
        &core,
        Command::VmDisk {
            targets: vec![vm("web")],
            op: VmDiskOp::Compact { slot: "scsi0:0".into() },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(fake.calls().iter().any(|c| c == r"vdiskmanager -k C:\VMs\web\web.vmdk"));
}

#[tokio::test]
async fn a_vm_with_snapshots_cant_have_a_disk_expanded() {
    let fake = workstation().with_snapshot(&vmx("web"), "base", time::OffsetDateTime::now_utc());
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let command = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Expand {
            slot: "scsi0:0".into(),
            size_mb: 60 * 1024,
        },
    };
    let request = asked(core.bus.submit(&core.ctx, command.clone()).await.unwrap());
    let problem = request.vm_change.as_ref().unwrap().targets[0].problem.clone().unwrap();
    assert_eq!(
        problem,
        "The VM has 1 snapshot: a disk can't be expanded while snapshots depend on it. Delete the snapshots first."
    );
    assert!(request.warnings.iter().any(|w| w == &format!("web: {problem}")));
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Failed);
    assert_eq!(vmware.disk_size_mb(r"C:\VMs\web\web.vmdk"), Some(40 * 1024));
    assert!(!vmware.calls().iter().any(|c| c.starts_with("vdiskmanager")));
}

#[tokio::test]
async fn removing_a_disk_is_critical_lists_its_files_and_deletes_them() {
    let fake = workstation()
        .with_vmx_text(
            &vmx("web"),
            &format!("{WEB_VMX}scsi0:1.present = \"TRUE\"\r\nscsi0:1.fileName = \"web-data.vmdk\"\r\nscsi0:2.present = \"TRUE\"\r\nscsi0:2.fileName = \"D:\\shared\\common.vmdk\"\r\n"),
        )
        .with_disk(r"C:\VMs\web\web-data.vmdk", 10 * 1024)
        .with_disk(r"D:\shared\common.vmdk", 10 * 1024);
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let command = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Remove { slot: "scsi0:1".into() },
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::Critical);
    assert!(request.steps.contains(&ApprovalStep::VaultReauth));
    let target = &request.vm_change.as_ref().unwrap().targets[0];
    assert_eq!(target.deletes.len(), 1);
    assert_eq!(target.deletes[0].path, r"C:\VMs\web\web-data.vmdk");
    assert_eq!(target.deletes[0].bytes, Some(10 * 1024 * 1024 * 1024 / 10));
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    assert!(!vmware.has_file(r"C:\VMs\web\web-data.vmdk"));
    assert!(!vmware.vmx_text(&vmx("web")).unwrap().contains("scsi0:1."));

    // A disk outside the VM's folder may be another VM's: refused.
    let outside = Command::VmDisk {
        targets: vec![vm("web")],
        op: VmDiskOp::Remove { slot: "scsi0:2".into() },
    };
    let request = asked(core.bus.submit(&core.ctx, outside).await.unwrap());
    assert!(request.vm_change.as_ref().unwrap().targets[0]
        .problem
        .as_deref()
        .unwrap()
        .contains("outside the VM's folder"));
    core.bus.cancel_approval(request.id).await.unwrap();
    assert!(vmware.has_file(r"D:\shared\common.vmdk"));
}

// ---- Workstation: devices -----------------------------------------------------------------------

#[tokio::test]
async fn an_iso_and_a_cable_change_a_running_vm_live_and_a_vm_that_is_off_in_its_vmx() {
    let fake = FakeVmware::with_running([vmx("app")])
        .in_library(&vmx("web"), Some("web"))
        .with_vmx_text(&vmx("web"), WEB_VMX)
        .in_library(&vmx("app"), Some("app"))
        .with_vmx_text(&vmx("app"), &WEB_VMX.replace("\"web", "\"app"))
        .with_file(r"C:\ISOs\ubuntu-24.04.iso", 3_000_000_000);
    let setup = Setup::new(fake);
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let iso = std::path::Path::new(r"C:\ISOs\ubuntu-24.04.iso");

    // Off: the .vmx (an ISO is Low: no approval).
    let SubmitOutcome::Queued { job_id, .. } = core.vm_settings.attach_iso(&vmx("web"), iso, None).await.unwrap()
    else {
        panic!("Low");
    };
    let mut rx = core.jobs.subscribe();
    let _ = wait_finished(&mut rx, job_id).await;
    let text = vmware.vmx_text(&vmx("web")).unwrap();
    assert!(
        text.contains(r#"sata0:1.fileName = "C:\ISOs\ubuntu-24.04.iso""#),
        "{text}"
    );
    assert!(text.contains("sata0:1.startConnected = \"TRUE\""));

    // Running: writeVariable and connectNamedDevice, the .vmx untouched.
    let SubmitOutcome::Queued { job_id, .. } = core.vm_settings.attach_iso(&vmx("app"), iso, None).await.unwrap()
    else {
        panic!("Low");
    };
    assert_eq!(wait_finished(&mut rx, job_id).await, JobStatus::Succeeded);
    let calls = vmware.calls();
    assert!(calls.iter().any(|c| c
        == &format!(
            r"vmrun writeVariable {} runtimeConfig sata0:1.fileName C:\ISOs\ubuntu-24.04.iso",
            vmx("app")
        )));
    assert!(calls
        .iter()
        .any(|c| c == &format!("vmrun connectNamedDevice {} sata0:1", vmx("app"))));
    assert!(vmware
        .vmx_text(&vmx("app"))
        .unwrap()
        .contains("sata0:1.fileName = \"\""));

    // A cable: Low to connect, Medium to pull out; vmrun is told only about an adapter the VM has.
    let cut = Command::VmDevice {
        targets: vec![vm("app")],
        op: VmDeviceOp::DisconnectNic {
            slot: "ethernet0".into(),
        },
    };
    let (_, status) = run(&core, cut).await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(vmware
        .calls()
        .iter()
        .any(|c| c == &format!("vmrun disconnectNamedDevice {} ethernet0", vmx("app"))));
    let (_, status) = run(
        &core,
        Command::VmDevice {
            targets: vec![vm("app")],
            op: VmDeviceOp::ConnectNic {
                slot: "ethernet3".into(),
            },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Failed);
    assert!(!vmware.calls().iter().any(|c| c.contains("ethernet3")));

    // Tools: the VM must run.
    let (_, status) = run(
        &core,
        Command::VmDevice {
            targets: vec![vm("web")],
            op: VmDeviceOp::InstallTools,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Failed, "web is off");
    let (_, status) = run(
        &core,
        Command::VmDevice {
            targets: vec![vm("app")],
            op: VmDeviceOp::InstallTools,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(vmware
        .calls()
        .iter()
        .any(|c| c == &format!("vmrun installTools {}", vmx("app"))));
}

// ---- Workstation: lifecycle ---------------------------------------------------------------------

#[tokio::test]
async fn deleting_a_vm_is_critical_lists_every_file_and_drops_it_from_the_list() {
    let setup = Setup::new(workstation());
    let vmware = Arc::clone(&setup.vmware);
    let core = built(setup).await;
    let command = Command::VmLifecycle {
        targets: vec![vm("web")],
        op: VmLifecycleOp::Delete,
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::Critical);
    let target = &request.vm_change.as_ref().unwrap().targets[0];
    let mut going: Vec<&str> = target.deletes.iter().map(|f| f.path.as_str()).collect();
    going.sort_unstable();
    assert_eq!(
        going,
        [r"C:\VMs\web\vmware.log", r"C:\VMs\web\web.vmdk", r"C:\VMs\web\web.vmx"]
    );
    assert!(
        target.keeps.iter().any(|k| k.starts_with("1 other file(s)")),
        "notes.txt stays"
    );
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    assert!(vmware.vmx_text(&vmx("web")).is_none());
    assert!(vmware.has_file(r"C:\VMs\web\notes.txt"));
}

#[tokio::test]
async fn an_existing_vmx_is_added_to_the_list_and_listed_on_refresh() {
    let fake = FakeVmware::default().with_vmx_text(r"D:\Lab\old\old.vmx", &WEB_VMX.replace("\"web", "\"old"));
    let core = built(Setup::new(fake)).await;
    assert!(core.inventory.refresh(&core.ctx).await.unwrap().vms.is_empty());
    let outcome = core
        .vm_settings
        .add_existing(std::path::Path::new(r"D:\Lab\old\old.vmx"))
        .await
        .unwrap();
    let SubmitOutcome::Queued { job_id, tier, .. } = outcome else {
        panic!("Low: {outcome:?}");
    };
    assert_eq!(tier, Tier::Low);
    let mut rx = core.jobs.subscribe();
    assert_eq!(wait_finished(&mut rx, job_id).await, JobStatus::Succeeded);
    let report = core.inventory.refresh(&core.ctx).await.unwrap();
    assert_eq!(
        report.vms.iter().map(|v| v.display_name.as_str()).collect::<Vec<_>>(),
        ["old"]
    );
    let share = core
        .vm_settings
        .add_existing(std::path::Path::new(r"\\nas.example.com\vms\x.vmx"))
        .await
        .unwrap_err();
    assert!(share.to_string().contains("network share"));
}

#[tokio::test]
async fn opening_a_console_is_audited_without_a_tier_and_refused_while_presenting() {
    let setup =
        Setup::new(workstation()).with_virtualbox(FakeVirtualBox::new().with_vm(DB, "db", PowerState::NotRunning));
    let vmware = Arc::clone(&setup.vmware);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    assert!(matches!(
        core.vm_settings.open_console(&vmx("web")).await.unwrap(),
        ConsoleOutcome::Opened
    ));
    assert!(vmware.calls().iter().any(|c| c == &format!("console {}", vmx("web"))));
    let audit = core.store.recent_audit(&core.ctx, 1).await.unwrap();
    assert_eq!(audit[0].event, "vm_console_opened");
    assert_eq!(audit[0].tier, None);
    assert!(audit[0].targets_json.contains("web"));

    // A VirtualBox VM that is off starts with its window: the power command.
    match core.vm_settings.open_console(DB).await.unwrap() {
        ConsoleOutcome::Starting { outcome } if matches!(*outcome, SubmitOutcome::Queued { .. }) => {}
        other => panic!("{other:?}"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(vbox.calls().iter().any(|c| c.starts_with("power Start { gui: true }")));

    core.presentation
        .set(remotely_core::presentation::Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .expect("presentation mode with the read-only lock");
    let err = core.vm_settings.open_console(&vmx("web")).await.unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
}

// ---- VirtualBox ---------------------------------------------------------------------------------

fn virtualbox() -> FakeVirtualBox {
    FakeVirtualBox::new()
        .with_vm(DB, "db", PowerState::NotRunning)
        .with_disk_size(r"C:\Users\alice\VirtualBox VMs\db\db.vdi", 25 * 1024)
        .with_file(r"C:\Users\alice\VirtualBox VMs\db\db.vbox", 4000)
        .with_file(r"C:\Users\alice\VirtualBox VMs\db\Logs\VBox.log", 80_000)
        .with_file(r"C:\ISOs\debian.iso", 700_000_000)
}

#[tokio::test]
async fn virtualbox_settings_go_through_modifyvm_and_its_disks_through_modifymedium() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox());
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let (_, status) = run(
        &core,
        Command::VmConfig {
            targets: vec![vbox_vm(DB)],
            edit: VmConfigEdit::Resources {
                vcpus: Some(4),
                cores_per_socket: None,
                memory_mb: Some(6144),
                nested_virtualization: Some(true),
            },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    let info = vbox.info(DB).unwrap();
    assert_eq!(
        (info.cpus, info.memory_mb, info.nested_hw_virt),
        (Some(4), Some(6144), Some(true))
    );
    assert!(vbox
        .calls()
        .iter()
        .any(|c| c == &format!("change modifyvm {DB} --cpus 4 --memory 6144 --nested-hw-virt on")));

    // UEFI with Secure Boot and a TPM 2.0 (Windows 11 on VirtualBox).
    let (_, status) = run(
        &core,
        Command::VmConfig {
            targets: vec![vbox_vm(DB)],
            edit: VmConfigEdit::Firmware {
                firmware: Firmware::Efi,
                secure_boot: true,
                tpm: Some(true),
            },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(vbox.info(DB).unwrap().secure_boot, Some(true));

    let (_, status) = run(
        &core,
        Command::VmDisk {
            targets: vec![vbox_vm(DB)],
            op: VmDiskOp::Expand {
                slot: "SATA-0-0".into(),
                size_mb: 50 * 1024,
            },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert_eq!(
        vbox.disk_size_mb(r"C:\Users\alice\VirtualBox VMs\db\db.vdi"),
        Some(50 * 1024)
    );

    let (_, status) = run(
        &core,
        Command::VmDisk {
            targets: vec![vbox_vm(DB)],
            op: VmDiskOp::Add {
                size_mb: 8 * 1024,
                thin: true,
                bus: None,
            },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    let info = vbox.info(DB).unwrap();
    assert!(
        info.disks
            .iter()
            .any(|d| d.path.ends_with("db-disk2.vdi") && d.slot == "SATA-2-0"),
        "{:?}",
        info.disks
    );

    let defrag = Command::VmDisk {
        targets: vec![vbox_vm(DB)],
        op: VmDiskOp::Defragment {
            slot: "SATA-0-0".into(),
        },
    };
    let err = core.bus.submit(&core.ctx, defrag).await.unwrap_err();
    assert_eq!(err.code(), "invalid_input", "VirtualBox has no defragment");
}

#[tokio::test]
async fn a_running_virtualbox_vm_gets_isos_cables_and_the_guest_additions_live() {
    let fake = FakeVirtualBox::new()
        .with_vm(DB, "db", PowerState::Running)
        .with_file(r"C:\ISOs\debian.iso", 1);
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(fake);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let SubmitOutcome::Queued { job_id, .. } = core
        .vm_settings
        .attach_iso(DB, std::path::Path::new(r"C:\ISOs\debian.iso"), None)
        .await
        .unwrap()
    else {
        panic!("Low");
    };
    let mut rx = core.jobs.subscribe();
    assert_eq!(wait_finished(&mut rx, job_id).await, JobStatus::Succeeded);
    assert_eq!(
        vbox.info(DB).unwrap().dvds[0].image.as_deref(),
        Some(std::path::Path::new(r"C:\ISOs\debian.iso"))
    );
    let (_, status) = run(
        &core,
        Command::VmDevice {
            targets: vec![vbox_vm(DB)],
            op: VmDeviceOp::DisconnectNic { slot: "nic1".into() },
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(vbox
        .calls()
        .iter()
        .any(|c| c == &format!("change controlvm {DB} setlinkstate1 off")));
    assert_eq!(vbox.info(DB).unwrap().nics[0].cable_connected, Some(false));

    let (_, status) = run(
        &core,
        Command::VmDevice {
            targets: vec![vbox_vm(DB)],
            op: VmDeviceOp::InstallTools,
        },
    )
    .await;
    assert_eq!(status, JobStatus::Succeeded);
    assert!(vbox.info(DB).unwrap().dvds[0]
        .image
        .as_ref()
        .is_some_and(|p| p.ends_with("VBoxGuestAdditions.iso")));
    assert!(!vbox.calls().iter().any(|c| c.contains("guestcontrol")));
    assert_eq!(core.vm_settings.screenshot(DB).await.unwrap()[..4], *b"\x89PNG");

    // Settings need it off.
    let (_, status) = run(
        &core,
        Command::VmConfig {
            targets: vec![vbox_vm(DB)],
            edit: resize(4, 4096),
        },
    )
    .await;
    assert_eq!(status, JobStatus::Failed);
    assert!(!vbox.calls().iter().any(|c| c.starts_with("change modifyvm")));
}

#[tokio::test]
async fn deleting_a_virtualbox_vm_lists_its_files_and_unregisters_it() {
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox());
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let command = Command::VmLifecycle {
        targets: vec![vbox_vm(DB)],
        op: VmLifecycleOp::Delete,
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    assert_eq!(request.tier, Tier::Critical);
    let going: Vec<&str> = request.vm_change.as_ref().unwrap().targets[0]
        .deletes
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    for file in [
        r"C:\Users\alice\VirtualBox VMs\db\db.vbox",
        r"C:\Users\alice\VirtualBox VMs\db\db.vdi",
        r"C:\Users\alice\VirtualBox VMs\db\Logs\VBox.log",
    ] {
        assert!(going.contains(&file), "{file} in {going:?}");
    }
    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    assert!(vbox.info(DB).is_none());
    assert!(!vbox.has_file(r"C:\Users\alice\VirtualBox VMs\db\db.vdi"));
    assert!(vbox
        .calls()
        .iter()
        .any(|c| c == &format!("change unregistervm {DB} --delete")));
}

#[tokio::test]
async fn deleting_a_virtualbox_vm_with_a_snapshot_lists_the_base_disks_it_keeps() {
    // VM-24, AP-02: after a snapshot the VM runs on a differencing image and the snapshot keeps the base disk;
    // VirtualBox deletes both, and a disk outside the folder it uses too, so the preview lists them all.
    let folder = r"C:\Users\alice\VirtualBox VMs\db";
    let diff = r"C:\Users\alice\VirtualBox VMs\db\Snapshots\{157a4207-b28b-4ae2-a0b7-fc64b88eb5ae}.vdi";
    let fake = virtualbox()
        .with_snapshot(DB, "before", time::OffsetDateTime::UNIX_EPOCH)
        .with_file(diff, 2_000_000)
        .with_file(r"D:\Disks\data.vdi", 5_000_000)
        .with_file(r"C:\Users\alice\VirtualBox VMs\db\notes.txt", 10)
        .with_extras(
            DB,
            VboxSettingsExtras {
                hard_disks: vec![
                    "db.vdi".into(),
                    "Snapshots/{157a4207-b28b-4ae2-a0b7-fc64b88eb5ae}.vdi".into(),
                    r"D:\Disks\data.vdi".into(),
                ],
                ..VboxSettingsExtras::default()
            },
        );
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(fake);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let command = Command::VmLifecycle {
        targets: vec![vbox_vm(DB)],
        op: VmLifecycleOp::Delete,
    };
    let request = asked(core.bus.submit(&core.ctx, command).await.unwrap());
    let target = &request.vm_change.as_ref().unwrap().targets[0];
    let going: Vec<(&str, Option<u64>)> = target.deletes.iter().map(|f| (f.path.as_str(), f.bytes)).collect();
    let base = format!(r"{folder}\db.vdi");
    for file in [base.as_str(), diff, r"D:\Disks\data.vdi"] {
        assert!(
            going.iter().any(|(p, _)| p.eq_ignore_ascii_case(file)),
            "{file} in {going:?}"
        );
    }
    assert!(
        going.contains(&(r"D:\Disks\data.vdi", Some(5_000_000))),
        "a disk outside the folder with its size: {going:?}"
    );
    assert!(!going.iter().any(|(p, _)| p.ends_with("notes.txt")));
    assert!(
        target.keeps.iter().any(|k| k.starts_with("1 other file(s)")),
        "only notes.txt is kept: {:?}",
        target.keeps
    );

    let mut rx = core.jobs.subscribe();
    let job = approve(&core, &request).await;
    assert_eq!(wait_finished(&mut rx, job).await, JobStatus::Succeeded);
    for file in [base.as_str(), diff, r"D:\Disks\data.vdi"] {
        assert!(!vbox.has_file(file), "{file} deleted");
    }
    assert!(vbox.has_file(r"C:\Users\alice\VirtualBox VMs\db\notes.txt"));
}

#[tokio::test]
async fn an_existing_vbox_is_registered_by_the_uuid_in_it() {
    let folder = common::temp_folder("r3-vbox");
    let file = folder.join("lab.vbox");
    std::fs::write(
        &file,
        format!("<?xml version=\"1.0\"?>\n<VirtualBox><Machine uuid=\"{{{DB}}}\" name=\"lab\" OSType=\"Ubuntu_64\"/></VirtualBox>\n"),
    )
    .unwrap();
    let fake = FakeVirtualBox::new().registerable(&file.display().to_string(), DB, "lab");
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(fake);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = built(setup).await;
    let SubmitOutcome::Queued { job_id, .. } = core.vm_settings.add_existing(&file).await.unwrap() else {
        panic!("Low");
    };
    let mut rx = core.jobs.subscribe();
    assert_eq!(wait_finished(&mut rx, job_id).await, JobStatus::Succeeded);
    assert_eq!(vbox.info(DB).unwrap().name, "lab");
    assert!(core
        .inventory
        .refresh(&core.ctx)
        .await
        .unwrap()
        .vms
        .iter()
        .any(|v| v.vmx_path == DB));
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn the_settings_tab_reads_everything_virtualbox_shows() {
    let fake = virtualbox().with_extras(
        DB,
        remotely_core::adapters::virtualbox::VboxSettingsExtras {
            tpm: Some("v2_0".into()),
            ..Default::default()
        },
    );
    let core = built(Setup::new(FakeVmware::default()).with_virtualbox(fake)).await;
    let hardware = core.host_details.vm_specs(&core.ctx, DB).await.unwrap().hardware;
    assert_eq!(hardware.tpm.as_deref(), Some("TPM 2.0"));
    assert_eq!(hardware.controllers[0].name, "SATA");
    assert_eq!(hardware.cdroms[0].slot, "SATA-1-0");
    assert_eq!(hardware.disks[0].provisioned_bytes, Some(25 * 1024 * 1024 * 1024));
    assert_eq!(hardware.disks[0].controller.as_deref(), Some("IntelAhci"));
    let types = core.vm_settings.guest_os_types(DB).await.unwrap();
    assert!(types.iter().any(|t| t.id == "Ubuntu_64"));
    let ws = core.vm_settings.guest_os_types(&vmx("x")).await.unwrap();
    assert!(ws.iter().any(|t| t.id == "ubuntu-64"));
}
