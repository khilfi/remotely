//! G1 (docs/plan-0.8.md), a cloud server's disks, end to end with the fakes: VM-31 "Attach an existing disk"
//! through the bus (tier, preview, approval, the job, the audit) on the fake Workstation's .vmx and the fake
//! VirtualBox's VBoxManage calls, its copies made by `FakeDiskTools`; and CV-04, a cloud export's system disk and
//! data disk imported as one VM, with SATA, the firmware its partition table says and the first boot's NoCloud seed.
//! Every disk is a small image from `fakes::disk_images`, made at run time in the system temp folder; no real VM,
//! disk or export is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::catalog::profiles::Firmware;
use remotely_core::catalog::sizes::DiskController;
use remotely_core::catalog::{AfterDeploy, Network};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SubmitOutcome};
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::seed::read_joliet;
use remotely_core::deploy::service::{ImportCloudInit, ImportRequest};
use remotely_core::domain::{Environment, PowerState, TargetRef};
use remotely_core::fakes::disk_images::{self as img, Table};
use remotely_core::fakes::{FakeDiskTools, FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ActionKind, ApprovalStep, Tier};
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::vault::SecretString;
use remotely_core::vm_settings::VmDiskOp;
use remotely_core::Core;

const MB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn vmx_text(name: &str) -> String {
    format!(
        ".encoding = \"UTF-8\"\r\nconfig.version = \"8\"\r\nvirtualHW.version = \"21\"\r\ndisplayName = \"{name}\"\r\nguestOS = \"ubuntu-64\"\r\nnumvcpus = \"2\"\r\nmemsize = \"4096\"\r\nscsi0.present = \"TRUE\"\r\nscsi0.virtualDev = \"pvscsi\"\r\nscsi0:0.present = \"TRUE\"\r\nscsi0:0.fileName = \"{name}.vmdk\"\r\nethernet0.present = \"TRUE\"\r\nethernet0.connectionType = \"nat\"\r\n"
    )
}

/// `web` and `app`, two Workstation VMs whose folders are in `root` with a real disk each.
fn workstation(root: &Path) -> FakeVmware {
    workstation_with(root, "")
}

/// The same, `app`'s .vmx with `app_extra`'s lines too.
fn workstation_with(root: &Path, app_extra: &str) -> FakeVmware {
    let mut fake = FakeVmware::default();
    for name in ["web", "app"] {
        let folder = root.join(name);
        std::fs::create_dir_all(&folder).unwrap();
        let disk = folder.join(format!("{name}.vmdk"));
        std::fs::write(&disk, img::vmdk_sparse(&format!("{name}.vmdk"), 32 * MB, false)).unwrap();
        let vmx = folder.join(format!("{name}.vmx")).display().to_string();
        let mut text = vmx_text(name);
        if name == "app" {
            text.push_str(app_extra);
        }
        fake = fake
            .in_library(&vmx, Some(name))
            .with_vmx_text(&vmx, &text)
            .with_disk(&disk.display().to_string(), 32);
    }
    fake
}

fn vmx_of(root: &Path, name: &str) -> String {
    root.join(name).join(format!("{name}.vmx")).display().to_string()
}

fn vm_at(key: &str) -> TargetRef {
    TargetRef::Vm {
        vmx_path: key.to_owned(),
    }
}

fn attach(key: &str, path: &Path, copy: bool) -> Command {
    Command::VmDisk {
        targets: vec![vm_at(key)],
        op: VmDiskOp::Attach {
            path: path.display().to_string(),
            copy,
            bus: None,
            seen: None,
        },
    }
}

fn asked(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

async fn approve(core: &Core, request: &ApprovalRequest) -> JobStatus {
    approve_job(core, request).await.1
}

/// The approval's job and how it ended.
async fn approve_job(core: &Core, request: &ApprovalRequest) -> (uuid::Uuid, JobStatus) {
    let mut rx = core.jobs.subscribe();
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("G1 test".into()),
        safety_snapshot: None,
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    (job, wait_finished(&mut rx, job).await)
}

/// Each target's error of a job that ran, joined.
async fn errors_of(core: &Core, job: uuid::Uuid) -> String {
    core.store
        .job_targets(&core.ctx(), job)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|t| t.error)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The one VM's preview line, or its problem.
fn change_of(request: &ApprovalRequest) -> (Vec<String>, Option<String>) {
    let preview = request.vm_change.as_ref().expect("a VM change preview");
    (preview.targets[0].changes.clone(), preview.targets[0].problem.clone())
}

async fn last_finished(core: &Core) -> String {
    core.store
        .recent_audit(&core.ctx(), 30)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event == "job_finished")
        .and_then(|e| e.detail)
        .unwrap_or_default()
}

// ---- VM-31 on Workstation ----------------------------------------------------------------------------

#[tokio::test]
async fn a_data_disk_is_copied_into_the_vms_folder_by_vdiskmanager_as_a_medium_change() {
    let root = temp_folder("vm31-copy");
    let exports = root.join("exports");
    std::fs::create_dir_all(&exports).unwrap();
    let data = exports.join("web01_Data_Disk.vmdk");
    let bytes = img::vmdk_sparse("web01_Data_Disk.vmdk", 16 * MB, false);
    std::fs::write(&data, &bytes).unwrap();
    let setup = Setup::new(workstation(&root));
    let fake = Arc::clone(&setup.vmware);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");

    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap());
    assert_eq!(request.action, ActionKind::VmDiskAttach);
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.steps, [ApprovalStep::Confirm]);
    assert_eq!(
        request.summary,
        "Attach web01_Data_Disk.vmdk to 1 VM (copied into its folder)"
    );
    let (changes, problem) = change_of(&request);
    assert_eq!(problem, None);
    // The file, its size and where it goes.
    let line = &changes[0];
    for part in [
        data.display().to_string(),
        "16 MB".into(),
        "on scsi0:1".into(),
        "copied by vmware-vdiskmanager".into(),
        root.join("web").join("web-1.vmdk").display().to_string(),
        "the source is only read".into(),
    ] {
        assert!(line.contains(&part), "{part} in {line}");
    }
    assert!(tools.calls().is_empty(), "the preview runs no tool");

    assert_eq!(approve(&core, &request).await, JobStatus::Succeeded);
    let text = fake.vmx_text(&web).unwrap();
    assert!(text.contains("scsi0:1.fileName = \"web-1.vmdk\""), "{text}");
    assert!(text.contains("scsi0:1.present = \"TRUE\""), "{text}");
    assert!(root.join("web").join("web-1.vmdk").is_file(), "the copy");
    assert!(
        tools
            .calls()
            .iter()
            .any(|c| c.contains("vmware-vdiskmanager") && c.contains("-r")),
        "{:?}",
        tools.calls()
    );
    assert_eq!(std::fs::read(&data).unwrap(), bytes, "the source as it was");
    assert!(
        fake.backups().is_empty(),
        "the .vmx backup went once the change was made"
    );
    let leftovers: Vec<_> = std::fs::read_dir(root.join("web"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".remotely-attach"))
        .collect();
    assert!(leftovers.is_empty(), "the work folder goes");
    assert!(last_finished(&core).await.contains("web-1.vmdk"));

    // The same disk again is refused: the VM has its copy, not the source, so a second copy goes in as web-2.
    let again = asked(core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap());
    assert!(change_of(&again).0[0].contains("web-2.vmdk"));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn a_disk_used_where_it_is_is_named_by_its_path_and_says_so() {
    let root = temp_folder("vm31-inplace");
    let exports = root.join("exports");
    std::fs::create_dir_all(&exports).unwrap();
    let data = exports.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let stream = exports.join("stream.vmdk");
    std::fs::write(&stream, img::vmdk_sparse("stream.vmdk", 8 * MB, true)).unwrap();
    let qcow = exports.join("data.qcow2");
    std::fs::write(&qcow, img::qcow2(8 * MB, None)).unwrap();
    let setup = Setup::new(workstation(&root));
    let fake = Arc::clone(&setup.vmware);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");

    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, false)).await.unwrap());
    assert_eq!(request.tier, Tier::Medium);
    assert!(
        request.reasons.iter().any(|r| r.contains("used where it is")),
        "{:?}",
        request.reasons
    );
    let (changes, problem) = change_of(&request);
    assert_eq!(problem, None);
    assert!(
        changes[0].contains("used where it is, outside the VM's folder")
            && changes[0].contains("deleting the VM keeps it"),
        "{changes:?}"
    );
    assert_eq!(approve(&core, &request).await, JobStatus::Succeeded);
    let text = fake.vmx_text(&web).unwrap();
    assert!(
        text.contains(&format!("scsi0:1.fileName = \"{}\"", data.display())),
        "named by its whole path: {text}"
    );
    assert!(tools.calls().is_empty(), "nothing copied");

    // Workstation can't write a stream-optimized VMDK, nor run a qcow2: both only by copying.
    let (_, problem) = change_of(&asked(
        core.bus
            .submit(&core.ctx(), attach(&web, &stream, false))
            .await
            .unwrap(),
    ));
    assert!(problem.unwrap().contains("stream-optimized"));
    let (_, problem) = change_of(&asked(
        core.bus.submit(&core.ctx(), attach(&web, &qcow, false)).await.unwrap(),
    ));
    assert!(problem.unwrap().contains("doesn't run a qcow2 disk as it is"));
    // Copying the qcow2 needs qemu-img, which isn't here.
    let (_, problem) = change_of(&asked(
        core.bus.submit(&core.ctx(), attach(&web, &qcow, true)).await.unwrap(),
    ));
    assert!(problem.unwrap().contains("qemu-img"));
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn another_vms_disk_or_folder_and_a_held_disk_are_refused() {
    let root = temp_folder("vm31-refused");
    let spare = root.join("app").join("spare.vmdk");
    let setup = Setup::new(workstation(&root));
    std::fs::write(&spare, img::vmdk_sparse("spare.vmdk", 8 * MB, false)).unwrap();
    let held = root.join("held.vmdk");
    std::fs::write(&held, img::vmdk_sparse("held.vmdk", 8 * MB, false)).unwrap();
    let fake = Arc::clone(&setup.vmware);
    fake.set_file(&format!("{}.lck", held.display()), true);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");
    let app_disk = root.join("app").join("app.vmdk");
    let own_disk = root.join("web").join("web.vmdk");

    for (path, copy, why) in [
        (&app_disk, true, "The VM 'app' uses"),
        (&app_disk, false, "The VM 'app' uses"),
        (&spare, true, "in the folder of the VM 'app'"),
        (&own_disk, false, "The VM has"),
        (&held, false, "Workstation has"),
    ] {
        let request = asked(core.bus.submit(&core.ctx(), attach(&web, path, copy)).await.unwrap());
        let (_, problem) = change_of(&request);
        let problem = problem.unwrap_or_default();
        assert!(problem.contains(why), "{}: {problem}", path.display());
        // Approved anyway, the job refuses it too, and nothing changes.
        let before = fake.vmx_text(&web).unwrap();
        assert_eq!(approve(&core, &request).await, JobStatus::Failed);
        assert_eq!(fake.vmx_text(&web).unwrap(), before);
    }
    // VM-23's rule: Workstation's lock on the VM itself.
    fake.set_file(&format!("{web}.lck"), true);
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let (_, problem) = change_of(&asked(
        core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap(),
    ));
    assert!(problem.unwrap().contains("Workstation is using the VM"));
    // A share is never opened.
    let err = core
        .vm_settings
        .attach_disk(&web, Path::new(r"\\nas.example.com\exports\data.vmdk"), true, None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_input");
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn a_prod_vm_asks_one_tier_higher() {
    let root = temp_folder("vm31-prod");
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let setup = Setup::new(workstation(&root));
    let core = setup.build().await;
    let web = vmx_of(&root, "web");
    core.inventory
        .set_environment(&core.ctx(), std::slice::from_ref(&web), Environment::Prod)
        .await
        .unwrap();
    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap());
    assert_eq!(request.tier, Tier::High);
    std::fs::remove_dir_all(&root).unwrap();
}

// ---- VM-31 on VirtualBox --------------------------------------------------------------------------------

const DB: &str = "9d1e2f3a-0000-4000-8000-0000000000aa";

fn virtualbox(root: &Path) -> FakeVirtualBox {
    let folder = root.join("db");
    std::fs::create_dir_all(&folder).unwrap();
    let disk = folder.join("db.vdi");
    std::fs::write(&disk, img::vdi(32 * MB, 1)).unwrap();
    let vbox = folder.join("db.vbox");
    let disk_path = disk.clone();
    FakeVirtualBox::new()
        .with_vm(DB, "db", PowerState::NotRunning)
        .with_info(DB, move |info| {
            info.config_file = Some(vbox);
            info.disks[0].path = disk_path;
        })
        .with_disk_size(&disk.display().to_string(), 32)
}

#[tokio::test]
async fn virtualbox_converts_a_qcow2_into_a_vdi_beside_the_vm_and_attaches_it() {
    let root = temp_folder("vm31-vbox");
    let data = root.join("data.qcow2");
    std::fs::write(&data, img::qcow2(16 * MB, None)).unwrap();
    let mut setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox(&root));
    // VirtualBox uses a disk where it is only in the VM's own folder.
    let vdi = root.join("db").join("other.vdi");
    std::fs::write(&vdi, img::vdi(8 * MB, 1)).unwrap();
    setup.disk_tools = Arc::new(FakeDiskTools::new().with_qemu_img());
    let vbox = Arc::clone(&setup.virtualbox);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;

    let request = asked(core.bus.submit(&core.ctx(), attach(DB, &data, true)).await.unwrap());
    assert_eq!(request.tier, Tier::Medium);
    let (changes, problem) = change_of(&request);
    assert_eq!(problem, None);
    let target = root.join("db").join("db-disk-2.vdi");
    assert!(changes[0].contains("copied by qemu-img"), "{changes:?}");
    assert!(changes[0].contains(&target.display().to_string()), "{changes:?}");
    assert_eq!(approve(&core, &request).await, JobStatus::Succeeded);
    assert!(target.is_file(), "the VDI beside the VM");
    let info = vbox.info(DB).unwrap();
    assert!(info.disks.iter().any(|d| d.path == target), "{:?}", info.disks);
    assert!(tools.calls().iter().any(|c| c.starts_with("qemu-img convert")));

    // A VDI VirtualBox runs as it is, used where it is.
    let (_, status) = {
        let request = asked(core.bus.submit(&core.ctx(), attach(DB, &vdi, false)).await.unwrap());
        assert!(change_of(&request).0[0].contains("used where it is"));
        ((), approve(&core, &request).await)
    };
    assert_eq!(status, JobStatus::Succeeded);
    assert!(vbox.info(DB).unwrap().disks.iter().any(|d| d.path == vdi));
    // Its own disk is refused.
    let own = root.join("db").join("db.vdi");
    let (_, problem) = change_of(&asked(
        core.bus.submit(&core.ctx(), attach(DB, &own, false)).await.unwrap(),
    ));
    assert!(problem.unwrap().contains("The VM has"));
    std::fs::remove_dir_all(&root).unwrap();
}

// ---- CV-04: a cloud server's disks as one VM ---------------------------------------------------------------

async fn deploy_key(core: &Core) -> remotely_core::vault::SecretId {
    core.keys
        .generate(
            &core.ctx(),
            GenerateKey {
                label: "cloud key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap()
        .id
}

fn fast(core: &Core) {
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(300)),
        cleanup_tries: 2,
        cleanup_pause: Duration::from_millis(10),
    });
}

/// A cloud export: `web01_System_Disk.vmdk` (stream-optimized, `table`) and `web01_Data_Disk.vmdk` beside it.
fn export(root: &Path, table: Table) -> (PathBuf, PathBuf) {
    let folder = root.join("export");
    std::fs::create_dir_all(&folder).unwrap();
    let system = folder.join("web01_System_Disk.vmdk");
    std::fs::write(
        &system,
        img::vmdk_sparse_with("web01_System_Disk.vmdk", &img::boot_sectors(table), 64 * MB, true),
    )
    .unwrap();
    let data = folder.join("web01_Data_Disk.vmdk");
    std::fs::write(&data, img::vmdk_sparse("web01_Data_Disk.vmdk", 32 * MB, true)).unwrap();
    (system, data)
}

fn request(system: &Path, data: &[&Path], hypervisor: Hypervisor, folder: &Path) -> ImportRequest {
    ImportRequest {
        source: system.display().to_string(),
        hypervisor,
        name: "web01".into(),
        folder: Some(folder.display().to_string()),
        profile_id: "ubuntu".into(),
        firmware: None,
        size_id: None,
        vcpus: Some(2),
        cores_per_socket: None,
        memory_mb: Some(2048),
        thick: false,
        network: Network::Nat,
        host_adapter: None,
        environment: Environment::Lab,
        tags: vec![],
        after_deploy: AfterDeploy {
            create_session: false,
            link_session: false,
            clean_snapshot: false,
            open_console: false,
        },
        cloud_init: None,
        data_disks: data.iter().map(|p| p.display().to_string()).collect(),
        controller: None,
    }
}

#[tokio::test]
async fn a_system_disk_and_its_data_disk_import_into_workstation_as_one_vm_with_a_seed() {
    let root = temp_folder("cv04-ws");
    let (system, data) = export(&root, Table::GptEsp);
    let lab = root.join("lab");
    let new_vmx = lab.join("web01").join("web01.vmx").display().to_string();
    let setup = Setup::new(FakeVmware::default().with_ip(&new_vmx, "192.0.2.41")).with_real_vault();
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = core.ctx();

    // The pair is offered; the boot disk's partition table says UEFI.
    let analysis = core.deploy.analyze_import(&system).await.unwrap();
    assert!(analysis.cloud_export);
    assert_eq!(analysis.firmware_hint, Some(Firmware::Efi));
    assert_eq!(analysis.data_disk_offers.len(), 1);
    assert_eq!(
        analysis.data_disk_offers[0].path.as_deref(),
        Some(data.to_str().unwrap())
    );

    let key = deploy_key(&core).await;
    let mut ask = request(&system, &[&data], Hypervisor::Vmware, &lab);
    ask.cloud_init = Some(ImportCloudInit {
        guest_user: Some("alice".into()),
        ssh_key_id: Some(key),
        packages: vec![],
    });
    let check = core.deploy.check_import(&ctx, &ask).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    let size = preview.size.as_ref().unwrap();
    assert_eq!(size.disks.len(), 2, "the system disk and the data disk");
    assert!(size.disks.iter().all(|d| d.controller == DiskController::Sata));
    assert_eq!(preview.disk_bytes, 2 * GIB, "every disk counts, each in whole GB");
    let capacity = check.capacity.unwrap();
    assert_eq!(
        capacity.drives.iter().map(|d| d.adds_bytes).sum::<u64>(),
        2 * GIB,
        "the capacity plan counts both disks"
    );
    for note in [
        "Its 2 disks go, the first booting and the others attached in order, on SATA (it was built for another hypervisor",
        "booting with UEFI (as its partition table says)",
        "Disk 2 (VMDK) becomes the VM's",
        "hostname web01, alice with sudo and your SSH key, and DHCP on whichever network card it has; never a password",
        "\"can't find root\"",
    ] {
        assert!(preview.notes.iter().any(|n| n.contains(note)), "{note}: {:?}", preview.notes);
    }

    let approval = asked(core.deploy.submit_import(&ctx, &ask).await.unwrap());
    assert_eq!(approval.tier, Tier::Medium);
    assert_eq!(approve(&core, &approval).await, JobStatus::Succeeded);

    let text = fake.vmx_text(&new_vmx).expect("the .vmx");
    for line in [
        "firmware = \"efi\"",
        "sata0.present = \"TRUE\"",
        "sata0:0.fileName = \"web01.vmdk\"",
        "sata0:1.fileName = \"web01-1.vmdk\"",
        "sata0:2.deviceType = \"cdrom-image\"",
        "sata0:2.fileName = \"web01-cidata.iso\"",
    ] {
        assert!(text.contains(line), "{line} in {text}");
    }
    assert!(
        !text.contains("guestinfo.userdata"),
        "a disk from another hypervisor reads the seed, not guestinfo"
    );
    assert!(!text.contains("scsi0"), "{text}");
    // The seed: the user, the key's public half, DHCP on any card; no password.
    let seed = read_joliet(&std::fs::read(lab.join("web01").join("web01-cidata.iso")).unwrap()).unwrap();
    let file = |name: &str| String::from_utf8(seed.files.iter().find(|(n, _)| n == name).unwrap().1.clone()).unwrap();
    let user_data = file("user-data");
    assert!(user_data.contains("  - name: \"alice\""), "{user_data}");
    assert!(user_data.contains("ssh-ed25519 "), "{user_data}");
    assert!(user_data.contains("hostname: \"web01\""));
    // Only the new user's locked password; sshd's own setting stays as the server had it.
    assert!(user_data.contains("    lock_passwd: true"));
    for word in [
        "plain_text_passwd",
        "hashed_passwd",
        "chpasswd",
        "password:",
        " passwd:",
        "ssh_pwauth",
    ] {
        assert!(!user_data.contains(word), "{word}");
    }
    let network = file("network-config");
    assert!(
        network.contains("version: 2") && network.contains("name: \"e*\""),
        "{network}"
    );
    // Once the guest has booted (its IP shows), the seed's drive is disconnected.
    assert!(
        fake.calls()
            .iter()
            .any(|c| c.contains("disconnectNamedDevice") && c.ends_with("sata0:2")),
        "{:?}",
        fake.calls()
    );
    let finished = last_finished(&core).await;
    assert!(
        finished.contains("seed disconnected after the first boot"),
        "{finished}"
    );
    assert!(finished.contains("\"can't find root\""), "{finished}");
    // Rule 8: the new VM is the workspace's.
    core.store.require_vm_here(&ctx, &new_vmx).await.unwrap();
    assert!(system.is_file() && data.is_file(), "the export stays as it was");
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn an_mbr_disk_boots_with_bios_unless_the_user_picks_and_the_pair_imports_into_virtualbox() {
    let root = temp_folder("cv04-vbox");
    let (system, data) = export(&root, Table::Mbr);
    let lab = root.join("lab");
    let setup = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new())
        .with_real_vault();
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = core.ctx();

    let ask = request(&system, &[&data], Hypervisor::VirtualBox, &lab);
    let preview = core.deploy.check_import(&ctx, &ask).await.unwrap().preview.unwrap();
    assert!(
        preview
            .notes
            .iter()
            .any(|n| n.contains("booting with BIOS (as its partition table says)")),
        "{:?}",
        preview.notes
    );
    let mut chosen = ask.clone();
    chosen.firmware = Some(Firmware::Efi);
    chosen.controller = Some(DiskController::Ide);
    let preview = core.deploy.check_import(&ctx, &chosen).await.unwrap().preview.unwrap();
    assert!(
        preview
            .notes
            .iter()
            .any(|n| n.contains("on IDE (as you chose), booting with UEFI (as you chose)")),
        "the user's choice wins: {:?}",
        preview.notes
    );

    let mut ask = ask;
    ask.cloud_init = Some(ImportCloudInit {
        guest_user: Some("bob".into()),
        ssh_key_id: Some(deploy_key(&core).await),
        packages: vec![],
    });
    let approval = asked(core.deploy.submit_import(&ctx, &ask).await.unwrap());
    assert_eq!(approve(&core, &approval).await, JobStatus::Succeeded);
    let vm = vbox.vm_named("web01").expect("the VM");
    assert_eq!(vm.disks.len(), 2, "{:?}", vm.disks);
    assert!(vm.disks.iter().all(|d| d.slot.starts_with("SATA")), "{:?}", vm.disks);
    assert!(
        vbox.calls().iter().any(|c| c.contains("--firmware bios")),
        "{:?}",
        vbox.calls()
    );
    // No IP showed, so the seed is still in: it has the network config.
    let iso = lab.join("web01").join("web01-cidata.iso");
    let seed = read_joliet(&std::fs::read(&iso).unwrap()).unwrap();
    assert!(seed.files.iter().any(|(n, _)| n == "network-config"));
    core.store.require_vm_here(&ctx, &vm.uuid).await.unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn data_disks_go_only_with_a_disk_image_and_at_most_eight_disks() {
    let root = temp_folder("cv04-limits");
    let (system, data) = export(&root, Table::GptEsp);
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = core.ctx();
    let lab = root.join("lab");
    let many: Vec<&Path> = std::iter::repeat_n(data.as_path(), 8).collect();
    assert!(core
        .deploy
        .check_import(&ctx, &request(&system, &many, Hypervisor::Vmware, &lab))
        .await
        .is_err());
    let twice = core
        .deploy
        .check_import(&ctx, &request(&system, &[&data, &data], Hypervisor::Vmware, &lab))
        .await
        .unwrap();
    assert!(
        twice.problems.iter().any(|p| p.message.contains("twice")),
        "{:?}",
        twice.problems
    );
    std::fs::remove_dir_all(&root).unwrap();
}

// ---- Review of PR #86 (13 Nov 2026): regression tests ------------------------------------------------------

/// A junction at `link` to `target` (no rights needed); false when this PC can't make one.
fn junction(link: &Path, target: &Path) -> bool {
    std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// HIGH 1: "another VM uses it" goes by the file, not by how its path is spelt: through `..`, a junction, a
/// snapshot delta's parent, a descriptor's extent, a VM no workspace has, and a VM whose settings can't be read.
#[tokio::test]
async fn another_vms_disk_is_refused_however_it_is_reached() {
    let root = temp_folder("vm31-spellings");
    let shared = root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    let data = shared.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let base = shared.join("base.vmdk");
    std::fs::write(&base, img::vmdk_sparse("base.vmdk", 8 * MB, false)).unwrap();
    // app names data.vmdk through `..`, and runs on a snapshot delta whose parent is base.vmdk.
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(
        root.join("app").join("app-000001.vmdk"),
        img::vmdk_descriptor(
            "monolithicSparse",
            &[(16384, "SPARSE", "app-000001-s001.vmdk")],
            Some(&base.display().to_string()),
        ),
    )
    .unwrap();
    let extra = "scsi0:1.present = \"TRUE\"\r\nscsi0:1.fileName = \"..\\shared\\data.vmdk\"\r\nscsi0:2.present = \"TRUE\"\r\nscsi0:2.fileName = \"app-000001.vmdk\"\r\n";
    // A descriptor outside every VM's folder whose flat extent is a file in app's.
    let victim = root.join("app").join("app-data-flat.vmdk");
    std::fs::write(&victim, vec![0u8; MB as usize]).unwrap();
    let exports = root.join("exports");
    std::fs::create_dir_all(&exports).unwrap();
    let evil = exports.join("evil.vmdk");
    std::fs::write(
        &evil,
        img::vmdk_descriptor("monolithicFlat", &[(2048, "FLAT", &victim.display().to_string())], None),
    )
    .unwrap();
    let setup = Setup::new(workstation_with(&root, extra));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let ctx = core.ctx();
    let web = vmx_of(&root, "web");
    let problem_of = |request: &ApprovalRequest| change_of(request).1.unwrap_or_default();

    for (path, why) in [
        (&data, "The VM 'app' uses"),
        (&base, "The VM 'app' uses"),
        (&evil, "in the folder of the VM 'app'"),
    ] {
        for copy in [false, true] {
            let request = asked(core.bus.submit(&ctx, attach(&web, path, copy)).await.unwrap());
            let problem = problem_of(&request);
            assert!(problem.contains(why), "{} (copy {copy}): {problem}", path.display());
        }
    }
    // Approved anyway, the job refuses it too and web's .vmx stays as it was.
    let before = fake.vmx_text(&web).unwrap();
    let request = asked(core.bus.submit(&ctx, attach(&web, &base, false)).await.unwrap());
    assert_eq!(approve(&core, &request).await, JobStatus::Failed);
    assert_eq!(fake.vmx_text(&web).unwrap(), before);

    // Through a junction to app's folder.
    let alias = root.join("alias");
    if junction(&alias, &root.join("app")) {
        let request = asked(
            core.bus
                .submit(&ctx, attach(&web, &alias.join("app.vmdk"), false))
                .await
                .unwrap(),
        );
        let problem = problem_of(&request);
        assert!(problem.contains("The VM 'app' uses"), "{problem}");
        std::fs::remove_dir(&alias).unwrap();
    } else {
        eprintln!("mklink /J failed here; the junction part was skipped");
    }

    // A VM no workspace has (released to Unassigned) still counts.
    core.workspaces
        .create(remotely_core::workspaces::WorkspaceInput {
            name: "Lab two".into(),
            color: Some("teal".into()),
        })
        .await
        .unwrap();
    let app = vmx_of(&root, "app");
    core.inventory.release(&ctx, std::slice::from_ref(&app)).await.unwrap();
    assert!(core.inventory.unassigned().iter().any(|v| v.vmx_path == app));
    let request = asked(core.bus.submit(&ctx, attach(&web, &data, false)).await.unwrap());
    let problem = problem_of(&request);
    assert!(problem.contains("The VM 'app' uses"), "{problem}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn a_vm_whose_settings_cant_be_read_stops_an_attach() {
    const OLD: &str = "9d1e2f3a-0000-4000-8000-0000000000bb";
    let root = temp_folder("vm31-unreadable");
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let setup = Setup::new(workstation(&root)).with_virtualbox(FakeVirtualBox::new().with_vm(
        OLD,
        "old",
        PowerState::NotRunning,
    ));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");
    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, false)).await.unwrap());
    assert_eq!(change_of(&request).1, None, "every VM read: fine");
    // From now on VirtualBox can't say what `old` uses.
    vbox.set_failing("showvminfo", true);
    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, false)).await.unwrap());
    let problem = change_of(&request).1.unwrap_or_default();
    assert!(problem.contains("couldn't read the VM 'old'"), "{problem}");
    std::fs::remove_dir_all(&root).unwrap();
}

/// HIGH 2: VirtualBox deletes a VM's disks with the VM and on Remove disk, so a disk outside its folder is never
/// used in place there, and Remove keeps a disk outside the folder; in the folder, the preview says it goes.
#[tokio::test]
async fn virtualbox_keeps_a_disk_outside_the_vms_folder() {
    let root = temp_folder("vm31-vbox-outside");
    let mine = root.join("mine");
    std::fs::create_dir_all(&mine).unwrap();
    let original = mine.join("original.vdi");
    std::fs::write(&original, img::vdi(8 * MB, 1)).unwrap();
    let outside = original.clone();
    let fake = virtualbox(&root).with_info(DB, move |info| {
        info.disks.push(remotely_core::adapters::virtualbox::VboxDisk {
            slot: "SATA-1-0".into(),
            path: outside,
        });
    });
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(fake);
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;

    let other = mine.join("other.vdi");
    std::fs::write(&other, img::vdi(8 * MB, 1)).unwrap();
    let request = asked(core.bus.submit(&core.ctx(), attach(DB, &other, false)).await.unwrap());
    let problem = change_of(&request).1.unwrap_or_default();
    assert!(problem.contains("VirtualBox deletes a VM's disks"), "{problem}");
    // The disk it has outside its folder (attached outside Remotely): Remove refuses rather than delete it.
    let remove = Command::VmDisk {
        targets: vec![vm_at(DB)],
        op: VmDiskOp::Remove {
            slot: "SATA-1-0".into(),
        },
    };
    let request = asked(core.bus.submit(&core.ctx(), remove).await.unwrap());
    let problem = change_of(&request).1.unwrap_or_default();
    assert!(problem.contains("outside the VM's folder"), "{problem}");
    assert_eq!(approve(&core, &request).await, JobStatus::Failed);
    assert!(original.is_file(), "the user's own file stays");
    assert!(!vbox
        .calls()
        .iter()
        .any(|c| c.contains("closemedium") && c.contains("original.vdi")));
    // In its folder, used where it is, the preview says deleting goes with it.
    let inner = root.join("db").join("extra.vdi");
    std::fs::write(&inner, img::vdi(8 * MB, 1)).unwrap();
    let request = asked(core.bus.submit(&core.ctx(), attach(DB, &inner, false)).await.unwrap());
    let (changes, problem) = change_of(&request);
    assert_eq!(problem, None);
    assert!(
        changes[0].contains("deleting the VM or removing the disk deletes it"),
        "{changes:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

/// HIGH 3, and copies that fail: only the files the job made go, never the user's.
#[tokio::test]
async fn a_failed_copy_deletes_only_what_it_made() {
    use remotely_core::adapters::disk_tools::Tool;
    let root = temp_folder("vm31-failed-copy");
    let theirs = root.join("web").join("web-1-flat.vmdk");
    let setup = Setup::new(workstation(&root));
    std::fs::write(&theirs, b"the user's own extent").unwrap();
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let fake = Arc::clone(&setup.vmware);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");
    let before = fake.vmx_text(&web).unwrap();

    // web-1's flat extent is taken, so the copy is web-2.
    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap());
    let line = change_of(&request).0[0].clone();
    assert!(line.contains("web-2.vmdk"), "{line}");
    // The copy fails.
    tools.set_failing(Tool::VdiskManager, true);
    assert_eq!(approve(&core, &request).await, JobStatus::Failed);
    tools.set_failing(Tool::VdiskManager, false);
    assert!(theirs.is_file(), "the user's file stays");
    assert!(!root.join("web").join("web-2.vmdk").exists());
    // The copy is made but the .vmx can't be written: the copy goes, the .vmx is as it was.
    fake.set_failing_vmx_write(true);
    let request = asked(core.bus.submit(&core.ctx(), attach(&web, &data, true)).await.unwrap());
    assert_eq!(approve(&core, &request).await, JobStatus::Failed);
    fake.set_failing_vmx_write(false);
    assert!(
        !root.join("web").join("web-2.vmdk").exists(),
        "the copy the VM didn't take"
    );
    assert!(theirs.is_file());
    assert_eq!(fake.vmx_text(&web).unwrap(), before);
    let leftovers: Vec<_> = std::fs::read_dir(root.join("web"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".remotely-attach"))
        .collect();
    assert!(leftovers.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn a_virtualbox_attach_that_fails_closes_and_deletes_its_copy() {
    let root = temp_folder("vm31-vbox-failed");
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox(&root));
    let vbox = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    vbox.set_failing("storageattach", true);
    let request = asked(core.bus.submit(&core.ctx(), attach(DB, &data, true)).await.unwrap());
    let target = root.join("db").join("db-disk-2.vmdk");
    assert!(change_of(&request).0[0].contains(&target.display().to_string()));
    assert_eq!(approve(&core, &request).await, JobStatus::Failed);
    assert!(!target.exists(), "the copy the VM didn't take");
    assert!(vbox
        .calls()
        .iter()
        .any(|c| c.contains("closemedium disk") && c.contains("db-disk-2.vmdk")));
    assert!(data.is_file());
    std::fs::remove_dir_all(&root).unwrap();
}

/// MEDIUM 4: what was approved is what is attached: a file changed between the approval and the job is refused.
#[tokio::test]
async fn a_disk_changed_since_its_approval_is_refused() {
    let root = temp_folder("vm31-changed");
    let data = root.join("data.vmdk");
    std::fs::write(&data, img::vmdk_sparse("data.vmdk", 8 * MB, false)).unwrap();
    let setup = Setup::new(workstation(&root));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    let web = vmx_of(&root, "web");
    for copy in [true, false] {
        let request = asked(core.vm_settings.attach_disk(&web, &data, copy, None).await.unwrap());
        assert_eq!(change_of(&request).1, None);
        // Swapped for a larger disk after the approval was asked.
        std::fs::write(&data, img::vmdk_sparse("data.vmdk", 16 * MB, false)).unwrap();
        let before = fake.vmx_text(&web).unwrap();
        let (job, status) = approve_job(&core, &request).await;
        assert_eq!(status, JobStatus::Failed);
        let errors = errors_of(&core, job).await;
        assert!(errors.contains("changed since you chose it"), "{errors}");
        assert_eq!(fake.vmx_text(&web).unwrap(), before);
    }
    // As it is now, it attaches.
    let request = asked(core.vm_settings.attach_disk(&web, &data, true, None).await.unwrap());
    assert_eq!(approve(&core, &request).await, JobStatus::Succeeded);
    std::fs::remove_dir_all(&root).unwrap();
}

/// MEDIUM 5: a disk VMware made keeps the controller its guest booted from; only disks built elsewhere go on SATA.
#[tokio::test]
async fn a_vmware_made_disk_keeps_its_controller() {
    let root = temp_folder("cv04-vmware-made");
    let folder = root.join("esx");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("app-flat.vmdk"),
        img::raw_with(&img::boot_sectors(Table::Mbr), 8 * MB),
    )
    .unwrap();
    let made_for = |adapter: &str| {
        img::vmdk_descriptor("monolithicFlat", &[(16384, "FLAT", "app-flat.vmdk")], None).replace(
            "ddb.adapterType = \"lsilogic\"",
            &format!("ddb.adapterType = \"{adapter}\"\nddb.longContentID = \"0123456789abcdef0123456789abcdef\""),
        )
    };
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = core.ctx();
    let lab = root.join("lab");
    for (adapter, controller, model, why) in [
        ("lsilogic", DiskController::Scsi, None, "made by VMware for SCSI"),
        ("buslogic", DiskController::Scsi, Some("buslogic"), "BusLogic"),
        ("ide", DiskController::Ide, None, "made by VMware for IDE"),
    ] {
        let disk = folder.join(format!("app-{adapter}.vmdk"));
        std::fs::write(&disk, made_for(adapter)).unwrap();
        let ask = request(&disk, &[], Hypervisor::Vmware, &lab);
        let check = core.deploy.check_import(&ctx, &ask).await.unwrap();
        assert!(check.problems.is_empty(), "{adapter}: {:?}", check.problems);
        let preview = check.preview.unwrap();
        let boot = &preview.size.as_ref().unwrap().disks[0];
        assert_eq!(boot.controller, controller, "{adapter}");
        if let Some(model) = model {
            assert_eq!(boot.controller_model, model);
        }
        assert!(
            preview.notes.iter().any(|n| n.contains(why)),
            "{adapter}: {:?}",
            preview.notes
        );
    }
    // The same descriptor without VMware's own keys (as qemu-img writes it): SATA.
    let qemu = folder.join("app-qemu.vmdk");
    std::fs::write(
        &qemu,
        img::vmdk_descriptor("monolithicFlat", &[(16384, "FLAT", "app-flat.vmdk")], None),
    )
    .unwrap();
    let preview = core
        .deploy
        .check_import(&ctx, &request(&qemu, &[], Hypervisor::Vmware, &lab))
        .await
        .unwrap()
        .preview
        .unwrap();
    assert_eq!(preview.size.as_ref().unwrap().disks[0].controller, DiskController::Sata);
    std::fs::remove_dir_all(&root).unwrap();
}

/// MEDIUM 6: IDE past its slots, and NVMe with BIOS, are refused before anything is made.
#[tokio::test]
async fn ide_past_its_slots_and_nvme_with_bios_are_refused() {
    let root = temp_folder("cv04-limits-controller");
    let (system, _) = export(&root, Table::Mbr);
    let mut data = Vec::new();
    for n in 1..=4 {
        let p = root.join("export").join(format!("web01_Data_Disk_{n}.vmdk"));
        std::fs::write(&p, img::vmdk_sparse(&format!("web01_Data_Disk_{n}.vmdk"), 8 * MB, true)).unwrap();
        data.push(p);
    }
    let core = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new())
        .build()
        .await;
    let ctx = core.ctx();
    let lab = root.join("lab");
    let refs: Vec<&Path> = data.iter().map(PathBuf::as_path).collect();
    let mut ide = request(&system, &refs, Hypervisor::Vmware, &lab);
    ide.controller = Some(DiskController::Ide);
    let check = core.deploy.check_import(&ctx, &ide).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains("IDE takes 4 disks")),
        "five disks on IDE: {:?}",
        check.problems
    );
    let mut four = ide.clone();
    four.data_disks.truncate(3);
    assert!(core.deploy.check_import(&ctx, &four).await.unwrap().problems.is_empty());
    // VirtualBox's IDE as the deploy lays it out: two ports, one of them the seed's DVD.
    let mut vbox = request(&system, &refs[..1], Hypervisor::VirtualBox, &lab);
    vbox.controller = Some(DiskController::Ide);
    assert!(core.deploy.check_import(&ctx, &vbox).await.unwrap().problems.is_empty());
    vbox.cloud_init = Some(ImportCloudInit {
        guest_user: Some("bob".into()),
        ssh_key_id: None,
        packages: vec![],
    });
    let check = core.deploy.check_import(&ctx, &vbox).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains("IDE takes 1 disk")),
        "{:?}",
        check.problems
    );
    // NVMe boots only with UEFI; this disk's MBR says BIOS.
    let mut nvme = request(&system, &[], Hypervisor::Vmware, &lab);
    nvme.controller = Some(DiskController::Nvme);
    let check = core.deploy.check_import(&ctx, &nvme).await.unwrap();
    assert!(
        check.problems.iter().any(|p| p.message.contains("NVMe only with UEFI")),
        "{:?}",
        check.problems
    );
    nvme.firmware = Some(Firmware::Efi);
    assert!(core.deploy.check_import(&ctx, &nvme).await.unwrap().problems.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

/// An import with data disks that fails after its seed was written leaves nothing in its folder.
#[tokio::test]
async fn an_import_that_fails_partway_leaves_nothing() {
    let root = temp_folder("cv04-partway");
    let (system, data) = export(&root, Table::GptEsp);
    let lab = root.join("lab");
    let setup = Setup::new(FakeVmware::default()).with_real_vault();
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = core.ctx();
    let mut ask = request(&system, &[&data], Hypervisor::Vmware, &lab);
    ask.cloud_init = Some(ImportCloudInit {
        guest_user: Some("alice".into()),
        ssh_key_id: Some(deploy_key(&core).await),
        packages: vec![],
    });
    let approval = asked(core.deploy.submit_import(&ctx, &ask).await.unwrap());
    // Both disks are copied and the seed written; then the .vmx can't be written.
    fake.set_failing_vmx_write(true);
    assert_eq!(approve(&core, &approval).await, JobStatus::Failed);
    assert!(
        !lab.join("web01").exists(),
        "the VM's folder, its disks and its seed went"
    );
    assert!(system.is_file() && data.is_file(), "the export stays");
    std::fs::remove_dir_all(&root).unwrap();
}
