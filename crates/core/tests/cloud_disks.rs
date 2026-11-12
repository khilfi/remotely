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
    let mut fake = FakeVmware::default();
    for name in ["web", "app"] {
        let folder = root.join(name);
        std::fs::create_dir_all(&folder).unwrap();
        let disk = folder.join(format!("{name}.vmdk"));
        std::fs::write(&disk, img::vmdk_sparse(&format!("{name}.vmdk"), 32 * MB, false)).unwrap();
        let vmx = folder.join(format!("{name}.vmx")).display().to_string();
        fake = fake
            .in_library(&vmx, Some(name))
            .with_vmx_text(&vmx, &vmx_text(name))
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
    wait_finished(&mut rx, job).await
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
    let vdi = root.join("other.vdi");
    std::fs::write(&vdi, img::vdi(8 * MB, 1)).unwrap();
    let mut setup = Setup::new(FakeVmware::default()).with_virtualbox(virtualbox(&root));
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
        "Its 2 disks go, the first booting and the others attached in order, on SATA, booting with UEFI (as its partition table says)",
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
            .any(|n| n.contains("on IDE, booting with UEFI (as you chose)")),
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
