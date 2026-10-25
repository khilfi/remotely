//! CV-01, CV-02, CV-03, VM-17: conversion end to end on a core with fake hypervisors and fake conversion tools
//! ([`FakeDiskTools`], which writes small files with each format's header). Image tools' Convert through the bus (a
//! Low job with progress, the work folder, VirtualBox's media list, cancel, failures, free space), an export of a
//! powered-off VM for KVM, Proxmox and as an OVA, and imports through R2's deploy. Images are a few MB, made at run
//! time in the system temp folder; no real VM, tool or network share is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{temp_folder, Setup, VAULT_PASSWORD};
use remotely_core::adapters::disk_tools::Tool;
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::adapters::vm_hardware::{VirtualDisk, VmHardware};
use remotely_core::catalog::{AfterDeploy, HashProgress, ImageInput, Network, SourceInput};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, SubmitOutcome};
use remotely_core::convert::args::OvfVersion;
use remotely_core::convert::formats::{DiskFormat, OutputKind};
use remotely_core::convert::runner::ConvertTuning;
use remotely_core::convert::ExportTarget;
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::service::ImportRequest;
use remotely_core::domain::{Environment, TargetRef};
use remotely_core::fakes::disk_images as img;
use remotely_core::fakes::{FakeDiskTools, FakeVirtualBox, FakeVmware};
use remotely_core::jobs::{JobEvent, JobStatus};
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::vault::SecretString;
use remotely_core::Core;
use uuid::Uuid;

const MB: u64 = 1 << 20;

fn queued(outcome: SubmitOutcome) -> Uuid {
    match outcome {
        SubmitOutcome::Queued { job_id, tier, .. } => {
            assert_eq!(tier, Tier::Low);
            job_id
        }
        other => panic!("expected a Low job, got {other:?}"),
    }
}

async fn wait(core: &Core, job: Uuid) -> JobStatus {
    tokio::time::timeout(Duration::from_secs(30), core.jobs.wait(job))
        .await
        .expect("the job finished in time")
        .unwrap()
}

async fn outputs(core: &Core, job: Uuid) -> Vec<(String, Option<String>, Option<String>)> {
    core.store
        .job_targets(&core.ctx, job)
        .await
        .unwrap()
        .into_iter()
        .map(|t| (t.status, t.output, t.error))
        .collect()
}

fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

async fn core_with(tools: FakeDiskTools) -> (Core, Arc<FakeDiskTools>) {
    let mut setup = Setup::new(FakeVmware::default());
    setup.disk_tools = Arc::new(tools);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    core.set_convert_tuning(ConvertTuning {
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
    });
    (core, tools)
}

#[tokio::test]
async fn a_qcow2_converts_to_a_vmdk_as_a_low_job_with_progress_and_the_source_unchanged() {
    let dir = temp_folder("conv-qcow2");
    let source = dir.join("rocky.qcow2");
    std::fs::write(&source, img::qcow2(64 * MB, None)).unwrap();
    let before = std::fs::read(&source).unwrap();
    let (core, tools) = core_with(FakeDiskTools::new().with_qemu_img()).await;

    // Convert's options: what each output takes, and with which tool.
    let options = core.convert.options(&source).await.unwrap();
    assert_eq!(options.info.format, DiskFormat::Qcow2);
    let vmdk = options
        .outputs
        .iter()
        .find(|o| o.kind == OutputKind::VmdkSparse)
        .unwrap();
    assert!(vmdk.reason.is_none());
    assert_eq!(vmdk.plan, "qemu-img (qcow2 to VMDK, growable (monolithicSparse))");
    let esx = options.outputs.iter().find(|o| o.kind == OutputKind::VmdkEsx).unwrap();
    assert_eq!(
        esx.steps.iter().map(|s| s.tool).collect::<Vec<_>>(),
        [Tool::QemuImg, Tool::VdiskManager]
    );

    let mut events = core.jobs.subscribe();
    let output = dir.join("rocky.vmdk");
    let job = queued(
        core.convert
            .submit_convert(&core.ctx, &source, &output, OutputKind::VmdkSparse, false)
            .await
            .unwrap(),
    );
    assert_eq!(
        wait(&core, job).await,
        JobStatus::Succeeded,
        "{:?}",
        outputs(&core, job).await
    );
    let made = core.convert.inspect(&output).await.unwrap();
    assert_eq!(made.format, DiskFormat::Vmdk);
    assert_eq!(made.virtual_bytes, Some(64 * MB));
    assert_eq!(std::fs::read(&source).unwrap(), before, "the source is never changed");
    assert_eq!(names_in(&dir), ["rocky.qcow2", "rocky.vmdk"], "the work folder is gone");
    let calls = tools.calls();
    assert!(
        calls[0].starts_with("qemu-img convert -p -f qcow2 -O vmdk -o subformat=monolithicSparse"),
        "{calls:?}"
    );
    let note = outputs(&core, job).await[0].1.clone().unwrap();
    assert!(note.contains("with qemu-img (qcow2 to VMDK"), "{note}");
    // The job told how far it was.
    let mut progress = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let JobEvent::TargetProgress {
            job_id,
            percent,
            step,
            target,
        } = event
        {
            if job_id == job {
                assert!(target.starts_with("disk-image/"));
                progress.push((percent, step));
            }
        }
    }
    assert!(!progress.is_empty());
    assert!(progress.iter().any(|(p, _)| *p >= 50.0), "{progress:?}");
    // The audit log names the job's start and end with what it made.
    let audit = core.store.recent_audit(&core.ctx, 50).await.unwrap();
    assert!(
        audit
            .iter()
            .any(|e| e.action.starts_with("Convert rocky.qcow2 to rocky.vmdk")),
        "{audit:?}"
    );

    // A second conversion to the same name is refused: nothing is ever replaced.
    let err = core
        .convert
        .submit_convert(&core.ctx, &source, &output, OutputKind::VmdkSparse, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("is there already"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn without_qemu_img_qcow2_and_vhdx_say_they_need_it() {
    let dir = temp_folder("conv-noqemu");
    let source = dir.join("rocky.qcow2");
    std::fs::write(&source, img::qcow2(64 * MB, None)).unwrap();
    let (core, _) = core_with(FakeDiskTools::new()).await;
    let tools = core.convert.tools(&core.ctx).await.unwrap();
    assert!(tools.paths.qemu_img.is_none());
    assert_eq!(tools.download_page, "https://www.qemu.org/download/#windows");
    let options = core.convert.options(&source).await.unwrap();
    assert!(options.outputs.iter().all(|o| o.needs_qemu_img && o.reason.is_some()));
    let err = core
        .convert
        .submit_convert(
            &core.ctx,
            &source,
            &dir.join("rocky.vdi"),
            OutputKind::VdiDynamic,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "conversion_refused");
    assert!(err.to_string().contains("needs qemu-img"), "{err}");
    // A VHD still converts: VirtualBox reads it.
    let vhd = dir.join("dc01.vhd");
    std::fs::write(&vhd, img::vhd_fixed(MB)).unwrap();
    let options = core.convert.options(&vhd).await.unwrap();
    let vdi = options
        .outputs
        .iter()
        .find(|o| o.kind == OutputKind::VdiDynamic)
        .unwrap();
    assert!(vdi.reason.is_none(), "{:?}", vdi.reason);
    let vhdx = options
        .outputs
        .iter()
        .find(|o| o.kind == OutputKind::VhdxDynamic)
        .unwrap();
    assert!(vhdx.needs_qemu_img);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn virtualbox_forgets_the_media_a_conversion_registered() {
    let dir = temp_folder("conv-vbox");
    let source = dir.join("dc01.vhd");
    std::fs::write(&source, img::vhd_fixed(2 * MB)).unwrap();
    let (core, tools) = core_with(FakeDiskTools::new()).await;
    // A medium VirtualBox knew before stays registered.
    let known = PathBuf::from(r"C:\VMs\other\other.vdi");
    tools.register(&known);
    let output = dir.join("dc01.vdi");
    let job = queued(
        core.convert
            .submit_convert(&core.ctx, &source, &output, OutputKind::VdiFixed, false)
            .await
            .unwrap(),
    );
    assert_eq!(
        wait(&core, job).await,
        JobStatus::Succeeded,
        "{:?}",
        outputs(&core, job).await
    );
    let calls = tools.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("VBoxManage clonemedium disk") && c.contains("--variant Fixed")),
        "{calls:?}"
    );
    assert!(
        calls.iter().filter(|c| c.starts_with("VBoxManage closemedium")).count() >= 2,
        "{calls:?}"
    );
    assert_eq!(tools.registered(), [known.display().to_string()]);
    assert_eq!(
        core.convert.inspect(&output).await.unwrap().subformat.as_deref(),
        Some("VDI (fixed)")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_failed_or_cancelled_conversion_leaves_nothing_and_space_is_checked_first() {
    let dir = temp_folder("conv-fail");
    let source = dir.join("disk.raw");
    std::fs::write(&source, img::raw_mbr(4 * MB)).unwrap();
    let (core, tools) = core_with(FakeDiskTools::new().with_qemu_img()).await;
    tools.set_failing(Tool::QemuImg, true);
    let job = queued(
        core.convert
            .submit_convert(&core.ctx, &source, &dir.join("disk.qcow2"), OutputKind::Qcow2, false)
            .await
            .unwrap(),
    );
    assert_eq!(wait(&core, job).await, JobStatus::Failed);
    let (_, _, error) = outputs(&core, job).await.remove(0);
    assert!(error.unwrap().contains("qemu-img failed"));
    assert_eq!(names_in(&dir), ["disk.raw"]);

    tools.set_failing(Tool::QemuImg, false);
    tools.set_delay(Duration::from_secs(20));
    let job = queued(
        core.convert
            .submit_convert(&core.ctx, &source, &dir.join("disk.qcow2"), OutputKind::Qcow2, false)
            .await
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(core.jobs.cancel(job));
    assert_eq!(wait(&core, job).await, JobStatus::Cancelled);
    assert_eq!(names_in(&dir), ["disk.raw"], "the work folder went with the cancel");

    // No room: refused before anything is written.
    let mut setup = Setup::new(FakeVmware::default());
    setup.disk_tools = Arc::new(FakeDiskTools::new().with_qemu_img());
    setup.host.free_disk_pct = 0.0;
    let full = setup.build().await;
    let err = full
        .convert
        .submit_convert(&full.ctx, &source, &dir.join("disk.vhd"), OutputKind::VhdFixed, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("free"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

const WEB_VMX: &str = "displayName = \"web01\"\r\nguestOS = \"ubuntu-64\"\r\nnumvcpus = \"2\"\r\nmemsize = \"2048\"\r\nscsi0:0.fileName = \"web01.vmdk\"\r\n";

/// A powered-off Workstation VM whose one disk is a real (small) file in `dir`.
fn workstation_vm(dir: &Path, environment_running: bool) -> (FakeVmware, String) {
    let folder = dir.join("web01");
    std::fs::create_dir_all(&folder).unwrap();
    let disk = folder.join("web01.vmdk");
    std::fs::write(&disk, img::vmdk_sparse("web01.vmdk", 8 * MB, false)).unwrap();
    let vmx = folder.join("web01.vmx").display().to_string();
    std::fs::write(&vmx, WEB_VMX).unwrap();
    let hardware = VmHardware {
        guest_os: Some("ubuntu-64".into()),
        guest_os_name: Some("Ubuntu 24.04.1 LTS".into()),
        vcpus: Some(2),
        cores_per_socket: Some(1),
        memory_mb: Some(2048),
        firmware: Some("UEFI".into()),
        disks: vec![VirtualDisk {
            slot: "scsi0:0".into(),
            path: disk.display().to_string(),
            format: Some("monolithicSparse".into()),
            provisioned_bytes: Some(8 * MB),
            ..Default::default()
        }],
        ..Default::default()
    };
    let fake = if environment_running {
        FakeVmware::with_running([vmx.clone()])
    } else {
        FakeVmware::default()
    };
    (
        fake.in_library(&vmx, Some("web01"))
            .with_vmx_text(&vmx, WEB_VMX)
            .with_hardware(&vmx, hardware),
        vmx,
    )
}

async fn export_core(fake: FakeVmware, tools: FakeDiskTools) -> (Core, Arc<FakeDiskTools>) {
    let mut setup = Setup::new(fake);
    setup.disk_tools = Arc::new(tools);
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx).await.unwrap();
    (core, tools)
}

#[tokio::test]
async fn a_vm_exports_for_kvm_with_its_xml_and_readme() {
    let dir = temp_folder("export-kvm");
    let (fake, vmx) = workstation_vm(&dir, false);
    let (core, tools) = export_core(fake, FakeDiskTools::new().with_qemu_img()).await;
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let options = core.convert.export_options(&core.ctx, &vmx).await.unwrap();
    assert_eq!(options.refusal, None);
    let kvm = options.targets.iter().find(|t| t.target == ExportTarget::Kvm).unwrap();
    assert!(kvm.reason.is_none(), "{:?}", kvm.reason);
    assert_eq!(kvm.disks[0].file, "web01.qcow2");
    assert_eq!(kvm.folder_name, "web01-kvm");
    let ovf2 = options
        .targets
        .iter()
        .find(|t| {
            t.target
                == ExportTarget::Appliance {
                    ova: true,
                    version: OvfVersion::V2,
                }
        })
        .unwrap();
    assert!(ovf2.reason.as_deref().unwrap().contains("OVF 1.0 only"));

    let job = queued(
        core.convert
            .submit_export(&core.ctx, &vmx, ExportTarget::Kvm, &out)
            .await
            .unwrap(),
    );
    assert_eq!(
        wait(&core, job).await,
        JobStatus::Succeeded,
        "{:?}",
        outputs(&core, job).await
    );
    let folder = out.join("web01-kvm");
    assert_eq!(names_in(&folder), ["README.md", "web01.qcow2", "web01.xml"]);
    let xml = std::fs::read_to_string(folder.join("web01.xml")).unwrap();
    assert!(
        xml.contains("<name>web01</name>") && xml.contains("<os firmware='efi'>"),
        "{xml}"
    );
    let readme = std::fs::read_to_string(folder.join("README.md")).unwrap();
    assert!(readme.contains("virsh define web01.xml"), "{readme}");
    assert!(readme.contains("Uninstall the VMware Tools"), "{readme}");
    assert!(
        tools
            .calls()
            .iter()
            .any(|c| c.starts_with("qemu-img convert -p -f vmdk -O qcow2")),
        "{:?}",
        tools.calls()
    );
    // Again into the same folder: refused, the first export stays.
    let err = core
        .convert
        .submit_export(&core.ctx, &vmx, ExportTarget::Kvm, &out)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("is there already"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn proxmox_takes_a_vmdk_without_qemu_img_and_an_ova_comes_from_ovftool() {
    let dir = temp_folder("export-proxmox");
    let (fake, vmx) = workstation_vm(&dir, false);
    let (core, tools) = export_core(fake, FakeDiskTools::new()).await;
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let job = queued(
        core.convert
            .submit_export(&core.ctx, &vmx, ExportTarget::Proxmox, &out)
            .await
            .unwrap(),
    );
    assert_eq!(
        wait(&core, job).await,
        JobStatus::Succeeded,
        "{:?}",
        outputs(&core, job).await
    );
    let folder = out.join("web01-proxmox");
    assert_eq!(names_in(&folder), ["README.md", "import-to-proxmox.sh", "web01.vmdk"]);
    let script = std::fs::read_to_string(folder.join("import-to-proxmox.sh")).unwrap();
    assert!(
        script.contains("qm importdisk \"$VMID\" 'web01.vmdk' \"$STORAGE\""),
        "{script}"
    );
    assert!(!script.contains('\r'), "the script runs on Linux");
    // KVM needs qemu-img: the option says so.
    let options = core.convert.export_options(&core.ctx, &vmx).await.unwrap();
    let kvm = options.targets.iter().find(|t| t.target == ExportTarget::Kvm).unwrap();
    assert!(kvm.needs_qemu_img, "{:?}", kvm.reason);

    let ova = ExportTarget::Appliance {
        ova: true,
        version: OvfVersion::V1,
    };
    let job = queued(core.convert.submit_export(&core.ctx, &vmx, ova, &out).await.unwrap());
    assert_eq!(
        wait(&core, job).await,
        JobStatus::Succeeded,
        "{:?}",
        outputs(&core, job).await
    );
    assert_eq!(names_in(&out.join("web01-ova")), ["README.md", "web01.ova"]);
    assert!(tools
        .calls()
        .iter()
        .any(|c| c.starts_with("ovftool --shaAlgorithm=SHA256 --noImageFiles") && c.ends_with("web01.ova")));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_running_vm_isnt_exported_and_a_prod_vms_export_asks() {
    let dir = temp_folder("export-refused");
    let (fake, vmx) = workstation_vm(&dir, true);
    let (core, _) = export_core(fake, FakeDiskTools::new().with_qemu_img()).await;
    let options = core.convert.export_options(&core.ctx, &vmx).await.unwrap();
    assert!(options.refusal.unwrap().contains("running"));
    let err = core
        .convert
        .submit_export(&core.ctx, &vmx, ExportTarget::Raw, &dir)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Shut it down first"), "{err}");

    let dir2 = temp_folder("export-prod");
    let (fake, vmx) = workstation_vm(&dir2, false);
    let (core, _) = export_core(fake, FakeDiskTools::new().with_qemu_img()).await;
    core.inventory
        .set_environment(&core.ctx, std::slice::from_ref(&vmx), Environment::Prod)
        .await
        .unwrap();
    let outcome = core
        .convert
        .submit_export(&core.ctx, &vmx, ExportTarget::Azure, &dir2)
        .await
        .unwrap();
    let SubmitOutcome::NeedsApproval { request } = outcome else {
        panic!("a Prod VM's export asks");
    };
    assert_eq!(request.tier, Tier::Medium);
    assert_eq!(request.steps, [ApprovalStep::Confirm]);
    assert!(request.summary.contains("Export web01 as fixed VHD for Azure"));
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&dir2).unwrap();
}

async fn approve(core: &Core, request: &ApprovalRequest) -> JobStatus {
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("lab".into()),
        safety_snapshot: None,
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    wait(core, job).await
}

fn import_request(source: &Path, hypervisor: Hypervisor, folder: &Path) -> ImportRequest {
    ImportRequest {
        source: source.display().to_string(),
        hypervisor,
        name: "db01".into(),
        folder: Some(folder.display().to_string()),
        profile_id: "ubuntu".into(),
        firmware: None,
        size_id: None,
        vcpus: None,
        cores_per_socket: None,
        memory_mb: None,
        thick: false,
        network: Network::Nat,
        host_adapter: None,
        environment: Environment::Lab,
        tags: vec!["imported".into()],
        after_deploy: AfterDeploy {
            create_session: false,
            link_session: false,
            clean_snapshot: false,
            open_console: false,
        },
        cloud_init: None,
    }
}

#[tokio::test]
async fn a_libvirt_vm_imports_into_workstation_as_a_deploy() {
    let dir = temp_folder("import-libvirt");
    std::fs::write(dir.join("db01.qcow2"), img::qcow2(64 * MB, None)).unwrap();
    let xml = "<domain type='kvm'><name>db01</name><memory unit='MiB'>3072</memory><vcpu>3</vcpu><os firmware='efi'/><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/db01.qcow2'/></disk></devices></domain>";
    let source = dir.join("db01.xml");
    std::fs::write(&source, xml).unwrap();
    let lab = dir.join("lab");
    let mut setup = Setup::new(FakeVmware::default());
    setup.disk_tools = Arc::new(FakeDiskTools::new().with_qemu_img());
    let tools = Arc::clone(&setup.disk_tools);
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(100)),
        cleanup_tries: 2,
        cleanup_pause: Duration::from_millis(10),
    });
    let analysis = core.deploy.analyze_import(&source).await.unwrap();
    assert_eq!(analysis.suggested_name, "db01");
    assert_eq!(analysis.described.memory_mb, Some(3072));

    let request = import_request(&source, Hypervisor::Vmware, &lab);
    let check = core.deploy.check_import(&core.ctx, &request).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    let size = preview.size.as_ref().unwrap();
    assert_eq!(
        (size.sockets * size.cores_per_socket, size.memory_mb),
        (3, 3072),
        "the XML's own CPU and memory"
    );
    assert_eq!(size.disks[0].size_gb, 1, "the disk's own size, in whole GB");
    assert!(
        preview
            .notes
            .iter()
            .any(|n| n.contains("converted by qemu-img (qcow2 to VMDK")),
        "{:?}",
        preview.notes
    );

    let SubmitOutcome::NeedsApproval { request: approval } =
        core.deploy.submit_import(&core.ctx, &request).await.unwrap()
    else {
        panic!("an import is a deploy, Medium");
    };
    assert_eq!(approval.tier, Tier::Medium);
    assert_eq!(approval.summary, "Import db01 from db01.xml");
    assert!(matches!(&approval.targets[0].target, TargetRef::NewVm { name, .. } if name == "db01"));
    assert_eq!(approve(&core, &approval).await, JobStatus::Succeeded);
    let vmx = lab.join("db01").join("db01.vmx").display().to_string();
    let text = fake.vmx_text(&vmx).expect("the .vmx was written");
    assert!(text.contains("firmware = \"efi\""), "{text}");
    assert!(text.contains("numvcpus = \"3\""), "{text}");
    assert!(lab.join("db01").join("db01.vmdk").is_file(), "the converted disk");
    assert!(tools
        .calls()
        .iter()
        .any(|c| c.starts_with("qemu-img convert -p -f qcow2 -O vmdk")));
    assert!(dir.join("db01.qcow2").is_file(), "the source stays");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_import_without_its_tools_is_refused_and_a_disk_imports_into_virtualbox() {
    let dir = temp_folder("import-vbox");
    let source = dir.join("dc01.vhdx");
    std::fs::write(&source, img::vhdx(64 * MB, false, false)).unwrap();
    let mut setup = Setup::new(FakeVmware::default()).with_virtualbox(FakeVirtualBox::new());
    setup.disk_tools = Arc::new(FakeDiskTools::new());
    let tools = Arc::clone(&setup.disk_tools);
    let core = setup.build().await;
    let lab = dir.join("lab");
    let mut request = import_request(&source, Hypervisor::VirtualBox, &lab);
    request.profile_id = "windows-server".into();
    let check = core.deploy.check_import(&core.ctx, &request).await.unwrap();
    assert!(check.problems[0].message.contains("qemu-img"), "{:?}", check.problems);
    assert!(core.deploy.submit_import(&core.ctx, &request).await.is_err());

    // A VHD from Hyper-V: VirtualBox copies it itself.
    let vhd = dir.join("dc01.vhd");
    std::fs::write(&vhd, img::vhd_fixed(2 * MB)).unwrap();
    let request = import_request(&vhd, Hypervisor::VirtualBox, &lab);
    let check = core.deploy.check_import(&core.ctx, &request).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    assert!(check
        .preview
        .unwrap()
        .notes
        .iter()
        .any(|n| n.contains("copied by VBoxManage")));
    assert!(tools.calls().is_empty(), "a check runs no tool");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_qcow2_cloud_image_deploys_once_qemu_img_is_installed() {
    let dir = temp_folder("conv-catalog");
    let file = dir.join("rocky.qcow2");
    std::fs::write(&file, img::qcow2(64 * MB, None)).unwrap();
    for (qemu, deployable) in [(false, false), (true, true)] {
        let tools = if qemu {
            FakeDiskTools::new().with_qemu_img()
        } else {
            FakeDiskTools::new()
        };
        let (core, _) = core_with(tools).await;
        let image = core
            .catalog
            .add_image(
                &core.ctx,
                Uuid::new_v4(),
                ImageInput {
                    name: "Rocky".into(),
                    source: SourceInput::CloudImage {
                        path: file.display().to_string(),
                    },
                    hypervisors: vec![],
                    os_profile: "rhel".into(),
                    notes: None,
                },
                Arc::new(|_: HashProgress| {}),
            )
            .await
            .unwrap();
        let listed = core.catalog.images(&core.ctx).await.unwrap();
        let found = listed.iter().find(|i| i.id == image.id).unwrap();
        assert_eq!(found.problem.is_none(), deployable, "{:?}", found.problem);
        if !deployable {
            assert!(found.problem.as_deref().unwrap().contains("qemu-img"));
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
