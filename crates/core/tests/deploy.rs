//! VM-21, VM-22, VM-10: deploys end to end on a core with fake hypervisors. Launch templates and Custom, every
//! source (a golden VM's clone, a cloud image with cloud-init, an ISO install, an OVA import, a bulk clone) on
//! Workstation and VirtualBox, the approval tiers, the AP-02 preview, what the job leaves behind after a failure or
//! a cancel, the after-deploy steps and the audit log. Image files and the VMs' folders are made at run time in the
//! system temp folder; no real VM is made.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use common::{temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::catalog::{
    AfterDeploy, CloneMode, HashProgress, Image, ImageInput, Network, SourceInput, TemplateInput,
};
use remotely_core::command_bus::{ApprovalAnswers, ApprovalRequest, Command, SnapshotOp, SubmitOutcome};
use remotely_core::deploy::runner::DeployTuning;
use remotely_core::deploy::seed::read_joliet;
use remotely_core::deploy::service::{CloneRequest, DeployFrom, DeployRequest};
use remotely_core::domain::{Environment, PowerState, TargetRef};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::policy::{ApprovalStep, Tier};
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::vm_settings::VmLifecycleOp;
use remotely_core::{Core, CoreError};
use time::macros::datetime;
use uuid::Uuid;

/// A file that looks like a VMDK (a sparse header).
fn vmdk_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8800];
    bytes[..4].copy_from_slice(b"KDMV");
    bytes
}

fn iso_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x9000];
    bytes[0x8001..0x8006].copy_from_slice(b"CD001");
    bytes
}

/// An OVA: a tar whose first member is the descriptor.
fn ova_bytes() -> Vec<u8> {
    let ovf = br#"<Envelope><DiskSection><Disk ovf:capacity="20" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1"/></DiskSection></Envelope>"#;
    let mut header = [0u8; 512];
    header[..13].copy_from_slice(b"appliance.ovf");
    header[124..136].copy_from_slice(format!("{:011o}\0", ovf.len()).as_bytes());
    // ustar magic, so the format check takes it for a tar.
    header[257..263].copy_from_slice(b"ustar\0");
    let mut out = header.to_vec();
    out.extend_from_slice(ovf);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out.extend([0u8; 1024]);
    out
}

fn write(folder: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = folder.join(name);
    std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
    path
}

fn no_progress() -> Arc<dyn Fn(HashProgress) + Send + Sync> {
    Arc::new(|_| {})
}

async fn add_image(core: &Core, name: &str, source: SourceInput, profile: &str) -> Image {
    core.catalog
        .add_image(
            &core.ctx(),
            Uuid::new_v4(),
            ImageInput {
                name: name.into(),
                source,
                hypervisors: vec![],
                os_profile: profile.into(),
                notes: None,
            },
            no_progress(),
        )
        .await
        .unwrap()
}

async fn deploy_key(core: &Core) -> remotely_core::vault::SecretId {
    core.keys
        .generate(
            &core.ctx(),
            GenerateKey {
                label: "deploy key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap()
        .id
}

fn template(name: &str, image: &Image, hypervisor: Hypervisor, folder: &Path, network: Network) -> TemplateInput {
    TemplateInput {
        name: name.into(),
        image_id: image.id,
        size_id: "gp.medium".into(),
        hypervisor,
        vm_folder: Some(folder.display().to_string()),
        network,
        ssh_key_id: None,
        naming_pattern: "web-{n}".into(),
        default_count: 2,
        environment: Environment::Lab,
        tags: vec!["web".into()],
        after_deploy: AfterDeploy {
            create_session: true,
            link_session: true,
            clean_snapshot: false,
            open_console: false,
        },
        guest_user: Some("alice".into()),
        packages: vec!["nginx".into()],
        clone_mode: CloneMode::Full,
    }
}

fn request(template: Uuid, count: u32) -> DeployRequest {
    DeployRequest {
        from: DeployFrom::Template { id: template },
        count,
        naming_pattern: None,
        host_adapter: None,
        guest_password_id: None,
    }
}

fn needs_approval(outcome: SubmitOutcome) -> ApprovalRequest {
    match outcome {
        SubmitOutcome::NeedsApproval { request } => request,
        other => panic!("expected an approval, got {other:?}"),
    }
}

/// Approves with every answer the steps ask for, and waits for the job.
async fn approve_and_wait(core: &Core, request: &ApprovalRequest) -> (Uuid, JobStatus) {
    let answers = ApprovalAnswers {
        confirmed: true,
        typed_target_count: Some(request.targets.len()),
        reason: Some("lab build".into()),
        safety_snapshot: None,
        vault_password: request
            .steps
            .contains(&ApprovalStep::VaultReauth)
            .then(|| SecretString::new(VAULT_PASSWORD)),
        change_id: None,
    };
    let job = core.bus.approve(request.id, answers).await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), core.jobs.wait(job))
        .await
        .expect("the deploy finished in time")
        .unwrap();
    (job, status)
}

fn fast(core: &Core) {
    core.set_deploy_tuning(DeployTuning {
        ip_poll: Duration::from_millis(10),
        ip_wait_cap: Some(Duration::from_millis(200)),
        cleanup_tries: 3,
        cleanup_pause: Duration::from_millis(10),
    });
}

async fn job_outputs(core: &Core, job: Uuid) -> Vec<(String, String, Option<String>, Option<String>)> {
    core.store
        .job_targets(&core.ctx(), job)
        .await
        .unwrap()
        .into_iter()
        .map(|t| (t.target_name, t.status, t.output, t.error))
        .collect()
}

fn decode(text: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(text).unwrap()).unwrap()
}

fn vmx_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.split_once(" = "))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        .map(|(_, v)| v.trim().trim_matches('"').to_owned())
}

#[tokio::test]
async fn a_cloud_image_template_deploys_on_workstation_with_cloud_init_and_after_deploy_steps() {
    let dir = temp_folder("deploy-ws-cloud");
    let lab = dir.join("lab");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let web1 = lab.join("web-1").join("web-1.vmx");
    let web2 = lab.join("web-2").join("web-2.vmx");
    let setup = Setup::new(
        FakeVmware::default()
            .with_ip(&web1.display().to_string(), "192.0.2.21")
            .with_ip(&web2.display().to_string(), "192.0.2.22"),
    )
    .with_real_vault();
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble",
        SourceInput::CloudImage {
            path: image_file.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let key = deploy_key(&core).await;
    let mut input = template("web", &image, Hypervisor::Vmware, &lab, Network::Vmnet { number: 3 });
    input.ssh_key_id = Some(key);
    input.after_deploy.clean_snapshot = true;
    let saved = core.catalog.add_template(ctx, input).await.unwrap();

    // The dialog's check: the AP-02 preview.
    let check = core.deploy.check(ctx, &request(saved.id, 2)).await.unwrap();
    assert!(check.problems.is_empty(), "{:?}", check.problems);
    let preview = check.preview.unwrap();
    assert_eq!(
        preview.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["web-1", "web-2"]
    );
    assert_eq!(preview.vms[0].folder, lab.join("web-1").display().to_string());
    assert_eq!(
        preview.disk_bytes,
        2 * 40 * (1 << 30),
        "gp.medium's 40 GB at its full size, twice"
    );
    assert_eq!(preview.network.as_deref(), Some("vmnet3"));
    assert_eq!(preview.first_boot.as_ref().unwrap().user.as_deref(), Some("alice"));
    assert!(preview.refusals.is_empty());

    // Submit: Medium, one confirm, with the preview in the approval.
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 2)).await.unwrap());
    assert_eq!(approval.tier, Tier::Medium);
    assert_eq!(approval.steps, [ApprovalStep::Confirm]);
    assert_eq!(approval.summary, "Deploy 2 VMs from 'web'");
    assert!(
        matches!(&approval.targets[0].target, TargetRef::NewVm { name, environment: Environment::Lab, .. } if name == "web-1")
    );
    assert_eq!(approval.deploy.as_ref().unwrap().vms.len(), 2);
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", job_outputs(&core, job).await);

    // Each VM: its disk a copy of the image, grown to the size's; its .vmx from the profile and size, with
    // cloud-init's data; a 'clean' snapshot before its first boot; running.
    for (name, vmx_path) in [("web-1", &web1), ("web-2", &web2)] {
        let text = fake
            .vmx_text(&vmx_path.display().to_string())
            .expect("the .vmx was written");
        assert_eq!(vmx_value(&text, "displayName").as_deref(), Some(name));
        assert_eq!(vmx_value(&text, "guestOS").as_deref(), Some("ubuntu-64"));
        assert_eq!(vmx_value(&text, "numvcpus").as_deref(), Some("2"));
        assert_eq!(vmx_value(&text, "memsize").as_deref(), Some("4096"));
        assert_eq!(vmx_value(&text, "ethernet0.vnet").as_deref(), Some("VMnet3"));
        assert_eq!(
            vmx_value(&text, "guestinfo.userdata.encoding").as_deref(),
            Some("base64")
        );
        let user_data = decode(&vmx_value(&text, "guestinfo.userdata").unwrap());
        assert!(user_data.starts_with("#cloud-config"), "{user_data}");
        assert!(user_data.contains(&format!("hostname: \"{name}\"")), "{user_data}");
        assert!(user_data.contains("- name: \"alice\""), "{user_data}");
        assert!(user_data.contains("ssh-ed25519 "), "the public key: {user_data}");
        assert!(!user_data.contains("PRIVATE"), "never the private key");
        assert!(user_data.contains("- \"nginx\""), "{user_data}");
        let meta = decode(&vmx_value(&text, "guestinfo.metadata").unwrap());
        assert!(meta.contains(&format!("local-hostname: \"{name}\"")), "{meta}");
        let boot = lab.join(name).join(format!("{name}.vmdk"));
        assert_eq!(
            fake.disk_size_mb(&boot.display().to_string()),
            Some(40 * 1024),
            "grown to 40 GB"
        );
        assert!(fake
            .snapshot_names(&vmx_path.display().to_string())
            .contains(&"clean".to_owned()));
    }
    let calls = fake.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("vdiskmanager -r ") && c.contains("noble.vmdk")),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("vdiskmanager -x 40960MB ")),
        "{calls:?}"
    );
    assert_eq!(common::running(&fake), ["web-1", "web-2"]);

    // In the VM list with their label and tag, the folder scanned from now on.
    let scanned = core.scan_folders().await.unwrap();
    assert!(scanned.iter().any(|f| f == &lab), "{scanned:?}");
    let listed = core
        .store
        .find_vm(ctx, &web1.display().to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(listed.environment, Environment::Lab);
    assert_eq!(listed.tags, ["web"]);
    // An SSH session to each, with the key and alice, linked to its VM by hand.
    let sessions = core.sessions.list(ctx, &Default::default()).await.unwrap();
    let session = sessions.iter().find(|s| s.name == "web-1").expect("web-1's session");
    assert_eq!(session.host, "192.0.2.21");
    assert_eq!(session.username.as_deref(), Some("alice"));
    assert_eq!(session.vm_id.as_deref(), Some(listed.id.as_str()));
    assert_eq!(session.vm_link, Some(remotely_core::vm_links::VmLink::Manual));

    // The job says what each VM came to; the audit log has the start and the end with each VM's result.
    let outputs = job_outputs(&core, job).await;
    let web1_note = outputs.iter().find(|o| o.0 == "web-1").unwrap().2.clone().unwrap();
    assert!(web1_note.contains("IP 192.0.2.21"), "{web1_note}");
    assert!(
        web1_note.contains("session 'web-1' made and linked to the VM"),
        "{web1_note}"
    );
    assert!(
        web1_note.contains("snapshot 'clean' taken before its first boot"),
        "{web1_note}"
    );
    let audit = core.store.recent_audit(ctx, 100).await.unwrap();
    let finished = audit.iter().find(|e| e.event == "job_finished").unwrap();
    assert!(
        finished.detail.as_deref().unwrap().contains("web-2: made in"),
        "{:?}",
        finished.detail
    );
    assert!(audit.iter().any(|e| e.event == "job_started"));
    assert!(
        !format!("{audit:?}").contains("AAAAC3"),
        "the audit names the key, never its data"
    );
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn golden_vm_clones_are_full_and_grow_or_linked_and_say_why_not() {
    let dir = temp_folder("deploy-ws-golden");
    let golden = vmx("golden");
    let golden_disk = r"C:\VMs\golden\golden.vmdk";
    let setup = Setup::new(
        FakeVmware::default()
            .in_library(&golden, Some("golden"))
            .with_vmx_text(
                &golden,
                "displayName = \"golden\"\nguestOS = \"ubuntu-64\"\nnumvcpus = \"1\"\nmemsize = \"1024\"\nscsi0.present = \"TRUE\"\nscsi0:0.present = \"TRUE\"\nscsi0:0.fileName = \"golden.vmdk\"\n",
            )
            .with_disk(golden_disk, 20 * 1024)
            .with_snapshot(&golden, "base", datetime!(2026-10-20 9:00 UTC)),
    );
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    let image = add_image(
        &core,
        "golden base",
        SourceInput::GoldenVm {
            vm_key: golden.clone(),
            snapshot: "base".into(),
        },
        "ubuntu",
    )
    .await;
    let mut full = template("full", &image, Hypervisor::Vmware, &dir, Network::Nat);
    full.naming_pattern = "full-{n}".into();
    full.after_deploy.create_session = false;
    full.after_deploy.link_session = false;
    let full = core.catalog.add_template(ctx, full).await.unwrap();
    let approval = needs_approval(core.deploy.submit(ctx, &request(full.id, 1)).await.unwrap());
    // The preview counts the golden VM's disk, grown to the size's.
    assert_eq!(
        approval.deploy.as_ref().unwrap().vms[0].disk_bytes,
        Some(40 * (1 << 30))
    );
    let (_, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let calls = fake.calls();
    let clone = calls.iter().find(|c| c.starts_with("vmrun clone")).unwrap();
    assert!(clone.contains(" full -snapshot=base -cloneName=full-1"), "{clone}");
    let full_vmx = dir.join("full-1").join("full-1.vmx").display().to_string();
    let text = fake.vmx_text(&full_vmx).unwrap();
    assert_eq!(
        vmx_value(&text, "memsize").as_deref(),
        Some("4096"),
        "the size's memory"
    );
    let disk = dir.join("full-1").join("full-1.vmdk").display().to_string();
    assert_eq!(
        fake.disk_size_mb(&disk),
        Some(40 * 1024),
        "grown from the golden VM's 20 GB"
    );

    let mut linked = template("linked", &image, Hypervisor::Vmware, &dir, Network::Nat);
    linked.naming_pattern = "linked-{n}".into();
    linked.clone_mode = CloneMode::Linked;
    linked.after_deploy.create_session = false;
    linked.after_deploy.link_session = false;
    let linked = core.catalog.add_template(ctx, linked).await.unwrap();

    // A linked clone writes the golden VM's .vmsd, so while Workstation holds the golden VM (running, or open in a
    // tab: a lock beside its .vmx or a disk) it is refused, like a VM-23 change; a full clone only reads it.
    let lock = format!("{golden_disk}.lck");
    fake.set_file(&lock, true);
    let check = core.deploy.check(ctx, &request(linked.id, 1)).await.unwrap();
    let refusals = &check.preview.as_ref().unwrap().refusals;
    assert!(
        refusals.iter().any(|r| r.contains("Workstation is using that VM")),
        "{refusals:?}"
    );
    assert!(core.deploy.submit(ctx, &request(linked.id, 1)).await.is_err());
    let check = core.deploy.check(ctx, &request(full.id, 1)).await.unwrap();
    assert!(check.preview.unwrap().refusals.is_empty(), "a full clone goes ahead");
    fake.set_file(&lock, false);
    // Off but open in a Workstation tab: the lock is beside the .vmx (vmrun itself clones regardless).
    let tab_lock = format!("{golden}.lck");
    fake.set_file(&tab_lock, true);
    let check = core.deploy.check(ctx, &request(linked.id, 1)).await.unwrap();
    assert!(
        check.preview.unwrap().refusals.iter().any(|r| r.contains(&tab_lock)),
        "the open tab's lock refuses it too"
    );
    fake.set_file(&tab_lock, false);
    // Workstation's window is open: the approval says to close the golden VM's tab.
    fake.set_workstation_open(true);
    let approval = needs_approval(core.deploy.submit(ctx, &request(linked.id, 1)).await.unwrap());
    fake.set_workstation_open(false);
    let warnings = &approval.deploy.as_ref().unwrap().warnings;
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("Close 'golden''s tab in Workstation")),
        "{warnings:?}"
    );
    // The golden VM starts after the approval: the runner checks again, and the clone isn't made.
    fake.set_file(&lock, true);
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Failed);
    let error = job_outputs(&core, job).await[0].3.clone().unwrap();
    assert!(error.contains("Workstation is using that VM"), "{error}");
    assert!(!fake.calls().iter().any(|c| c.contains(" linked ")));
    assert!(!dir.join("linked-1").exists());
    fake.set_file(&lock, false);

    let approval = needs_approval(core.deploy.submit(ctx, &request(linked.id, 1)).await.unwrap());
    let notes = &approval.deploy.as_ref().unwrap().notes;
    assert!(
        notes.iter().any(|n| n.contains("Linked clones need 'golden'")),
        "{notes:?}"
    );
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let calls = fake.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.contains(" linked -snapshot=base -cloneName=linked-1")),
        "{calls:?}"
    );
    let disk = dir.join("linked-1").join("linked-1.vmdk").display().to_string();
    assert_eq!(
        fake.disk_size_mb(&disk),
        Some(20 * 1024),
        "a linked clone's disk doesn't grow"
    );
    let note = job_outputs(&core, job).await[0].2.clone().unwrap();
    assert!(
        note.contains("a linked clone keeps the golden VM's disk size"),
        "{note}"
    );

    // VM-04, VM-21, VM-24: the clone is recorded in the golden VM's .vmsd, so deleting "base" or the golden VM, which
    // would break linked-1, is refused before anything is asked.
    let linked_vmx = dir.join("linked-1").join("linked-1.vmx").display().to_string();
    assert_eq!(
        fake.linked_clones(&golden),
        [("base".to_owned(), vec![linked_vmx.clone()])]
    );
    let golden_target = TargetRef::Vm {
        vmx_path: golden.clone(),
    };
    for command in [
        Command::VmSnapshot {
            targets: vec![golden_target.clone()],
            op: SnapshotOp::Delete { name: "base".into() },
        },
        Command::VmLifecycle {
            targets: vec![golden_target.clone()],
            op: VmLifecycleOp::Delete,
        },
    ] {
        let err = core.bus.submit(ctx, command).await.unwrap_err();
        assert!(matches!(err, CoreError::LinkedClones(_)), "{err:?}");
        assert!(err.to_string().contains(&format!("linked-1 ({linked_vmx})")), "{err}");
    }
    assert!(!fake
        .calls()
        .iter()
        .any(|c| c.contains("snapshot delete") || c.contains("deleteVM")));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_failed_or_cancelled_vm_leaves_only_what_was_there_before() {
    let dir = temp_folder("deploy-ws-cleanup");
    let golden = vmx("golden");
    let setup = Setup::new(
        FakeVmware::default()
            .in_library(&golden, Some("golden"))
            .with_snapshot(&golden, "base", datetime!(2026-10-20 9:00 UTC))
            .with_clone_delay(Duration::from_secs(20)),
    );
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    let image = add_image(
        &core,
        "golden base",
        SourceInput::GoldenVm {
            vm_key: golden.clone(),
            snapshot: "base".into(),
        },
        "ubuntu",
    )
    .await;
    // Something of the owner's in the deploy's folder stays whatever happens.
    let theirs = write(&dir, "notes.txt", b"mine");
    let saved = core
        .catalog
        .add_template(ctx, template("web", &image, Hypervisor::Vmware, &dir, Network::Nat))
        .await
        .unwrap();

    // Cancelled while the clone runs: the clone it left and the VM's folder go.
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap());
    let job = core
        .bus
        .approve(
            approval.id,
            ApprovalAnswers {
                confirmed: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let web1 = dir.join("web-1").join("web-1.vmx");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !fake.has_vm(&web1.display().to_string()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the clone started");
    assert!(core.jobs.cancel(job));
    assert_eq!(core.jobs.wait(job).await.unwrap(), JobStatus::Cancelled);
    assert!(
        !fake.has_vm(&web1.display().to_string()),
        "the half-made clone is deleted"
    );
    assert!(!dir.join("web-1").exists(), "its folder is gone");
    assert!(theirs.exists(), "the owner's file stays");
    assert!(
        fake.calls().iter().any(|c| c.starts_with("vmrun deleteVM")),
        "{:?}",
        fake.calls()
    );

    // A clone that fails halfway: the same, and the job says what was removed.
    let setup = Setup::new(FakeVmware::default().in_library(&golden, Some("golden")).with_snapshot(
        &golden,
        "base",
        datetime!(2026-10-20 9:00 UTC),
    ));
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    let image = add_image(
        &core,
        "golden base",
        SourceInput::GoldenVm {
            vm_key: golden.clone(),
            snapshot: "base".into(),
        },
        "ubuntu",
    )
    .await;
    let saved = core
        .catalog
        .add_template(ctx, template("web", &image, Hypervisor::Vmware, &dir, Network::Nat))
        .await
        .unwrap();
    fake.set_failing("clone", true);
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 2)).await.unwrap());
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Failed);
    for name in ["web-1", "web-2"] {
        assert!(!dir.join(name).exists(), "{name}'s folder is gone");
        assert!(!fake.has_vm(&dir.join(name).join(format!("{name}.vmx")).display().to_string()));
    }
    assert!(theirs.exists());
    let outputs = job_outputs(&core, job).await;
    let error = outputs[0].3.clone().unwrap();
    assert!(error.contains("was not made"), "{error}");
    assert!(
        error.contains("Insufficient permission"),
        "the tool's own words: {error}"
    );
    assert!(error.contains("what it made was removed"), "{error}");

    // A folder that is there already is refused before anything is made.
    fake.set_failing("clone", false);
    std::fs::create_dir_all(dir.join("web-1")).unwrap();
    let err = core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap_err();
    assert!(err.to_string().contains("is there already"), "{err}");
    assert!(dir.join("web-1").exists(), "never removed: it wasn't the deploy's");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_virtualbox_cloud_image_boots_with_a_nocloud_seed() {
    let dir = temp_folder("deploy-vbox-cloud");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let setup = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new().with_ip_for_name("web-2", "192.0.2.32"))
        .with_real_vault();
    let fake = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble",
        SourceInput::CloudImage {
            path: image_file.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let key = deploy_key(&core).await;
    let mut input = template("web", &image, Hypervisor::VirtualBox, &dir, Network::HostOnly);
    input.ssh_key_id = Some(key);
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 2)).await.unwrap());
    assert_eq!(
        approval.deploy.as_ref().unwrap().host_adapter.as_deref(),
        Some("VirtualBox Host-Only Ethernet Adapter"),
        "the first host-only adapter, when none was picked"
    );
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded, "{:?}", job_outputs(&core, job).await);

    // web-1 got no IP, so its seed stays in its DVD drive: it holds cloud-init's files under Joliet names.
    let web1 = fake.vm_named("web-1").expect("web-1 is registered");
    assert_eq!((web1.cpus, web1.memory_mb), (Some(2), Some(4096)));
    assert_eq!(web1.config_file, Some(dir.join("web-1").join("web-1.vbox")));
    let seed_path = dir.join("web-1").join("web-1-cidata.iso");
    assert!(
        web1.dvds
            .iter()
            .any(|d| d.image.as_deref() == Some(seed_path.as_path())),
        "{:?}",
        web1.dvds
    );
    let seed = read_joliet(&std::fs::read(&seed_path).unwrap()).unwrap();
    assert_eq!(seed.joliet_label, "cidata");
    let names: Vec<&str> = seed.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["meta-data", "user-data"]);
    let user_data = String::from_utf8(seed.files[1].1.clone()).unwrap();
    assert!(
        user_data.contains("hostname: \"web-1\"") && user_data.contains("ssh-ed25519 "),
        "{user_data}"
    );
    assert!(!user_data.to_lowercase().contains("password:"), "{user_data}");
    let disk = web1
        .disks
        .iter()
        .find(|d| d.slot == "SATA-0-0")
        .expect("the boot disk on SATA port 0");
    assert_eq!(disk.path, dir.join("web-1").join("web-1.vdi"));
    assert_eq!(
        fake.disk_size_mb(&disk.path.display().to_string()),
        Some(40 * 1024),
        "grown to the size's"
    );
    let calls = fake.calls().join("\n");
    assert!(calls.contains("change createvm --name web-1 --uuid "), "{calls}");
    assert!(
        calls.contains("--nic1 hostonly --hostonlyadapter1 VirtualBox Host-Only Ethernet Adapter"),
        "{calls}"
    );
    assert!(
        calls.contains(&format!("change clonemedium disk {}", image_file.display())),
        "{calls}"
    );
    assert_eq!(fake.power_state(&web1.uuid), PowerState::Running);

    // web-2's guest booted (it has an IP): its seed is ejected and deleted, and its session made.
    let web2 = fake.vm_named("web-2").unwrap();
    assert!(web2.dvds.iter().all(|d| d.image.is_none()), "{:?}", web2.dvds);
    assert!(!dir.join("web-2").join("web-2-cidata.iso").exists());
    let outputs = job_outputs(&core, job).await;
    let web1_note = outputs.iter().find(|o| o.0 == "web-1").unwrap().2.clone().unwrap();
    assert!(web1_note.contains("no IP within"), "{web1_note}");
    let web2_note = outputs.iter().find(|o| o.0 == "web-2").unwrap().2.clone().unwrap();
    assert!(web2_note.contains("IP 192.0.2.32"), "{web2_note}");
    assert!(web2_note.contains("seed ejected"), "{web2_note}");
    let sessions = core.sessions.list(ctx, &Default::default()).await.unwrap();
    assert_eq!(sessions.iter().filter(|s| s.host == "192.0.2.32").count(), 1);
    assert!(
        core.store.find_vm(ctx, &web2.uuid).await.unwrap().is_some(),
        "in the VM list"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_failed_virtualbox_clone_is_unregistered_with_its_files() {
    let dir = temp_folder("deploy-vbox-fail");
    let golden = "0b9c3c3e-2f4e-4e1a-9f61-5c0f2d1a7e01";
    let setup = Setup::new(FakeVmware::default()).with_virtualbox(
        FakeVirtualBox::new()
            .with_vm(golden, "golden", PowerState::NotRunning)
            .with_snapshot(golden, "clean install", datetime!(2026-10-20 9:00 UTC)),
    );
    let fake = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    let image = add_image(
        &core,
        "golden",
        SourceInput::GoldenVm {
            vm_key: golden.into(),
            snapshot: "clean install".into(),
        },
        "ubuntu",
    )
    .await;
    let mut input = template(
        "web",
        &image,
        Hypervisor::VirtualBox,
        &dir,
        Network::Internal { name: "lab".into() },
    );
    input.clone_mode = CloneMode::Linked;
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    fake.set_failing("clonevm", true);
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap());
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Failed);
    assert!(fake.vm_named("web-1").is_none(), "unregistered");
    assert!(!dir.join("web-1").exists());
    let calls = fake.calls().join("\n");
    assert!(calls.contains("--options=Link"), "{calls}");
    assert!(calls.contains("change unregistervm "), "{calls}");
    assert!(fake.vm_named("golden").is_some(), "the golden VM stays");
    // VM-04, VM-21: the half-made clone's disk went with it, so nothing holds the golden VM's snapshot any more.
    assert!(fake.linked_clones(golden).is_empty());
    let error = job_outputs(&core, job).await[0].3.clone().unwrap();
    assert!(error.contains("what it made was removed"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A VirtualBox VM that fails after its NoCloud seed is attached: cleanup unregisters it, closes the seed in
/// VirtualBox's media list (`unregistervm --delete` leaves DVD images there) and removes its folder.
#[tokio::test]
async fn a_virtualbox_deploy_that_fails_to_start_closes_its_seed() {
    let dir = temp_folder("deploy-vbox-start");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let setup = Setup::new(FakeVmware::default());
    let fake = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble",
        SourceInput::CloudImage {
            path: image_file.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let input = template("web", &image, Hypervisor::VirtualBox, &dir, Network::Nat);
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    fake.set_failing("startvm", true);
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap());
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Failed);
    let seed = dir.join("web-1").join("web-1-cidata.iso");
    let calls = fake.calls().join("\n");
    assert!(
        calls.contains(&format!("change closemedium dvd {}", seed.display())),
        "{calls}"
    );
    assert!(fake.vm_named("web-1").is_none(), "unregistered");
    assert!(!dir.join("web-1").exists());
    let error = job_outputs(&core, job).await[0].3.clone().unwrap();
    assert!(error.contains("VT-x is not available"), "{error}");
    assert!(error.contains("what it made was removed"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn appliances_import_on_both_hypervisors_with_the_sizes_cpu_and_memory() {
    let dir = temp_folder("deploy-ova");
    let ova = write(&dir, "app.ova", &ova_bytes());
    let setup = Setup::new(FakeVmware::default());
    let ws = Arc::clone(&setup.vmware);
    let vb = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "app",
        SourceInput::Appliance {
            path: ova.display().to_string(),
        },
        "other-linux",
    )
    .await;
    for hypervisor in Hypervisor::ALL {
        let name = format!("app-{}", hypervisor.as_str());
        let mut input = template(&name, &image, hypervisor, &dir, Network::Nat);
        input.naming_pattern = format!("{name}-{{n}}");
        input.guest_user = None;
        input.packages = Vec::new();
        input.after_deploy.create_session = false;
        input.after_deploy.link_session = false;
        let saved = core.catalog.add_template(ctx, input).await.unwrap();
        let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap());
        // The OVF's own 20 GB disk grows to the size's 40 GB.
        assert_eq!(
            approval.deploy.as_ref().unwrap().vms[0].disk_bytes,
            Some(40 * (1 << 30))
        );
        let (job, status) = approve_and_wait(&core, &approval).await;
        assert_eq!(
            status,
            JobStatus::Succeeded,
            "{hypervisor:?}: {:?}",
            job_outputs(&core, job).await
        );
    }
    let ws_vmx = dir.join("app-vmware-1").join("app-vmware-1.vmx").display().to_string();
    let text = ws.vmx_text(&ws_vmx).unwrap();
    assert_eq!(vmx_value(&text, "numvcpus").as_deref(), Some("2"));
    assert_eq!(vmx_value(&text, "memsize").as_deref(), Some("4096"));
    assert!(
        ws.calls().iter().any(|c| c.starts_with("ovftool --name=app-vmware-1 ")),
        "{:?}",
        ws.calls()
    );
    let imported = vb.vm_named("app-virtualbox-1").unwrap();
    assert_eq!((imported.cpus, imported.memory_mb), (Some(2), Some(4096)));
    let calls = vb.calls().join("\n");
    assert!(calls.contains("change import "), "{calls}");
    assert!(calls.contains("--vsys 0 --vmname app-virtualbox-1"), "{calls}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn iso_installs_boot_the_iso_and_virtualbox_installs_by_itself_with_a_vault_password() {
    let dir = temp_folder("deploy-iso");
    let iso = write(&dir, "noble.iso", &iso_bytes());
    let setup = Setup::new(FakeVmware::default())
        .with_virtualbox(FakeVirtualBox::new().with_unattended_iso(&iso.display().to_string()))
        .with_real_vault();
    let ws = Arc::clone(&setup.vmware);
    let vb = Arc::clone(&setup.virtualbox);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble ISO",
        SourceInput::Iso {
            path: iso.display().to_string(),
        },
        "ubuntu",
    )
    .await;

    // Workstation: a blank VM booting the ISO; no first-boot setup, no IP to wait for.
    let mut input = template("ws", &image, Hypervisor::Vmware, &dir, Network::Bridged);
    input.naming_pattern = "ws-{n}".into();
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap());
    assert!(approval.deploy.as_ref().unwrap().first_boot.is_none());
    let (job, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let text = ws
        .vmx_text(&dir.join("ws-1").join("ws-1.vmx").display().to_string())
        .unwrap();
    assert_eq!(vmx_value(&text, "sata0:0.deviceType").as_deref(), Some("cdrom-image"));
    assert_eq!(vmx_value(&text, "sata0:0.fileName"), Some(iso.display().to_string()));
    assert_eq!(
        vmx_value(&text, "guestinfo.userdata"),
        None,
        "no cloud-init for an ISO install"
    );
    assert!(job_outputs(&core, job).await[0]
        .2
        .clone()
        .unwrap()
        .starts_with("made in"));

    // VirtualBox, unattended with a vault password: the approval asks for the vault password, and VBoxManage gets
    // the password as a file, never on its command line.
    let password = core
        .vault
        .add(
            ctx,
            SecretKind::Password,
            "lab guest",
            SecretString::new("guest-pw-Example-1"),
        )
        .await
        .unwrap();
    let mut input = template("vb", &image, Hypervisor::VirtualBox, &dir, Network::Nat);
    input.naming_pattern = "vb-{n}".into();
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    let asked = DeployRequest {
        guest_password_id: Some(password.id),
        ..request(saved.id, 1)
    };
    let approval = needs_approval(core.deploy.submit(ctx, &asked).await.unwrap());
    assert!(
        approval.steps.contains(&ApprovalStep::VaultReauth),
        "{:?}",
        approval.steps
    );
    assert!(
        approval.warnings.iter().any(|w| w.contains("unattended install gives")),
        "{:?}",
        approval.warnings
    );
    let (_, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let vm = vb.vm_named("vb-1").unwrap();
    assert_eq!(vb.unattended_installs(), [(vm.uuid.clone(), "alice".to_owned())]);
    let calls = vb.calls().join("\n");
    assert!(calls.contains("--password-file"), "{calls}");
    assert!(!calls.contains("guest-pw-Example-1"), "never on a command line");
    assert!(calls.contains("--boot1 dvd"), "{calls}");
    assert!(
        vm.dvds.iter().any(|d| d.image.as_deref() == Some(iso.as_path())),
        "{:?}",
        vm.dvds
    );
    let audit = core.store.recent_audit(ctx, 100).await.unwrap();
    assert!(!format!("{audit:?}").contains("guest-pw-Example-1"));
    // An ISO VirtualBox doesn't know can't be installed by itself.
    let other = write(&dir, "other.iso", &iso_bytes());
    let image = add_image(
        &core,
        "Other ISO",
        SourceInput::Iso {
            path: other.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let mut input = template("vb2", &image, Hypervisor::VirtualBox, &dir, Network::Nat);
    input.naming_pattern = "vb2-{n}".into();
    let saved = core.catalog.add_template(ctx, input).await.unwrap();
    let check = core
        .deploy
        .check(
            ctx,
            &DeployRequest {
                guest_password_id: Some(password.id),
                ..request(saved.id, 1)
            },
        )
        .await
        .unwrap();
    assert!(
        check.problems[0].message.contains("can't install"),
        "{:?}",
        check.problems
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_bulk_clone_copies_the_picked_vms_as_one_job() {
    let dir = temp_folder("deploy-bulk");
    let setup = Setup::new(
        FakeVmware::with_running([vmx("app01")])
            .in_library(&vmx("web01"), Some("web01"))
            .in_library(&vmx("db01"), Some("db01"))
            .in_library(&vmx("app01"), Some("app01")),
    );
    let fake = Arc::clone(&setup.vmware);
    let core = setup.build().await;
    fast(&core);
    let ctx = &core.ctx();
    core.inventory.refresh(ctx).await.unwrap();
    core.inventory
        .set_environment(ctx, &[vmx("db01")], Environment::Prod)
        .await
        .unwrap();
    let ask = |keys: &[String]| CloneRequest {
        vm_keys: keys.to_vec(),
        naming_pattern: "{template}-clone".into(),
        folder: Some(dir.display().to_string()),
        environment: None,
    };
    // A running VM can't be cloned as it is now.
    let check = core.deploy.check_clone(ctx, &ask(&[vmx("app01")])).await.unwrap();
    assert!(check.problems[0].message.contains("is running"), "{:?}", check.problems);

    let picked = [vmx("web01"), vmx("db01")];
    let check = core.deploy.check_clone(ctx, &ask(&picked)).await.unwrap();
    let preview = check.preview.unwrap();
    assert_eq!(
        preview.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["web01-clone", "db01-clone"]
    );
    assert_eq!(preview.vms[1].clone_of.as_deref(), Some("db01"));
    // A Prod source makes the clones Prod: High.
    let approval = needs_approval(core.deploy.submit_clone(ctx, &ask(&picked)).await.unwrap());
    assert_eq!(approval.tier, Tier::High);
    assert_eq!(approval.summary, "Clone 2 VMs");
    let (_, status) = approve_and_wait(&core, &approval).await;
    assert_eq!(status, JobStatus::Succeeded);
    let calls = fake.calls();
    assert!(
        calls.iter().any(
            |c| c.starts_with(r"vmrun clone C:\VMs\web01\web01.vmx") && c.ends_with(" full -cloneName=web01-clone")
        ),
        "{calls:?}"
    );
    assert!(fake.has_vm(&dir.join("db01-clone").join("db01-clone.vmx").display().to_string()));
    // The copies of VMs that are shut down stay off.
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("power Start") && c.contains("-clone")),
        "{calls:?}"
    );
    let clone = core
        .store
        .find_vm(
            ctx,
            &dir.join("db01-clone").join("db01-clone.vmx").display().to_string(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(clone.environment, Environment::Prod);
    // Again: the names are taken now, and the pattern has no {n}.
    let check = core.deploy.check_clone(ctx, &ask(&picked)).await.unwrap();
    assert_eq!(check.problems.len(), 2, "{:?}", check.problems);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn tiers_the_read_only_lock_and_the_free_space_check() {
    let dir = temp_folder("deploy-tiers");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let mut setup = Setup::new(FakeVmware::default());
    // A 1 TB drive with about 50 GB free.
    setup.host.free_disk_pct = 5.0;
    let core = setup.build().await;
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble",
        SourceInput::CloudImage {
            path: image_file.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let saved = core
        .catalog
        .add_template(ctx, template("web", &image, Hypervisor::Vmware, &dir, Network::Nat))
        .await
        .unwrap();
    // 5 VMs: High, with every High step but a safety snapshot.
    let approval = needs_approval(core.deploy.submit(ctx, &request(saved.id, 5)).await.unwrap());
    assert_eq!(approval.tier, Tier::High);
    assert!(approval.steps.contains(&ApprovalStep::TypeTargetCount { expected: 5 }));
    assert!(!approval
        .steps
        .iter()
        .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    // Their thin disks may take 200 GB, more than is free: a warning to read.
    assert!(
        approval.warnings.iter().any(|w| w.contains("thin disks")),
        "{:?}",
        approval.warnings
    );
    core.bus.cancel_approval(approval.id).await.unwrap();
    // A Prod label: High for one VM.
    let mut prod = template("prod", &image, Hypervisor::Vmware, &dir, Network::Nat);
    prod.environment = Environment::Prod;
    prod.naming_pattern = "prod-{n}".into();
    let prod = core.catalog.add_template(ctx, prod).await.unwrap();
    let approval = needs_approval(core.deploy.submit(ctx, &request(prod.id, 1)).await.unwrap());
    assert_eq!(approval.tier, Tier::High);
    core.bus.cancel_approval(approval.id).await.unwrap();

    // Thick disks that don't fit are refused before anything is asked.
    let thick = core
        .catalog
        .add_size(
            ctx,
            remotely_core::catalog::SizeInput {
                name: "thick.large".into(),
                sockets: 1,
                cores_per_socket: 2,
                memory_mb: 4096,
                disks: vec![remotely_core::catalog::DiskSpec {
                    size_gb: 100,
                    provisioning: remotely_core::catalog::Provisioning::Thick,
                    controller: None,
                }],
                description: None,
            },
        )
        .await
        .unwrap();
    let mut thick_template = template("thick", &image, Hypervisor::Vmware, &dir, Network::Nat);
    thick_template.size_id = thick.id;
    thick_template.naming_pattern = "thick-{n}".into();
    let thick_template = core.catalog.add_template(ctx, thick_template).await.unwrap();
    let err = core
        .deploy
        .submit(ctx, &request(thick_template.id, 1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("The thick disks need"), "{err}");

    // The UI can't build a deploy itself: its paths and values come from the catalogue.
    let spec: remotely_core::deploy::DeploySpec = serde_json::from_value(serde_json::json!({
        "origin": { "kind": "custom", "name": "x" },
        "hypervisor": "vmware",
        "source": { "kind": "iso", "path": r"C:\ISOs\x.iso" },
        "folder": r"C:\VMs",
        "profile": null,
        "size": null,
        "network": null,
        "firstBoot": null,
        "sshKeyId": null,
        "environment": "none",
        "tags": [],
        "afterDeploy": { "createSession": false, "linkSession": false, "cleanSnapshot": false, "openConsole": false },
        "ipWaitSecs": 0,
        "vms": []
    }))
    .unwrap();
    let command = remotely_core::command_bus::Command::Deploy {
        targets: spec.targets(),
        spec: Box::new(spec),
    };
    assert!(command
        .check_from_ui()
        .unwrap_err()
        .to_string()
        .contains("Deploy dialog"));

    // The read-only lock refuses deploys.
    core.presentation
        .set(remotely_core::presentation::Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let err = core.deploy.submit(ctx, &request(saved.id, 1)).await.unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_templates_first_boot_settings_are_saved_audited_and_checked() {
    let dir = temp_folder("deploy-template-fields");
    let image_file = write(&dir, "noble.vmdk", &vmdk_bytes());
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = &core.ctx();
    let image = add_image(
        &core,
        "Noble",
        SourceInput::CloudImage {
            path: image_file.display().to_string(),
        },
        "ubuntu",
    )
    .await;
    let mut input = template("web", &image, Hypervisor::Vmware, &dir, Network::Nat);
    input.packages = vec!["nginx".into(), " htop ".into(), "nginx".into()];
    input.clone_mode = CloneMode::Linked;
    let saved = core.catalog.add_template(ctx, input.clone()).await.unwrap();
    assert_eq!(saved.spec.guest_user.as_deref(), Some("alice"));
    assert_eq!(saved.spec.packages, ["nginx", "htop"]);
    assert_eq!(saved.spec.clone_mode, CloneMode::Linked);
    let read = core.catalog.template(ctx, saved.id).await.unwrap();
    assert_eq!(read.spec, saved.spec, "kept as saved");
    let mut edit = saved.spec.clone();
    edit.guest_user = Some("bob".into());
    edit.packages = Vec::new();
    edit.clone_mode = CloneMode::Full;
    core.catalog.update_template(ctx, saved.id, edit).await.unwrap();
    let audit = core.store.recent_audit(ctx, 20).await.unwrap();
    let changed = audit
        .iter()
        .find(|e| e.action == "Changed the launch template 'web'")
        .unwrap();
    assert_eq!(
        changed.detail.as_deref(),
        Some("guest user -> bob; packages -> none; golden VMs: full clone")
    );
    for bad in ["Bob", "root", "x;y"] {
        let mut wrong = input.clone();
        wrong.name = format!("bad {bad}");
        wrong.guest_user = Some(bad.into());
        assert!(core.catalog.add_template(ctx, wrong).await.is_err(), "{bad}");
    }
    let mut wrong = input.clone();
    wrong.name = "bad packages".into();
    wrong.packages = vec!["curl|sh".into()];
    assert!(core.catalog.add_template(ctx, wrong).await.is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
