//! VM-19 to VM-21: the spec catalogue end to end, on a core with fake adapters: the built-in sizes, own sizes,
//! images (files made at run time in the system temp folder, golden VMs on the fake hypervisors), launch templates
//! with their problems and plans, the audit log, the read-only lock, the migration and FD-07 between two laptops.
//! No VM is created: deploying is R2's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{temp_folder, vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::hypervisor::Hypervisor;
use remotely_core::catalog::{
    AfterDeploy, CloneMode, DiskSpec, HashProgress, Image, ImageEdit, ImageFormat, ImageInput, ImageSource, Network,
    ProblemCode, Provisioning, SizeInput, SourceInput, TemplateInput,
};
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::presentation::Presentation;
use remotely_core::ssh_keys::{GenerateKey, KeyType};
use remotely_core::store::AuditEntry;
use remotely_core::transfer::{ExportRequest, ItemAction, ItemChoice, ItemStatus, TransferCommit};
use remotely_core::vault::{KdfParams, SecretString};
use remotely_core::Core;
use time::macros::datetime;
use uuid::Uuid;

/// A file that looks like a VMDK (a sparse header) and is `extra` bytes longer.
fn vmdk_bytes(extra: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8800];
    bytes[..4].copy_from_slice(b"KDMV");
    bytes.extend(std::iter::repeat_n(0x5a, extra));
    bytes
}

fn iso_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x9000];
    bytes[0x8001..0x8006].copy_from_slice(b"CD001");
    bytes
}

fn write(folder: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = folder.join(name);
    std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
    path
}

fn no_progress() -> Arc<dyn Fn(HashProgress) + Send + Sync> {
    Arc::new(|_| {})
}

fn cloud(name: &str, path: &Path, os_profile: &str) -> ImageInput {
    ImageInput {
        name: name.into(),
        source: SourceInput::CloudImage {
            path: path.display().to_string(),
        },
        hypervisors: vec![],
        os_profile: os_profile.into(),
        notes: Some("from cloud-images.ubuntu.com".into()),
    }
}

async fn add_image(core: &Core, input: ImageInput) -> Image {
    core.catalog
        .add_image(&core.ctx, Uuid::new_v4(), input, no_progress())
        .await
        .unwrap()
}

fn own_size(name: &str) -> SizeInput {
    SizeInput {
        name: name.into(),
        sockets: 2,
        cores_per_socket: 2,
        memory_mb: 6144,
        disks: vec![
            DiskSpec {
                size_gb: 50,
                provisioning: Provisioning::Thin,
                controller: None,
            },
            DiskSpec {
                size_gb: 200,
                provisioning: Provisioning::Thick,
                controller: None,
            },
        ],
        description: Some("web tier".into()),
    }
}

fn template(name: &str, image: &Image, size_id: &str) -> TemplateInput {
    TemplateInput {
        name: name.into(),
        image_id: image.id,
        size_id: size_id.into(),
        hypervisor: Hypervisor::Vmware,
        vm_folder: None,
        network: Network::Nat,
        ssh_key_id: None,
        naming_pattern: "web-{n}".into(),
        default_count: 2,
        environment: Environment::Lab,
        tags: vec!["web".into()],
        after_deploy: AfterDeploy::default(),
        guest_user: None,
        packages: Vec::new(),
        clone_mode: CloneMode::Full,
    }
}

async fn catalog_audit(core: &Core) -> Vec<AuditEntry> {
    let mut entries: Vec<AuditEntry> = core
        .store
        .recent_audit(&core.ctx, 200)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "catalog_changed")
        .collect();
    entries.reverse();
    entries
}

fn actions(entries: &[AuditEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.action.as_str()).collect()
}

#[tokio::test]
async fn built_in_sizes_come_first_and_are_read_only() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = &core.ctx;
    let sizes = core.catalog.sizes(ctx).await.unwrap();
    assert_eq!(sizes.len(), 12);
    assert!(sizes.iter().all(|s| s.built_in));
    assert_eq!(sizes[3].name, "gp.medium");

    for err in [
        core.catalog
            .update_size(ctx, "gp.medium", own_size("gp.medium-2"))
            .await
            .unwrap_err(),
        core.catalog.delete_size(ctx, "GP.MEDIUM").await.unwrap_err(),
        core.catalog.add_size(ctx, own_size("gp.medium")).await.unwrap_err(),
    ] {
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("built-in size"), "{err}");
    }

    // Duplicate: a built-in's values under a name of the owner's, then edited and deleted.
    let built_in = core.catalog.size(ctx, "disk.large").await.unwrap();
    let mut copy = SizeInput::from(&built_in);
    copy.name = "disk.large-copy".into();
    let saved = core.catalog.add_size(ctx, copy.clone()).await.unwrap();
    assert!(!saved.built_in);
    assert_eq!(saved.disks, built_in.disks);
    assert!(Uuid::parse_str(&saved.id).is_ok(), "own sizes go by a UUID");
    let err = core.catalog.add_size(ctx, copy).await.unwrap_err();
    assert!(err.to_string().contains("exists already"), "{err}");
    let edited = core
        .catalog
        .update_size(ctx, &saved.id, own_size("files.large"))
        .await
        .unwrap();
    assert_eq!((edited.vcpus(), edited.memory_mb), (4, 6144));
    // Saving it unchanged writes nothing.
    core.catalog
        .update_size(ctx, &saved.id, own_size("files.large"))
        .await
        .unwrap();
    let all = core.catalog.sizes(ctx).await.unwrap();
    assert_eq!(all.len(), 13);
    assert_eq!(all[12].name, "files.large");
    core.catalog.delete_size(ctx, &saved.id).await.unwrap();
    assert_eq!(core.catalog.sizes(ctx).await.unwrap().len(), 12);

    let audit = catalog_audit(&core).await;
    assert_eq!(
        actions(&audit),
        [
            "Added the size 'disk.large-copy'",
            "Changed the size 'files.large'",
            "Deleted the size 'files.large'"
        ]
    );
    assert_eq!(
        audit[0].detail.as_deref(),
        Some("2 vCPU, 4 GB RAM, 40 GB thin + 500 GB thin")
    );
    assert!(audit[1].detail.as_deref().unwrap().contains("renamed to 'files.large'"));
    assert!(audit.iter().all(|e| e.tier.is_none()), "no approval tier");
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn image_files_are_checked_hashed_and_audited() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = &core.ctx;
    let folder = temp_folder("catalog-images");
    let bytes = vmdk_bytes(3 * 1024 * 1024);
    let noble = write(&folder, "noble.vmdk", &bytes);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let progress = {
        let seen = Arc::clone(&seen);
        Arc::new(move |p: HashProgress| seen.lock().unwrap().push(p))
    };
    let image = core
        .catalog
        .add_image(
            ctx,
            Uuid::new_v4(),
            cloud("Ubuntu 24.04 cloud", &noble, "ubuntu"),
            progress,
        )
        .await
        .unwrap();
    assert_eq!(
        image.source,
        ImageSource::CloudImage {
            path: noble.display().to_string(),
            format: ImageFormat::Vmdk
        }
    );
    assert_eq!(image.hypervisors, Hypervisor::ALL, "a file deploys on both by default");
    {
        use sha2::Digest;
        assert_eq!(
            image.sha256.as_deref(),
            Some(hex::encode(sha2::Sha256::digest(&bytes)).as_str())
        );
    }
    assert_eq!(image.size_bytes, Some(bytes.len() as u64));
    assert_eq!(image.problem, None);
    let last = *seen.lock().unwrap().last().unwrap();
    assert_eq!((last.done, last.total), (bytes.len() as u64, bytes.len() as u64));

    // A .img is qcow2 or raw by its bytes; an ISO; an appliance must be .ova or .ovf.
    let mut qcow2 = vec![0u8; 0x9000];
    qcow2[..4].copy_from_slice(b"QFI\xfb");
    let rocky = write(&folder, "rocky.img", &qcow2);
    let rocky = add_image(&core, cloud("Rocky 9", &rocky, "rhel")).await;
    assert_eq!(rocky.source.format(), Some(ImageFormat::Qcow2));
    let iso = write(&folder, "server.iso", &iso_bytes());
    let iso = add_image(
        &core,
        ImageInput {
            name: "Windows Server ISO".into(),
            source: SourceInput::Iso {
                path: iso.display().to_string(),
            },
            hypervisors: vec![],
            os_profile: "windows-server".into(),
            notes: None,
        },
    )
    .await;
    assert_eq!(iso.kind(), remotely_core::catalog::ImageKind::Iso);
    let err = core
        .catalog
        .add_image(
            ctx,
            Uuid::new_v4(),
            ImageInput {
                name: "not an appliance".into(),
                source: SourceInput::Appliance {
                    path: noble.display().to_string(),
                },
                hypervisors: vec![],
                os_profile: "ubuntu".into(),
                notes: None,
            },
            no_progress(),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("A .vmdk file isn't an OVA/OVF appliance"),
        "{err}"
    );
    let fake = write(&folder, "fake.vmdk", &iso_bytes());
    let err = core
        .catalog
        .add_image(ctx, Uuid::new_v4(), cloud("fake", &fake, "ubuntu"), no_progress())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("doesn't look like a VMDK"), "{err}");

    // Network shares and device paths are refused before the file system sees them (the path is never opened).
    for path in [
        r"\\fileserver.example.com\images\noble.vmdk",
        "//fileserver.example.com/images/noble.vmdk",
        r"\\?\UNC\fileserver.example.com\images\noble.vmdk",
    ] {
        let input = ImageInput {
            source: SourceInput::CloudImage { path: path.into() },
            ..cloud("share", &noble, "ubuntu")
        };
        let err = core
            .catalog
            .add_image(ctx, Uuid::new_v4(), input, no_progress())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{path}");
        assert!(err.to_string().contains("network share"), "{path}: {err}");
    }

    // Windows 11 deploys on VirtualBox only.
    let w11 = write(&folder, "w11.iso", &iso_bytes());
    let mut input = ImageInput {
        name: "Windows 11".into(),
        source: SourceInput::Iso {
            path: w11.display().to_string(),
        },
        hypervisors: vec![Hypervisor::Vmware],
        os_profile: "windows-11".into(),
        notes: None,
    };
    let err = core
        .catalog
        .add_image(ctx, Uuid::new_v4(), input.clone(), no_progress())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Windows 11 deploys on VirtualBox only"),
        "{err}"
    );
    input.hypervisors = vec![];
    assert_eq!(add_image(&core, input).await.hypervisors, [Hypervisor::VirtualBox]);

    // Editing changes what it says about the file, never the file.
    let edited = core
        .catalog
        .update_image(
            ctx,
            image.id,
            ImageEdit {
                name: "Noble".into(),
                hypervisors: vec![Hypervisor::VirtualBox],
                os_profile: "ubuntu".into(),
                notes: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (edited.name.as_str(), edited.hypervisors.as_slice()),
        ("Noble", &[Hypervisor::VirtualBox][..])
    );
    assert_eq!(edited.sha256, image.sha256);
    let err = core
        .catalog
        .update_image(
            ctx,
            rocky.id,
            ImageEdit {
                name: "noble".into(),
                hypervisors: vec![],
                os_profile: "rhel".into(),
                notes: None,
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exists already"), "{err}");

    // A file that went away or changed shows as the image's problem.
    std::fs::write(&noble, b"KDMV short").unwrap();
    let listed = core.catalog.image(ctx, image.id).await.unwrap();
    assert!(listed.problem.unwrap().contains("changed since it was added"));
    std::fs::remove_file(&noble).unwrap();
    let listed = core.catalog.image(ctx, image.id).await.unwrap();
    assert!(listed.problem.unwrap().contains("isn't on this PC"));

    core.catalog.delete_image(ctx, image.id).await.unwrap();
    let audit = catalog_audit(&core).await;
    assert_eq!(
        actions(&audit),
        [
            "Added the image 'Ubuntu 24.04 cloud'",
            "Added the image 'Rocky 9'",
            "Added the image 'Windows Server ISO'",
            "Added the image 'Windows 11'",
            "Changed the image 'Ubuntu 24.04 cloud'",
            "Deleted the image 'Noble'"
        ]
    );
    assert!(audit[0].detail.as_deref().unwrap().contains("SHA-256 "));
    assert!(audit[5].detail.as_deref().unwrap().contains("the file or VM stays"));
    assert!(
        noble.parent().unwrap().join("rocky.img").exists(),
        "deleting an image never deletes a file"
    );
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn hashing_can_be_cancelled() {
    let core = Arc::new(Setup::new(FakeVmware::default()).build().await);
    let folder = temp_folder("catalog-cancel");
    let big = write(&folder, "big.vmdk", &vmdk_bytes(8 * 1024 * 1024));
    let request = Uuid::new_v4();
    let started = Arc::new(tokio::sync::Notify::new());
    // The first progress report (before any byte is read) waits on the hashing thread until Cancel was pressed.
    let (go_on, wait) = std::sync::mpsc::channel::<()>();
    let wait = Mutex::new(Some(wait));
    let progress = {
        let started = Arc::clone(&started);
        Arc::new(move |_: HashProgress| {
            if let Some(wait) = wait.lock().unwrap().take() {
                started.notify_one();
                let _ = wait.recv();
            }
        })
    };
    let adding = {
        let core = Arc::clone(&core);
        let input = cloud("big", &big, "ubuntu");
        tokio::spawn(async move { core.catalog.add_image(&core.ctx, request, input, progress).await })
    };
    started.notified().await;
    assert!(core.catalog.cancel_hash(request));
    go_on.send(()).unwrap();
    let err = adding.await.unwrap().unwrap_err();
    assert_eq!(err.code(), "cancelled");
    assert!(core.catalog.images(&core.ctx).await.unwrap().is_empty());
    assert!(!core.catalog.cancel_hash(request), "nothing is hashed under it now");
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn golden_vm_images_name_a_snapshot_on_the_vms_own_hypervisor() {
    let at = datetime!(2026-10-20 9:00 UTC);
    let golden = vmx("golden");
    let uuid = "0b9c3c3e-2f4e-4e1a-9f61-5c0f2d1a7e01";
    let core = Setup::new(
        FakeVmware::default()
            .in_library(&golden, Some("golden"))
            .with_snapshot(&golden, "base", at)
            .with_snapshot(&golden, "patched", at),
    )
    .with_virtualbox(
        FakeVirtualBox::new()
            .with_vm(uuid, "vbox-golden", PowerState::NotRunning)
            .with_snapshot(uuid, "clean install", at),
    )
    .build()
    .await;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();

    let input = |vm_key: &str, snapshot: &str, hypervisors: Vec<Hypervisor>| ImageInput {
        name: format!("{vm_key} {snapshot}"),
        source: SourceInput::GoldenVm {
            vm_key: vm_key.into(),
            snapshot: snapshot.into(),
        },
        hypervisors,
        os_profile: "ubuntu".into(),
        notes: None,
    };
    // By its path in the tree ("base/patched"), kept by its uid.
    let image = add_image(&core, input(&golden, "base/patched", vec![])).await;
    let ImageSource::GoldenVm {
        vm_key,
        snapshot_id,
        snapshot_name,
    } = &image.source
    else {
        panic!("{:?}", image.source)
    };
    assert_eq!(vm_key, &golden);
    assert_eq!(snapshot_name, "patched");
    assert!(
        snapshot_id.parse::<u32>().is_ok(),
        "Workstation's snapshot uid: {snapshot_id}"
    );
    assert_eq!(image.hypervisors, [Hypervisor::Vmware]);
    assert_eq!(image.sha256, None);
    assert_eq!(image.vm_name.as_deref(), Some("golden"));
    assert_eq!(image.problem, None);

    // VirtualBox: by its UUID.
    let vbox = add_image(&core, input(uuid, "clean install", vec![])).await;
    let ImageSource::GoldenVm { snapshot_id, .. } = &vbox.source else {
        panic!()
    };
    assert!(
        Uuid::parse_str(snapshot_id).is_ok(),
        "VirtualBox's snapshot UUID: {snapshot_id}"
    );
    assert_eq!(vbox.hypervisors, [Hypervisor::VirtualBox]);

    for (input, why) in [
        (
            input(&golden, "base", vec![Hypervisor::VirtualBox]),
            "the VM's own hypervisor",
        ),
        (input(&golden, "nope", vec![]), "has no snapshot 'nope'"),
        (input(&vmx("other"), "base", vec![]), "Pick a VM from the VM list"),
    ] {
        let err = core
            .catalog
            .add_image(ctx, Uuid::new_v4(), input, no_progress())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(why), "{why}: {err}");
    }
}

#[tokio::test]
async fn launch_templates_check_what_they_name_and_resolve_into_a_plan() {
    let core = Setup::new(FakeVmware::default().in_library(&vmx("web-1"), Some("web-1")))
        .build()
        .await;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let folder = temp_folder("catalog-templates");
    let noble = write(&folder, "noble.vmdk", &vmdk_bytes(1024));
    let image = add_image(&core, cloud("Noble", &noble, "ubuntu")).await;
    let size = core.catalog.add_size(ctx, own_size("web.small")).await.unwrap();

    let saved = core
        .catalog
        .add_template(ctx, template("web", &image, "gp.medium"))
        .await
        .unwrap();
    assert!(saved.problems.is_empty(), "{:?}", saved.problems);
    assert!(saved.can_deploy());

    // The editor's preview: names numbered past the VM that is already here.
    let preview = core
        .catalog
        .preview(ctx, &template("web", &image, "gp.medium"))
        .await
        .unwrap();
    let names: Vec<&str> = preview.vms.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["web-2", "web-3"]);

    // R2's entry: a plan with each VM and the size's and profile's values on Workstation.
    let plan = core.catalog.plan(ctx, saved.id, 3).await.unwrap().unwrap();
    let names: Vec<&str> = plan.vms.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["web-2", "web-3", "web-4"]);
    assert_eq!(plan.profile.guest_os, "ubuntu-64");
    assert_eq!(plan.size.name, "gp.medium");
    assert_eq!(plan.image.id, image.id);

    // Saving refuses what the editor can fix.
    let w11 = write(&folder, "w11.iso", &iso_bytes());
    let w11 = add_image(
        &core,
        ImageInput {
            name: "Windows 11".into(),
            source: SourceInput::Iso {
                path: w11.display().to_string(),
            },
            hypervisors: vec![],
            os_profile: "windows-11".into(),
            notes: None,
        },
    )
    .await;
    for (input, why) in [
        (
            template("w11", &w11, "gp.large"),
            "deploys on VirtualBox only, and this template is for Workstation",
        ),
        (template("gone", &image, "no.such.size"), "Its size was deleted"),
        (
            TemplateInput {
                network: Network::Internal { name: "lab".into() },
                ..template("intnet", &image, "gp.small")
            },
            "VirtualBox's",
        ),
        (
            TemplateInput {
                naming_pattern: "{template}-{date}".into(),
                ..template("single", &image, "gp.small")
            },
            "has no {n}",
        ),
        (template("Web", &image, "gp.small"), "exists already"),
    ] {
        let err = core.catalog.add_template(ctx, input).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains(why), "{why}: {err}");
    }
    let w11_on_vbox = core
        .catalog
        .add_template(
            ctx,
            TemplateInput {
                hypervisor: Hypervisor::VirtualBox,
                ..template("w11", &w11, "gp.large")
            },
        )
        .await
        .unwrap();
    assert!(w11_on_vbox.problems.is_empty());

    // A template on the own size; then the size and the image go, and the templates say why they can't deploy.
    let own = core
        .catalog
        .add_template(ctx, template("web-own", &image, &size.id))
        .await
        .unwrap();
    let mut edit = template("web-own", &image, &size.id);
    edit.default_count = 4;
    edit.network = Network::Vmnet { number: 3 };
    core.catalog.update_template(ctx, own.id, edit).await.unwrap();
    core.catalog.delete_size(ctx, &size.id).await.unwrap();
    let own = core.catalog.template(ctx, own.id).await.unwrap();
    assert_eq!(
        own.problems.iter().map(|p| p.code).collect::<Vec<_>>(),
        [ProblemCode::SizeGone]
    );
    core.catalog.delete_image(ctx, image.id).await.unwrap();
    let listed = core.catalog.templates(ctx).await.unwrap();
    let codes = |name: &str| -> Vec<ProblemCode> {
        listed
            .iter()
            .find(|t| t.spec.name == name)
            .unwrap()
            .problems
            .iter()
            .map(|p| p.code)
            .collect()
    };
    assert_eq!(codes("web"), [ProblemCode::ImageGone]);
    assert_eq!(codes("web-own"), [ProblemCode::ImageGone, ProblemCode::SizeGone]);
    assert!(codes("w11").is_empty());
    let problems = core.catalog.plan(ctx, saved.id, 1).await.unwrap().unwrap_err();
    assert_eq!(problems[0].code, ProblemCode::ImageGone);
    core.catalog.delete_template(ctx, saved.id).await.unwrap();

    let audit = catalog_audit(&core).await;
    let template_actions: Vec<&str> = actions(&audit)
        .into_iter()
        .filter(|a| a.contains("launch template"))
        .collect();
    assert_eq!(
        template_actions,
        [
            "Added the launch template 'web'",
            "Added the launch template 'w11'",
            "Added the launch template 'web-own'",
            "Changed the launch template 'web-own'",
            "Deleted the launch template 'web'"
        ]
    );
    let change = audit
        .iter()
        .find(|e| e.action == "Changed the launch template 'web-own'")
        .unwrap();
    assert_eq!(
        change.detail.as_deref(),
        Some("network NAT -> vmnet3; default count 2 -> 4")
    );
    let deleted = audit
        .iter()
        .find(|e| e.action == "Deleted the size 'web.small'")
        .unwrap();
    assert!(deleted.detail.as_deref().unwrap().contains("used by 'web-own'"));
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn a_templates_ssh_key_goes_by_its_public_half() {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    let ctx = &core.ctx;
    let folder = temp_folder("catalog-keys");
    let image = add_image(
        &core,
        cloud("Noble", &write(&folder, "noble.vmdk", &vmdk_bytes(16)), "ubuntu"),
    )
    .await;
    let key = core
        .keys
        .generate(
            ctx,
            GenerateKey {
                label: "deploy key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap();
    let mut input = template("web", &image, "gp.small");
    input.ssh_key_id = Some(key.id);
    let saved = core.catalog.add_template(ctx, input.clone()).await.unwrap();
    assert!(saved.problems.is_empty());
    let plan = core.catalog.plan(ctx, saved.id, 1).await.unwrap().unwrap();
    let planned = plan.ssh_key.unwrap();
    assert_eq!(planned.id, key.id);
    assert_eq!(
        Some(planned.public_key.as_str()),
        key.public.as_ref().map(|p| p.line.as_str())
    );
    assert!(!planned.public_key.contains("PRIVATE"), "only the public half");

    // A key that isn't in the vault can't be picked, and one deleted later shows as the template's problem.
    let mut stray = input.clone();
    stray.name = "stray".into();
    stray.ssh_key_id = Some(remotely_core::vault::SecretId(Uuid::new_v4()));
    let err = core.catalog.add_template(ctx, stray).await.unwrap_err();
    assert!(err.to_string().contains("no longer in the vault"), "{err}");
    core.vault.delete(ctx, key.id).await.unwrap();
    let listed = core.catalog.template(ctx, saved.id).await.unwrap();
    assert_eq!(listed.problems[0].code, ProblemCode::KeyGone);
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn the_read_only_lock_refuses_every_catalogue_edit() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let ctx = &core.ctx;
    let folder = temp_folder("catalog-lock");
    let noble = write(&folder, "noble.vmdk", &vmdk_bytes(16));
    let image = add_image(&core, cloud("Noble", &noble, "ubuntu")).await;
    let size = core.catalog.add_size(ctx, own_size("web.small")).await.unwrap();
    let saved = core
        .catalog
        .add_template(ctx, template("web", &image, "gp.small"))
        .await
        .unwrap();
    let before = catalog_audit(&core).await.len();

    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let edit = ImageEdit {
        name: "x".into(),
        hypervisors: vec![],
        os_profile: "ubuntu".into(),
        notes: None,
    };
    let refused = [
        core.catalog.add_size(ctx, own_size("other")).await.err(),
        core.catalog.update_size(ctx, &size.id, own_size("other")).await.err(),
        core.catalog.delete_size(ctx, &size.id).await.err(),
        core.catalog
            .add_image(ctx, Uuid::new_v4(), cloud("other", &noble, "ubuntu"), no_progress())
            .await
            .err(),
        core.catalog.update_image(ctx, image.id, edit).await.err(),
        core.catalog.delete_image(ctx, image.id).await.err(),
        core.catalog
            .add_template(ctx, template("other", &image, "gp.small"))
            .await
            .err(),
        core.catalog
            .update_template(ctx, saved.id, template("other", &image, "gp.small"))
            .await
            .err(),
        core.catalog.delete_template(ctx, saved.id).await.err(),
    ];
    for err in refused {
        let err = err.expect("refused");
        assert_eq!(err.code(), "read_only_lock");
        assert!(
            err.to_string().contains("Edit sizes, images and launch templates"),
            "{err}"
        );
    }
    // Reads go on.
    assert_eq!(core.catalog.sizes(ctx).await.unwrap().len(), 13);
    assert_eq!(core.catalog.images(ctx).await.unwrap().len(), 1);
    assert!(core.catalog.plan(ctx, saved.id, 1).await.unwrap().is_ok());
    assert_eq!(
        catalog_audit(&core).await.len(),
        before,
        "nothing changed, nothing audited"
    );
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn the_catalogue_tables_carry_workspace_and_user() {
    let core = Setup::new(FakeVmware::default()).build().await;
    for (table, sql) in [
        (
            "catalog_sizes",
            "SELECT name, \"notnull\" FROM pragma_table_info('catalog_sizes')",
        ),
        (
            "catalog_images",
            "SELECT name, \"notnull\" FROM pragma_table_info('catalog_images')",
        ),
        (
            "catalog_templates",
            "SELECT name, \"notnull\" FROM pragma_table_info('catalog_templates')",
        ),
    ] {
        let columns: Vec<(String, i64)> = sqlx::query_as(sql).fetch_all(core.store.pool()).await.unwrap();
        for wanted in ["workspace_id", "user_id", "created_at", "updated_at"] {
            assert!(
                columns.iter().any(|(name, not_null)| name == wanted && *not_null == 1),
                "{table}.{wanted}: {columns:?}"
            );
        }
    }
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1")
        .fetch_one(core.store.pool())
        .await
        .unwrap();
    assert!(version >= 19, "{version}");
}

const PASSPHRASE: &str = "tulip anvil orbit";

async fn laptop() -> Core {
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.transfer.use_insecure_fast_kdf();
    core
}

#[tokio::test]
async fn the_catalogue_travels_to_another_laptop() {
    let folder = temp_folder("catalog-transfer");
    let a = laptop().await;
    let ctx = &a.ctx;
    let noble = write(&folder, "noble.vmdk", &vmdk_bytes(4096));
    let image = add_image(&a, cloud("Noble", &noble, "ubuntu")).await;
    let gone = write(&folder, "gone.vmdk", &vmdk_bytes(16));
    add_image(&a, cloud("Gone", &gone, "ubuntu")).await;
    let size = a.catalog.add_size(ctx, own_size("web.small")).await.unwrap();
    let key = a
        .keys
        .generate(
            ctx,
            GenerateKey {
                label: "deploy key".into(),
                key_type: KeyType::Ed25519,
                comment: "alice@example.com".into(),
            },
        )
        .await
        .unwrap();
    let mut web = template("web", &image, &size.id);
    web.ssh_key_id = Some(key.id);
    // VM-21, VM-22: the first-boot settings and the clone mode travel with the template.
    web.guest_user = Some("alice".into());
    web.packages = vec!["nginx".into(), "htop".into()];
    web.clone_mode = CloneMode::Linked;
    a.catalog.add_template(ctx, web).await.unwrap();
    a.catalog
        .add_template(ctx, template("web-medium", &image, "gp.medium"))
        .await
        .unwrap();

    let file = folder.join("export.remotely");
    let report = a
        .transfer
        .export(
            ctx,
            &file,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: true,
                include_secrets: true,
                vault_password: Some(SecretString::new(VAULT_PASSWORD)),
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    assert_eq!(
        (report.catalog.sizes, report.catalog.images, report.catalog.templates),
        (1, 2, 2),
        "the built-in sizes stay out"
    );
    // One image's file isn't on the other laptop (both laptops are this PC here).
    std::fs::remove_file(&gone).unwrap();

    let b = laptop().await;
    let preview = b
        .transfer
        .open(&b.ctx, &file, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    let catalog = &preview.catalog;
    assert_eq!(catalog.sizes.len(), 1);
    assert_eq!(
        catalog.sizes[0].detail,
        "4 vCPU (2 x 2), 6 GB RAM, 50 GB thin + 200 GB thick"
    );
    assert!(catalog.images.iter().all(|i| i.status == ItemStatus::New));
    let gone_row = catalog.images.iter().find(|i| i.name == "Gone").unwrap();
    assert!(gone_row.notes[0].contains("isn't on this PC"), "{:?}", gone_row.notes);
    assert!(catalog.templates.iter().all(|t| t.status == ItemStatus::New));
    let report = b
        .transfer
        .commit(
            &b.ctx,
            TransferCommit {
                preview_id: preview.id,
                catalog: Default::default(),
                sessions: vec![],
                known_hosts: vec![],
                secrets: vec![],
                favourites: vec![],
                keep_startup: vec![],
                keep_forwards: vec![],
                vault_password: None,
                folder_defaults: vec![],
                groups: vec![],
            },
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(
        (
            report.catalog.sizes.added,
            report.catalog.images.added,
            report.catalog.templates.added
        ),
        (1, 2, 2)
    );
    assert_eq!(report.catalog.images_missing_here, 1);

    // On the other laptop, the templates point at its own image, size and key.
    let b_sizes = b.catalog.sizes(&b.ctx).await.unwrap();
    let b_size = b_sizes.iter().find(|s| s.name == "web.small").unwrap();
    let b_images = b.catalog.images(&b.ctx).await.unwrap();
    let b_noble = b_images.iter().find(|i| i.name == "Noble").unwrap();
    assert_eq!(b_noble.sha256, image.sha256, "the checksum taken on the first laptop");
    assert_eq!(b_noble.source, image.source, "by path");
    assert!(b_images.iter().find(|i| i.name == "Gone").unwrap().problem.is_some());
    let b_templates = b.catalog.templates(&b.ctx).await.unwrap();
    let b_web = b_templates.iter().find(|t| t.spec.name == "web").unwrap();
    assert_eq!(b_web.spec.image_id, b_noble.id);
    assert_eq!(b_web.spec.size_id, b_size.id);
    let b_key = b
        .keys
        .list(&b.ctx)
        .await
        .unwrap()
        .into_iter()
        .find(|k| k.label == "deploy key")
        .unwrap();
    assert_eq!(b_web.spec.ssh_key_id, Some(b_key.id));
    assert_eq!(b_web.spec.guest_user.as_deref(), Some("alice"));
    assert_eq!(b_web.spec.packages, ["nginx", "htop"]);
    assert_eq!(b_web.spec.clone_mode, CloneMode::Linked);
    assert!(b_web.problems.is_empty(), "{:?}", b_web.problems);
    let medium = b_templates.iter().find(|t| t.spec.name == "web-medium").unwrap();
    assert_eq!(medium.spec.size_id, "gp.medium");
    let imported: Vec<String> = catalog_audit(&b).await.into_iter().map(|e| e.action).collect();
    assert!(
        imported.contains(&"Imported the size 'web.small'".to_owned()),
        "{imported:?}"
    );
    assert!(imported.contains(&"Imported the launch template 'web' from a Remotely export".to_owned()));
    let summary = b.store.recent_audit(&b.ctx, 1).await.unwrap().remove(0);
    assert_eq!(summary.event, "data_imported");
    assert!(summary.detail.unwrap().contains("sizes 1 added"));

    // The same file again: everything is here already.
    let again = b
        .transfer
        .open(&b.ctx, &file, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    assert!(again.catalog.sizes.iter().all(|i| i.status == ItemStatus::Same));
    assert!(again.catalog.images.iter().all(|i| i.status == ItemStatus::Same));
    assert!(
        again.catalog.templates.iter().all(|i| i.status == ItemStatus::Same),
        "{:?}",
        again.catalog.templates
    );
    b.transfer.close(again.id);

    // A changed size is a conflict: replace keeps its identity here, keep both adds a second under a free name.
    a.catalog
        .update_size(
            ctx,
            &size.id,
            SizeInput {
                memory_mb: 8192,
                ..own_size("web.small")
            },
        )
        .await
        .unwrap();
    std::fs::remove_file(&file).unwrap();
    a.transfer
        .export(
            ctx,
            &file,
            ExportRequest {
                passphrase: SecretString::new(PASSPHRASE),
                include_known_hosts: false,
                include_secrets: false,
                vault_password: None,
            },
            &a.vault,
            "Remotely test",
        )
        .await
        .unwrap();
    for (action, sizes) in [(ItemAction::KeepBoth, 14), (ItemAction::Replace, 14)] {
        let preview = b
            .transfer
            .open(&b.ctx, &file, SecretString::new(PASSPHRASE), &b.vault)
            .await
            .unwrap();
        let row = &preview.catalog.sizes[0];
        assert_eq!(row.status, ItemStatus::Conflict);
        let mut choices = remotely_core::transfer::CatalogChoices::default();
        choices.sizes.push(ItemChoice {
            index: row.index,
            action,
        });
        let report = b
            .transfer
            .commit(
                &b.ctx,
                TransferCommit {
                    preview_id: preview.id,
                    catalog: choices,
                    sessions: vec![],
                    known_hosts: vec![],
                    secrets: vec![],
                    favourites: vec![],
                    keep_startup: vec![],
                    keep_forwards: vec![],
                    vault_password: None,
                    folder_defaults: vec![],
                    groups: vec![],
                },
                &b.sessions,
                &b.vault,
                &b.known_hosts,
                &b.snippets,
            )
            .await
            .unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert_eq!(b.catalog.sizes(&b.ctx).await.unwrap().len(), sizes);
    }
    let b_sizes = b.catalog.sizes(&b.ctx).await.unwrap();
    let names: Vec<(&str, u32)> = b_sizes[12..].iter().map(|s| (s.name.as_str(), s.memory_mb)).collect();
    assert_eq!(names, [("web.small", 8192), ("web.small-2", 8192)]);
    assert_eq!(
        b_sizes.iter().find(|s| s.name == "web.small").unwrap().id,
        b_size.id,
        "replace keeps the size's identity, so templates still point at it"
    );
    std::fs::remove_dir_all(folder).unwrap();
}

#[tokio::test]
async fn an_image_on_a_network_share_in_a_file_can_only_be_skipped() {
    let folder = temp_folder("catalog-share");
    let image_id = Uuid::new_v4();
    let payload = serde_json::json!({
        "exportedAt": "2026-10-25T09:00:00Z",
        "exportedBy": "a crafted file",
        "catalog": {
            "images": [{
                "id": image_id,
                "name": "On a share",
                "source": {
                    "kind": "cloudImage",
                    "path": r"\\fileserver.example.com\images\noble.vmdk",
                    "format": "vmdk"
                },
                "hypervisors": ["vmware"],
                "osProfile": "ubuntu"
            }],
            "templates": [{
                "id": Uuid::new_v4(),
                "name": "web",
                "imageId": image_id,
                "sizeId": "gp.small",
                "hypervisor": "vmware",
                "network": { "kind": "nat" },
                "namingPattern": "web-{n}",
                "defaultCount": 1
            }]
        }
    });
    let sealed = remotely_core::transfer::file::seal(
        &serde_json::to_vec(&payload).unwrap(),
        &SecretString::new(PASSPHRASE),
        &KdfParams::INSECURE_FAST,
    )
    .unwrap();
    let file = write(&folder, "crafted.remotely", &sealed);
    let b = laptop().await;
    let preview = b
        .transfer
        .open(&b.ctx, &file, SecretString::new(PASSPHRASE), &b.vault)
        .await
        .unwrap();
    let row = &preview.catalog.images[0];
    assert_eq!(row.choices, [ItemAction::Skip]);
    assert_eq!(row.default_action, ItemAction::Skip);
    assert!(row.notes[0].contains("is on a network share"), "{:?}", row.notes);
    // Choosing to import it anyway is refused before anything changes.
    let mut choices = remotely_core::transfer::CatalogChoices::default();
    choices.images.push(ItemChoice {
        index: 0,
        action: ItemAction::Import,
    });
    let commit = |catalog| TransferCommit {
        preview_id: preview.id,
        catalog,
        sessions: vec![],
        known_hosts: vec![],
        secrets: vec![],
        favourites: vec![],
        keep_startup: vec![],
        keep_forwards: vec![],
        vault_password: None,
        folder_defaults: vec![],
        groups: vec![],
    };
    let err = b
        .transfer
        .commit(
            &b.ctx,
            commit(choices),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("can't be imported"), "{err}");
    let report = b
        .transfer
        .commit(
            &b.ctx,
            commit(Default::default()),
            &b.sessions,
            &b.vault,
            &b.known_hosts,
            &b.snippets,
        )
        .await
        .unwrap();
    assert_eq!(report.catalog.images.skipped, 1);
    assert!(b.catalog.images(&b.ctx).await.unwrap().is_empty());
    // The template came, and says it can't deploy until it gets an image.
    let templates = b.catalog.templates(&b.ctx).await.unwrap();
    assert_eq!(templates[0].problems[0].code, ProblemCode::ImageGone);
    std::fs::remove_dir_all(folder).unwrap();
}
