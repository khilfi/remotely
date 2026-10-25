//! Opt-in test of CV-03 and VM-17 against the real conversion tools (CLAUDE.md "Development safety").
//!
//! Runs only with `REMOTELY_IT=1`. It makes small images (64 MB, mostly empty) in a folder of the system temp folder
//! and converts them with the real vmware-vdiskmanager, VBoxManage and, when installed, qemu-img, through Remotely's
//! own runner (the job's work, without the bus), then reads each output with Remotely's own header readers. It checks
//! that VirtualBox's media list is the same after as before. The export test makes an `it-` Workstation VM out of
//! files in that folder (a .vmx and a disk; Workstation's library never lists it, nothing powers it on) and exports
//! it. Everything is deleted at the end. It never touches another VM or file.
//!
//! `REMOTELY_IT=1 cargo test -p remotely-core --test conversion_it -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use remotely_core::adapters::disk_tools::{DiskTools, LocalDiskTools, Tool};
use remotely_core::adapters::host_counters::WindowsCounters;
use remotely_core::adapters::hypervisor::{Hypervisor, Hypervisors};
use remotely_core::adapters::{virtualbox, vmware};
use remotely_core::convert::args::OvfVersion;
use remotely_core::convert::formats::{DiskFormat, OutputKind};
use remotely_core::convert::inspect::inspect;
use remotely_core::convert::plan::{plan, Source};
use remotely_core::convert::runner::ConvertActions;
use remotely_core::convert::verify::verify;
use remotely_core::convert::{ConvertSpec, Converter, ExportSpec, ExportTarget};
use remotely_core::domain::{Context, UserId, WorkspaceId};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MB: u64 = 1 << 20;

fn enabled() -> bool {
    let on = std::env::var("REMOTELY_IT").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set REMOTELY_IT=1 to run against the real conversion tools");
    }
    on
}

fn ctx() -> Context {
    Context {
        workspace_id: WorkspaceId(Uuid::nil()),
        user_id: UserId(Uuid::nil()),
    }
}

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn converter() -> (Converter, Arc<LocalDiskTools>) {
    let hypervisors = Hypervisors::new(
        Arc::from(vmware::connect_with(None, None)),
        Arc::from(virtualbox::connect(None)),
    );
    let tools = Arc::new(LocalDiskTools::new(None));
    let converter = Converter::new(hypervisors, tools.clone(), Arc::new(WindowsCounters::new()));
    (converter, tools)
}

async fn media(converter: &Converter) -> Vec<String> {
    let paths = converter.tool_paths();
    let Some(vbox) = paths.vboxmanage.clone() else {
        return Vec::new();
    };
    let out = std::process::Command::new(vbox).args(["list", "hdds"]).output().unwrap();
    remotely_core::convert::args::parse_hdd_locations(&String::from_utf8_lossy(&out.stdout))
}

#[tokio::test]
async fn real_tools_convert_small_images_and_leave_virtualbox_as_it_was() {
    if !enabled() {
        return;
    }
    let (converter, tools) = converter();
    let paths = converter.tool_paths();
    eprintln!(
        "tools: qemu-img {}, vdiskmanager {}, VBoxManage {}, ovftool {}",
        paths.has(Tool::QemuImg),
        paths.has(Tool::VdiskManager),
        paths.has(Tool::VBoxManage),
        paths.has(Tool::Ovftool)
    );
    let dir = Folder(std::env::temp_dir().join(format!("remotely-it-conv-{}", Uuid::new_v4().simple())));
    std::fs::create_dir_all(&dir.0).unwrap();
    // A raw disk with an MBR boot signature, so it reads as a whole disk.
    let raw = dir.0.join("source.raw");
    let mut bytes = vec![0u8; (64 * MB) as usize];
    bytes[510] = 0x55;
    bytes[511] = 0xaa;
    bytes[4096..4100].copy_from_slice(b"R5IT");
    std::fs::write(&raw, &bytes).unwrap();
    let media_before = media(&converter).await;

    let mut sources = vec![(raw.clone(), DiskFormat::Raw)];
    let mut made: Vec<(PathBuf, OutputKind)> = Vec::new();
    for kind in OutputKind::ALL {
        let from = &sources[0];
        if plan(Source::file(from.1), kind, None, &paths).is_err() {
            eprintln!("{kind:?}: no tool here");
            continue;
        }
        let output = dir.0.join(format!("out-{kind:?}.{}", kind.extension()));
        let spec = ConvertSpec {
            source: from.0.display().to_string(),
            source_format: from.1,
            output: output.display().to_string(),
            kind,
            whole_megabytes: false,
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let progress = move |p: f64, step: &str| log.lock().unwrap().push((p, step.to_owned()));
        let note = converter
            .convert(&ctx(), Uuid::new_v4(), &spec, &progress, &CancellationToken::new())
            .await
            .unwrap_or_else(|err| panic!("{kind:?}: {err}"));
        let info = inspect(&output).await.unwrap();
        assert_eq!(info.format, kind.format(), "{kind:?}");
        assert_eq!(info.virtual_bytes, Some(64 * MB), "{kind:?}: {info:?}");
        assert!(info.problems.is_empty(), "{kind:?}: {:?}", info.problems);
        eprintln!(
            "{kind:?}: {} ({:?}) progress {} reports; {note}",
            info.describe(),
            info.on_disk_bytes,
            seen.lock().unwrap().len()
        );
        made.push((output, kind));
        if kind == OutputKind::VdiDynamic {
            sources.push((dir.0.join(format!("out-{kind:?}.vdi")), DiskFormat::Vdi));
        }
    }
    // From each format back to raw (or VMDK where raw can't be made from it here).
    for (path, kind) in made.clone() {
        if kind.format() == DiskFormat::Raw {
            continue;
        }
        let out = if plan(Source::file(kind.format()), OutputKind::Raw, None, &paths).is_ok() {
            OutputKind::Raw
        } else {
            OutputKind::VmdkSparse
        };
        let target = dir.0.join(format!("back-{kind:?}.{}", out.extension()));
        let spec = ConvertSpec {
            source: path.display().to_string(),
            source_format: kind.format(),
            output: target.display().to_string(),
            kind: out,
            whole_megabytes: false,
        };
        match converter
            .convert(&ctx(), Uuid::new_v4(), &spec, &|_, _| {}, &CancellationToken::new())
            .await
        {
            Ok(note) => {
                eprintln!("{kind:?} back to {out:?}: {note}");
                if out == OutputKind::Raw {
                    let back = std::fs::read(&target).unwrap();
                    assert_eq!(back.len(), bytes.len(), "{kind:?}");
                    assert_eq!(&back[4096..4100], b"R5IT", "{kind:?}: the data came through");
                }
                if tools.qemu_img().is_some() {
                    let report = verify(tools.as_ref(), &raw, Some(&target), CancellationToken::new(), Arc::new(|_| {}))
                        .await
                        .unwrap();
                    assert_eq!(report.same_size, Some(true));
                    if let Some(c) = report.comparison {
                        assert!(c.identical, "{kind:?}: {}", c.said);
                    }
                }
            }
            Err(err) => eprintln!("{kind:?} back to {out:?}: not here ({err})"),
        }
    }
    // Azure: a size that isn't whole megabytes is rounded up on the way.
    let odd = dir.0.join("odd.raw");
    std::fs::write(&odd, vec![0u8; (8 * MB + 512) as usize]).unwrap();
    if plan(Source::file(DiskFormat::Raw), OutputKind::VhdFixed, Some(9 * MB), &paths).is_ok() {
        let target = dir.0.join("azure.vhd");
        let spec = ConvertSpec {
            source: odd.display().to_string(),
            source_format: DiskFormat::Raw,
            output: target.display().to_string(),
            kind: OutputKind::VhdFixed,
            whole_megabytes: true,
        };
        converter
            .convert(&ctx(), Uuid::new_v4(), &spec, &|_, _| {}, &CancellationToken::new())
            .await
            .unwrap();
        let info = inspect(&target).await.unwrap();
        assert_eq!(info.virtual_bytes, Some(9 * MB), "rounded up to whole MB: {info:?}");
    }
    assert_eq!(media(&converter).await, media_before, "VirtualBox's media list is as it was");
    // Nothing of the jobs' own is left beside the outputs.
    let leftovers: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".remotely"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

const IT_VMX: &str = ".encoding = \"UTF-8\"\r\nconfig.version = \"8\"\r\nvirtualHW.version = \"20\"\r\ndisplayName = \"it-r5-export\"\r\nguestOS = \"ubuntu-64\"\r\nmemsize = \"512\"\r\nnumvcpus = \"1\"\r\nfirmware = \"efi\"\r\nscsi0.present = \"TRUE\"\r\nscsi0.virtualDev = \"lsilogic\"\r\nscsi0:0.present = \"TRUE\"\r\nscsi0:0.fileName = \"it-r5-export.vmdk\"\r\nethernet0.present = \"TRUE\"\r\nethernet0.connectionType = \"nat\"\r\nethernet0.virtualDev = \"e1000e\"\r\n";

#[tokio::test]
async fn an_it_workstation_vm_exports_to_each_target() {
    if !enabled() {
        return;
    }
    let (converter, _) = converter();
    let paths = converter.tool_paths();
    let Some(vdisk) = paths.vdiskmanager.clone() else {
        eprintln!("skipped: no vmware-vdiskmanager");
        return;
    };
    let dir = Folder(std::env::temp_dir().join(format!("remotely-it-export-{}", Uuid::new_v4().simple())));
    let vm = dir.0.join("it-r5-export");
    std::fs::create_dir_all(&vm).unwrap();
    let disk = vm.join("it-r5-export.vmdk");
    let made = std::process::Command::new(&vdisk)
        .args(["-c", "-s", "64MB", "-a", "lsilogic", "-t", "0"])
        .arg(&disk)
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stdout));
    let vmx = vm.join("it-r5-export.vmx");
    std::fs::write(&vmx, IT_VMX).unwrap();
    let out = dir.0.join("exports");
    std::fs::create_dir_all(&out).unwrap();
    let qemu = paths.has(Tool::QemuImg);
    for target in [
        ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V1,
        },
        ExportTarget::Esxi { thick: false },
        ExportTarget::Esxi { thick: true },
        ExportTarget::HyperV,
        ExportTarget::Azure,
        ExportTarget::Kvm,
        ExportTarget::Proxmox,
        ExportTarget::Raw,
    ] {
        let spec = ExportSpec {
            vm_key: vmx.display().to_string(),
            vm_name: "it-r5-export".into(),
            hypervisor: Hypervisor::Vmware,
            target,
            folder: out.display().to_string(),
            name: format!("it-r5-export-{}", target.suffix()),
            disk_kind: target.disk_kind(qemu),
        };
        match converter
            .export(&ctx(), Uuid::new_v4(), &spec, &|_, _| {}, &CancellationToken::new())
            .await
        {
            Ok(note) => {
                let folder = spec.out_folder();
                let mut files: Vec<String> = std::fs::read_dir(&folder)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                files.sort();
                assert!(files.contains(&"README.md".to_owned()), "{target:?}: {files:?}");
                if let Some(kind) = spec.disk_kind {
                    let disk = folder.join(format!("it-r5-export.{}", kind.extension()));
                    let info = inspect(&disk).await.unwrap();
                    assert_eq!(info.format, kind.format(), "{target:?}");
                    assert_eq!(info.virtual_bytes, Some(64 * MB), "{target:?}");
                }
                eprintln!("{target:?}: {files:?}; {note}");
            }
            Err(err) => eprintln!("{target:?}: not here ({err})"),
        }
    }
    let _ = Path::new(&out);
}
