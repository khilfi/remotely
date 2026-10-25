//! VM-21, VM-22, VM-10: the job's work for one new VM ([`DeployActions`]): make it, then its after-deploy steps.
//!
//! Making a VM is everything up to its first power-on: its own folder (`<folder>\<name>`, which must not be there
//! yet), the clone, import or new VM with its disks, the size's CPU, memory and boot disk, cloud-init's first-boot
//! data (Workstation's `guestinfo`, VirtualBox's NoCloud seed), the VM in the list with its label and tags, the
//! "clean" snapshot when asked, and the power-on. When any of that fails, or the job is cancelled meanwhile (the
//! running tool is killed), what this step made is removed, and only that: the VM it made (`vmrun deleteVM`,
//! `VBoxManage unregistervm --delete`), then its folder. A folder that was there before is never touched, since
//! the step refuses to start in one.
//!
//! The after-deploy steps never fail the VM: the guest's IP (within the deploy's wait), the SSH session to it
//! (QL-01: linked to the VM by hand), ejecting VirtualBox's seed once the guest has booted, and the console. What
//! each did, or why it didn't, goes into the job's note for the VM.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::cloud_init::{self, FirstBoot};
use super::spec::{DeploySource, DeploySpec, DeployVm};
use super::{seed, virtualbox as vb, vmx, workstation as ws, DeployActions};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmx_file::VmxFile;
use crate::catalog::images::ImageFormat;
use crate::convert::formats::{DiskFormat, OutputKind};
use crate::catalog::sizes::{DiskController, Provisioning};
use crate::catalog::templates::Network;
use crate::command_bus::{PowerOp, SnapshotOp};
use crate::domain::{Context, Environment};
use crate::error::{CoreError, Result};
use crate::inventory::Inventory;
use crate::locks;
use crate::sessions::{SessionAuth, SessionInput, SessionLibrary};
use crate::store::{self, NewAuditEntry, Store};
use crate::vault::Vault;

/// Clones, imports and disk copies of large VMs take long; the job's cancel stops them sooner.
const LONG: Duration = Duration::from_secs(6 * 60 * 60);
/// Settings and attaches.
const SHORT: Duration = Duration::from_secs(2 * 60);
/// A power-on.
const START: Duration = Duration::from_secs(10 * 60);

/// How the runner waits; tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct DeployTuning {
    /// How often the guest's IP is asked for while the deploy waits for it.
    pub ip_poll: Duration,
    /// At most this long, whatever the deploy's own wait (tests).
    pub ip_wait_cap: Option<Duration>,
    /// VirtualBox may still hold a VM whose clone was cancelled: removing it is tried this often...
    pub cleanup_tries: u32,
    /// ...this long apart.
    pub cleanup_pause: Duration,
}

impl Default for DeployTuning {
    fn default() -> Self {
        Self {
            ip_poll: Duration::from_secs(5),
            ip_wait_cap: None,
            cleanup_tries: 10,
            cleanup_pause: Duration::from_secs(3),
        }
    }
}

/// What one step made, so a failure or a cancel removes exactly that.
#[derive(Debug, Default)]
struct Made {
    /// The VM's own folder, which this step made.
    folder: Option<PathBuf>,
    /// The deploy's folder, when this step made it (it is removed only if it is empty then).
    parent: Option<PathBuf>,
    /// A Workstation VM this step made.
    vmx: Option<PathBuf>,
    /// A VirtualBox VM this step registered, by UUID; or by name (an import, whose UUID VirtualBox picks).
    vbox: Option<String>,
    vbox_name: Option<String>,
    /// VirtualBox: the seed's DVD drive (controller, port, device), ejected after the first boot.
    seed: Option<(String, u32, u32)>,
    seed_file: Option<PathBuf>,
    /// What the job says about the VM besides where it is.
    notes: Vec<String>,
}

/// The deploy runner the job runner calls (`JobRunner::set_deployer`).
pub struct Deployer {
    store: Store,
    hypervisors: Hypervisors,
    inventory: Arc<Inventory>,
    sessions: Arc<SessionLibrary>,
    vault: Arc<dyn Vault>,
    tuning: RwLock<DeployTuning>,
    /// One scanned-folder change at a time (two VMs of a deploy finish together).
    scan_folders: tokio::sync::Mutex<()>,
    /// CV-01, CV-03: converts what the hypervisor's own copy can't read (qcow2, VHDX; VHD and VDI on Workstation).
    converter: RwLock<Option<Arc<crate::convert::Converter>>>,
}

impl Deployer {
    pub fn new(
        store: Store,
        hypervisors: Hypervisors,
        inventory: Arc<Inventory>,
        sessions: Arc<SessionLibrary>,
        vault: Arc<dyn Vault>,
    ) -> Self {
        Self {
            store,
            hypervisors,
            inventory,
            sessions,
            vault,
            tuning: RwLock::new(DeployTuning::default()),
            scan_folders: tokio::sync::Mutex::new(()),
            converter: RwLock::new(None),
        }
    }

    pub fn set_tuning(&self, tuning: DeployTuning) {
        *locks::write(&self.tuning) = tuning;
    }

    /// CV-01, CV-03: what converts imported disks and qcow2 cloud images.
    pub fn set_converter(&self, converter: Arc<crate::convert::Converter>) {
        *locks::write(&self.converter) = Some(converter);
    }

    /// CV-01, CV-03: `source` (of `format`) converted into `target`, the new VM's disk of `kind`, through a work
    /// folder inside the VM's own folder.
    async fn convert_disk(&self, source: &str, format: DiskFormat, target: &Path, kind: OutputKind) -> Result<()> {
        let converter = locks::read(&self.converter)
            .clone()
            .ok_or(CoreError::NotImplemented("conversions"))?;
        let info = crate::convert::inspect::inspect(Path::new(source)).await?;
        if info.format != format {
            return Err(CoreError::ConversionRefused(format!(
                "{source} is a {} now, not the {} it was when the deploy was asked.",
                info.format.label(),
                format.label()
            )));
        }
        if let Some(problem) = info.problems.first() {
            return Err(CoreError::ConversionRefused(format!("{source}: {problem}.")));
        }
        let work = target
            .parent()
            .unwrap_or(Path::new("."))
            .join(format!(".convert-{}", Uuid::new_v4().simple()));
        tokio::fs::create_dir(&work).await?;
        // The deploy's cancel stops this (the runner's select); this token is the conversion's own.
        let ran = converter
            .convert_into(Path::new(source), &info, kind, target, &work, &CancellationToken::new())
            .await;
        let _ = tokio::fs::remove_dir_all(&work).await;
        ran.map(drop)
    }

    fn tuning(&self) -> DeployTuning {
        *locks::read(&self.tuning)
    }
}

/// A cloud image's format as a disk format (an OVA named as a cloud image goes to vdiskmanager as before).
fn disk_format(format: ImageFormat) -> DiskFormat {
    match format {
        ImageFormat::Raw => DiskFormat::Raw,
        ImageFormat::Qcow2 => DiskFormat::Qcow2,
        ImageFormat::Vmdk | ImageFormat::Ova | ImageFormat::Ovf | ImageFormat::Iso => DiskFormat::Vmdk,
    }
}

/// The boot disk's size in bytes, when the deploy has a size.
fn boot_bytes(spec: &DeploySpec) -> Option<u64> {
    spec.size.as_ref().map(|s| u64::from(s.boot_disk_gb()) * (1 << 30))
}

fn boot_provisioning(spec: &DeploySpec) -> Provisioning {
    spec.size
        .as_ref()
        .and_then(|s| s.disks.first())
        .map_or(Provisioning::Thin, |d| d.provisioning)
}

/// The image's default user, when cloud-init makes none: Ubuntu's and Debian's cloud images name theirs after
/// the distribution.
fn default_user(spec: &DeploySpec) -> Option<String> {
    match spec.profile.as_ref().map(|p| p.id.as_str()) {
        Some("ubuntu") => Some("ubuntu".into()),
        Some("debian") => Some("debian".into()),
        _ => None,
    }
}

/// The deploy's folder for the VM, made by this step: it must not be there yet.
async fn make_folder(folder: &Path, made: &mut Made) -> Result<()> {
    if let Some(parent) = folder.parent() {
        if tokio::fs::metadata(parent).await.is_err() {
            tokio::fs::create_dir_all(parent).await?;
            made.parent = Some(parent.to_path_buf());
        }
    }
    match tokio::fs::create_dir(folder).await {
        Ok(()) => {
            made.folder = Some(folder.to_path_buf());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Err(CoreError::InvalidInput(format!(
            "{} is there already, and a deploy makes each VM's folder itself",
            folder.display()
        ))),
        Err(err) => Err(err.into()),
    }
}

impl Deployer {
    /// Makes the VM, up to its first power-on, and returns its key.
    async fn make(&self, ctx: &Context, spec: &DeploySpec, vm: &DeployVm, made: &mut Made) -> Result<String> {
        let folder = spec.vm_folder(vm);
        make_folder(&folder, made).await?;
        let first_boot = spec.first_boot.as_ref().map(|f| FirstBoot {
            instance_id: format!("iid-remotely-{}", Uuid::new_v4()),
            hostname: vm.hostname.clone(),
            user: f.user.clone(),
            public_key: f.public_key.clone(),
            packages: f.packages.clone(),
        });
        let key = match spec.hypervisor {
            Hypervisor::Vmware => {
                self.make_workstation(spec, vm, &folder, first_boot.as_ref(), made)
                    .await?
            }
            Hypervisor::VirtualBox => {
                self.make_virtualbox(ctx, spec, vm, &folder, first_boot.as_ref(), made)
                    .await?
            }
        };
        self.list(ctx, spec, &key, made).await?;
        if spec.after_deploy.clean_snapshot {
            // Before the first boot: quick, with no memory to save, and going back to it boots the VM as deployed.
            match self
                .hypervisors
                .snapshot(
                    &key,
                    &SnapshotOp::Take {
                        name: crate::catalog::templates::CLEAN_SNAPSHOT_NAME.into(),
                    },
                )
                .await
            {
                Ok(()) => made.notes.push("snapshot 'clean' taken before its first boot".into()),
                Err(err) => made.notes.push(format!("the 'clean' snapshot wasn't taken: {err}")),
            }
        }
        if matches!(spec.source, DeploySource::BulkClone) {
            // VM-10: a copy of a VM that is shut down stays off; it would start with its source's name and addresses.
            made.notes.push("left off, like the VM it copies".into());
            return Ok(key);
        }
        let start = PowerOp::Start { gui: false };
        match spec.hypervisor {
            Hypervisor::Vmware => tokio::time::timeout(START, self.hypervisors.vmware().power(Path::new(&key), start))
                .await
                .map_err(|_| CoreError::Timeout {
                    command: "vmrun start".into(),
                    seconds: START.as_secs(),
                })??,
            Hypervisor::VirtualBox => tokio::time::timeout(START, self.hypervisors.virtualbox().power(&key, start))
                .await
                .map_err(|_| CoreError::Timeout {
                    command: "VBoxManage startvm".into(),
                    seconds: START.as_secs(),
                })??,
        }
        Ok(key)
    }

    // ---- Workstation ---------------------------------------------------------------------------------------

    async fn make_workstation(
        &self,
        spec: &DeploySpec,
        vm: &DeployVm,
        folder: &Path,
        first_boot: Option<&FirstBoot>,
        made: &mut Made,
    ) -> Result<String> {
        let vmware = self.hypervisors.vmware();
        let vmx_path = folder.join(format!("{}.vmx", vm.name));
        let guestinfo = first_boot.map(cloud_init::guestinfo_keys).unwrap_or_default();
        let settings = ws::vmx_settings(&vm.name, spec.size.as_ref(), spec.network.as_ref(), &guestinfo);
        match &spec.source {
            DeploySource::GoldenVm {
                vm_key,
                snapshot_id,
                snapshot_name,
                linked,
                ..
            } => {
                let path = self.snapshot_path(vm_key, snapshot_id, snapshot_name).await?;
                if *linked {
                    // Checked again here: the golden VM may have started or opened in Workstation since the approval.
                    if let Some(refusal) = super::preview::linked_clone_refusal(&self.hypervisors, vm_key).await {
                        return Err(CoreError::InvalidInput(refusal));
                    }
                }
                made.vmx = Some(vmx_path.clone());
                vmware
                    .vmrun_change(
                        ws::clone_args(Path::new(vm_key), &vmx_path, *linked, Some(&path), &vm.name),
                        LONG,
                    )
                    .await?;
                self.set_vmx(&vmx_path, &settings).await?;
                if *linked {
                    made.notes.push(
                        "a linked clone keeps the golden VM's disk size (it can't grow; give the golden VM a larger disk)"
                            .into(),
                    );
                } else {
                    self.grow_workstation(&vmx_path, spec, made).await?;
                }
            }
            DeploySource::BulkClone => {
                let (source, _) = vm
                    .clone_of
                    .as_ref()
                    .ok_or_else(|| CoreError::InvalidInput("A bulk clone names each VM's source.".into()))?;
                made.vmx = Some(vmx_path.clone());
                vmware
                    .vmrun_change(
                        ws::clone_args(Path::new(source), &vmx_path, false, None, &vm.name),
                        LONG,
                    )
                    .await?;
                self.set_vmx(&vmx_path, &ws::vmx_settings(&vm.name, None, None, &[]))
                    .await?;
            }
            DeploySource::Appliance { path, .. } => {
                made.vmx = Some(vmx_path.clone());
                vmware
                    .ovftool(
                        ws::ovftool_args(Path::new(path), &vmx_path, &vm.name, boot_provisioning(spec)),
                        LONG,
                    )
                    .await?;
                self.set_vmx(&vmx_path, &settings).await?;
                self.grow_workstation(&vmx_path, spec, made).await?;
            }
            DeploySource::CloudImage { path, format } => {
                let disks = self
                    .new_workstation_disks(spec, vm, folder, &[(path.clone(), disk_format(*format))])
                    .await?;
                made.vmx = Some(vmx_path.clone());
                self.write_new_vmx(spec, vm, &vmx_path, disks, None, guestinfo).await?;
                self.grow_workstation(&vmx_path, spec, made).await?;
            }
            // CV-01: each imported disk converted into the VM's folder.
            DeploySource::Import { disks: sources, .. } => {
                let sources: Vec<(String, DiskFormat)> = sources.iter().map(|d| (d.path.clone(), d.format)).collect();
                let disks = self.new_workstation_disks(spec, vm, folder, &sources).await?;
                made.vmx = Some(vmx_path.clone());
                self.write_new_vmx(spec, vm, &vmx_path, disks, None, guestinfo).await?;
                self.grow_workstation(&vmx_path, spec, made).await?;
            }
            DeploySource::Iso { path } => {
                let disks = self.new_workstation_disks(spec, vm, folder, &[]).await?;
                made.vmx = Some(vmx_path.clone());
                self.write_new_vmx(spec, vm, &vmx_path, disks, Some(path.clone()), guestinfo)
                    .await?;
            }
        }
        Ok(vmx_path.display().to_string())
    }

    /// The disks of a new Workstation VM: the first ones copies of the cloud image or the imported disks when there
    /// are some, the others new, each `-t 0` (thin) or `-t 2` (thick). A VMDK or raw source is copied by
    /// vdiskmanager itself; any other format (qcow2, VHD, VHDX, VDI) through the conversion plan (CV-01, CV-03).
    async fn new_workstation_disks(
        &self,
        spec: &DeploySpec,
        vm: &DeployVm,
        folder: &Path,
        images: &[(String, DiskFormat)],
    ) -> Result<Vec<vmx::VmxDisk>> {
        let vmware = self.hypervisors.vmware();
        let size = spec
            .size
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("A new VM needs a size.".into()))?;
        let mut out = Vec::new();
        for (i, disk) in size.disks.iter().enumerate() {
            let file_name = ws::disk_file_name(&vm.name, i);
            let path = folder.join(&file_name);
            match images.get(i) {
                Some((image, format)) if !crate::convert::import::copied_by_deploy(Hypervisor::Vmware, *format) => {
                    let kind = crate::convert::import::native_kind(Hypervisor::Vmware, disk.provisioning == Provisioning::Thin);
                    self.convert_disk(image, *format, &path, kind).await?;
                }
                Some((image, format)) => {
                    let (image, format) = (image, *format);
                    let source = if format == DiskFormat::Raw {
                        let bytes = tokio::fs::metadata(image).await?.len();
                        let descriptor = folder.join(format!("{}-image.vmdk", vm.name));
                        tokio::fs::write(&descriptor, ws::raw_descriptor(Path::new(image), bytes)).await?;
                        descriptor
                    } else {
                        PathBuf::from(image)
                    };
                    let copied = vmware
                        .vdiskmanager(ws::convert_args(&source, &path, disk.provisioning), LONG)
                        .await;
                    if format == DiskFormat::Raw {
                        let _ = tokio::fs::remove_file(&source).await;
                    }
                    copied?;
                }
                None => {
                    let adapter = if disk.controller == DiskController::Ide {
                        "ide"
                    } else {
                        "lsilogic"
                    };
                    vmware
                        .vdiskmanager(
                            crate::vm_settings::vmware::create_args(
                                &path,
                                u64::from(disk.size_gb) * 1024,
                                adapter,
                                disk.provisioning == Provisioning::Thin,
                            ),
                            LONG,
                        )
                        .await?;
                }
            }
            out.push(vmx::VmxDisk {
                file_name,
                controller: disk.controller,
                controller_model: disk.controller_model.clone(),
            });
        }
        Ok(out)
    }

    async fn write_new_vmx(
        &self,
        spec: &DeploySpec,
        vm: &DeployVm,
        path: &Path,
        disks: Vec<vmx::VmxDisk>,
        iso: Option<String>,
        guestinfo: Vec<(&'static str, String)>,
    ) -> Result<()> {
        let (Some(size), Some(profile)) = (&spec.size, &spec.profile) else {
            return Err(CoreError::InvalidInput(
                "A new VM needs a size and an OS profile.".into(),
            ));
        };
        let text = vmx::render(&vmx::NewVmx {
            display_name: vm.name.clone(),
            guest_os: profile.guest_os.clone(),
            hardware_version: profile
                .hardware_version
                .unwrap_or(crate::catalog::profiles::WORKSTATION_HARDWARE_VERSION),
            firmware: profile.firmware,
            sockets: size.sockets,
            cores_per_socket: size.cores_per_socket,
            memory_mb: size.memory_mb,
            disks,
            iso,
            network: spec.network.clone().unwrap_or(Network::Nat),
            nic: profile.nic.clone(),
            extra: guestinfo.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        });
        self.hypervisors.vmware().write_vmx(path, text.as_bytes()).await
    }

    /// Sets these keys in the .vmx (R3's [`VmxFile`] keeps the rest as it was).
    async fn set_vmx(&self, path: &Path, settings: &[(String, String)]) -> Result<()> {
        let vmware = self.hypervisors.vmware();
        let mut file = VmxFile::parse(&vmware.vmx_bytes(path).await?)?;
        for (key, value) in settings {
            file.set(key, value)?;
        }
        vmware.write_vmx(path, &file.to_bytes()).await
    }

    /// The boot disk grows to the size's when it is smaller; a disk never shrinks.
    async fn grow_workstation(&self, path: &Path, spec: &DeploySpec, made: &mut Made) -> Result<()> {
        let Some(want) = boot_bytes(spec) else {
            return Ok(());
        };
        let hardware = self.hypervisors.vmware().hardware(path).await?;
        let Some(boot) = hardware.disks.first() else {
            made.notes.push("it has no disk to grow".into());
            return Ok(());
        };
        match boot.provisioned_bytes {
            Some(now) if now < want => {
                self.hypervisors
                    .vmware()
                    .vdiskmanager(
                        crate::vm_settings::vmware::expand_args(Path::new(&boot.path), want / (1 << 20)),
                        LONG,
                    )
                    .await?;
                made.notes.push(format!(
                    "boot disk grown from {} to {}",
                    super::preview::size_text(now),
                    super::preview::size_text(want)
                ));
            }
            Some(_) => {}
            None => made
                .notes
                .push("its boot disk's size couldn't be read, so it wasn't grown".into()),
        }
        Ok(())
    }

    /// vmrun's name for the golden VM's snapshot, which may have been renamed since the image was added.
    async fn snapshot_path(&self, vm_key: &str, snapshot_id: &str, name: &str) -> Result<String> {
        let tree = self.hypervisors.snapshots(vm_key).await?;
        let nodes = crate::snapshots::tree_nodes(&tree, time::OffsetDateTime::now_utc());
        tree.snapshots
            .iter()
            .find(|s| s.id.clone().unwrap_or_else(|| s.uid.to_string()) == snapshot_id)
            .and_then(|s| nodes.iter().find(|n| n.uid == s.uid))
            .map(|n| n.path.clone())
            .ok_or_else(|| {
                CoreError::InvalidInput(format!(
                    "The golden VM's snapshot '{name}' is no longer there: add the image again with another snapshot."
                ))
            })
    }

    // ---- VirtualBox ----------------------------------------------------------------------------------------

    async fn vbox(&self, args: Vec<String>, timeout: Duration) -> Result<String> {
        self.hypervisors.virtualbox().change(args, timeout).await
    }

    async fn make_virtualbox(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        vm: &DeployVm,
        folder: &Path,
        first_boot: Option<&FirstBoot>,
        made: &mut Made,
    ) -> Result<String> {
        let base = Path::new(&spec.folder);
        let mut uuid = Uuid::new_v4().hyphenated().to_string();
        match &spec.source {
            DeploySource::GoldenVm {
                vm_key,
                snapshot_id,
                linked,
                ..
            } => {
                made.vbox = Some(uuid.clone());
                self.vbox(
                    vb::clonevm_args(vm_key, Some(snapshot_id), *linked, &vm.name, &uuid, base),
                    LONG,
                )
                .await?;
                self.after_copy(&uuid, spec, !*linked, made).await?;
                if *linked {
                    made.notes.push(
                        "a linked clone keeps the golden VM's disk size (it can't grow; give the golden VM a larger disk)"
                            .into(),
                    );
                }
                self.attach_seed(&uuid, folder, vm, first_boot, None, made).await?;
            }
            DeploySource::BulkClone => {
                let (source, _) = vm
                    .clone_of
                    .as_ref()
                    .ok_or_else(|| CoreError::InvalidInput("A bulk clone names each VM's source.".into()))?;
                made.vbox = Some(uuid.clone());
                self.vbox(vb::clonevm_args(source, None, false, &vm.name, &uuid, base), LONG)
                    .await?;
            }
            DeploySource::Appliance { path, .. } => {
                made.vbox_name = Some(vm.name.clone());
                self.vbox(
                    vb::import_args(Path::new(path), &vm.name, base, spec.size.as_ref()),
                    LONG,
                )
                .await?;
                uuid = self.find_vbox(&vm.name, folder).await?;
                made.vbox = Some(uuid.clone());
                self.after_copy(&uuid, spec, true, made).await?;
                self.attach_seed(&uuid, folder, vm, first_boot, None, made).await?;
            }
            DeploySource::CloudImage { path, format } => {
                made.vbox = Some(uuid.clone());
                let dvd = self.new_vbox_vm(&uuid, spec, vm, false).await?;
                self.vbox_disks(&uuid, spec, vm, folder, &[(path.clone(), disk_format(*format))])
                    .await?;
                self.grow_virtualbox(&uuid, spec, made).await?;
                self.attach_seed(&uuid, folder, vm, first_boot, Some(dvd), made).await?;
            }
            // CV-01: each imported disk converted into the VM's folder.
            DeploySource::Import { disks, .. } => {
                made.vbox = Some(uuid.clone());
                let dvd = self.new_vbox_vm(&uuid, spec, vm, false).await?;
                let sources: Vec<(String, DiskFormat)> = disks.iter().map(|d| (d.path.clone(), d.format)).collect();
                self.vbox_disks(&uuid, spec, vm, folder, &sources).await?;
                self.grow_virtualbox(&uuid, spec, made).await?;
                self.attach_seed(&uuid, folder, vm, first_boot, Some(dvd), made).await?;
            }
            DeploySource::Iso { path } => {
                made.vbox = Some(uuid.clone());
                let (controller, port) = self.new_vbox_vm(&uuid, spec, vm, true).await?;
                self.vbox_disks(&uuid, spec, vm, folder, &[]).await?;
                self.vbox(vb::attach_args(&uuid, controller, port, true, path), SHORT)
                    .await?;
                if let Some(unattended) = &spec.unattended {
                    self.unattended(ctx, &uuid, path, vm, unattended).await?;
                    made.notes.push(format!(
                        "VirtualBox installs the OS by itself as {}: it goes on for a while after the job ends",
                        unattended.user
                    ));
                }
            }
        }
        Ok(uuid)
    }

    /// A new VirtualBox VM with the profile's and size's settings and its storage controllers; returns where its
    /// DVD drive goes.
    async fn new_vbox_vm(
        &self,
        uuid: &str,
        spec: &DeploySpec,
        vm: &DeployVm,
        boot_dvd_first: bool,
    ) -> Result<(DiskController, u32)> {
        let (Some(size), Some(profile)) = (&spec.size, &spec.profile) else {
            return Err(CoreError::InvalidInput(
                "A new VM needs a size and an OS profile.".into(),
            ));
        };
        self.vbox(
            vb::createvm_args(&vm.name, uuid, &profile.guest_os, Path::new(&spec.folder)),
            SHORT,
        )
        .await?;
        self.vbox(
            vb::modifyvm_args(
                uuid,
                size,
                profile,
                spec.network.as_ref().unwrap_or(&Network::Nat),
                spec.host_adapter.as_deref(),
                boot_dvd_first,
            ),
            SHORT,
        )
        .await?;
        if profile.firmware == crate::catalog::profiles::Firmware::EfiSecureBoot {
            for call in vb::secure_boot_calls(uuid) {
                self.vbox(call, SHORT).await?;
            }
        }
        let dvd = vb::dvd_port(&size.disks);
        let mut controllers: Vec<(DiskController, String, u32)> = Vec::new();
        for disk in &size.disks {
            match controllers.iter_mut().find(|(c, _, _)| *c == disk.controller) {
                Some(entry) => entry.2 += 1,
                None => controllers.push((disk.controller, disk.controller_model.clone(), 1)),
            }
        }
        if let Some(entry) = controllers.iter_mut().find(|(c, _, _)| *c == dvd.0) {
            entry.2 += 1;
        }
        for (controller, model, ports) in controllers {
            self.vbox(vb::storagectl_args(uuid, controller, &model, ports), SHORT)
                .await?;
        }
        Ok(dvd)
    }

    /// The disks of a new VirtualBox VM: the first ones copies of the cloud image or the imported disks when there are
    /// some, the others new. VMDK, VDI, VHD and raw sources are copied by VirtualBox itself (`clonemedium`,
    /// `convertfromraw`); qcow2 and VHDX through the conversion plan (CV-01, CV-03).
    async fn vbox_disks(
        &self,
        uuid: &str,
        spec: &DeploySpec,
        vm: &DeployVm,
        folder: &Path,
        images: &[(String, DiskFormat)],
    ) -> Result<()> {
        let size = spec
            .size
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("A new VM needs a size.".into()))?;
        let ports = vb::disk_ports(&size.disks);
        for (i, (disk, (controller, port))) in size.disks.iter().zip(ports).enumerate() {
            let path = if i == 0 {
                folder.join(format!("{}.vdi", vm.name))
            } else {
                folder.join(format!("{}-{i}.vdi", vm.name))
            };
            match images.get(i) {
                Some((image, format)) if !crate::convert::import::copied_by_deploy(Hypervisor::VirtualBox, *format) => {
                    let kind = crate::convert::import::native_kind(
                        Hypervisor::VirtualBox,
                        disk.provisioning == Provisioning::Thin,
                    );
                    self.convert_disk(image, *format, &path, kind).await?;
                }
                Some((image, format)) => {
                    self.vbox(
                        vb::copy_image_args(Path::new(image), *format == DiskFormat::Raw, &path, disk.provisioning),
                        LONG,
                    )
                    .await?;
                }
                None => {
                    self.vbox(vb::createmedium_args(&path, disk.size_gb, disk.provisioning), LONG)
                        .await?;
                }
            }
            self.vbox(
                vb::attach_args(uuid, controller, port, false, &path.display().to_string()),
                SHORT,
            )
            .await?;
        }
        Ok(())
    }

    /// After a clone or an import: the size's CPU and memory, the deploy's network, and the boot disk grown.
    async fn after_copy(&self, uuid: &str, spec: &DeploySpec, grow: bool, made: &mut Made) -> Result<()> {
        if let Some(size) = &spec.size {
            let nic = spec.profile.as_ref().map_or("82540EM", |p| p.nic.as_str());
            let network = spec.network.as_ref().map(|n| (n, spec.host_adapter.as_deref(), nic));
            self.vbox(vb::resize_vm_args(uuid, size, network), SHORT).await?;
        }
        if grow {
            self.grow_virtualbox(uuid, spec, made).await?;
        }
        Ok(())
    }

    async fn grow_virtualbox(&self, uuid: &str, spec: &DeploySpec, made: &mut Made) -> Result<()> {
        let Some(want) = boot_bytes(spec) else {
            return Ok(());
        };
        let hardware = self.hypervisors.virtualbox().hardware(uuid).await?;
        let Some(boot) = hardware.disks.first() else {
            made.notes.push("it has no disk to grow".into());
            return Ok(());
        };
        match boot.provisioned_bytes {
            Some(now) if now < want => {
                let gb = u32::try_from(want >> 30).unwrap_or(u32::MAX);
                self.vbox(vb::resize_args(&boot.path, gb), LONG).await?;
                made.notes.push(format!(
                    "boot disk grown from {} to {}",
                    super::preview::size_text(now),
                    super::preview::size_text(want)
                ));
            }
            Some(_) => {}
            None => made
                .notes
                .push("its boot disk's size couldn't be read, so it wasn't grown".into()),
        }
        Ok(())
    }

    /// VM-22: the NoCloud seed, written into the VM's folder and attached as a DVD: on the new VM's DVD port, else
    /// in the clone's own DVD drive, else in a new drive on its boot disk's controller.
    async fn attach_seed(
        &self,
        uuid: &str,
        folder: &Path,
        vm: &DeployVm,
        first_boot: Option<&FirstBoot>,
        dvd: Option<(DiskController, u32)>,
        made: &mut Made,
    ) -> Result<()> {
        let Some(first_boot) = first_boot else {
            return Ok(());
        };
        let user_data = first_boot.user_data();
        let meta_data = first_boot.meta_data();
        let image = seed::write_seed(
            &[("user-data", user_data.as_bytes()), ("meta-data", meta_data.as_bytes())],
            time::OffsetDateTime::now_utc(),
        )?;
        let file = folder.join(format!("{}-cidata.iso", vm.name));
        tokio::fs::write(&file, image).await?;
        made.seed_file = Some(file.clone());
        let (controller, port, device) = match dvd {
            Some((controller, port)) => (vb::controller_name(controller).to_owned(), port, 0),
            None => self.dvd_slot(uuid).await?,
        };
        self.vbox(
            vb::attach_named(uuid, &controller, port, device, true, &file.display().to_string()),
            SHORT,
        )
        .await?;
        made.seed = Some((controller, port, device));
        Ok(())
    }

    /// A clone's or an import's DVD drive, or a new one on its boot disk's controller (one more port).
    async fn dvd_slot(&self, uuid: &str) -> Result<(String, u32, u32)> {
        let info = self.hypervisors.virtualbox().vm_info(uuid).await?;
        if let Some(found) = info.dvds.first().and_then(|d| vb::parse_slot(&d.slot)) {
            return Ok(found);
        }
        let controller = info
            .disks
            .first()
            .and_then(|d| vb::parse_slot(&d.slot))
            .map(|(c, _, _)| c)
            .or_else(|| info.controllers.first().map(|c| c.name.clone()))
            .ok_or_else(|| {
                CoreError::InvalidInput("The VM has no storage controller for the cloud-init seed.".into())
            })?;
        let used: Vec<u32> = info
            .disks
            .iter()
            .map(|d| d.slot.as_str())
            .chain(info.dvds.iter().map(|d| d.slot.as_str()))
            .filter_map(vb::parse_slot)
            .filter(|(c, _, _)| *c == controller)
            .map(|(_, port, _)| port)
            .collect();
        let port = used.iter().max().map_or(0, |p| p + 1);
        let ports = info
            .controllers
            .iter()
            .find(|c| c.name == controller)
            .and_then(|c| c.ports);
        if ports.is_some_and(|n| port >= n) {
            self.vbox(
                vec![
                    "storagectl".into(),
                    uuid.into(),
                    "--name".into(),
                    controller.clone(),
                    "--portcount".into(),
                    (port + 1).to_string(),
                ],
                SHORT,
            )
            .await?;
        }
        Ok((controller, port, 0))
    }

    /// An import's UUID: VirtualBox picks it, so the VM is found by its name and folder.
    async fn find_vbox(&self, name: &str, folder: &Path) -> Result<String> {
        let vbox = self.hypervisors.virtualbox();
        let folder_key = crate::adapters::vmware::path_key(folder);
        for listed in vbox.list_vms().await? {
            if listed.name != name {
                continue;
            }
            let Ok(info) = vbox.vm_info(&listed.uuid).await else {
                continue;
            };
            let in_folder = info
                .config_file
                .as_ref()
                .and_then(|f| f.parent())
                .is_some_and(|f| crate::adapters::vmware::path_key(f) == folder_key);
            if in_folder {
                return Ok(info.uuid);
            }
        }
        Err(CoreError::InvalidInput(format!(
            "VirtualBox imported the appliance, but no VM named {name} is in {}",
            folder.display()
        )))
    }

    /// VirtualBox installs the OS by itself. The guest password goes from the vault into a file only this
    /// Windows user can read (their own temp folder), which VBoxManage reads (`--password-file`) and which is
    /// deleted as soon as it returns, whatever it says.
    async fn unattended(
        &self,
        ctx: &Context,
        uuid: &str,
        iso: &str,
        vm: &DeployVm,
        unattended: &super::spec::UnattendedSpec,
    ) -> Result<()> {
        let password = self.vault.get(ctx, unattended.password_id).await?;
        let dir = std::env::temp_dir().join(format!("remotely-unattended-{}", Uuid::new_v4()));
        tokio::fs::create_dir(&dir).await?;
        let file = dir.join("password");
        let written = tokio::fs::write(&file, password.expose().as_bytes()).await;
        drop(password);
        let ran = match written {
            Ok(()) => {
                self.vbox(
                    vb::unattended_args(uuid, Path::new(iso), &unattended.user, &file, &vm.hostname),
                    LONG,
                )
                .await
            }
            Err(err) => Err(err.into()),
        };
        if let Err(err) = tokio::fs::remove_dir_all(&dir).await {
            tracing::error!(error = %err, "could not delete the unattended install's password file");
        }
        ran.map(drop)
    }

    // ---- The VM list -----------------------------------------------------------------------------------------

    /// The new VM in the VM list with the deploy's label and tags. Workstation's VMs show once their folder is
    /// scanned: the deploy's folder joins the scanned folders unless one of them holds it already.
    async fn list(&self, ctx: &Context, spec: &DeploySpec, key: &str, made: &mut Made) -> Result<()> {
        if spec.hypervisor == Hypervisor::Vmware {
            self.scan(ctx, Path::new(&spec.folder)).await?;
        }
        self.inventory.refresh(ctx).await?;
        if self.store.find_vm(ctx, key).await?.is_none() {
            made.notes.push("it isn't in the VM list yet: refresh it".into());
            return Ok(());
        }
        if spec.environment != Environment::None {
            if let Err(err) = self
                .inventory
                .set_environment(ctx, &[key.to_owned()], spec.environment)
                .await
            {
                made.notes.push(format!("its label wasn't set: {err}"));
            }
        }
        for tag in &spec.tags {
            if let Err(err) = self.store.tag_vms(ctx, &[key.to_owned()], tag).await {
                made.notes.push(format!("the tag {tag} wasn't set: {err}"));
            }
        }
        Ok(())
    }

    /// Adds `folder` to the folders scanned for .vmx files, unless a scanned folder holds it (audited).
    async fn scan(&self, ctx: &Context, folder: &Path) -> Result<()> {
        let _one = self.scan_folders.lock().await;
        let saved = self
            .store
            .get_setting::<Vec<String>>(ctx, store::SCAN_FOLDERS_KEY)
            .await?
            .unwrap_or_default();
        let key = crate::adapters::vmware::path_key(folder);
        let held = saved.iter().any(|s| {
            let scanned = crate::adapters::vmware::path_key(Path::new(s));
            key == scanned || key.starts_with(&format!("{}\\", scanned.trim_end_matches('\\')))
        });
        if held {
            return Ok(());
        }
        let mut folders = saved;
        folders.push(folder.display().to_string());
        self.store.put_setting(ctx, store::SCAN_FOLDERS_KEY, &folders).await?;
        let detail = format!("added {} for the VMs a deploy made there", folder.display());
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: "Set the VM folders to scan",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await
            .map(drop)
    }

    // ---- Cleanup ---------------------------------------------------------------------------------------------

    /// Removes what `made` says this step made; returns what couldn't be removed, in words.
    async fn clean_up(&self, spec: &DeploySpec, made: &Made) -> Vec<String> {
        let mut left = Vec::new();
        match spec.hypervisor {
            Hypervisor::Vmware => {
                if let Some(vmx) = &made.vmx {
                    let vmware = self.hypervisors.vmware();
                    // The VM's own files, and Workstation forgets it; a VM that didn't get as far has none.
                    if vmware.vmx_bytes(vmx).await.is_ok() {
                        if let Err(err) = vmware
                            .vmrun_change(vec!["deleteVM".into(), vmx.clone().into_os_string()], SHORT)
                            .await
                        {
                            tracing::warn!(error = %err, vmx = %vmx.display(), "deploy cleanup: vmrun deleteVM failed");
                        }
                    }
                }
            }
            Hypervisor::VirtualBox => {
                let mut uuid = made.vbox.clone();
                if uuid.is_none() {
                    if let (Some(name), Some(folder)) = (&made.vbox_name, &made.folder) {
                        uuid = self.find_vbox(name, folder).await.ok();
                    }
                }
                if let Some(uuid) = uuid {
                    if let Some(problem) = self.unregister(&uuid).await {
                        left.push(problem);
                    }
                }
                if let Some(seed) = &made.seed_file {
                    // `unregistervm --delete` deletes the VM's disks but leaves a DVD image in VirtualBox's media list.
                    let close = vec!["closemedium".into(), "dvd".into(), seed.display().to_string()];
                    let _ = self.hypervisors.virtualbox().change(close, SHORT).await;
                }
            }
        }
        if let Some(folder) = &made.folder {
            if let Err(err) = tokio::fs::remove_dir_all(folder).await {
                if err.kind() != std::io::ErrorKind::NotFound {
                    left.push(format!("{} ({err}): delete it by hand", folder.display()));
                }
            }
        }
        if let Some(parent) = &made.parent {
            // Only when nothing else went in since.
            let _ = tokio::fs::remove_dir(parent).await;
        }
        left
    }

    /// `unregistervm --delete`, tried again while VirtualBox still holds the VM (a cancelled clone that it is
    /// still finishing). `None` when it is gone.
    async fn unregister(&self, uuid: &str) -> Option<String> {
        let vbox = self.hypervisors.virtualbox();
        let tuning = self.tuning();
        let mut last = None;
        for attempt in 0..tuning.cleanup_tries.max(1) {
            if vbox.vm_info(uuid).await.is_err() {
                return None;
            }
            match vbox.change(vb::unregister_args(uuid), SHORT).await {
                Ok(_) => return None,
                Err(err) => last = Some(err.to_string()),
            }
            if attempt + 1 < tuning.cleanup_tries {
                tokio::time::sleep(tuning.cleanup_pause).await;
            }
        }
        last.map(|err| format!("the VirtualBox VM {uuid} ({err}): remove it in VirtualBox"))
    }

    // ---- After deploy ------------------------------------------------------------------------------------------

    async fn guest_ip(&self, spec: &DeploySpec, key: &str) -> Option<String> {
        match spec.hypervisor {
            Hypervisor::Vmware => self.hypervisors.vmware().guest_ip(Path::new(key)).await.ok().flatten(),
            Hypervisor::VirtualBox => {
                let vbox = self.hypervisors.virtualbox();
                let props = vbox.guest_properties(key).await.ok()?;
                let info = vbox.vm_info(key).await.ok()?;
                crate::adapters::virtualbox::guest_ip(&props, &info.nics)
            }
        }
    }

    /// Waits for the guest's IP, at most the deploy's wait; `None` when it doesn't show (or the job is cancelled).
    async fn wait_for_ip(&self, spec: &DeploySpec, key: &str, token: &CancellationToken) -> Option<String> {
        let tuning = self.tuning();
        let mut wait = Duration::from_secs(u64::from(spec.ip_wait_secs));
        if let Some(cap) = tuning.ip_wait_cap {
            wait = wait.min(cap);
        }
        let poll = tuning.ip_poll;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(ip) = self.guest_ip(spec, key).await {
                return Some(ip);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = token.cancelled() => return None,
                _ = tokio::time::sleep(poll) => {}
            }
        }
    }

    async fn after_deploy(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        vm: &DeployVm,
        key: &str,
        made: &mut Made,
        token: &CancellationToken,
    ) -> String {
        let mut notes = vec![format!("made in {}", spec.vm_folder(vm).display())];
        notes.append(&mut made.notes);
        // An ISO install has no OS yet, and a bulk clone keeps its own sessions and network.
        let has_os = !matches!(spec.source, DeploySource::Iso { .. } | DeploySource::BulkClone);
        let wants_ip = has_os && (spec.after_deploy.create_session || made.seed.is_some());
        let ip = if wants_ip {
            let ip = self.wait_for_ip(spec, key, token).await;
            match &ip {
                Some(ip) => notes.push(format!("IP {ip}")),
                None if token.is_cancelled() => notes.push("cancelled while waiting for its IP".into()),
                None => notes.push(format!(
                    "no IP within {} minutes ({} report it): make its session once it shows",
                    spec.ip_wait_secs.div_ceil(60),
                    spec.hypervisor.tools_name()
                )),
            }
            ip
        } else {
            None
        };
        if let (Some(_), Some((controller, port, device))) = (&ip, &made.seed) {
            // The guest has booted, so cloud-init has read its seed.
            let ejected = self
                .vbox(
                    vb::attach_named(key, controller, *port, *device, true, "emptydrive"),
                    SHORT,
                )
                .await;
            match ejected {
                Ok(_) => {
                    if let Some(file) = &made.seed_file {
                        let _ = self
                            .vbox(
                                vec!["closemedium".into(), "dvd".into(), file.display().to_string()],
                                SHORT,
                            )
                            .await;
                        let _ = tokio::fs::remove_file(file).await;
                    }
                    notes.push("cloud-init's seed ejected after the first boot".into());
                }
                Err(err) => notes.push(format!("cloud-init's seed is still in its DVD drive ({err})")),
            }
        }
        if spec.after_deploy.create_session && has_os {
            if spec.hypervisor == Hypervisor::VirtualBox && spec.network == Some(Network::Nat) {
                notes.push("no SSH session: on VirtualBox's NAT the guest can't be reached from this PC".into());
            } else if let Some(ip) = &ip {
                notes.push(self.make_session(ctx, spec, vm, key, ip).await);
            }
        }
        if spec.after_deploy.open_console {
            let opened = match spec.hypervisor {
                Hypervisor::Vmware => self.hypervisors.vmware().open_console(Path::new(key)).await,
                Hypervisor::VirtualBox => self.hypervisors.virtualbox().open_console(key).await,
            };
            notes.push(match opened {
                Ok(()) => "console opened".into(),
                Err(err) => format!("the console didn't open: {err}"),
            });
        }
        notes.join("; ")
    }

    /// The SSH session to the guest, linked to the VM by hand (QL-01) when the deploy says so.
    async fn make_session(&self, ctx: &Context, spec: &DeploySpec, vm: &DeployVm, key: &str, ip: &str) -> String {
        let vm_id = if spec.after_deploy.link_session {
            match self.store.find_vm(ctx, key).await {
                Ok(Some(record)) => Some(record.id),
                _ => None,
            }
        } else {
            None
        };
        let linked = vm_id.is_some();
        let auth = match spec.ssh_key_id {
            Some(key_id) => SessionAuth::Key {
                key_id: Some(key_id),
                passphrase_id: None,
            },
            None => SessionAuth::Password { password_id: None },
        };
        let username = spec
            .first_boot
            .as_ref()
            .and_then(|f| f.user.clone())
            .or_else(|| spec.unattended.as_ref().map(|u| u.user.clone()))
            .or_else(|| default_user(spec));
        let input = SessionInput {
            name: vm.name.clone(),
            folder_id: None,
            host: ip.to_owned(),
            port: 22,
            username,
            auth,
            jump_session_id: None,
            // The VM is on this PC's own network: no jump host.
            jump_direct: true,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: spec.environment,
            color: None,
            tags: spec.tags.clone(),
            vm_id,
        };
        match self.sessions.create(ctx, input).await {
            Ok(session) if linked => format!("session '{}' made and linked to the VM", session.name),
            Ok(session) => format!("session '{}' made", session.name),
            Err(err) => format!("the SSH session wasn't made: {err}"),
        }
    }
}

#[async_trait]
impl DeployActions for Deployer {
    async fn deploy_vm(
        &self,
        ctx: &Context,
        _job_id: Uuid,
        spec: &DeploySpec,
        vm: &DeployVm,
        token: &CancellationToken,
    ) -> Result<String> {
        let mut made = Made::default();
        let outcome = {
            let work = self.make(ctx, spec, vm, &mut made);
            tokio::select! {
                biased;
                _ = token.cancelled() => Err(CoreError::Cancelled),
                done = work => done,
            }
        };
        match outcome {
            Ok(key) => Ok(self.after_deploy(ctx, spec, vm, &key, &mut made, token).await),
            Err(err) => {
                let left = self.clean_up(spec, &made).await;
                if matches!(err, CoreError::Cancelled) && left.is_empty() {
                    return Err(CoreError::Cancelled);
                }
                let mut message = err.to_string();
                if left.is_empty() {
                    message.push_str("; what it made was removed");
                } else {
                    message.push_str(&format!("; what it made was removed but for {}", left.join(", ")));
                }
                Err(CoreError::DeployFailed {
                    vm: vm.name.clone(),
                    message,
                })
            }
        }
    }
}
