//! CV-01: an import is a deploy. The Import dialog's request (a file analysed by [`crate::convert::import`], a name,
//! the hypervisor, an OS profile, a size or the source's own CPU and memory) becomes a [`DeploySpec`] whose source
//! is the appliance (an OVA or OVF, R2's own import) or the foreign disks ([`DeploySource::Import`]), and goes
//! through the same preview, bus command, tiers, job and cleanup as every deploy.
//!
//! CV-04 (G1), a cloud server's disks as one VM: a disk image takes data disks after it ([`ImportRequest::data_disks`],
//! attached in order, each copied or converted as it needs; a `System_Disk` file offers its `Data_Disk` siblings),
//! and every disk counts in the preview and the capacity plan. A foreign disk goes on SATA unless the request picks
//! another controller (a disk built for KVM boots with virtio, and its initramfs often lacks VMware's SCSI drivers,
//! while every Linux and Windows has AHCI's); its firmware is the request's, else the source's description's, else
//! what its partition table says ([`crate::convert::boot`]), else the OS profile's. Its first boot, when asked, is a
//! NoCloud seed with the hostname, a user with sudo, the vault key's public half and DHCP on any network card
//! ([`crate::deploy::cloud_init`]), never a password.

use std::path::Path;

use serde::Deserialize;

use super::{problem, refused, DeployCheck, Deploys};
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::profiles::{profile, Firmware};
use crate::catalog::sizes::{DiskController, Provisioning};
use crate::catalog::templates::{self, check_guest_user, check_packages, AfterDeploy, Network, Problem, ProblemCode};
use crate::command_bus::SubmitOutcome;
use crate::convert::formats::GIB;
use crate::convert::import::{add_data_disks, analyze, copied_by_deploy, ImportAnalysis, ImportKind};
use crate::deploy::spec::{
    DeployOrigin, DeploySource, DeploySpec, DeployVm, DiskPlan, FirstBootSpec, ImportDisk, ProfileSpec, SizeSpec,
    DEFAULT_IP_WAIT_SECS,
};
use crate::domain::{Context, Environment};
use crate::error::{CoreError, Result};
use crate::vault::SecretId;

/// CV-01: cloud-init's first boot for an imported cloud image (OpenStack and KVM images have it; a VM's own disk
/// usually doesn't need it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCloudInit {
    #[serde(default)]
    pub guest_user: Option<String>,
    #[serde(default)]
    pub ssh_key_id: Option<SecretId>,
    #[serde(default)]
    pub packages: Vec<String>,
}

/// What the Import dialog sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    /// The file picked: an OVA or OVF, a disk image, a libvirt XML or a Proxmox `.conf`.
    pub source: String,
    pub hypervisor: Hypervisor,
    pub name: String,
    /// `None`: the hypervisor's default folder.
    #[serde(default)]
    pub folder: Option<String>,
    pub profile_id: String,
    /// `None`: what the source's description says, else the profile's.
    #[serde(default)]
    pub firmware: Option<Firmware>,
    /// A catalogue size; `None`: the source's own CPU and memory (below, or its description's) and disks.
    #[serde(default)]
    pub size_id: Option<String>,
    #[serde(default)]
    pub vcpus: Option<u32>,
    #[serde(default)]
    pub cores_per_socket: Option<u32>,
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// The converted disks take their full size at once.
    #[serde(default)]
    pub thick: bool,
    pub network: Network,
    #[serde(default)]
    pub host_adapter: Option<String>,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "no_after_deploy")]
    pub after_deploy: AfterDeploy,
    /// cloud-init's first boot, from a NoCloud seed (CV-04: on both hypervisors, with DHCP on any network card).
    #[serde(default)]
    pub cloud_init: Option<ImportCloudInit>,
    /// CV-04: data disks after a disk image's boot disk, in the order they attach. Files the shell's dialog
    /// picked, or the analysis offered; each is only read.
    #[serde(default)]
    pub data_disks: Vec<String>,
    /// CV-04: the disks' controller; `None`: SATA for foreign disks.
    #[serde(default)]
    pub controller: Option<DiskController>,
}

fn no_after_deploy() -> AfterDeploy {
    AfterDeploy {
        create_session: false,
        link_session: false,
        clean_snapshot: false,
        open_console: false,
    }
}

/// The most vCPU and memory an import asks for (a size's own limits).
const MAX_VCPUS: u32 = 64;
const MAX_MEMORY_MB: u32 = 1024 * 1024;

fn coded(code: ProblemCode, message: impl Into<String>) -> Problem {
    Problem {
        code,
        message: message.into(),
    }
}

/// CV-04, review of PR #86: what the disks' controller can't take. Workstation's IDE has four slots (`ide0:0` to
/// `ide1:1`); VirtualBox's IDE as the deploy lays it out (each disk a port of its own, the DVD drive after them) has
/// two ports, the seed's DVD taking one. A VM boots from NVMe only with UEFI.
fn controller_problem(hv: Hypervisor, size: &SizeSpec, firmware: Firmware, seed: bool) -> Option<Problem> {
    let on = |c: DiskController| size.disks.iter().filter(|d| d.controller == c).count();
    let ide = on(DiskController::Ide);
    let ide_slots = match hv {
        Hypervisor::Vmware => 4,
        Hypervisor::VirtualBox => {
            if seed {
                1
            } else {
                2
            }
        }
    };
    if ide > ide_slots {
        return Some(problem(format!(
            "IDE takes {ide_slots} disk{} here and the import has {ide}: pick SATA, or leave data disks out.",
            if ide_slots == 1 { "" } else { "s" }
        )));
    }
    let boots_from_nvme = size.disks.first().is_some_and(|d| d.controller == DiskController::Nvme);
    if boots_from_nvme && firmware == Firmware::Bios {
        return Some(problem(
            "A VM boots from NVMe only with UEFI: pick UEFI, or another disk controller.",
        ));
    }
    None
}

/// `bytes` as whole GB, at least 1.
fn gb(bytes: u64) -> u32 {
    u32::try_from(bytes.div_ceil(GIB).max(1)).unwrap_or(u32::MAX)
}

impl Deploys {
    /// CV-01: what the picked file is and brings. A read.
    pub async fn analyze_import(&self, source: &Path) -> Result<ImportAnalysis> {
        let tools = self.tool_paths()?;
        analyze(source, &tools).await
    }

    fn tool_paths(&self) -> Result<crate::adapters::disk_tools::ToolPaths> {
        Ok(self
            .converter
            .as_ref()
            .ok_or(CoreError::NotImplemented("conversions"))?
            .tool_paths())
    }

    async fn import_spec(
        &self,
        ctx: &Context,
        request: &ImportRequest,
    ) -> Result<std::result::Result<(DeploySpec, ImportAnalysis), Vec<Problem>>> {
        let hv = request.hypervisor;
        let mut analysis = self.analyze_import(Path::new(&request.source)).await?;
        if request.data_disks.len() >= crate::convert::import::MAX_IMPORT_DISKS {
            return Err(CoreError::InvalidInput(format!(
                "An import takes at most {} disks.",
                crate::convert::import::MAX_IMPORT_DISKS
            )));
        }
        let data: Vec<std::path::PathBuf> = request.data_disks.iter().map(std::path::PathBuf::from).collect();
        add_data_disks(&mut analysis, &data, &self.tool_paths()?).await;
        let mut problems = Vec::new();
        if let Some(why) = analysis.refusal(hv) {
            problems.push(problem(format!("It can't be imported into {}: {why}", hv.label())));
        }
        let name = request.name.trim().to_owned();
        match templates::expand(&name, "", 1, crate::catalog::today()) {
            Err(err) => problems.push(coded(ProblemCode::NameTaken, err.to_string())),
            Ok(_) if name.contains(['{', '}']) => {
                problems.push(coded(ProblemCode::NameTaken, format!("'{name}' can't be a VM's name.")))
            }
            Ok(_) => {
                let taken = self
                    .store
                    .list_vms(ctx)
                    .await?
                    .iter()
                    .any(|vm| vm.display_name.eq_ignore_ascii_case(&name));
                if taken {
                    problems.push(coded(
                        ProblemCode::NameTaken,
                        format!("A VM named '{name}' is here already: pick another name."),
                    ));
                }
            }
        }
        let Some(os) = profile(&request.profile_id) else {
            problems.push(coded(
                ProblemCode::UnknownProfile,
                format!("'{}' isn't an OS profile this version has.", request.profile_id),
            ));
            return Ok(Err(problems));
        };
        if let Some(why) = os.refusal(hv) {
            problems.push(coded(ProblemCode::NotOnHypervisor, why));
        }
        if request.network.only_on().is_some_and(|only| only != hv) {
            problems.push(coded(
                ProblemCode::NetworkMismatch,
                format!("The network {} isn't {}'s.", request.network.describe(), hv.label()),
            ));
        }
        let provisioning = if request.thick {
            Provisioning::Thick
        } else {
            Provisioning::Thin
        };
        // CV-04: a foreign disk boots on SATA unless asked otherwise; an appliance keeps its import tool's.
        let foreign = analysis.kind != ImportKind::Appliance;
        // The user's pick, else what the disk says (review of PR #86: a VMware-made disk keeps its SCSI or IDE;
        // a disk built for another hypervisor goes on SATA), else the profile's.
        let hint = analysis.controller_hint.as_ref().filter(|_| foreign);
        let controller = match (request.controller, hint) {
            (Some(chosen), _) => chosen,
            (None, Some(hint)) => hint.controller,
            (None, None) => os.controller(hv),
        };
        let controller_model = match (request.controller, hint.and_then(|h| h.scsi_adapter.as_deref())) {
            (None, Some("buslogic")) if controller == DiskController::Scsi => match hv {
                Hypervisor::Vmware => "buslogic".to_owned(),
                Hypervisor::VirtualBox => "BusLogic".to_owned(),
            },
            _ => templates::controller_model(hv, controller, &os).to_owned(),
        };
        let disk = |size_gb: u32| DiskPlan {
            size_gb,
            provisioning,
            controller,
            controller_model: controller_model.clone(),
        };
        let found = analysis.found_disks();
        let source_disks: Vec<u32> = if analysis.kind == ImportKind::Appliance {
            analysis
                .disks
                .iter()
                .map(|d| gb(d.virtual_bytes.unwrap_or(16 * GIB)))
                .collect()
        } else {
            found.iter().map(|(_, _, bytes)| gb(*bytes)).collect()
        };
        let size = match &request.size_id {
            Some(id) => match self.catalog.size(ctx, id).await {
                Ok(size) => {
                    let mut disks: Vec<DiskPlan> = Vec::new();
                    let count = size.disks.len().max(source_disks.len());
                    for i in 0..count {
                        let from_size = size.disks.get(i).map_or(0, |d| d.size_gb);
                        let from_source = source_disks.get(i).copied().unwrap_or(0);
                        let mut plan = disk(from_size.max(from_source).max(1));
                        if let Some(d) = size.disks.get(i) {
                            plan.provisioning = if request.thick {
                                Provisioning::Thick
                            } else {
                                d.provisioning
                            };
                            // CV-04: foreign disks stay on the import's controller (SATA by default): the size's is
                            // for its own new disks.
                            if let (Some(c), false) = (d.controller, foreign && i < source_disks.len()) {
                                plan.controller = c;
                                plan.controller_model = templates::controller_model(hv, c, &os).to_owned();
                            }
                        }
                        disks.push(plan);
                    }
                    SizeSpec {
                        id: size.id.clone(),
                        name: size.name.clone(),
                        sockets: size.sockets,
                        cores_per_socket: size.cores_per_socket,
                        memory_mb: size.memory_mb,
                        disks,
                    }
                }
                Err(_) => {
                    problems.push(coded(
                        ProblemCode::SizeGone,
                        format!("The size '{id}' isn't in the catalogue."),
                    ));
                    return Ok(Err(problems));
                }
            },
            None => {
                let vcpus = request
                    .vcpus
                    .or(analysis.described.vcpus)
                    .unwrap_or(2)
                    .clamp(1, MAX_VCPUS);
                let cores = request
                    .cores_per_socket
                    .or(analysis.described.cores_per_socket)
                    .filter(|c| *c > 0 && vcpus.is_multiple_of(*c))
                    .unwrap_or(vcpus);
                let memory_mb = request
                    .memory_mb
                    .or(analysis.described.memory_mb)
                    .unwrap_or(2048)
                    .clamp(4, MAX_MEMORY_MB);
                let mut disks: Vec<DiskPlan> = source_disks.iter().map(|g| disk(*g)).collect();
                if disks.is_empty() {
                    disks.push(disk(16));
                }
                SizeSpec {
                    id: "source".into(),
                    name: "the source's own".into(),
                    sockets: vcpus / cores,
                    cores_per_socket: cores,
                    memory_mb,
                    disks,
                }
            }
        };
        let first_boot = match &request.cloud_init {
            None => None,
            Some(cloud) => {
                let user = match check_guest_user(cloud.guest_user.as_deref()) {
                    Ok(user) => user,
                    Err(err) => {
                        problems.push(problem(err.to_string()));
                        None
                    }
                };
                let packages = match check_packages(&cloud.packages) {
                    Ok(packages) => packages,
                    Err(err) => {
                        problems.push(problem(err.to_string()));
                        Vec::new()
                    }
                };
                let public_key = match cloud.ssh_key_id {
                    None => None,
                    Some(id) => match self.store.ssh_key_rows(ctx).await?.get(&id) {
                        Some(row) => Some(row.public.line.clone()),
                        None => {
                            problems.push(coded(ProblemCode::KeyGone, "That SSH key isn't in the vault."));
                            None
                        }
                    },
                };
                Some(FirstBootSpec {
                    user,
                    public_key,
                    packages,
                    // An appliance is set up as a template's VM is (guestinfo on Workstation).
                    imported: foreign,
                })
            }
        };
        if !problems.is_empty() {
            return Ok(Err(problems));
        }
        let folder = match request.folder.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            Some(folder) => {
                if let Some(why) = crate::catalog::images::folder_problem(folder) {
                    return Ok(Err(vec![problem(why)]));
                }
                crate::adapters::vmware::with_backslashes(Path::new(folder))
                    .display()
                    .to_string()
            }
            None => self.default_folder(hv).await?,
        };
        let host_adapter = match self
            .host_adapter_for(hv, &request.network, request.host_adapter.as_deref())
            .await
        {
            Ok(adapter) => adapter,
            Err(problem) => return Ok(Err(vec![problem])),
        };
        let (workstation, virtualbox) = (os.workstation, os.virtualbox);
        let (guest_os, hardware_version, nic, tpm) = match (hv, workstation) {
            (Hypervisor::Vmware, Some(ws)) => (ws.guest_os, Some(ws.hardware_version), ws.nic, None),
            _ => (virtualbox.os_type, None, virtualbox.nic, virtualbox.tpm),
        };
        // The user's choice, else the description's, else the boot disk's partition table (CV-04), else the profile's.
        let firmware = request.firmware.unwrap_or(match analysis.described.efi {
            Some(true) => Firmware::Efi,
            Some(false) => Firmware::Bios,
            None => analysis.firmware_hint.unwrap_or(os.firmware),
        });
        if let Some(problem) = controller_problem(hv, &size, firmware, first_boot.is_some()) {
            return Ok(Err(vec![problem]));
        }
        let file_name = Path::new(&request.source)
            .file_name()
            .map_or_else(|| request.source.clone(), |n| n.to_string_lossy().into_owned());
        let source = match (analysis.kind, analysis.appliance) {
            (ImportKind::Appliance, Some(format)) => DeploySource::Appliance {
                path: analysis.path.clone(),
                format,
            },
            _ => DeploySource::Import {
                disks: found
                    .iter()
                    .map(|(path, format, _)| ImportDisk {
                        path: path.display().to_string(),
                        format: *format,
                    })
                    .collect(),
                description: matches!(analysis.kind, ImportKind::Libvirt | ImportKind::Proxmox)
                    .then(|| analysis.path.clone()),
            },
        };
        let spec = DeploySpec {
            origin: DeployOrigin::Import { name: file_name },
            hypervisor: hv,
            source,
            folder,
            profile: Some(ProfileSpec {
                id: os.id.to_owned(),
                name: os.name.to_owned(),
                family: os.family,
                firmware,
                guest_os: guest_os.to_owned(),
                hardware_version,
                nic: nic.to_owned(),
                tpm: tpm.map(str::to_owned),
            }),
            size: Some(size),
            network: Some(templates::check_network(&request.network)?),
            host_adapter,
            ssh_key_id: request.cloud_init.as_ref().and_then(|c| c.ssh_key_id),
            first_boot,
            environment: request.environment,
            tags: templates::check_tags(&request.tags)?,
            after_deploy: request.after_deploy,
            ip_wait_secs: DEFAULT_IP_WAIT_SECS,
            unattended: None,
            stack: None,
            vms: vec![DeployVm {
                number: 1,
                hostname: templates::hostname(&name, 1),
                name,
                clone_of: None,
            }],
        };
        spec.validate()?;
        Ok(Ok((spec, analysis)))
    }

    /// What the import's preview adds: how each disk is converted, where it goes, how it boots and what to try when
    /// it doesn't. (The dialog shows the analysis's own notes above the preview, so they aren't repeated here.)
    fn import_notes(&self, spec: &DeploySpec, analysis: &ImportAnalysis, request: &ImportRequest) -> Vec<String> {
        let mut notes = Vec::new();
        if let DeploySource::Import { disks, .. } = &spec.source {
            let tools = self.tool_paths().unwrap_or_default();
            if let (Some(size), Some(profile)) = (&spec.size, &spec.profile) {
                let controller = size.disks.first().map_or("SATA", |d| d.controller.label());
                let controller = match (&request.controller, &analysis.controller_hint) {
                    (Some(_), _) => format!("{controller} (as you chose)"),
                    (None, Some(hint)) => format!("{controller} (it was {})", hint.why),
                    (None, None) => controller.to_owned(),
                };
                let how = match (request.firmware, analysis.described.efi, analysis.firmware_hint) {
                    (Some(_), _, _) => "as you chose".to_owned(),
                    (None, Some(_), _) => "as its description says".to_owned(),
                    (None, None, Some(_)) => "as its partition table says".to_owned(),
                    (None, None, None) => "the OS profile's: its partition table couldn't be read".to_owned(),
                };
                notes.push(format!(
                    "{} on {controller}, booting with {} ({how}).",
                    if disks.len() == 1 {
                        "Its disk goes".to_owned()
                    } else {
                        format!(
                            "Its {} disks go, the first booting and the others attached in order,",
                            disks.len()
                        )
                    },
                    match profile.firmware {
                        Firmware::Bios => "BIOS",
                        Firmware::Efi => "UEFI",
                        Firmware::EfiSecureBoot => "UEFI with Secure Boot",
                    }
                ));
            }
            for (i, disk) in disks.iter().enumerate() {
                let thin = spec
                    .size
                    .as_ref()
                    .and_then(|s| s.disks.get(i))
                    .is_none_or(|d| d.provisioning == Provisioning::Thin);
                let kind = crate::convert::import::native_kind(spec.hypervisor, thin);
                let how = if copied_by_deploy(spec.hypervisor, disk.format) {
                    format!(
                        "copied by {}",
                        match spec.hypervisor {
                            Hypervisor::Vmware => "vmware-vdiskmanager",
                            Hypervisor::VirtualBox => "VBoxManage",
                        }
                    )
                } else {
                    match crate::convert::plan::plan(
                        crate::convert::plan::Source::file(disk.format),
                        kind,
                        None,
                        &tools,
                    ) {
                        Ok(steps) => format!("converted by {}", crate::convert::plan::describe(&steps)),
                        Err(why) => why.describe(disk.format, kind),
                    }
                };
                notes.push(format!(
                    "Disk {} ({}) becomes the VM's {}: {how}. The source is only read.",
                    i + 1,
                    disk.format.label(),
                    kind.label()
                ));
            }
            if let Some(first_boot) = &spec.first_boot {
                notes.push(format!(
                    "Its first boot gets a cloud-init seed: hostname {}, {} with sudo{}, and DHCP on whichever network card it has; never a password. It takes effect if the disk's cloud-init reads NoCloud seeds (most do); a disk without cloud-init boots as it was. {}",
                    spec.vms.first().map_or("", |vm| vm.hostname.as_str()),
                    first_boot.user.as_deref().unwrap_or("its default user"),
                    if first_boot.public_key.is_some() {
                        " and your SSH key"
                    } else {
                        ", but no SSH key: pick one, or sign in as before"
                    },
                    match spec.hypervisor {
                        Hypervisor::VirtualBox => "The seed is ejected once the guest has booted.",
                        Hypervisor::Vmware => "Its drive is disconnected once the guest has booted, and stays in the VM's settings until you eject it while the VM is off.",
                    }
                ));
            }
            let mut tip = crate::deploy::runner::IMPORT_BOOT_TIPS.to_owned();
            if let Some(first) = tip.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            notes.push(format!("{tip}."));
        }
        notes
    }

    /// CV-01: the Import dialog's check: why it can't import, or its AP-02 preview. A read.
    pub async fn check_import(&self, ctx: &Context, request: &ImportRequest) -> Result<DeployCheck> {
        match self.import_spec(ctx, request).await? {
            Err(problems) => Ok(DeployCheck {
                problems,
                preview: None,
                capacity: None,
            }),
            Ok((spec, analysis)) => {
                // VM-26: an import is a deploy, so it shows this PC after it too (every disk counts).
                let (mut checked, capacity) = self.preview_spec(ctx, &spec).await;
                let mut notes = self.import_notes(&spec, &analysis, request);
                notes.append(&mut checked.notes);
                checked.notes = notes;
                Ok(DeployCheck {
                    problems: Vec::new(),
                    preview: Some(checked),
                    capacity: Some(capacity),
                })
            }
        }
    }

    /// CV-01: submits the import to the bus as a deploy (Medium, a Prod label High).
    pub async fn submit_import(&self, ctx: &Context, request: &ImportRequest) -> Result<SubmitOutcome> {
        match self.import_spec(ctx, request).await? {
            Ok((spec, _)) => self.submit_spec(ctx, spec).await,
            Err(problems) => Err(refused(problems.into_iter().map(|p| p.message).collect())),
        }
    }
}
