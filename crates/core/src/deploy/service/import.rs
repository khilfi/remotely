//! CV-01: an import is a deploy. The Import dialog's request (a file analysed by [`crate::convert::import`], a name,
//! the hypervisor, an OS profile, a size or the source's own CPU and memory) becomes a [`DeploySpec`] whose source
//! is the appliance (an OVA or OVF, R2's own import) or the foreign disks ([`DeploySource::Import`]), and goes
//! through the same preview, bus command, tiers, job and cleanup as every deploy.

use std::path::Path;

use serde::Deserialize;

use super::{problem, refused, DeployCheck, Deploys};
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::profiles::{profile, Firmware};
use crate::catalog::sizes::Provisioning;
use crate::catalog::templates::{self, check_guest_user, check_packages, AfterDeploy, Network, Problem, ProblemCode};
use crate::command_bus::SubmitOutcome;
use crate::convert::formats::GIB;
use crate::convert::import::{analyze, copied_by_deploy, ImportAnalysis, ImportKind};
use crate::deploy::preview::preview;
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
    #[serde(default)]
    pub cloud_init: Option<ImportCloudInit>,
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
        let analysis = self.analyze_import(Path::new(&request.source)).await?;
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
        let controller = os.controller(hv);
        let controller_model = templates::controller_model(hv, controller, &os).to_owned();
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
                            if let Some(c) = d.controller {
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
        let firmware = request.firmware.unwrap_or(match analysis.described.efi {
            Some(true) => Firmware::Efi,
            Some(false) => Firmware::Bios,
            None => os.firmware,
        });
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

    /// What the import's preview adds: how each disk is converted, and the analysis's notes.
    fn import_notes(&self, spec: &DeploySpec, analysis: &ImportAnalysis) -> Vec<String> {
        let mut notes = analysis.notes.clone();
        if let DeploySource::Import { disks, .. } = &spec.source {
            let tools = self.tool_paths().unwrap_or_default();
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
        }
        notes
    }

    /// CV-01: the Import dialog's check: why it can't import, or its AP-02 preview. A read.
    pub async fn check_import(&self, ctx: &Context, request: &ImportRequest) -> Result<DeployCheck> {
        match self.import_spec(ctx, request).await? {
            Err(problems) => Ok(DeployCheck {
                problems,
                preview: None,
            }),
            Ok((spec, analysis)) => {
                let mut checked = preview(&spec, &self.hypervisors, self.host.as_ref()).await;
                let mut notes = self.import_notes(&spec, &analysis);
                notes.append(&mut checked.notes);
                checked.notes = notes;
                Ok(DeployCheck {
                    problems: Vec::new(),
                    preview: Some(checked),
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
