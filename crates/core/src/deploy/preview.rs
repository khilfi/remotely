//! AP-02 for a deploy: what the approval dialog (and the Deploy dialog before it) shows. Each VM's name, hostname
//! and folder, the hypervisor, the size, the disk space each VM may take and all of them together (thin disks at
//! their full size, the worst case), the network, first-boot setup and after-deploy steps; and the free-space
//! check on the folder's drive: refused when the thick disks don't fit, a warning when the thin ones might not.
//! Reads only.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::spec::{DeployOrigin, DeploySource, DeploySpec, FirstBootSpec, SizeSpec};
use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::catalog::profiles::GuestFamily;
use crate::catalog::sizes::Provisioning;
use crate::catalog::templates::{hypervisor_label, AfterDeploy, Network};
use crate::command_bus::human_size;
use crate::domain::Environment;

const GIB: u64 = 1 << 30;

/// One VM as the preview shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewVm {
    pub name: String,
    pub hostname: String,
    /// `<folder>\<name>`, which the deploy makes.
    pub folder: String,
    /// VM-10: the name of the VM it is a clone of.
    pub clone_of: Option<String>,
    /// What its disks may take, thin ones at their full size; `None` when it isn't known (a clone's source
    /// couldn't be read).
    pub disk_bytes: Option<u64>,
    /// Of that, what thick disks take at once.
    pub thick_bytes: u64,
    /// Why it can't be made.
    pub problem: Option<String>,
}

/// What cloud-init sets, as the dialog shows it: the key by its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstBootPreview {
    pub user: Option<String>,
    pub key_fingerprint: Option<String>,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployPreview {
    pub summary: String,
    pub origin: DeployOrigin,
    pub hypervisor: Hypervisor,
    /// Where the OS comes from, in words.
    pub source: String,
    pub folder: String,
    pub size: Option<SizeSpec>,
    /// The network in words; `None`: each VM keeps its own.
    pub network: Option<String>,
    pub host_adapter: Option<String>,
    pub environment: Environment,
    pub tags: Vec<String>,
    pub first_boot: Option<FirstBootPreview>,
    pub after_deploy: AfterDeploy,
    pub vms: Vec<PreviewVm>,
    /// What all the VMs may take, thin disks at their full size.
    pub disk_bytes: u64,
    /// What the thick disks take at once.
    pub thick_bytes: u64,
    /// Free space on the folder's drive, when it could be read.
    pub free_bytes: Option<u64>,
    /// What to know before approving.
    pub notes: Vec<String>,
    /// What may go wrong (thin disks that might not fit): the approval shows them.
    pub warnings: Vec<String>,
    /// Why the deploy can't run as it is (a folder that is there already, thick disks that don't fit).
    pub refusals: Vec<String>,
}

/// The nearest folder of `path` that is there (the deploy's folder may not be yet), for its drive's free space.
fn existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut at = Some(path);
    while let Some(dir) = at {
        if dir.is_dir() {
            return Some(dir.to_path_buf());
        }
        at = dir.parent();
    }
    None
}

/// The size's disks, the boot disk at `boot_bytes` when it is larger than the size's: (all, thick).
fn size_disks(size: &SizeSpec, boot_bytes: Option<u64>) -> (u64, u64) {
    let mut all = 0u64;
    let mut thick = 0u64;
    for (i, disk) in size.disks.iter().enumerate() {
        let mut bytes = u64::from(disk.size_gb) * GIB;
        if i == 0 {
            bytes = bytes.max(boot_bytes.unwrap_or(0));
        }
        all = all.saturating_add(bytes);
        if disk.provisioning == Provisioning::Thick {
            thick = thick.saturating_add(bytes);
        }
    }
    (all, thick)
}

/// What a clone of the VM `key` may take: its disks at their provisioned size, the first grown to `grow_to`.
async fn clone_disks(hypervisors: &Hypervisors, key: &str, grow_to: Option<u64>) -> Option<u64> {
    let hardware = hypervisors.hardware(key).await.ok()?;
    let mut total = 0u64;
    for (i, disk) in hardware.disks.iter().enumerate() {
        let mut bytes = disk.provisioned_bytes?;
        if i == 0 {
            bytes = bytes.max(grow_to.unwrap_or(0));
        }
        total = total.saturating_add(bytes);
    }
    Some(total)
}

/// Reads what it needs (a clone's source, an appliance's descriptor, the drive's free space, whether each VM's
/// folder is there) and says what the deploy will make.
pub async fn preview(spec: &DeploySpec, hypervisors: &Hypervisors, host: &dyn HostCounters) -> DeployPreview {
    let mut notes = Vec::new();
    let mut warnings = Vec::new();
    let mut refusals = Vec::new();
    let boot_bytes = spec.size.as_ref().map(|s| u64::from(s.boot_disk_gb()) * GIB);

    // Each VM's disks, by where its OS comes from.
    let (per_vm, per_vm_thick): (Option<u64>, u64) = match (&spec.source, &spec.size) {
        (DeploySource::CloudImage { .. } | DeploySource::Iso { .. }, Some(size)) => {
            let (all, thick) = size_disks(size, None);
            (Some(all), thick)
        }
        (DeploySource::Appliance { path, format }, Some(size)) => {
            let disks = super::ovf::appliance_disks(path, *format).await.unwrap_or_default();
            let thick = size
                .disks
                .first()
                .is_some_and(|d| d.provisioning == Provisioning::Thick);
            match disks.split_first() {
                Some((boot, rest)) => {
                    let boot = (*boot).max(boot_bytes.unwrap_or(0));
                    let all = rest.iter().fold(boot, |sum, d| sum.saturating_add(*d));
                    (Some(all), if thick { all } else { 0 })
                }
                None => {
                    notes.push(
                        "The appliance's disks couldn't be read, so its size counts as the size's boot disk.".into(),
                    );
                    let boot = boot_bytes.unwrap_or(0);
                    (Some(boot), if thick { boot } else { 0 })
                }
            }
        }
        (DeploySource::GoldenVm { vm_key, linked, .. }, _) => {
            let grow = if *linked { None } else { boot_bytes };
            (clone_disks(hypervisors, vm_key, grow).await, 0)
        }
        _ => (None, 0),
    };

    let mut vms = Vec::with_capacity(spec.vms.len());
    for vm in &spec.vms {
        let folder = spec.vm_folder(vm);
        let (disk_bytes, thick_bytes) = match &vm.clone_of {
            Some((key, _)) => (clone_disks(hypervisors, key, None).await, 0),
            None => (per_vm, per_vm_thick),
        };
        let problem = match tokio::fs::metadata(&folder).await {
            Ok(_) => Some(format!(
                "{} is there already: a deploy makes each VM's folder itself, so pick another name or folder.",
                folder.display()
            )),
            Err(_) => None,
        };
        if let Some(problem) = &problem {
            refusals.push(format!("{}: {problem}", vm.name));
        }
        vms.push(PreviewVm {
            name: vm.name.clone(),
            hostname: vm.hostname.clone(),
            folder: folder.display().to_string(),
            clone_of: vm.clone_of.as_ref().map(|(_, name)| name.clone()),
            disk_bytes,
            thick_bytes,
            problem,
        });
    }
    let disk_bytes = vms.iter().filter_map(|v| v.disk_bytes).fold(0u64, u64::saturating_add);
    let thick_bytes = vms.iter().map(|v| v.thick_bytes).fold(0u64, u64::saturating_add);
    if vms.iter().any(|v| v.disk_bytes.is_none()) {
        notes.push("Some VMs' disk sizes couldn't be read, so the total leaves them out.".into());
    }

    // The free space on the folder's drive.
    let free_bytes = match existing_ancestor(Path::new(&spec.folder)) {
        Some(dir) => host.disk_space(&dir).await.ok().map(|d| d.free_bytes),
        None => {
            refusals.push(format!(
                "{} isn't on a drive of this PC that is there now.",
                spec.folder
            ));
            None
        }
    };
    if let Some(free) = free_bytes {
        if thick_bytes > free {
            refusals.push(format!(
                "The thick disks need {}, and the drive of {} has {} free.",
                human_size(thick_bytes),
                spec.folder,
                human_size(free)
            ));
        } else if disk_bytes > free {
            warnings.push(format!(
                "If the guests fill their thin disks, they take up to {}, and the drive of {} has {} free.",
                human_size(disk_bytes),
                spec.folder,
                human_size(free)
            ));
        }
    }

    // What to know.
    match &spec.source {
        DeploySource::GoldenVm {
            linked: true,
            snapshot_name,
            vm_name,
            ..
        } => notes.push(format!(
            "Linked clones need '{vm_name}' and its snapshot '{snapshot_name}' to stay; their disks keep the golden VM's size, which a linked clone can't grow."
        )),
        DeploySource::GoldenVm { .. } | DeploySource::CloudImage { .. } | DeploySource::Appliance { .. } => {
            if let Some(size) = &spec.size {
                notes.push(format!(
                    "CPU and memory are the size's ({} vCPU, {} MB); a boot disk smaller than {} GB grows to it, and none shrinks. {}",
                    size.vcpus(),
                    size.memory_mb,
                    size.boot_disk_gb(),
                    if spec.first_boot.is_some() {
                        "cloud-init's growpart fills a grown disk on first boot."
                    } else {
                        "Grow the guest's partition into a grown disk yourself."
                    }
                ));
            }
        }
        DeploySource::Iso { .. } => notes.push(match &spec.unattended {
            Some(unattended) => format!(
                "VirtualBox installs the OS by itself, as user {} with the vault password chosen; that goes on for 10 to 30 minutes after the job ends. Steps that need the guest's IP are left out: make the session once it is installed.",
                unattended.user
            ),
            None => "An ISO install starts with no OS: install it from the console. Steps that need the guest's IP wait for an OS, so they are left out."
                .into(),
        }),
        DeploySource::BulkClone => {
            notes.push("Each clone is a full copy of its VM as it is now, with its CPU, memory, disks and network.".into())
        }
    }
    if let (Some(profile), None) = (&spec.profile, &spec.first_boot) {
        if profile.family == GuestFamily::Windows {
            notes.push("Windows guests get no first-boot setup: set the computer name and users in the guest.".into());
        }
    }
    if let Some(FirstBootSpec { public_key: None, .. }) = &spec.first_boot {
        warnings.push("No SSH key: cloud images have no password, so no one can log in to them over SSH.".into());
    }
    if spec.hypervisor == Hypervisor::VirtualBox
        && spec.after_deploy.create_session
        && matches!(spec.network, Some(Network::Nat))
    {
        notes.push(
            "On VirtualBox's NAT the guest's address can't be reached from this PC, so no SSH session is made: use a host-only network."
                .into(),
        );
    }
    if spec.after_deploy.create_session && spec.first_boot.is_some() {
        notes.push(format!(
            "The session is made once {} report the guest's IP, within {} minutes; a VM whose IP doesn't show is reported, not failed.",
            spec.hypervisor.tools_name(),
            spec.ip_wait_secs.div_ceil(60)
        ));
    }

    DeployPreview {
        summary: spec.summary(),
        origin: spec.origin.clone(),
        hypervisor: spec.hypervisor,
        source: format!("{} on {}", spec.source.describe(), hypervisor_label(spec.hypervisor)),
        folder: spec.folder.clone(),
        size: spec.size.clone(),
        network: spec.network.as_ref().map(Network::describe),
        host_adapter: spec.host_adapter.clone(),
        environment: spec.environment,
        tags: spec.tags.clone(),
        first_boot: spec.first_boot.as_ref().map(|f| FirstBootPreview {
            user: f.user.clone(),
            key_fingerprint: f
                .public_key
                .as_deref()
                .and_then(|k| crate::ssh_keys::parse_public_key(k).ok())
                .map(|k| k.fingerprint),
            packages: f.packages.clone(),
        }),
        after_deploy: spec.after_deploy,
        vms,
        disk_bytes,
        thick_bytes,
        free_bytes,
        notes,
        warnings,
        refusals,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::catalog::images::ImageSource;
    use crate::deploy::spec::tests::{cloud, plan};
    use crate::fakes::{FakeHostCounters, FakeVirtualBox, FakeVmware};

    fn hypervisors() -> Hypervisors {
        Hypervisors::new(Arc::new(FakeVmware::default()), Arc::new(FakeVirtualBox::default()))
    }

    fn spec_in(folder: &Path, source: ImageSource, count: u32) -> DeploySpec {
        DeploySpec::from_plan(
            &plan(source, "ubuntu", Hypervisor::Vmware, count),
            DeployOrigin::Template {
                id: uuid::Uuid::from_u128(1),
                name: "web".into(),
            },
            folder.display().to_string(),
            None,
        )
    }

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remotely-deploy-preview-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_preview_counts_thin_disks_at_their_full_size() {
        let dir = temp();
        let spec = spec_in(&dir.join("lab"), cloud(), 3);
        let host = FakeHostCounters::default();
        let p = preview(&spec, &hypervisors(), &host).await;
        assert_eq!(p.vms.len(), 3);
        assert_eq!(p.vms[0].folder, dir.join("lab").join("web-1").display().to_string());
        // disk.large: 40 GB + 500 GB data disk, both thin.
        assert_eq!(p.vms[0].disk_bytes, Some(540 * GIB));
        assert_eq!(p.disk_bytes, 3 * 540 * GIB);
        assert_eq!(p.thick_bytes, 0);
        assert!(p.free_bytes.is_some());
        assert!(p.refusals.is_empty(), "{:?}", p.refusals);
        assert!(p.notes.iter().any(|n| n.contains("growpart")), "{:?}", p.notes);
        assert_eq!(p.first_boot.as_ref().unwrap().user.as_deref(), Some("alice"));
        assert!(p
            .first_boot
            .as_ref()
            .unwrap()
            .key_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:"));
        assert_eq!(p.network.as_deref(), Some("host-only"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn thick_disks_that_dont_fit_are_refused_and_thin_ones_warned() {
        let dir = temp();
        let mut spec = spec_in(&dir, cloud(), 2);
        // 1 TiB drive with 0.01 % free: about 110 MB.
        let mut host = FakeHostCounters::default();
        host.free_disk_pct = 0.01;
        let p = preview(&spec, &hypervisors(), &host).await;
        assert!(p.refusals.is_empty());
        assert!(p.warnings.iter().any(|w| w.contains("thin disks")), "{:?}", p.warnings);
        spec.size.as_mut().unwrap().disks[0].provisioning = Provisioning::Thick;
        let p = preview(&spec, &hypervisors(), &host).await;
        assert_eq!(p.thick_bytes, 2 * 40 * GIB);
        assert!(
            p.refusals.iter().any(|r| r.contains("The thick disks need")),
            "{:?}",
            p.refusals
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_folder_that_is_there_already_is_refused() {
        let dir = temp();
        std::fs::create_dir_all(dir.join("web-2")).unwrap();
        let spec = spec_in(&dir, cloud(), 2);
        let p = preview(&spec, &hypervisors(), &FakeHostCounters::default()).await;
        assert_eq!(p.vms[0].problem, None);
        assert!(p.vms[1].problem.as_deref().unwrap().contains("is there already"));
        assert_eq!(p.refusals.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn an_iso_install_and_a_linked_clone_say_what_they_leave_out() {
        let dir = temp();
        let iso = spec_in(
            &dir,
            ImageSource::Iso {
                path: r"C:\ISOs\noble.iso".into(),
            },
            1,
        );
        let p = preview(&iso, &hypervisors(), &FakeHostCounters::default()).await;
        assert!(
            p.notes.iter().any(|n| n.contains("An ISO install starts with no OS")),
            "{:?}",
            p.notes
        );
        assert_eq!(p.first_boot, None);
        let golden = spec_in(
            &dir,
            ImageSource::GoldenVm {
                vm_key: r"C:\VMs\golden\golden.vmx".into(),
                snapshot_id: "1".into(),
                snapshot_name: "base".into(),
            },
            1,
        );
        let p = preview(&golden, &hypervisors(), &FakeHostCounters::default()).await;
        assert!(
            p.notes.iter().any(|n| n.contains("Linked clones need 'golden'")),
            "{:?}",
            p.notes
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
