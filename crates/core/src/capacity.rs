//! VM-07: capacity check before power-on. Warns when the RAM assigned to running VMs (each .vmx's
//! `memsize`, each VirtualBox VM's `memory`) would exceed the host's physical RAM, or when a VM
//! folder's drive has under 10% free. VMware and VirtualBox VMs share the host, so both count.
//! MO-04: the same reads make the dashboard's host capacity panel ([`CapacityChecker::host_capacity`]).
//!
//! It only warns: the command bus shows the warnings and asks for a confirm (see
//! [`crate::policy::Decision::add_warnings`]); the user decides. A check that cannot run is a
//! warning too, so a failed read never passes silently.
//!
//! VM-02: starting several VMs also names the ones with a bridged network adapter that is plugged in
//! at power-on ([`CapacityChecker::bridged`]): such a VM joins the network this PC is on, so a clone
//! with a fixed IP address can take an address the customer's network already uses.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use crate::adapters::host_counters::HostCounters;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::path_key;
use crate::domain::{Context, Target, TargetRef};
use crate::store::{Store, VmRecord};

/// A VM folder's drive with less free space than this is flagged.
pub const MIN_FREE_DISK_PCT: f64 = 10.0;

/// VM-02: how long reading the starting VMs' adapters may take before the rest are left unchecked.
pub const BRIDGED_CHECK_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum CapacityWarning {
    /// Running VMs plus the ones starting would be assigned more RAM than the host has.
    Ram { assigned_mb: u64, physical_mb: u64 },
    /// A drive holding a VM that is starting is low on space.
    Disk { drive: String, free_pct: f64 },
    /// Part of the check could not run.
    Unchecked { message: String },
}

impl CapacityWarning {
    pub fn message(&self) -> String {
        let gb = |mb: u64| format!("{:.1} GB", mb as f64 / 1024.0);
        match self {
            CapacityWarning::Ram {
                assigned_mb,
                physical_mb,
            } => format!(
                "Running VMs would be assigned {} of RAM, more than this host's {}.",
                gb(*assigned_mb),
                gb(*physical_mb)
            ),
            CapacityWarning::Disk { drive, free_pct } => {
                format!("Drive {drive} has {free_pct:.1}% free space, under {MIN_FREE_DISK_PCT:.0}%.")
            }
            CapacityWarning::Unchecked { message } => format!("Capacity not checked: {message}"),
        }
    }
}

/// MO-04: assigned vs physical resources on this machine.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCapacity {
    pub physical_ram_mb: u64,
    /// RAM Windows has free right now; `None` when it could not be read.
    pub available_ram_mb: Option<u64>,
    /// RAM assigned to the running VMs (each .vmx's `memsize`).
    pub assigned_ram_mb: u64,
    pub logical_cpus: u32,
    pub assigned_vcpus: u32,
    /// The host's busy CPU share over the last metrics round, when there was one.
    pub host_cpu_pct: Option<f64>,
    pub running_vms: usize,
    /// Running VMs whose RAM or vCPU count is unknown, so the totals leave them out.
    pub unsized_vms: usize,
    /// One entry per drive that holds a known VM's folder.
    pub drives: Vec<DriveCapacity>,
    /// MO-15: this PC's paging files and commit charge, from the last metrics round.
    pub paging: Option<crate::adapters::paging::PagingInfo>,
    /// RAM over-committed, drives under [`MIN_FREE_DISK_PCT`], and reads that failed.
    pub warnings: Vec<CapacityWarning>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveCapacity {
    /// `C:`, or the share (`\\server\share`) for a network folder.
    pub drive: String,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub free_pct: f64,
    /// Under [`MIN_FREE_DISK_PCT`] free.
    pub low: bool,
    /// Known VMs with their folder on this drive.
    pub vms: usize,
}

/// The rule itself, without any reads: RAM over the host's, or a drive under [`MIN_FREE_DISK_PCT`].
pub fn power_on_warnings(
    running_mb: u64,
    starting_mb: u64,
    physical_mb: u64,
    drives: &[(String, f64)],
) -> Vec<CapacityWarning> {
    let mut warnings = Vec::new();
    let assigned_mb = running_mb + starting_mb;
    if starting_mb > 0 && assigned_mb > physical_mb {
        warnings.push(CapacityWarning::Ram {
            assigned_mb,
            physical_mb,
        });
    }
    for (drive, free_pct) in drives {
        if *free_pct < MIN_FREE_DISK_PCT {
            warnings.push(CapacityWarning::Disk {
                drive: drive.clone(),
                free_pct: *free_pct,
            });
        }
    }
    warnings
}

/// Gathers what [`power_on_warnings`] needs: reads only (vmrun list, .vmx files, `VBoxManage list
/// runningvms` and `showvminfo`, Windows counters).
pub struct CapacityChecker {
    store: Store,
    hypervisors: Hypervisors,
    host: Arc<dyn HostCounters>,
}

impl CapacityChecker {
    /// This PC's counters (SS-07: who else is signed in to it).
    pub fn host(&self) -> &Arc<dyn HostCounters> {
        &self.host
    }

    pub fn new(store: Store, hypervisors: Hypervisors, host: Arc<dyn HostCounters>) -> Self {
        Self {
            store,
            hypervisors,
            host,
        }
    }

    /// The keys of the VMs running now: each hypervisor's own list, or for one that can't be asked,
    /// what the last refresh saw of its VMs.
    async fn running(&self, inventory: &[VmRecord]) -> Vec<String> {
        let now = self.hypervisors.running().await;
        let last_seen = |hypervisor: Hypervisor| {
            inventory
                .iter()
                .filter(move |v| v.hypervisor == hypervisor && v.power_state.is_on())
                .map(|v| v.vmx_path.clone())
        };
        let mut keys: Vec<String> = match now.vmware {
            Ok(paths) => paths,
            Err(_) => last_seen(Hypervisor::Vmware).collect(),
        };
        match now.virtualbox {
            Ok(uuids) => keys.extend(uuids),
            Err(_) => keys.extend(last_seen(Hypervisor::VirtualBox)),
        }
        keys
    }

    /// Warnings for powering on `targets` (VMs that are already running are not counted twice).
    /// Never fails: what cannot be read becomes a [`CapacityWarning::Unchecked`].
    pub async fn check_power_on(&self, ctx: &Context, targets: &[Target]) -> Vec<CapacityWarning> {
        let mut warnings = Vec::new();

        let inventory = match self.store.list_vms(ctx).await {
            Ok(vms) => vms,
            Err(err) => {
                warnings.push(unchecked("which VMs are running", &err));
                Vec::new()
            }
        };
        let running = self.running(&inventory).await;
        let running_keys: HashSet<String> = running.iter().map(|p| path_key(Path::new(p))).collect();
        let starting: Vec<&str> = targets
            .iter()
            .filter_map(|t| match &t.target {
                TargetRef::Vm { vmx_path } => Some(vmx_path.as_str()),
                _ => None,
            })
            .filter(|p| !running_keys.contains(&path_key(Path::new(p))))
            .collect();
        if starting.is_empty() {
            return warnings;
        }

        let mut running_mb = 0;
        for path in &running {
            running_mb += self.memsize_mb(ctx, path).await;
        }
        let mut starting_mb = 0;
        for path in &starting {
            starting_mb += self.memsize_mb(ctx, path).await;
        }
        let physical_mb = match self.host.host_totals().await {
            Ok(totals) => totals.physical_ram_mb,
            Err(err) => {
                warnings.push(unchecked("the host's RAM", &err));
                u64::MAX
            }
        };

        // One free-space read per drive, through one of its VM folders.
        let mut folders: BTreeMap<String, PathBuf> = BTreeMap::new();
        for path in &starting {
            if let Some(folder) = self.folder(ctx, path).await {
                folders.entry(drive_of(&folder)).or_insert(folder);
            }
        }
        let mut drives = Vec::new();
        for (drive, folder) in folders {
            match self.host.free_disk_pct(&folder).await {
                Ok(free) => drives.push((drive, free)),
                Err(err) => warnings.push(unchecked(&format!("free space on {drive}"), &err)),
            }
        }

        warnings.extend(power_on_warnings(running_mb, starting_mb, physical_mb, &drives));
        warnings
    }

    /// VM-02: for a start of two or more VMs, a warning for those with a bridged adapter plugged in at
    /// power-on, which put them on this PC's own network. Read from each VM's .vmx or `showvminfo`
    /// within [`BRIDGED_CHECK_BUDGET`]; VMs that can't be read in time are left out.
    pub async fn bridged(&self, targets: &[Target]) -> Vec<String> {
        let vms: Vec<(&str, &str)> = targets
            .iter()
            .filter_map(|t| match &t.target {
                TargetRef::Vm { vmx_path } => Some((vmx_path.as_str(), t.name.as_str())),
                _ => None,
            })
            .collect();
        if vms.len() < 2 {
            return Vec::new();
        }
        let started = std::time::Instant::now();
        let mut bridged = Vec::new();
        for (key, name) in vms {
            let left = BRIDGED_CHECK_BUDGET.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, self.hypervisors.hardware(key)).await {
                Ok(Ok(hardware)) => {
                    let nics: Vec<&str> = hardware
                        .nics
                        .iter()
                        .filter(|n| n.connection.as_deref() == Some("bridged") && n.connected != Some(false))
                        .map(|n| n.slot.as_str())
                        .collect();
                    if !nics.is_empty() {
                        bridged.push(format!("'{name}' ({})", nics.join(", ")));
                    }
                }
                // Like the RAM check, a VM whose files can't be read is left out (its start fails anyway).
                Ok(Err(err)) => tracing::debug!(vm = %name, error = %err, "could not read a VM's adapters"),
                Err(_) => {
                    tracing::debug!(vm = %name, "no time left to read a VM's adapters");
                    break;
                }
            }
        }
        if bridged.is_empty() {
            return Vec::new();
        }
        vec![format!(
            "Bridged network adapter: {} join the network this PC is on. A clone keeps the fixed IP address of the VM it was made from, which may clash with a machine on that network.",
            bridged.join(", ")
        )]
    }

    /// The VM's assigned RAM: from the inventory, else its .vmx; 0 when neither says.
    async fn memsize_mb(&self, ctx: &Context, vmx_path: &str) -> u64 {
        self.size(ctx, vmx_path).await.0.map_or(0, u64::from)
    }

    /// The VM's assigned RAM (MB) and vCPUs: from the inventory, else its .vmx (VirtualBox:
    /// `showvminfo`).
    async fn size(&self, ctx: &Context, vmx_path: &str) -> (Option<u32>, Option<u32>) {
        let (mut ram, mut cpus) = match self.store.find_vm(ctx, vmx_path).await {
            Ok(Some(vm)) => (vm.memsize_mb, vm.num_vcpus),
            _ => (None, None),
        };
        if ram.is_none() || cpus.is_none() {
            match Hypervisor::of_key(vmx_path) {
                Hypervisor::Vmware => {
                    if let Ok(info) = self.hypervisors.vmware().read_vmx(Path::new(vmx_path)).await {
                        ram = ram.or(info.memsize_mb);
                        // Workstation's default when the .vmx leaves numvcpus out.
                        cpus = cpus.or(info.num_vcpus).or(Some(1));
                    }
                }
                Hypervisor::VirtualBox => {
                    if let Ok(info) = self.hypervisors.virtualbox().vm_info(vmx_path).await {
                        ram = ram.or(info.memory_mb);
                        cpus = cpus.or(info.cpus);
                    }
                }
            }
        }
        (ram, cpus)
    }

    /// The folder holding a VM's files: from the inventory, else the .vmx's folder (VirtualBox: the
    /// .vbox's, from `showvminfo`).
    async fn folder(&self, ctx: &Context, key: &str) -> Option<PathBuf> {
        if let Ok(Some(vm)) = self.store.find_vm(ctx, key).await {
            if let Some(folder) = vm.folder() {
                return Some(folder.to_path_buf());
            }
        }
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => Path::new(key).parent().map(Path::to_path_buf),
            Hypervisor::VirtualBox => self
                .hypervisors
                .virtualbox()
                .vm_info(key)
                .await
                .ok()?
                .config_file?
                .parent()
                .map(Path::to_path_buf),
        }
    }

    /// MO-04: assigned RAM and vCPUs of the running VMs against the host's, and free space on each
    /// drive that holds a VM folder. `running` is the keys of the VMs running now (from the metrics
    /// collector's process list); `None` asks vmrun and VBoxManage, then falls back to the last
    /// inventory refresh.
    /// Never fails: what cannot be read becomes a [`CapacityWarning::Unchecked`].
    pub async fn host_capacity(&self, ctx: &Context, running: Option<Vec<String>>) -> HostCapacity {
        let mut capacity = HostCapacity::default();
        let inventory = match self.store.list_vms(ctx).await {
            Ok(vms) => vms,
            Err(err) => {
                capacity.warnings.push(unchecked("the VM list", &err));
                Vec::new()
            }
        };
        let running = match running {
            Some(paths) => paths,
            None => self.running(&inventory).await,
        };
        capacity.running_vms = running.len();
        for path in &running {
            match self.size(ctx, path).await {
                (Some(ram), Some(cpus)) => {
                    capacity.assigned_ram_mb += u64::from(ram);
                    capacity.assigned_vcpus += cpus;
                }
                _ => capacity.unsized_vms += 1,
            }
        }
        match self.host.host_totals().await {
            Ok(totals) => {
                capacity.physical_ram_mb = totals.physical_ram_mb;
                capacity.available_ram_mb = Some(totals.available_ram_mb);
                capacity.logical_cpus = totals.logical_cpus;
                if capacity.assigned_ram_mb > totals.physical_ram_mb {
                    capacity.warnings.push(CapacityWarning::Ram {
                        assigned_mb: capacity.assigned_ram_mb,
                        physical_mb: totals.physical_ram_mb,
                    });
                }
            }
            Err(err) => capacity.warnings.push(unchecked("the host's RAM and CPUs", &err)),
        }

        // One read per drive, through one of its VM folders. Running VMware VMs count even when the
        // inventory has not seen them (a VirtualBox VM's key says nothing about where it lives).
        let mut folders: BTreeMap<String, (&Path, usize)> = BTreeMap::new();
        let mut seen = HashSet::new();
        let known = inventory.iter().map(|v| (v.vmx_path.as_str(), v.folder()));
        let unseen = running
            .iter()
            .filter(|key| Hypervisor::of_key(key) == Hypervisor::Vmware)
            .map(|key| (key.as_str(), Path::new(key.as_str()).parent()));
        for (key, folder) in known.chain(unseen) {
            if !seen.insert(path_key(Path::new(key))) {
                continue;
            }
            if let Some(folder) = folder {
                folders.entry(drive_of(folder)).or_insert((folder, 0)).1 += 1;
            }
        }
        for (drive, (folder, vms)) in folders {
            match self.host.disk_space(folder).await {
                Ok(space) if space.total_bytes > 0 => {
                    let free_pct = space.free_pct();
                    let low = free_pct < MIN_FREE_DISK_PCT;
                    if low {
                        capacity.warnings.push(CapacityWarning::Disk {
                            drive: drive.clone(),
                            free_pct,
                        });
                    }
                    capacity.drives.push(DriveCapacity {
                        drive,
                        free_bytes: space.free_bytes,
                        total_bytes: space.total_bytes,
                        free_pct,
                        low,
                        vms,
                    });
                }
                Ok(_) => capacity.warnings.push(CapacityWarning::Unchecked {
                    message: format!("{drive} reports a size of 0 bytes"),
                }),
                Err(err) => capacity
                    .warnings
                    .push(unchecked(&format!("free space on {drive}"), &err)),
            }
        }
        capacity
    }
}

fn unchecked(what: &str, err: &crate::error::CoreError) -> CapacityWarning {
    CapacityWarning::Unchecked {
        message: format!("could not read {what} ({err})"),
    }
}

/// `C:` for `C:\VMs\web`, `\\server\share` for a UNC path; the folder itself otherwise.
fn drive_of(folder: &Path) -> String {
    match folder.components().next() {
        Some(Component::Prefix(prefix)) => prefix.as_os_str().to_string_lossy().into_owned(),
        _ => folder.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024;

    #[test]
    fn warns_when_assigned_ram_would_exceed_the_host() {
        assert_eq!(
            power_on_warnings(16 * GB, 20 * GB, 32 * GB, &[]),
            [CapacityWarning::Ram {
                assigned_mb: 36 * GB,
                physical_mb: 32 * GB
            }]
        );
        assert!(
            power_on_warnings(16 * GB, 16 * GB, 32 * GB, &[]).is_empty(),
            "exactly full is fine"
        );
        assert!(
            power_on_warnings(40 * GB, 0, 32 * GB, &[]).is_empty(),
            "nothing starting, nothing to warn about"
        );
    }

    #[test]
    fn warns_when_a_vm_drive_has_under_ten_percent_free() {
        let drives = [("C:".to_owned(), 9.9), ("D:".to_owned(), 10.0), ("E:".to_owned(), 55.0)];
        assert_eq!(
            power_on_warnings(0, GB, 32 * GB, &drives),
            [CapacityWarning::Disk {
                drive: "C:".into(),
                free_pct: 9.9
            }]
        );
    }

    #[test]
    fn messages_are_readable() {
        let ram = CapacityWarning::Ram {
            assigned_mb: 36 * GB,
            physical_mb: 32 * GB,
        };
        assert_eq!(
            ram.message(),
            "Running VMs would be assigned 36.0 GB of RAM, more than this host's 32.0 GB."
        );
        let disk = CapacityWarning::Disk {
            drive: "D:".into(),
            free_pct: 7.25,
        };
        assert_eq!(disk.message(), "Drive D: has 7.2% free space, under 10%.");
    }

    #[cfg(windows)]
    #[test]
    fn drives_are_named_by_their_prefix() {
        assert_eq!(drive_of(Path::new(r"D:\Labs\web01")), "D:");
        assert_eq!(
            drive_of(Path::new(r"\\nas.example.com\vms\web01")),
            r"\\nas.example.com\vms"
        );
    }
}
