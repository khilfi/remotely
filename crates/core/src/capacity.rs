//! VM-07: capacity check before power-on. Warns when the RAM assigned to running VMs (each .vmx's
//! `memsize`) would exceed the host's physical RAM, or when a VM folder's drive has under 10% free.
//!
//! It only warns: the command bus shows the warnings and asks for a confirm (see
//! [`crate::policy::Decision::add_warnings`]); the user decides. A check that cannot run is a
//! warning too, so a failed read never passes silently.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path};
use std::sync::Arc;

use serde::Serialize;

use crate::adapters::host_counters::HostCounters;
use crate::adapters::vmware::{path_key, VmwareAdapter};
use crate::domain::{Context, Target, TargetRef};
use crate::store::Store;

/// A VM folder's drive with less free space than this is flagged.
pub const MIN_FREE_DISK_PCT: f64 = 10.0;

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

/// Gathers what [`power_on_warnings`] needs: reads only (vmrun list, .vmx files, Windows counters).
pub struct CapacityChecker {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
    host: Arc<dyn HostCounters>,
}

impl CapacityChecker {
    pub fn new(store: Store, vmware: Arc<dyn VmwareAdapter>, host: Arc<dyn HostCounters>) -> Self {
        Self { store, vmware, host }
    }

    /// Warnings for powering on `targets` (VMs that are already running are not counted twice).
    /// Never fails: what cannot be read becomes a [`CapacityWarning::Unchecked`].
    pub async fn check_power_on(&self, ctx: &Context, targets: &[Target]) -> Vec<CapacityWarning> {
        let mut warnings = Vec::new();

        let running: Vec<String> = match self.vmware.list_running().await {
            Ok(paths) => paths.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
            // Fall back to what the last refresh saw.
            Err(_) => match self.store.list_vms(ctx).await {
                Ok(vms) => vms
                    .into_iter()
                    .filter(|v| v.power_state.is_on())
                    .map(|v| v.vmx_path)
                    .collect(),
                Err(err) => {
                    warnings.push(unchecked("which VMs are running", &err));
                    Vec::new()
                }
            },
        };
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
        let mut folders: BTreeMap<String, &Path> = BTreeMap::new();
        for path in &starting {
            if let Some(folder) = Path::new(path).parent() {
                folders.entry(drive_of(folder)).or_insert(folder);
            }
        }
        let mut drives = Vec::new();
        for (drive, folder) in folders {
            match self.host.free_disk_pct(folder).await {
                Ok(free) => drives.push((drive, free)),
                Err(err) => warnings.push(unchecked(&format!("free space on {drive}"), &err)),
            }
        }

        warnings.extend(power_on_warnings(running_mb, starting_mb, physical_mb, &drives));
        warnings
    }

    /// The VM's assigned RAM: from the inventory, else its .vmx; 0 when neither says.
    async fn memsize_mb(&self, ctx: &Context, vmx_path: &str) -> u64 {
        if let Ok(Some(vm)) = self.store.find_vm(ctx, vmx_path).await {
            if let Some(mb) = vm.memsize_mb {
                return mb.into();
            }
        }
        match self.vmware.read_vmx(Path::new(vmx_path)).await {
            Ok(info) => info.memsize_mb.map_or(0, u64::from),
            Err(_) => 0,
        }
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
