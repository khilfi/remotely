//! VM-26: the deploy capacity planner. Before any deploy (R2's Deploy and Clone dialogs, a stack's deploy, and
//! their approvals), RAM, CPU and disk on this PC after it, next to what runs now:
//!
//! * RAM: what the running VMs are assigned now, what the new VMs that start add, and the total against this PC's
//!   physical RAM. Over it, the deploy won't fit: VM-07's rule, which still runs at every power-on.
//! * CPU: vCPUs assigned now and after, against this PC's logical CPUs. A VM with more vCPUs than this PC has won't
//!   start; more than twice as many vCPUs as logical CPUs in all is a warning (busy guests slow each other).
//! * Disk, per drive: what the new VMs' disks may take, thin disks at their full size (the worst case), against the
//!   drive's free space. Thick disks over it won't fit (R2's preview refuses them); thin ones over it may not, and a
//!   drive left under [`MIN_FREE_DISK_PCT`] free is a warning.
//!
//! When the RAM won't fit, the planner names running VMs to suspend to make room ([`suggest_suspend`]): never a
//! protected one, Prod only when nothing else frees enough, as few VMs as it can. Suspending goes through the usual
//! power command and its approval; the planner only reads.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vmware::path_key;
use crate::capacity::{by_key, drive_of, CapacityChecker, MIN_FREE_DISK_PCT};
use crate::domain::{Context, Environment, PowerState};

/// More vCPUs than this many times the logical CPUs is a warning.
pub const CPU_SHARE_WARNING: u32 = 2;

/// What one new VM asks of this PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDemand {
    pub name: String,
    /// Assigned RAM; 0 when it isn't known.
    pub ram_mb: u64,
    pub vcpus: u32,
    /// It starts once made (VM-10's bulk clones stay off, so their RAM and CPU aren't taken yet).
    pub starts: bool,
    /// The folder its files go in: its drive is what counts.
    pub folder: PathBuf,
    /// What its disks may take, thin disks at their full size; `None` when it isn't known.
    pub disk_bytes: Option<u64>,
    /// Of that, what thick disks take at once.
    pub thick_bytes: u64,
}

/// A VM running now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningVm {
    pub key: String,
    pub name: String,
    pub ram_mb: Option<u64>,
    pub vcpus: Option<u32>,
    pub protected: bool,
    pub environment: Environment,
    /// Paused VMs hold their RAM too, but a suspend is suggested for running ones only.
    pub paused: bool,
}

/// A drive's space now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveNow {
    pub drive: String,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// What the plan reads about this PC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNow {
    pub physical_ram_mb: Option<u64>,
    pub available_ram_mb: Option<u64>,
    pub logical_cpus: Option<u32>,
    pub running: Vec<RunningVm>,
    pub drives: Vec<DriveNow>,
    /// What couldn't be read.
    pub unchecked: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RamPlan {
    pub physical_mb: Option<u64>,
    /// What Windows has in use now, VMs included.
    pub in_use_mb: Option<u64>,
    /// Assigned to the running VMs now.
    pub running_mb: u64,
    /// What the new VMs that start add.
    pub adds_mb: u64,
    pub after_mb: u64,
    pub fits: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuPlan {
    pub logical_cpus: Option<u32>,
    pub running_vcpus: u32,
    pub adds_vcpus: u32,
    pub after_vcpus: u32,
    /// The most vCPUs one new VM has.
    pub largest_vm_vcpus: u32,
    pub fits: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DrivePlan {
    pub drive: String,
    /// `None` when it couldn't be read.
    pub free_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    /// What the new VMs' disks may take on it, thin disks at their full size.
    pub adds_bytes: u64,
    pub thick_bytes: u64,
    /// Free space left in the worst case; 0 when it doesn't fit.
    pub free_after_bytes: Option<u64>,
    /// The thick disks fit (thin ones start small).
    pub fits: bool,
    /// Every disk fits even at its full size.
    pub worst_case_fits: bool,
    /// Under [`MIN_FREE_DISK_PCT`] free after it, in the worst case.
    pub low_after: bool,
}

/// A running VM the planner suggests suspending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspendVm {
    pub key: String,
    pub name: String,
    pub ram_mb: u64,
    pub environment: Environment,
}

/// VM-26: running VMs to suspend so the deploy's RAM fits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspendPlan {
    pub vms: Vec<SuspendVm>,
    /// What suspending them gives back.
    pub frees_mb: u64,
    /// What the deploy needs freed.
    pub needs_mb: u64,
    /// They free enough; when false, they are every VM that could be suspended and still don't.
    pub enough: bool,
}

/// VM-26: this PC after the deploy, next to now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployCapacity {
    pub ram: RamPlan,
    pub cpu: CpuPlan,
    pub drives: Vec<DrivePlan>,
    /// VMs running now.
    pub running_vms: usize,
    /// Running VMs whose size isn't known, left out of the sums.
    pub unsized_vms: usize,
    /// New VMs, and of them those that start once made.
    pub new_vms: usize,
    pub starting_vms: usize,
    /// RAM, CPU and the thick disks fit.
    pub fits: bool,
    /// Why it won't fit.
    pub problems: Vec<String>,
    /// What may go wrong although it fits.
    pub warnings: Vec<String>,
    /// When the RAM won't fit: running VMs to suspend.
    pub suspend: Option<SuspendPlan>,
    /// What couldn't be read, so a gap is never silent.
    pub unchecked: Vec<String>,
}

fn gb(mb: u64) -> String {
    format!("{:.1} GB", mb as f64 / 1024.0)
}

fn bytes(n: u64) -> String {
    crate::deploy::preview::size_text(n)
}

/// How much a suspend of a VM labelled `environment` costs: Prod last.
fn label_rank(environment: Environment) -> u8 {
    match environment {
        Environment::None | Environment::Lab => 0,
        Environment::Staging => 1,
        Environment::Prod => 2,
    }
}

/// The fewest running VMs to suspend to free `needs_mb` of RAM: never a protected or paused one, nor one whose
/// size isn't known; Staging only when unlabelled and Lab VMs don't free enough, Prod only when those don't
/// either. Within that, one VM that frees enough (the smallest such), else the largest first and then any that
/// turn out not to be needed dropped. `None` when nothing needs freeing or no VM can be suspended.
pub fn suggest_suspend(needs_mb: u64, running: &[RunningVm]) -> Option<SuspendPlan> {
    if needs_mb == 0 {
        return None;
    }
    let candidates: Vec<SuspendVm> = running
        .iter()
        .filter(|vm| !vm.protected && !vm.paused)
        .filter_map(|vm| {
            Some(SuspendVm {
                key: vm.key.clone(),
                name: vm.name.clone(),
                ram_mb: vm.ram_mb.filter(|mb| *mb > 0)?,
                environment: vm.environment,
            })
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let mut last = None;
    for rank in 0..=2u8 {
        let mut pool: Vec<&SuspendVm> = candidates
            .iter()
            .filter(|vm| label_rank(vm.environment) <= rank)
            .collect();
        if pool.is_empty() {
            continue;
        }
        // Largest first; by name for a stable answer.
        pool.sort_by(|a, b| b.ram_mb.cmp(&a.ram_mb).then_with(|| a.name.cmp(&b.name)));
        let total: u64 = pool.iter().map(|vm| vm.ram_mb).sum();
        if total < needs_mb {
            last = Some(pool);
            continue;
        }
        if let Some(one) = pool.iter().rev().find(|vm| vm.ram_mb >= needs_mb) {
            return Some(SuspendPlan {
                frees_mb: one.ram_mb,
                vms: vec![(*one).clone()],
                needs_mb,
                enough: true,
            });
        }
        let mut chosen: Vec<&SuspendVm> = Vec::new();
        let mut freed = 0u64;
        for vm in &pool {
            if freed >= needs_mb {
                break;
            }
            chosen.push(vm);
            freed += vm.ram_mb;
        }
        // Drop the smallest ones that aren't needed after all.
        let mut i = chosen.len();
        while i > 0 {
            i -= 1;
            if freed - chosen[i].ram_mb >= needs_mb {
                freed -= chosen[i].ram_mb;
                chosen.remove(i);
            }
        }
        return Some(SuspendPlan {
            vms: chosen.into_iter().cloned().collect(),
            frees_mb: freed,
            needs_mb,
            enough: true,
        });
    }
    let pool = last?;
    Some(SuspendPlan {
        frees_mb: pool.iter().map(|vm| vm.ram_mb).sum(),
        vms: pool.into_iter().cloned().collect(),
        needs_mb,
        enough: false,
    })
}

/// The plan itself, without any reads.
pub fn plan(now: &HostNow, demands: &[VmDemand]) -> DeployCapacity {
    let mut out = DeployCapacity {
        running_vms: now.running.len(),
        new_vms: demands.len(),
        starting_vms: demands.iter().filter(|d| d.starts).count(),
        unchecked: now.unchecked.clone(),
        ..DeployCapacity::default()
    };

    // RAM.
    let running_mb: u64 = now.running.iter().filter_map(|vm| vm.ram_mb).sum();
    let running_vcpus: u32 = now.running.iter().filter_map(|vm| vm.vcpus).sum();
    out.unsized_vms = now
        .running
        .iter()
        .filter(|vm| vm.ram_mb.is_none() || vm.vcpus.is_none())
        .count();
    let adds_mb: u64 = demands.iter().filter(|d| d.starts).map(|d| d.ram_mb).sum();
    let after_mb = running_mb + adds_mb;
    let ram_fits = now
        .physical_ram_mb
        .is_none_or(|physical| adds_mb == 0 || after_mb <= physical);
    out.ram = RamPlan {
        physical_mb: now.physical_ram_mb,
        in_use_mb: now
            .physical_ram_mb
            .zip(now.available_ram_mb)
            .map(|(physical, available)| physical.saturating_sub(available)),
        running_mb,
        adds_mb,
        after_mb,
        fits: ram_fits,
    };
    if let (false, Some(physical)) = (ram_fits, now.physical_ram_mb) {
        out.problems.push(format!(
            "RAM: the running VMs are assigned {} now, and the new VMs that start add {}: {} in all, more than this PC's {}.",
            gb(running_mb),
            gb(adds_mb),
            gb(after_mb),
            gb(physical)
        ));
        out.suspend = suggest_suspend(after_mb - physical, &now.running);
    }
    if demands.iter().any(|d| d.starts && d.ram_mb == 0) {
        out.unchecked
            .push("Some new VMs' memory isn't known yet (their source couldn't be read), so the RAM after it leaves them out.".into());
    }

    // CPU.
    let starting = demands.iter().filter(|d| d.starts);
    let adds_vcpus: u32 = starting.clone().map(|d| d.vcpus).sum();
    let largest = demands.iter().map(|d| d.vcpus).max().unwrap_or(0);
    let after_vcpus = running_vcpus + adds_vcpus;
    let cpu_fits = now.logical_cpus.is_none_or(|cpus| largest <= cpus);
    out.cpu = CpuPlan {
        logical_cpus: now.logical_cpus,
        running_vcpus,
        adds_vcpus,
        after_vcpus,
        largest_vm_vcpus: largest,
        fits: cpu_fits,
    };
    if let Some(cpus) = now.logical_cpus {
        if !cpu_fits {
            out.problems.push(format!(
                "CPU: a new VM has {largest} vCPUs, and this PC has {cpus} logical CPUs, so it can't start."
            ));
        } else if adds_vcpus > 0 && after_vcpus > cpus.saturating_mul(CPU_SHARE_WARNING) {
            out.warnings.push(format!(
                "CPU: {after_vcpus} vCPUs on {cpus} logical CPUs after it: busy guests will slow each other down."
            ));
        }
    }

    // Disk, per drive.
    let mut per_drive: BTreeMap<String, (u64, u64, bool)> = BTreeMap::new();
    for d in demands {
        let drive = drive_of(&d.folder);
        let entry = per_drive.entry(drive).or_insert((0, 0, false));
        entry.0 = entry.0.saturating_add(d.disk_bytes.unwrap_or(0));
        entry.1 = entry.1.saturating_add(d.thick_bytes);
        entry.2 |= d.disk_bytes.is_none();
    }
    let mut disk_fits = true;
    for (drive, (adds, thick, unknown)) in per_drive {
        let space = now.drives.iter().find(|s| s.drive.eq_ignore_ascii_case(&drive));
        let (free, total) = (space.map(|s| s.free_bytes), space.map(|s| s.total_bytes));
        let fits = free.is_none_or(|f| thick <= f);
        let worst_case_fits = free.is_none_or(|f| adds <= f);
        let free_after = free.map(|f| f.saturating_sub(adds));
        let low_after = match (free_after, total) {
            (Some(after), Some(total)) if total > 0 && worst_case_fits => {
                (after as f64 * 100.0 / total as f64) < MIN_FREE_DISK_PCT
            }
            _ => false,
        };
        if let Some(free) = free {
            if !fits {
                out.problems.push(format!(
                    "Disk: the thick disks need {} on {drive}, which has {} free.",
                    bytes(thick),
                    bytes(free)
                ));
            } else if !worst_case_fits {
                out.warnings.push(format!(
                    "Disk: if the guests fill their thin disks, they take up to {} on {drive}, which has {} free.",
                    bytes(adds),
                    bytes(free)
                ));
            } else if low_after {
                out.warnings.push(format!(
                    "Disk: {drive} would have under {MIN_FREE_DISK_PCT:.0}% free if the guests fill their disks ({} left).",
                    bytes(free_after.unwrap_or(0))
                ));
            }
        }
        if unknown {
            out.unchecked.push(format!(
                "Some new VMs' disks on {drive} couldn't be read, so they are left out."
            ));
        }
        disk_fits &= fits;
        out.drives.push(DrivePlan {
            drive,
            free_bytes: free,
            total_bytes: total,
            adds_bytes: adds,
            thick_bytes: thick,
            free_after_bytes: free_after,
            fits,
            worst_case_fits,
            low_after,
        });
    }
    out.fits = ram_fits && cpu_fits && disk_fits;
    out
}

impl DeployCapacity {
    /// What the approval says when it won't fit: RAM and CPU (the deploy preview says the disks'), then the suspend
    /// suggestion.
    pub fn approval_warnings(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .problems
            .iter()
            .filter(|p| p.starts_with("RAM:") || p.starts_with("CPU:"))
            .cloned()
            .collect();
        if let Some(suspend) = &self.suspend {
            out.push(suspend.describe());
        }
        out
    }
}

impl SuspendPlan {
    pub fn describe(&self) -> String {
        let names: Vec<String> = self.vms.iter().map(|vm| format!("'{}'", vm.name)).collect();
        if self.enough {
            format!(
                "Suspending {} would free {}, enough to make room (suspending writes each VM's memory to its folder's drive).",
                names.join(", "),
                gb(self.frees_mb)
            )
        } else {
            format!(
                "Even suspending every running VM that can be ({}) frees only {} of the {} needed.",
                names.join(", "),
                gb(self.frees_mb),
                gb(self.needs_mb)
            )
        }
    }
}

/// What each VM of a deploy asks of this PC: the size's RAM and vCPUs (a clone or an import gets them too), and its
/// disks as the deploy's preview counts them (thin at their full size). VM-10's bulk clones stay off.
pub fn deploy_demands(
    spec: &crate::deploy::DeploySpec,
    preview: &crate::deploy::preview::DeployPreview,
) -> Vec<VmDemand> {
    let starts = !matches!(spec.source, crate::deploy::DeploySource::BulkClone);
    spec.vms
        .iter()
        .map(|vm| {
            let shown = preview.vms.iter().find(|p| p.name.eq_ignore_ascii_case(&vm.name));
            VmDemand {
                name: vm.name.clone(),
                ram_mb: spec.size.as_ref().map_or(0, |s| u64::from(s.memory_mb)),
                vcpus: spec.size.as_ref().map_or(0, |s| s.vcpus()),
                starts,
                folder: spec.vm_folder(vm),
                disk_bytes: shown.and_then(|p| p.disk_bytes),
                thick_bytes: shown.map_or(0, |p| p.thick_bytes),
            }
        })
        .collect()
}

/// The nearest folder of `path` that is there (a deploy's folder may not be yet), for its drive's space.
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

impl CapacityChecker {
    /// The running VMs with their sizes, names, labels and protection: from the hypervisors' own lists (the last
    /// refresh for one that can't be asked) and the inventory.
    ///
    /// FD-02: every running VM holds this PC's RAM, whichever workspace has it, so all are counted; only the
    /// workspace's own are named, labelled and offered for a suspend.
    pub async fn running_vms(&self, ctx: &Context, unchecked: &mut Vec<String>) -> Vec<RunningVm> {
        let inventory = match self.store().list_vms_all_workspaces(ctx.user_id).await {
            Ok(vms) => vms,
            Err(err) => {
                unchecked.push(format!("could not read the VM list ({err})"));
                Vec::new()
            }
        };
        let mine: std::collections::HashSet<String> = match self.store().list_vms(ctx).await {
            Ok(vms) => vms.iter().map(|vm| path_key(Path::new(&vm.vmx_path))).collect(),
            Err(_) => std::collections::HashSet::new(),
        };
        let running = self.running(&inventory).await;
        let known = by_key(&inventory);
        let mut out = Vec::with_capacity(running.len());
        for key in running {
            let (ram, cpus) = self.size(&known, &key).await;
            if !mine.contains(&path_key(Path::new(&key))) {
                // Another workspace's VM, or one none has: counted, never named, never suggested (as if protected).
                out.push(RunningVm {
                    name: "a VM outside this workspace".to_owned(),
                    ram_mb: ram.map(u64::from),
                    vcpus: cpus,
                    protected: true,
                    environment: Environment::None,
                    paused: false,
                    key,
                });
                continue;
            }
            let record = known.get(&path_key(Path::new(&key)));
            let name = record
                .map(|vm| vm.display_name.clone())
                .unwrap_or_else(|| match Hypervisor::of_key(&key) {
                    Hypervisor::Vmware => Path::new(&key)
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| key.clone()),
                    Hypervisor::VirtualBox => key.clone(),
                });
            out.push(RunningVm {
                name,
                ram_mb: ram.map(u64::from),
                vcpus: cpus,
                protected: record.is_some_and(|vm| vm.protected),
                environment: record.map(|vm| vm.environment).unwrap_or_default(),
                paused: record.is_some_and(|vm| vm.power_state == PowerState::Paused),
                key,
            });
        }
        out
    }

    /// VM-26: this PC after a deploy of `demands`, next to now. Reads only; never fails (what can't be read is
    /// said in `unchecked`).
    pub async fn deploy_capacity(&self, ctx: &Context, demands: &[VmDemand]) -> DeployCapacity {
        let mut now = HostNow::default();
        now.running = self.running_vms(ctx, &mut now.unchecked).await;
        match self.host().host_totals().await {
            Ok(totals) => {
                now.physical_ram_mb = Some(totals.physical_ram_mb);
                now.available_ram_mb = Some(totals.available_ram_mb);
                now.logical_cpus = Some(totals.logical_cpus);
            }
            Err(err) => now
                .unchecked
                .push(format!("could not read this PC's RAM and CPUs ({err})")),
        }
        let mut seen = BTreeMap::new();
        for d in demands {
            seen.entry(drive_of(&d.folder)).or_insert_with(|| d.folder.clone());
        }
        for (drive, folder) in seen {
            let Some(dir) = existing_ancestor(&folder) else {
                now.unchecked.push(format!(
                    "{} isn't on a drive of this PC that is there now",
                    folder.display()
                ));
                continue;
            };
            match self.host().disk_space(&dir).await {
                Ok(space) => now.drives.push(DriveNow {
                    drive,
                    free_bytes: space.free_bytes,
                    total_bytes: space.total_bytes,
                }),
                Err(err) => now
                    .unchecked
                    .push(format!("could not read the free space on {drive} ({err})")),
            }
        }
        plan(&now, demands)
    }

    /// VM-07, VM-26: at a power-on whose RAM won't fit, which other running VMs to suspend to make room for
    /// `needs_mb`. `None` when none can be.
    pub async fn suspend_advice(&self, ctx: &Context, needs_mb: u64, starting: &[String]) -> Option<SuspendPlan> {
        let starting: Vec<String> = starting.iter().map(|k| path_key(Path::new(k))).collect();
        let mut unchecked = Vec::new();
        let running: Vec<RunningVm> = self
            .running_vms(ctx, &mut unchecked)
            .await
            .into_iter()
            .filter(|vm| !starting.contains(&path_key(Path::new(&vm.key))))
            .collect();
        suggest_suspend(needs_mb, &running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn vm(name: &str, ram_gb: u64, environment: Environment) -> RunningVm {
        RunningVm {
            key: format!(r"C:\VMs\{name}\{name}.vmx"),
            name: name.into(),
            ram_mb: Some(ram_gb * 1024),
            vcpus: Some(2),
            protected: false,
            environment,
            paused: false,
        }
    }

    fn demand(name: &str, ram_gb: u64, vcpus: u32, disk_gb: u64, thick_gb: u64) -> VmDemand {
        VmDemand {
            name: name.into(),
            ram_mb: ram_gb * 1024,
            vcpus,
            starts: true,
            folder: PathBuf::from(r"D:\Labs"),
            disk_bytes: Some(disk_gb * GIB),
            thick_bytes: thick_gb * GIB,
        }
    }

    fn host(running: Vec<RunningVm>) -> HostNow {
        HostNow {
            physical_ram_mb: Some(32 * 1024),
            available_ram_mb: Some(12 * 1024),
            logical_cpus: Some(8),
            running,
            drives: vec![DriveNow {
                drive: "D:".into(),
                free_bytes: 500 * GIB,
                total_bytes: 1000 * GIB,
            }],
            unchecked: Vec::new(),
        }
    }

    #[test]
    fn the_plan_sums_now_and_after() {
        let now = host(vec![
            vm("dc01", 4, Environment::Lab),
            vm("sql01", 8, Environment::Staging),
        ]);
        let p = plan(&now, &[demand("web-1", 4, 2, 40, 0), demand("web-2", 4, 2, 40, 0)]);
        assert_eq!(p.ram.running_mb, 12 * 1024);
        assert_eq!(p.ram.adds_mb, 8 * 1024);
        assert_eq!(p.ram.after_mb, 20 * 1024);
        assert_eq!(p.ram.in_use_mb, Some(20 * 1024));
        assert_eq!((p.cpu.running_vcpus, p.cpu.adds_vcpus, p.cpu.after_vcpus), (4, 4, 8));
        assert_eq!(p.drives.len(), 1);
        assert_eq!(p.drives[0].adds_bytes, 80 * GIB);
        assert_eq!(p.drives[0].free_after_bytes, Some(420 * GIB));
        assert!(p.fits, "{:?}", p.problems);
        assert!(p.problems.is_empty() && p.warnings.is_empty() && p.suspend.is_none());
        assert_eq!((p.running_vms, p.new_vms, p.starting_vms), (2, 2, 2));
    }

    #[test]
    fn thin_disks_count_at_their_full_size_and_thick_ones_must_fit() {
        let now = host(vec![]);
        // 540 GB thin on a drive with 500 GB free: it may not fit, but it isn't refused.
        let p = plan(&now, &[demand("files-1", 4, 2, 540, 0)]);
        assert!(p.fits);
        assert!(!p.drives[0].worst_case_fits);
        assert!(p.warnings.iter().any(|w| w.contains("thin disks")), "{:?}", p.warnings);
        // 520 GB of it thick: it won't fit.
        let p = plan(&now, &[demand("files-1", 4, 2, 540, 520)]);
        assert!(!p.fits);
        assert!(
            p.problems.iter().any(|w| w.contains("thick disks need")),
            "{:?}",
            p.problems
        );
        // 460 GB: fits, but leaves the drive under 10 % free.
        let p = plan(&now, &[demand("files-1", 4, 2, 460, 0)]);
        assert!(p.fits && p.drives[0].low_after);
        assert!(
            p.warnings.iter().any(|w| w.contains("under 10% free")),
            "{:?}",
            p.warnings
        );
    }

    #[test]
    fn ram_over_the_pc_suggests_vms_to_suspend() {
        let now = host(vec![
            vm("dc01", 4, Environment::Lab),
            vm("sql01", 16, Environment::Prod),
            vm("build01", 8, Environment::None),
            vm("tiny", 1, Environment::Lab),
        ]);
        // 29 GB running + 8 GB = 37 GB on 32 GB: 5 GB to free. build01 (8 GB) alone does it; Prod isn't asked.
        let p = plan(&now, &[demand("web-1", 8, 2, 40, 0)]);
        assert!(!p.fits && !p.ram.fits);
        assert!(p.problems[0].starts_with("RAM:"), "{:?}", p.problems);
        let s = p.suspend.as_ref().unwrap();
        assert!(s.enough);
        assert_eq!(s.needs_mb, 5 * 1024);
        assert_eq!(s.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["build01"]);
        assert!(p.approval_warnings()[1].contains("Suspending 'build01' would free 8.0 GB"));
    }

    #[test]
    fn suspend_suggestions_take_as_few_vms_as_they_can_and_prod_last() {
        let lab = [
            vm("a", 3, Environment::Lab),
            vm("b", 2, Environment::Lab),
            vm("c", 2, Environment::None),
            vm("p", 16, Environment::Prod),
        ];
        // 4 GB: no single non-Prod VM frees it; the largest first, then nothing to drop: a (3) + b (2).
        let s = suggest_suspend(4 * 1024, &lab).unwrap();
        assert!(s.enough);
        assert_eq!(s.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(s.frees_mb, 5 * 1024);
        // 3 GB: one VM does it, the smallest such.
        let s = suggest_suspend(3 * 1024, &lab).unwrap();
        assert_eq!(s.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["a"]);
        // 10 GB: the Lab and unlabelled VMs free only 7, so Prod is in: p alone frees it.
        let s = suggest_suspend(10 * 1024, &lab).unwrap();
        assert_eq!(s.vms.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), ["p"]);
        // 40 GB: not even all of them.
        let s = suggest_suspend(40 * 1024, &lab).unwrap();
        assert!(!s.enough);
        assert_eq!(s.vms.len(), 4);
        assert_eq!(s.frees_mb, 23 * 1024);
        assert!(s.describe().contains("frees only 23.0 GB of the 40.0 GB"));
        // Nothing to free, or nothing that can be suspended: no suggestion.
        assert!(suggest_suspend(0, &lab).is_none());
        let mut locked = vm("dc01", 8, Environment::Lab);
        locked.protected = true;
        let mut paused = vm("web01", 8, Environment::Lab);
        paused.paused = true;
        let mut no_size = vm("x", 8, Environment::Lab);
        no_size.ram_mb = None;
        assert!(suggest_suspend(1024, &[locked, paused, no_size]).is_none());
    }

    #[test]
    fn a_vm_with_more_vcpus_than_this_pc_wont_start_and_many_vcpus_warn() {
        let now = host(vec![]);
        let p = plan(&now, &[demand("big", 4, 16, 40, 0)]);
        assert!(!p.fits && !p.cpu.fits);
        assert!(p.problems.iter().any(|w| w.contains("16 vCPUs")), "{:?}", p.problems);
        let many: Vec<VmDemand> = (0..5).map(|i| demand(&format!("w{i}"), 1, 4, 10, 0)).collect();
        let p = plan(&now, &many);
        assert!(p.fits);
        assert!(
            p.warnings.iter().any(|w| w.contains("20 vCPUs on 8")),
            "{:?}",
            p.warnings
        );
    }

    #[test]
    fn vms_that_stay_off_take_disk_but_no_ram() {
        let now = host(vec![vm("dc01", 30, Environment::Lab)]);
        let mut clone = demand("dc01-clone", 30, 2, 100, 0);
        clone.starts = false;
        let p = plan(&now, &[clone]);
        assert!(p.fits, "{:?}", p.problems);
        assert_eq!(p.ram.adds_mb, 0);
        assert_eq!(p.starting_vms, 0);
        assert_eq!(p.drives[0].adds_bytes, 100 * GIB);
    }

    #[test]
    fn what_isnt_known_is_said() {
        let mut now = host(vec![]);
        now.physical_ram_mb = None;
        now.logical_cpus = None;
        now.drives.clear();
        let mut d = demand("web-1", 0, 2, 40, 0);
        d.disk_bytes = None;
        let p = plan(&now, &[d]);
        assert!(p.fits);
        assert_eq!(p.drives[0].free_bytes, None);
        assert!(
            p.unchecked.iter().any(|u| u.contains("memory isn't known")),
            "{:?}",
            p.unchecked
        );
        assert!(
            p.unchecked.iter().any(|u| u.contains("couldn't be read")),
            "{:?}",
            p.unchecked
        );
    }
}
