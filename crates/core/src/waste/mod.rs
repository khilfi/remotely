//! VM-16, VM-14: the waste finder, a read-only report of what takes this PC's disk and memory for little:
//!
//! - running VMs idle for days, from the dashboard's history on disk (MO-06): the VM's share of this PC's CPU,
//!   and its guest's CPU and network when a linked session is watched ([`rules::idle_verdict`]);
//! - suspended VMs and what their saved state and folder take on disk;
//! - long or large snapshot chains (depth, and the snapshot files' size);
//! - folders with VM files no VM in the list uses, in the folders Remotely was given only ([`folders::orphans`]).
//!
//! Each row's action (suspend, review or delete snapshots, delete the VM, open its folder) goes through the bus
//! and its approvals like anywhere else; the report itself changes nothing, is not audited, and the read-only lock
//! doesn't stop it. Opening a folder in Explorer takes only a folder the last report or a known VM names
//! ([`WasteFinder::folder_to_open`]).

pub mod folders;
pub mod rules;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::adapters::host_networks::{showvminfo_pairs, vm_paths};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vmware::path_key;
use crate::domain::{now_rfc3339, Environment, PowerState};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::metrics::history::{now_ms, HistoryRetention, HistorySource, HISTORY_RETENTION_KEY, MINUTE_MS};
use crate::store::{Store, VmRecord, SCAN_FOLDERS_KEY};
use crate::workspaces::Current;

pub use folders::{OrphanFolder, OrphanKind, SkippedFolder};
pub use rules::{IdleVerdict, WasteOptions};

const VBOX_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(15);

/// Each VirtualBox VM's files, read once per report.
type VboxPaths = std::collections::HashMap<String, crate::adapters::host_networks::VboxVmPaths>;

/// A VM as each section of the report names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasteVm {
    pub vmx_path: String,
    pub name: String,
    pub hypervisor: Hypervisor,
    pub power_state: PowerState,
    pub environment: Environment,
    pub protected: bool,
    pub memory_mb: Option<u32>,
    /// The folder its files are in.
    pub folder: Option<String>,
}

impl WasteVm {
    fn of(vm: &VmRecord) -> Self {
        Self {
            vmx_path: vm.vmx_path.clone(),
            name: vm.display_name.clone(),
            hypervisor: vm.hypervisor,
            power_state: vm.power_state,
            environment: vm.environment,
            protected: vm.protected,
            memory_mb: vm.memsize_mb,
            folder: vm_folder(vm).map(|f| f.display().to_string()),
        }
    }
}

/// A running VM that was idle over the window.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdleVm {
    pub vm: WasteVm,
    pub verdict: IdleVerdict,
    /// The linked session whose guest metrics were read too.
    pub guest_session: Option<String>,
}

/// A suspended VM and what it takes on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspendedVm {
    pub vm: WasteVm,
    /// When it was suspended, as far as its saved state's file tells.
    pub since: Option<String>,
    /// The saved state (Workstation's `.vmss` and `.vmem`, VirtualBox's `.sav`).
    pub state_bytes: Option<u64>,
    /// Everything in its folder.
    pub folder_bytes: Option<u64>,
}

/// A VM whose snapshot chain is long or large.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotChain {
    pub vm: WasteVm,
    pub snapshots: usize,
    pub depth: usize,
    /// Snapshot files: Workstation's delta disks and snapshot states, VirtualBox's Snapshots folder (its saved state
    /// left out).
    pub snapshot_bytes: Option<u64>,
    pub oldest: Option<String>,
    /// "5 snapshots deep", "34 GB of snapshot files".
    pub why: Vec<String>,
}

/// VM-16, VM-14: the waste finder's report.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasteReport {
    pub options: WasteOptions,
    /// The idle window used: the option, or the history kept when that is shorter.
    pub idle_days: u32,
    pub idle: Vec<IdleVm>,
    pub suspended: Vec<SuspendedVm>,
    pub chains: Vec<SnapshotChain>,
    pub orphans: Vec<OrphanFolder>,
    /// The folders searched for orphans.
    pub searched: Vec<String>,
    pub skipped: Vec<SkippedFolder>,
    /// VMs whose snapshots or files could not be read, and why.
    pub problems: Vec<String>,
    pub notes: Vec<String>,
    pub read_at: String,
}

/// The folder a VM's files are in: a .vmx's folder, a .vbox's folder.
pub fn vm_folder(vm: &VmRecord) -> Option<PathBuf> {
    match vm.hypervisor {
        Hypervisor::Vmware => Path::new(&vm.vmx_path).parent().map(Path::to_path_buf),
        Hypervisor::VirtualBox => vm
            .config_path
            .as_deref()
            .and_then(|p| Path::new(p).parent())
            .map(Path::to_path_buf),
    }
}

fn gb(bytes: u64) -> String {
    crate::command_bus::human_size(bytes)
}

/// VM-16, VM-14: the waste finder.
pub struct WasteFinder {
    /// FD-02: the workspace shown.
    current: Current,
    store: Store,
    hypervisors: Hypervisors,
    /// The folders the last report named, which Open folder may open (by [`path_key`]).
    reported: Mutex<HashSet<String>>,
    /// FD-02: the VMs no workspace has, which hold their folders as much as any workspace's VM does.
    inventory: Option<Arc<crate::inventory::Inventory>>,
}

impl WasteFinder {
    /// FD-02: the inventory's Unassigned list, so their folders don't look orphaned.
    pub fn with_inventory(mut self, inventory: Arc<crate::inventory::Inventory>) -> Self {
        self.inventory = Some(inventory);
        self
    }

    pub fn new(current: Current, store: Store, hypervisors: Hypervisors) -> Self {
        Self {
            inventory: None,
            current,
            store,
            hypervisors,
            reported: Mutex::new(HashSet::new()),
        }
    }

    /// VM-16, VM-14: the report, read now.
    pub async fn report(&self, options: WasteOptions) -> Result<WasteReport> {
        let options = options.clamped();
        let vms = self.store.list_vms(&self.current.get()).await?;
        let mut notes = Vec::new();
        let retention = self
            .store
            .get_setting::<HistoryRetention>(&self.current.get(), HISTORY_RETENTION_KEY)
            .await?
            .unwrap_or_default();
        let kept = u32::try_from(retention.days()).unwrap_or(u32::MAX);
        let idle_days = options.idle_days.min(kept);
        if idle_days < options.idle_days {
            notes.push(format!(
                "The dashboard keeps {} of history (Settings, Dashboard), so idle VMs are judged on {idle_days} day(s).",
                retention.label()
            ));
        }
        // VirtualBox refuses a second session lock on a VM while one is pending, so its VMs are asked one at a time:
        // their files first (once each), then their snapshots while nothing else asks.
        let mut problems = Vec::new();
        let mut paths = VboxPaths::new();
        for vm in vms.iter().filter(|v| v.hypervisor == Hypervisor::VirtualBox) {
            match self.vbox_paths(&vm.vmx_path).await {
                Ok(found) => {
                    paths.insert(vm.vmx_path.clone(), found);
                }
                Err(CoreError::VboxManageNotFound) => break,
                Err(err) => problems.push(format!("{}: {err}", vm.display_name)),
            }
        }
        let (idle, suspended, chains, searched) = tokio::join!(
            self.idle(&vms, idle_days),
            self.suspended(&vms, &paths),
            self.chains(&vms, options, &paths),
            self.orphans(&vms),
        );
        let idle = idle?;
        let (chains, chain_problems) = chains;
        problems.extend(chain_problems);
        let (orphans, searched, skipped) = searched?;
        let mut reported = HashSet::new();
        for folder in orphans.iter().map(|o| o.path.as_str()).chain(
            suspended
                .iter()
                .map(|s| &s.vm)
                .chain(chains.iter().map(|c| &c.vm))
                .chain(idle.iter().map(|i| &i.vm))
                .filter_map(|vm| vm.folder.as_deref()),
        ) {
            reported.insert(path_key(Path::new(folder)));
        }
        *locks::lock(&self.reported) = reported;
        if vms.iter().any(|v| v.power_state == PowerState::Unknown) {
            notes.push("Some VMs' state is unknown (their hypervisor could not be asked), so they are left out of idle and suspended.".into());
        }
        Ok(WasteReport {
            options,
            idle_days,
            idle,
            suspended,
            chains,
            orphans,
            searched,
            skipped,
            problems,
            notes,
            read_at: now_rfc3339(),
        })
    }

    async fn idle(&self, vms: &[VmRecord], days: u32) -> Result<Vec<IdleVm>> {
        let to = now_ms().div_euclid(MINUTE_MS);
        let from = to - i64::from(days) * 24 * 60;
        let linked = self.store.sessions_by_vm(&self.current.get()).await?;
        let mut out = Vec::new();
        for vm in vms.iter().filter(|v| v.power_state == PowerState::Running) {
            let host = self
                .store
                .read_history(&self.current.get(), HistorySource::Host, &vm.vmx_path, from, to)
                .await?;
            // The linked session with the most guest history, if any is watched.
            let mut guest: Option<(uuid::Uuid, Vec<crate::metrics::history::MinuteRow>)> = None;
            for session in linked.get(&vm.id).into_iter().flatten() {
                let rows = self
                    .store
                    .read_history(
                        &self.current.get(),
                        HistorySource::Guest,
                        &session.to_string(),
                        from,
                        to,
                    )
                    .await?;
                if !rows.is_empty() && guest.as_ref().is_none_or(|(_, g)| g.len() < rows.len()) {
                    guest = Some((*session, rows));
                }
            }
            let verdict = rules::idle_verdict(
                &host,
                guest.as_ref().map(|(_, g)| g.as_slice()),
                from,
                to,
                rules::IDLE_LIMITS,
            );
            if !verdict.idle {
                continue;
            }
            let guest_session = match &guest {
                Some((id, _)) => self.store.get_session(&self.current.get(), *id).await?.map(|s| s.name),
                None => None,
            };
            out.push(IdleVm {
                vm: WasteVm::of(vm),
                verdict,
                guest_session,
            });
        }
        Ok(out)
    }

    /// A VirtualBox VM's files as `showvminfo` names them.
    async fn vbox_paths(&self, key: &str) -> Result<crate::adapters::host_networks::VboxVmPaths> {
        let pairs = showvminfo_pairs(self.hypervisors.virtualbox().as_ref(), key, VBOX_TIMEOUT).await?;
        Ok(vm_paths(&pairs))
    }

    async fn suspended(&self, vms: &[VmRecord], paths: &VboxPaths) -> Vec<SuspendedVm> {
        let mut out = Vec::new();
        for vm in vms.iter().filter(|v| v.power_state == PowerState::Suspended) {
            let mut row = SuspendedVm {
                vm: WasteVm::of(vm),
                since: None,
                state_bytes: None,
                folder_bytes: None,
            };
            let folder = vm_folder(vm);
            match vm.hypervisor {
                Hypervisor::Vmware => {
                    if let Some(folder) = folder.clone() {
                        let files = blocking(move || state_files(&folder)).await.ok().flatten();
                        if let Some((bytes, since)) = files {
                            row.state_bytes = Some(bytes);
                            row.since = since;
                        }
                    }
                }
                Hypervisor::VirtualBox => {
                    // A3: a state file on a share or a device path is never opened.
                    let state = paths
                        .get(&vm.vmx_path)
                        .and_then(|p| p.state_file.clone())
                        .filter(|p| crate::untrusted::path_refusal(p).is_none());
                    if let Some(state) = state {
                        if let Ok(meta) = tokio::fs::metadata(&state).await {
                            row.state_bytes = Some(meta.len());
                            row.since = meta.modified().ok().and_then(folders::rfc3339);
                        }
                    }
                }
            }
            if let Some(folder) = folder {
                row.folder_bytes = blocking(move || folders::folder_size(&folder, &HashSet::new()).bytes)
                    .await
                    .ok();
            }
            out.push(row);
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.state_bytes));
        out
    }

    async fn chains(
        &self,
        vms: &[VmRecord],
        options: WasteOptions,
        paths: &VboxPaths,
    ) -> (Vec<SnapshotChain>, Vec<String>) {
        let mut out = Vec::new();
        let mut problems = Vec::new();
        let limit = options.chain_gb.saturating_mul(1_000_000_000);
        for vm in vms {
            let tree = match tokio::time::timeout(SNAPSHOT_TIMEOUT, self.hypervisors.snapshots(&vm.vmx_path)).await {
                Ok(Ok(tree)) => tree,
                Ok(Err(CoreError::VboxManageNotFound | CoreError::VmrunNotFound)) => continue,
                Ok(Err(err)) => {
                    problems.push(format!("{}: {err}", vm.display_name));
                    continue;
                }
                Err(_) => {
                    problems.push(format!("{}: reading its snapshots took too long", vm.display_name));
                    continue;
                }
            };
            if tree.snapshots.is_empty() {
                continue;
            }
            let depth = rules::chain_depth(&tree);
            let bytes = self.snapshot_bytes(vm, paths).await;
            let mut why = Vec::new();
            if depth >= options.chain_depth as usize {
                why.push(format!("{depth} snapshots deep"));
            }
            if bytes.is_some_and(|b| b >= limit) {
                why.push(format!("{} of snapshot files", gb(bytes.unwrap_or(0))));
            }
            if why.is_empty() {
                continue;
            }
            let oldest = tree
                .snapshots
                .iter()
                .filter_map(|s| s.created_at)
                .min()
                .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok());
            out.push(SnapshotChain {
                vm: WasteVm::of(vm),
                snapshots: tree.snapshots.len(),
                depth,
                snapshot_bytes: bytes,
                oldest,
                why,
            });
        }
        out.sort_by(|a, b| b.snapshot_bytes.cmp(&a.snapshot_bytes).then(b.depth.cmp(&a.depth)));
        (out, problems)
    }

    /// What a VM's snapshot files take.
    async fn snapshot_bytes(&self, vm: &VmRecord, paths: &VboxPaths) -> Option<u64> {
        match vm.hypervisor {
            Hypervisor::Vmware => {
                let folder = vm_folder(vm)?;
                blocking(move || snapshot_files(&folder)).await.ok().flatten()
            }
            Hypervisor::VirtualBox => {
                let found = paths.get(&vm.vmx_path)?;
                let folder = found.snapshot_folder.clone()?;
                let state = found.state_file.clone();
                blocking(move || {
                    if folders::refusal(&folder).is_some() {
                        return None;
                    }
                    let all = folders::folder_size(&folder, &HashSet::new()).bytes;
                    let state = state
                        .filter(|s| crate::untrusted::path_refusal(s).is_none())
                        .and_then(|s| std::fs::metadata(s).ok())
                        .map_or(0, |m| m.len());
                    Some(all.saturating_sub(state))
                })
                .await
                .ok()
                .flatten()
            }
        }
    }

    /// The folders searched for orphans, and the orphans found.
    async fn orphans(&self, vms: &[VmRecord]) -> Result<(Vec<OrphanFolder>, Vec<String>, Vec<SkippedFolder>)> {
        let mut roots: Vec<PathBuf> = self
            .store
            .get_setting::<Vec<String>>(&self.current.get(), SCAN_FOLDERS_KEY)
            .await?
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        // R2's reads (VM-21): Workstation's preference or Documents, and VirtualBox's default machine folder.
        roots.extend(self.hypervisors.vmware().default_vm_folder().await.ok());
        roots.extend(self.hypervisors.virtualbox().default_machine_folder().await.ok());
        for template in self.store.list_catalog_templates(&self.current.get()).await? {
            roots.extend(template.spec.vm_folder.map(PathBuf::from));
        }
        let mut seen = HashSet::new();
        roots.retain(|r| seen.insert(path_key(r)));
        // A root inside another root is searched with it.
        let keys: Vec<String> = roots.iter().map(|r| path_key(r)).collect();
        let roots: Vec<PathBuf> = roots
            .into_iter()
            .zip(&keys)
            .filter(|(_, key)| {
                !keys
                    .iter()
                    .any(|other| other != *key && key.starts_with(&format!("{}\\", other.trim_end_matches('\\'))))
            })
            .map(|(root, _)| root)
            .collect();
        // FD-02: a folder is a VM's when any workspace's VM, or one no workspace has yet, uses it: those VMs are
        // this PC's, not this workspace's to call orphans.
        let all = self.store.list_vms_all_workspaces(self.current.get().user_id).await?;
        let unassigned = self
            .inventory
            .as_ref()
            .map(|inventory| inventory.unassigned())
            .unwrap_or_default();
        let known: HashSet<String> = vms
            .iter()
            .chain(&all)
            .filter_map(vm_folder)
            .chain(unassigned.iter().filter_map(|vm| {
                match vm.hypervisor {
                    Hypervisor::Vmware => Path::new(&vm.vmx_path).parent().map(Path::to_path_buf),
                    Hypervisor::VirtualBox => vm
                        .config_path
                        .as_deref()
                        .and_then(|p| Path::new(p).parent())
                        .map(Path::to_path_buf),
                }
            }))
            .map(|f| path_key(&f))
            .collect();
        blocking(move || {
            let mut found = Vec::new();
            let mut searched = Vec::new();
            let mut skipped = Vec::new();
            for root in roots {
                // A folder that isn't there (a default folder never made) has nothing to search; a refused one is named.
                if crate::untrusted::path_refusal(&root).is_none() && !root.is_dir() {
                    continue;
                }
                if let Some(reason) = folders::refusal(&root) {
                    skipped.push(SkippedFolder {
                        path: root.display().to_string(),
                        reason,
                    });
                    continue;
                }
                found.extend(folders::orphans(&root, &known));
                searched.push(root.display().to_string());
            }
            found.sort_by_key(|o: &OrphanFolder| std::cmp::Reverse(o.bytes));
            (found, searched, skipped)
        })
        .await
    }

    /// VM-16: the folder Open folder may show in Explorer: one the last report named, or a known VM's (by its key).
    /// A folder on a share or a device path is refused.
    pub async fn folder_to_open(&self, folder: Option<&str>, vm_key: Option<&str>) -> Result<PathBuf> {
        let path = match (folder, vm_key) {
            (_, Some(key)) => {
                let vm = self
                    .store
                    .find_vm(&self.current.get(), key)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(key.to_owned()))?;
                vm_folder(&vm).ok_or_else(|| CoreError::InvalidInput("That VM's folder is not known.".into()))?
            }
            (Some(folder), None) => {
                let path = PathBuf::from(folder);
                if !locks::lock(&self.reported).contains(&path_key(&path)) {
                    return Err(CoreError::InvalidInput(
                        "Only a folder the waste finder listed can be opened from it. Run it again.".into(),
                    ));
                }
                path
            }
            (None, None) => return Err(CoreError::InvalidInput("Say which folder to open.".into())),
        };
        if let Some(reason) = folders::refusal(&path) {
            return Err(CoreError::InvalidInput(format!(
                "{} can't be opened: {reason}",
                path.display()
            )));
        }
        Ok(path)
    }
}

/// Workstation's suspended state in `folder`: the `.vmss` and `.vmem` files that aren't a snapshot's, and when the
/// newest was written.
fn state_files(folder: &Path) -> Option<(u64, Option<String>)> {
    if folders::refusal(folder).is_some() {
        return None;
    }
    let mut bytes = 0;
    let mut newest = None;
    let mut any = false;
    for entry in std::fs::read_dir(folder).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !rules::is_suspend_file(&name) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        any = true;
        bytes += meta.len();
        let modified = meta.modified().ok();
        if modified > newest {
            newest = modified;
        }
    }
    any.then(|| (bytes, newest.and_then(folders::rfc3339)))
}

/// Workstation's snapshot files in `folder` (delta disks, snapshot states).
fn snapshot_files(folder: &Path) -> Option<u64> {
    if folders::refusal(folder).is_some() {
        return None;
    }
    let mut bytes = 0;
    for entry in std::fs::read_dir(folder).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if rules::is_snapshot_file(&name) {
            bytes += entry.metadata().map_or(0, |m| m.len());
        }
    }
    Some(bytes)
}

/// Runs file system work on a blocking thread.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| CoreError::Io(std::io::Error::other(err)))
}
