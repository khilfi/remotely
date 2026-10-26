//! Inventory reads (VM-01, VM-02). Reads skip the command bus: they go to the adapter and the store only.
//!
//! A refresh finds every VM, not only running ones: Workstation's library (`inventory.vmls`), the
//! folders chosen in Settings (scanned for .vmx files) and `vmrun list`. For running VMs it also asks
//! vmrun for the VMware Tools state and the guest's IP address.
//!
//! VM-18: it also lists VirtualBox's registered VMs (`VBoxManage list vms`, then `showvminfo` for
//! each), and for running ones whose Guest Additions run, the guest's IP address and OS name. Without
//! VirtualBox there are simply no VirtualBox VMs; when VirtualBox can't be asked, its VMs stay listed
//! as the last refresh found them, with a warning.
//!
//! A VM's environment label (SS-06, as for sessions) is the app's own data: setting it changes no VM,
//! so it skips the bus too, and it is audited like a setting.
//!
//! After each refresh, saved sessions are linked to the VMs whose new guest IPs they reach (QL-01,
//! [`crate::vm_links`]).
//!
//! A refresh starts processes (vmrun, and VBoxManage twice per running VirtualBox VM), so refreshes
//! run one at a time, and all those asked for while one runs share one more run after it
//! ([`Inventory::refresh`]): ten uploads finishing together cost two refreshes, not ten.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::virtualbox::{self, VboxListedVm, VboxVmInfo, VirtualBoxAdapter};
use crate::adapters::vmware::{path_key, with_backslashes, ToolsState, VmxInfo};
use crate::command_bus::TargetDirectory;
use crate::domain::{Context, Environment, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::presentation::Change;
use crate::store::{self, DiscoveredVm, NewAuditEntry, Store, VmRecord};
use crate::terminal::Terminals;
use crate::vm_links::{AutoLinkReport, VmLinks};

/// How the app names itself in dialogs, jobs and the audit log.
pub const APP_NAME: &str = "Remotely";

/// vmrun calls at once while asking running VMs for Tools state and IP address.
const GUEST_QUERY_PARALLELISM: usize = 4;

/// Something a refresh could not read. The rest of the list is still shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryWarning {
    /// [`CoreError::code`] of the cause, e.g. `vmrun_not_found`.
    pub code: String,
    pub message: String,
}

impl InventoryWarning {
    fn new(context: &str, err: &CoreError) -> Self {
        Self {
            code: err.code().to_owned(),
            message: format!("{context}: {err}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReport {
    /// The workspace's VMs (FD-02).
    pub vms: Vec<VmRecord>,
    pub warnings: Vec<InventoryWarning>,
    /// QL-01: sessions linked to VMs (or unlinked) by IP address after this refresh.
    pub links: AutoLinkReport,
    /// FD-02: VMs on this PC that no workspace has yet, which the VMs page's Unassigned view lists.
    pub unassigned: Vec<UnassignedVm>,
}

/// FD-02: a VM on this PC that no workspace has. It belongs to no engagement, so every workspace may see it in the
/// Unassigned view; none can act on it until it is added to one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnassignedVm {
    /// Its key: the .vmx path, or a VirtualBox VM's UUID.
    pub vmx_path: String,
    pub hypervisor: Hypervisor,
    /// VM-18: a VirtualBox VM's .vbox file.
    pub config_path: Option<String>,
    pub display_name: String,
    pub guest_os: Option<String>,
    pub power_state: PowerState,
}

impl UnassignedVm {
    fn of(vm: &DiscoveredVm) -> Self {
        Self {
            vmx_path: vm.vmx_path.clone(),
            hypervisor: vm.hypervisor,
            config_path: vm.config_path.clone(),
            display_name: vm.display_name.clone(),
            guest_os: vm.info.guest_os_name.clone().or_else(|| vm.info.guest_os.clone()),
            power_state: vm.power_state,
        }
    }
}

/// What one look at this PC found, shared by every workspace's report (FD-02).
#[derive(Debug, Clone, Default)]
struct Discovery {
    warnings: Vec<InventoryWarning>,
}

/// Which VMs to show or select (VM-02). Empty fields match everything; a VM must match every field
/// that is set, and any one of the values listed in a field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmFilter {
    /// Case-insensitive text in the name, .vmx path (VirtualBox: UUID or .vbox path), guest OS, IP
    /// address or a tag.
    pub text: String,
    pub tags: Vec<String>,
    pub power_states: Vec<PowerState>,
    pub environments: Vec<Environment>,
    /// VM-18: VMware, VirtualBox or both.
    pub hypervisors: Vec<Hypervisor>,
    /// `Some(true)`: only protected VMs; `Some(false)`: only unprotected ones.
    pub protected: Option<bool>,
}

impl VmFilter {
    pub fn matches(&self, vm: &VmRecord) -> bool {
        let text = self.text.trim().to_lowercase();
        if !text.is_empty() {
            let fields = [
                Some(&vm.display_name),
                Some(&vm.vmx_path),
                vm.config_path.as_ref(),
                vm.guest_os.as_ref(),
                vm.guest_os_name.as_ref(),
                vm.ip_address.as_ref(),
            ];
            let hit = fields
                .into_iter()
                .flatten()
                .chain(&vm.tags)
                .any(|f| f.to_lowercase().contains(&text));
            if !hit {
                return false;
            }
        }
        if !self.tags.is_empty()
            && !self
                .tags
                .iter()
                .any(|want| vm.tags.iter().any(|t| t.eq_ignore_ascii_case(want.trim())))
        {
            return false;
        }
        if !self.power_states.is_empty() && !self.power_states.contains(&vm.power_state) {
            return false;
        }
        if !self.environments.is_empty() && !self.environments.contains(&vm.environment) {
            return false;
        }
        if !self.hypervisors.is_empty() && !self.hypervisors.contains(&vm.hypervisor) {
            return false;
        }
        self.protected.is_none_or(|p| vm.protected == p)
    }
}

pub struct Inventory {
    store: Store,
    hypervisors: Hypervisors,
    links: Arc<VmLinks>,
    refreshes: RefreshGate,
    /// FD-02: the VMs the last refresh found that no workspace has.
    unassigned: Mutex<Vec<DiscoveredVm>>,
}

/// VM-01: one refresh at a time. Each request takes a ticket; a run covers every ticket taken before
/// it started, so a request whose ticket an earlier run covers takes that run's report.
#[derive(Default)]
struct RefreshGate {
    tickets: AtomicU64,
    running: tokio::sync::Mutex<()>,
    /// The last good run: the newest ticket it covers, and what it found.
    last: Mutex<Option<(u64, Discovery)>>,
}

/// A .vmx path found by one of the sources, before its file is read.
struct Candidate {
    path: PathBuf,
    library_name: Option<String>,
}

impl Inventory {
    pub fn new(store: Store, hypervisors: Hypervisors, links: Arc<VmLinks>) -> Self {
        Self {
            store,
            hypervisors,
            links,
            refreshes: RefreshGate::default(),
            unassigned: Mutex::new(Vec::new()),
        }
    }

    /// VM-01: folders scanned for .vmx files, as saved in Settings.
    pub async fn scan_folders(&self, ctx: &Context) -> Result<Vec<PathBuf>> {
        let saved = self
            .store
            .get_setting::<Vec<String>>(ctx, store::SCAN_FOLDERS_KEY)
            .await?;
        Ok(saved.unwrap_or_default().into_iter().map(PathBuf::from).collect())
    }

    /// VM-01: finds every VM, saves what it found and returns the workspace's list. A source that cannot be
    /// read (vmrun missing, a folder gone) becomes a warning instead of failing the refresh.
    ///
    /// FD-02: the look at this PC is the same for every workspace: each VM found goes to the workspace it belongs to,
    /// and those no workspace has wait in [`RefreshReport::unassigned`] (while the user has one active workspace,
    /// they join it). The report is the asking workspace's: its VMs and its sessions' links.
    ///
    /// Single-flight and coalesced: while a refresh runs, the requests that come in wait, and when it
    /// is done the first of them runs once more for all of them (what they asked about may have changed
    /// after the running one read it); the others take what that run found. A request made after a run
    /// started never takes an older one. A run that fails is shared with nobody: the next waiting
    /// request runs again.
    pub async fn refresh(&self, ctx: &Context) -> Result<RefreshReport> {
        let discovery = self.discover(ctx).await?;
        let mut warnings = discovery.warnings;
        let links = match self.links.auto_link(ctx).await {
            Ok(links) => links,
            Err(err) => {
                warnings.push(InventoryWarning::new(
                    "Could not link sessions to VMs by IP address",
                    &err,
                ));
                AutoLinkReport::default()
            }
        };
        Ok(RefreshReport {
            vms: self.store.list_vms(ctx).await?,
            warnings,
            links,
            unassigned: self.unassigned(),
        })
    }

    async fn discover(&self, ctx: &Context) -> Result<Discovery> {
        let gate = &self.refreshes;
        let ticket = gate.tickets.fetch_add(1, Ordering::SeqCst) + 1;
        let _running = gate.running.lock().await;
        if let Some((covers, found)) = locks::lock(&gate.last).as_ref() {
            if *covers >= ticket {
                return Ok(found.clone());
            }
        }
        // Every ticket taken so far was asked for before this run reads anything.
        let covers = gate.tickets.load(Ordering::SeqCst);
        let found = self.discover_now(ctx).await?;
        *locks::lock(&gate.last) = Some((covers, found.clone()));
        Ok(found)
    }

    async fn discover_now(&self, ctx: &Context) -> Result<Discovery> {
        let mut warnings = Vec::new();
        let mut found = self.refresh_vmware(ctx, &mut warnings).await?;
        let mut read = vec![Hypervisor::Vmware];
        // VM-18: someone who uses only VirtualBox has no Workstation and no Workstation VM; saying so on
        // every refresh would be noise. With a Workstation VM listed, the warning stays.
        if found.is_empty() && self.hypervisors.virtualbox().tool_path().is_some() {
            warnings.retain(|w| w.code != CoreError::VmrunNotFound.code());
        }
        // VM-18: VirtualBox's VMs, unless it could not be asked this time.
        let (vbox, vbox_read) = self.refresh_virtualbox(&mut warnings).await;
        found.extend(vbox);
        if vbox_read {
            read.push(Hypervisor::VirtualBox);
        }
        // FD-02: with one active workspace, every VM is in it, as before workspaces.
        let active = self.store.active_workspaces(ctx.user_id).await?;
        let auto = match active.as_slice() {
            [only] => Some(*only),
            _ => None,
        };
        let unassigned = self
            .store
            .record_discovery(ctx.user_id, &found, &read, auto.as_ref())
            .await?;
        *locks::lock(&self.unassigned) = unassigned;
        Ok(Discovery { warnings })
    }

    /// FD-02: the VMs on this PC that no workspace has, as the last refresh found them.
    pub fn unassigned(&self) -> Vec<UnassignedVm> {
        locks::lock(&self.unassigned).iter().map(UnassignedVm::of).collect()
    }

    /// FD-02: adds VMs from the Unassigned view to the workspace: from now on only it lists them and can act on
    /// them. Each must be one the last refresh found with no workspace (refresh again otherwise). Audited in the
    /// workspace; refused by the read-only lock. Returns the workspace's VMs.
    pub async fn claim(&self, ctx: &Context, keys: &[String]) -> Result<Vec<VmRecord>> {
        self.store.read_only().check(Change::Workspaces)?;
        if keys.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let waiting: Vec<DiscoveredVm> = locks::lock(&self.unassigned).clone();
        let mut picked: Vec<DiscoveredVm> = Vec::new();
        for key in keys {
            let found = waiting
                .iter()
                .find(|vm| vm.vmx_path.eq_ignore_ascii_case(key))
                .ok_or_else(|| {
                    CoreError::InvalidInput(format!(
                        "{key} isn't waiting in Unassigned any more: refresh the VM list."
                    ))
                })?;
            if !picked
                .iter()
                .any(|vm| vm.vmx_path.eq_ignore_ascii_case(&found.vmx_path))
            {
                picked.push(found.clone());
            }
        }
        let mut added = Vec::new();
        for vm in &picked {
            if self.store.assign_vm(ctx, &vm.vmx_path).await? {
                added.push(vm.clone());
            }
        }
        // Listed at once, as the refresh found them; the next refresh reads them again.
        self.store.record_discovery(ctx.user_id, &added, &[], None).await?;
        locks::lock(&self.unassigned).retain(|vm| !added.iter().any(|a| a.vmx_path.eq_ignore_ascii_case(&vm.vmx_path)));
        if !added.is_empty() {
            let mut targets = Vec::with_capacity(added.len());
            for vm in &added {
                if let Some(record) = self.store.find_vm(ctx, &vm.vmx_path).await? {
                    targets.push(vm_target(&record));
                }
            }
            let action = match added.as_slice() {
                [vm] => format!("Added VM '{}' to this workspace", vm.display_name),
                vms => format!("Added {} VMs to this workspace", vms.len()),
            };
            self.audit(ctx, "vm_assigned", &action, &targets, None).await?;
        }
        self.store.list_vms(ctx).await
    }

    /// FD-02: takes VMs out of the workspace, into the Unassigned view, where another workspace can add them. Their
    /// label, tags and links stay with this workspace (they come back if the VM does). A protected or Prod VM is
    /// refused: unprotect it or change its label first, which is audited too. With one active workspace every VM
    /// is in it, so nothing can be taken out. Audited in the workspace; refused by the read-only lock.
    pub async fn release(&self, ctx: &Context, keys: &[String]) -> Result<Vec<VmRecord>> {
        self.store.read_only().check(Change::Workspaces)?;
        if keys.is_empty() {
            return Err(CoreError::NoTargets);
        }
        if self.store.active_workspaces(ctx.user_id).await?.len() < 2 {
            return Err(CoreError::InvalidInput(
                "With one workspace, every VM is in it. Make another workspace first.".into(),
            ));
        }
        let mut vms = Vec::new();
        for key in keys {
            let vm = match self.store.find_vm(ctx, key).await? {
                Some(vm) if self.store.vm_in_workspace(ctx, key).await? => vm,
                _ => return Err(CoreError::NotInWorkspace(format!("The VM {key}"))),
            };
            if vm.protected {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' is protected: unprotect it before taking it out of the workspace.",
                    vm.display_name
                )));
            }
            if vm.environment == Environment::Prod {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' is labelled Prod: change its label before taking it out of the workspace.",
                    vm.display_name
                )));
            }
            if !vms.iter().any(|v: &VmRecord| v.id == vm.id) {
                vms.push(vm);
            }
        }
        for vm in &vms {
            self.store.release_vm(ctx, &vm.vmx_path).await?;
        }
        {
            let mut waiting = locks::lock(&self.unassigned);
            for vm in &vms {
                if !waiting.iter().any(|w| w.vmx_path.eq_ignore_ascii_case(&vm.vmx_path)) {
                    waiting.push(released(vm));
                }
            }
        }
        let targets: Vec<Target> = vms.iter().map(vm_target).collect();
        let action = match vms.as_slice() {
            [vm] => format!("Took VM '{}' out of this workspace", vm.display_name),
            vms => format!("Took {} VMs out of this workspace", vms.len()),
        };
        self.audit(
            ctx,
            "vm_released",
            &action,
            &targets,
            Some("it waits in Unassigned until a workspace adds it"),
        )
        .await?;
        self.store.list_vms(ctx).await
    }

    async fn audit(
        &self,
        ctx: &Context,
        event: &str,
        action: &str,
        targets: &[Target],
        detail: Option<&str>,
    ) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail,
                },
            )
            .await
            .map(drop)
    }

    /// VM-01: Workstation's VMs: the library, the scanned folders and `vmrun list`.
    async fn refresh_vmware(&self, ctx: &Context, warnings: &mut Vec<InventoryWarning>) -> Result<Vec<DiscoveredVm>> {
        let vmware = self.hypervisors.vmware();
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut add = |path: PathBuf, library_name: Option<String>| {
            if seen.insert(path_key(&path)) {
                candidates.push(Candidate {
                    path: with_backslashes(&path),
                    library_name,
                });
            }
        };

        match vmware.library().await {
            Ok(entries) => entries.into_iter().for_each(|e| add(e.vmx_path, e.display_name)),
            Err(err) => warnings.push(InventoryWarning::new("Could not read the Workstation library", &err)),
        }
        // VM-24: .vmx files added by hand (Add existing VM).
        let added = self
            .store
            .get_setting::<Vec<String>>(ctx, crate::vm_settings::ADDED_VMS_KEY)
            .await?
            .unwrap_or_default();
        added.into_iter().for_each(|p| add(PathBuf::from(p), None));
        for folder in self.scan_folders(ctx).await? {
            match vmware.scan_folder(&folder).await {
                Ok(paths) => paths.into_iter().for_each(|p| add(p, None)),
                Err(err) => warnings.push(InventoryWarning::new(
                    &format!("Could not scan {}", folder.display()),
                    &err,
                )),
            }
        }
        let running: Option<HashSet<String>> = match vmware.list_running().await {
            Ok(paths) => {
                let keys = paths.iter().map(|p| path_key(p)).collect();
                paths.into_iter().for_each(|p| add(p, None));
                Some(keys)
            }
            Err(err) => {
                warnings.push(InventoryWarning::new(
                    "Could not ask Workstation which VMs are running",
                    &err,
                ));
                None
            }
        };

        let previous = self.store.vm_power_states(ctx).await?;
        let mut found = Vec::with_capacity(candidates.len());
        let mut to_query = Vec::new();
        for candidate in candidates {
            let key = path_key(&candidate.path);
            let is_running = running.as_ref().map(|r| r.contains(&key));
            let info = match vmware.read_vmx(&candidate.path).await {
                Ok(info) => info,
                Err(err) if is_running == Some(true) => {
                    tracing::warn!(vmx = %candidate.path.display(), error = %err, "could not read a running VM's .vmx");
                    VmxInfo::default()
                }
                // Listed in the library but gone from disk, or an unreadable file: not found.
                Err(err) => {
                    tracing::debug!(vmx = %candidate.path.display(), error = %err, "skipping unreadable .vmx");
                    continue;
                }
            };
            let power_state = match is_running {
                Some(true) => PowerState::Running,
                _ if info.suspended => PowerState::Suspended,
                Some(false) => PowerState::NotRunning,
                None => PowerState::Unknown,
            };
            // A paused guest cannot answer; it keeps its last Tools state and IP until unpaused.
            let paused = previous.get(&key) == Some(&PowerState::Paused);
            if power_state == PowerState::Running && !paused {
                to_query.push(found.len());
            }
            let display_name = info
                .display_name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .or(candidate.library_name)
                .unwrap_or_else(|| file_stem(&candidate.path));
            found.push(DiscoveredVm {
                vmx_path: candidate.path.to_string_lossy().into_owned(),
                display_name,
                info,
                power_state,
                tools_state: None,
                ip_address: None,
                hypervisor: Hypervisor::Vmware,
                config_path: None,
            });
        }

        self.query_guests(&mut found, &to_query).await;
        Ok(found)
    }

    /// VM-18: VirtualBox's registered VMs, and whether they were all read. Not installed: none, read.
    /// `list vms` failing, or a VM's `showvminfo`: a warning, and not read, so no VirtualBox VM drops
    /// out of the list because VirtualBox was busy. A VM whose settings VirtualBox can't open
    /// (`accessible="off"`) is left out, like a .vmx gone from disk.
    async fn refresh_virtualbox(&self, warnings: &mut Vec<InventoryWarning>) -> (Vec<DiscoveredVm>, bool) {
        let vbox = Arc::clone(self.hypervisors.virtualbox());
        let listed = match vbox.list_vms().await {
            Ok(listed) => listed,
            Err(CoreError::VboxManageNotFound) => return (Vec::new(), true),
            Err(err) => {
                warnings.push(InventoryWarning::new("Could not ask VirtualBox for its VMs", &err));
                return (Vec::new(), false);
            }
        };
        let limit = Arc::new(Semaphore::new(GUEST_QUERY_PARALLELISM));
        let mut tasks = JoinSet::new();
        for (index, vm) in listed.into_iter().enumerate() {
            let vbox = Arc::clone(&vbox);
            let limit = Arc::clone(&limit);
            tasks.spawn(async move {
                let _permit = limit.acquire_owned().await.ok();
                let read = read_virtualbox_vm(vbox.as_ref(), &vm).await;
                (index, vm, read)
            });
        }
        let mut read: Vec<(usize, DiscoveredVm)> = Vec::new();
        let mut complete = true;
        while let Some(joined) = tasks.join_next().await {
            let Ok((index, vm, result)) = joined else {
                complete = false;
                continue;
            };
            match result {
                Ok(Some(found)) => read.push((index, found)),
                Ok(None) => tracing::debug!(uuid = %vm.uuid, "skipping an inaccessible VirtualBox VM"),
                Err(err) => {
                    complete = false;
                    warnings.push(InventoryWarning::new(
                        &format!("Could not read VirtualBox VM '{}'", vm.name),
                        &err,
                    ));
                }
            }
        }
        read.sort_by_key(|(index, _)| *index);
        (read.into_iter().map(|(_, vm)| vm).collect(), complete)
    }

    /// Tools state, then the IP address when Tools is running, for each VM in `indexes`. A failing
    /// query leaves the field empty; it never fails the refresh.
    async fn query_guests(&self, found: &mut [DiscoveredVm], indexes: &[usize]) {
        let limit = Arc::new(Semaphore::new(GUEST_QUERY_PARALLELISM));
        let mut tasks = JoinSet::new();
        for &index in indexes {
            let vmware = Arc::clone(self.hypervisors.vmware());
            let limit = Arc::clone(&limit);
            let vmx = PathBuf::from(&found[index].vmx_path);
            tasks.spawn(async move {
                let _permit = limit.acquire_owned().await.ok();
                let tools = match vmware.tools_state(&vmx).await {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::debug!(vmx = %vmx.display(), error = %err, "checkToolsState failed");
                        ToolsState::Unknown
                    }
                };
                let ip = if tools == ToolsState::Running {
                    vmware.guest_ip(&vmx).await.unwrap_or_else(|err| {
                        tracing::debug!(vmx = %vmx.display(), error = %err, "getGuestIPAddress failed");
                        None
                    })
                } else {
                    None
                };
                (index, tools, ip)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Ok((index, tools, ip)) = joined {
                found[index].tools_state = Some(tools.as_str().to_owned());
                found[index].ip_address = ip;
            }
        }
    }

    /// The VMs the last refresh found that match `filter` (VM-02).
    pub async fn list(&self, ctx: &Context, filter: &VmFilter) -> Result<Vec<VmRecord>> {
        let mut vms = self.store.list_vms(ctx).await?;
        vms.retain(|vm| filter.matches(vm));
        Ok(vms)
    }

    /// SS-06 for VMs: labels each VM Lab, Staging or Prod, or removes the label with `None`. The
    /// policy engine reads it: a Prod target moves an action up one tier. The label is the app's own
    /// data, so it skips the command bus and has no approval tier; the change is audited like a
    /// setting, with what changed and each VM it changed as a target. VMs that already have the label
    /// are left alone, and a change that changes nothing writes nothing. Every VM must be in the
    /// inventory, or nothing changes. Returns the VMs it changed.
    pub async fn set_environment(
        &self,
        ctx: &Context,
        vmx_paths: &[String],
        environment: Environment,
    ) -> Result<Vec<VmRecord>> {
        self.store.read_only().check(Change::VmLabels)?;
        if vmx_paths.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let mut seen = HashSet::new();
        let mut before = Vec::new();
        for path in vmx_paths {
            let vm = self
                .store
                .find_vm(ctx, path)
                .await?
                .ok_or_else(|| CoreError::UnknownTarget(path.clone()))?;
            if seen.insert(vm.id.clone()) && vm.environment != environment {
                before.push(vm);
            }
        }
        if before.is_empty() {
            return Ok(Vec::new());
        }
        let paths: Vec<String> = before.iter().map(|vm| vm.vmx_path.clone()).collect();
        self.store.set_vm_environment(ctx, &paths, environment).await?;
        let mut after = Vec::with_capacity(paths.len());
        for path in &paths {
            after.extend(self.store.find_vm(ctx, path).await?);
        }

        let targets: Vec<Target> = after.iter().map(vm_target).collect();
        let action = match after.as_slice() {
            [vm] => format!("Changed the label of VM '{}'", vm.display_name),
            vms => format!("Changed the label of {} VMs", vms.len()),
        };
        let detail = label_change(&before, environment);
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "vm_label_changed",
                    action: &action,
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        Ok(after)
    }
}

/// VM-18: one VirtualBox VM as a refresh finds it. For a running VM whose Guest Additions run, also
/// the guest's IP address and OS name; a guest that can't be asked leaves them empty. `None` for a VM
/// VirtualBox can't open.
async fn read_virtualbox_vm(vbox: &dyn VirtualBoxAdapter, listed: &VboxListedVm) -> Result<Option<DiscoveredVm>> {
    let info = vbox.vm_info(&listed.uuid).await?;
    if !info.accessible {
        return Ok(None);
    }
    let power_state = info.power_state();
    let tools = info.tools_state();
    let (mut ip, mut os_name) = (None, None);
    // A paused guest can't answer; the store keeps what it last reported. One `guestproperty
    // enumerate` gives both the address and the OS.
    if power_state == PowerState::Running && tools == Some(ToolsState::Running) {
        match vbox.guest_properties(&listed.uuid).await {
            Ok(props) => {
                ip = virtualbox::guest_ip(&props, &info.nics);
                os_name = virtualbox::guest_os_name(&props);
            }
            Err(err) => {
                tracing::debug!(uuid = %listed.uuid, error = %err, "could not read the guest's properties");
            }
        }
    }
    Ok(Some(virtualbox_discovered(listed, info, tools, ip, os_name)))
}

fn virtualbox_discovered(
    listed: &VboxListedVm,
    info: VboxVmInfo,
    tools: Option<ToolsState>,
    ip_address: Option<String>,
    guest_os_name: Option<String>,
) -> DiscoveredVm {
    let display_name = Some(info.name.clone())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| listed.name.clone());
    let power_state = info.power_state();
    DiscoveredVm {
        vmx_path: listed.uuid.clone(),
        display_name: display_name.clone(),
        info: VmxInfo {
            display_name: Some(display_name),
            guest_os: info.os_type.clone(),
            guest_os_name,
            num_vcpus: info.cpus,
            memsize_mb: info.memory_mb,
            suspended: power_state == PowerState::Suspended,
        },
        power_state,
        tools_state: tools.map(|t| t.as_str().to_owned()),
        ip_address,
        hypervisor: Hypervisor::VirtualBox,
        config_path: info.config_file.map(|p| p.display().to_string()),
    }
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// FD-02: a VM taken out of a workspace, as the Unassigned view lists it until the next refresh.
fn released(vm: &VmRecord) -> DiscoveredVm {
    DiscoveredVm {
        vmx_path: vm.vmx_path.clone(),
        display_name: vm.display_name.clone(),
        info: VmxInfo {
            display_name: Some(vm.display_name.clone()),
            guest_os: vm.guest_os.clone(),
            guest_os_name: vm.guest_os_name.clone(),
            num_vcpus: vm.num_vcpus,
            memsize_mb: vm.memsize_mb,
            suspended: vm.power_state == PowerState::Suspended,
        },
        power_state: vm.power_state,
        tools_state: vm.tools_state.clone(),
        ip_address: vm.ip_address.clone(),
        hypervisor: vm.hypervisor,
        config_path: vm.config_path.clone(),
    }
}

/// A VM's name before the VM list has it: its .vmx file's name, or a VirtualBox VM's UUID.
pub(crate) fn unlisted_name(key: &str) -> String {
    match Hypervisor::of_key(key) {
        Hypervisor::Vmware => file_stem(Path::new(key)),
        Hypervisor::VirtualBox => format!("VirtualBox VM {key}"),
    }
}

/// FD-02: how a refusal names a VM the workspace doesn't have: by its key only, never by another workspace's name
/// for it.
pub(crate) fn vm_named(key: &str) -> String {
    match Hypervisor::of_key(key) {
        Hypervisor::Vmware => format!("The VM '{}'", file_stem(Path::new(key))),
        Hypervisor::VirtualBox => format!("The VirtualBox VM {key}"),
    }
}

fn vm_target(vm: &VmRecord) -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: vm.vmx_path.clone(),
        },
        name: vm.display_name.clone(),
        environment: vm.environment,
        protected: vm.protected,
    }
}

/// For the audit log: "label: none -> prod" when every VM had the same label before, otherwise one
/// part per earlier label with the VMs that had it, "label: none -> prod (web01, web02); lab -> prod (db01)".
fn label_change(before: &[VmRecord], to: Environment) -> String {
    let mut groups: Vec<(Environment, Vec<&str>)> = Vec::new();
    for vm in before {
        match groups.iter_mut().find(|(from, _)| *from == vm.environment) {
            Some((_, names)) => names.push(&vm.display_name),
            None => groups.push((vm.environment, vec![&vm.display_name])),
        }
    }
    let to = to.as_str();
    if let [(from, _)] = groups.as_slice() {
        return format!("label: {} -> {to}", from.as_str());
    }
    let parts: Vec<String> = groups
        .iter()
        .map(|(from, names)| format!("{} -> {to} ({})", from.as_str(), names.join(", ")))
        .collect();
    format!("label: {}", parts.join("; "))
}

/// Resolves targets from the store so the policy engine sees their labels and protection; open
/// terminals (SS-10 MultiExec) by the session behind each.
pub struct StoreDirectory {
    store: Store,
    terminals: Option<Terminals>,
    containers: Option<crate::containers::Containers>,
    networks: Option<crate::host_networks::HostNetworks>,
}

impl StoreDirectory {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            terminals: None,
            containers: None,
            networks: None,
        }
    }

    /// SS-10: terminal targets are the open panes.
    pub fn with_terminals(mut self, terminals: Terminals) -> Self {
        self.terminals = Some(terminals);
        self
    }

    /// CT-01, CT-02: container targets are what the engines list.
    pub fn with_containers(mut self, containers: crate::containers::Containers) -> Self {
        self.containers = Some(containers);
        self
    }

    /// VM-11: network targets are the hypervisors' host networks.
    pub fn with_host_networks(mut self, networks: crate::host_networks::HostNetworks) -> Self {
        self.networks = Some(networks);
        self
    }
}

#[async_trait]
impl TargetDirectory for StoreDirectory {
    async fn resolve(&self, ctx: &Context, target: &TargetRef) -> Result<Target> {
        match target {
            TargetRef::Vm { vmx_path } => {
                // FD-02: a VM another workspace has, or none has, can't be acted on from this one.
                if !self.store.vm_in_workspace(ctx, vmx_path).await? {
                    return Err(CoreError::NotInWorkspace(vm_named(vmx_path)));
                }
                let known = self.store.find_vm(ctx, vmx_path).await?;
                Ok(match known {
                    Some(vm) => Target {
                        target: target.clone(),
                        name: vm.display_name,
                        environment: vm.environment,
                        protected: vm.protected,
                    },
                    // In this workspace but not listed yet (a VM it just made or added): no label, not protected.
                    None => Target {
                        target: target.clone(),
                        name: unlisted_name(vmx_path),
                        environment: Environment::None,
                        protected: false,
                    },
                })
            }
            TargetRef::Session { session_id } => {
                let (name, environment, protected) = self
                    .store
                    .find_session_target(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(session_id.to_string()))?;
                Ok(Target {
                    target: target.clone(),
                    name,
                    environment,
                    protected,
                })
            }
            TargetRef::App => Ok(Target {
                target: TargetRef::App,
                name: APP_NAME.to_owned(),
                environment: Environment::None,
                protected: false,
            }),
            TargetRef::Terminal { terminal_id, .. } => match &self.terminals {
                Some(terminals) => terminals.target(ctx, *terminal_id).await,
                None => Err(CoreError::UnknownTarget(format!("terminal {terminal_id}"))),
            },
            TargetRef::Container { .. } => match &self.containers {
                Some(containers) => containers.target(ctx, target).await,
                None => Err(CoreError::UnknownTarget(target.key())),
            },
            TargetRef::Network { .. } => match &self.networks {
                Some(networks) => networks.target(ctx, target).await,
                None => Err(CoreError::UnknownTarget(target.key())),
            },
            // VM-21: not made yet, so nothing to look up: the name and label it will have; never protected.
            TargetRef::NewVm { name, environment, .. } => Ok(Target {
                target: target.clone(),
                name: name.clone(),
                environment: *environment,
                protected: false,
            }),
            // CV-03: a new file on this PC: named by its file name; no label, never protected.
            TargetRef::DiskImage { path } => Ok(Target {
                target: target.clone(),
                name: std::path::Path::new(path)
                    .file_name()
                    .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned()),
                environment: Environment::None,
                protected: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str) -> VmRecord {
        VmRecord {
            id: name.into(),
            vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
            hypervisor: Hypervisor::Vmware,
            config_path: None,
            display_name: name.into(),
            guest_os: Some("ubuntu-64".into()),
            guest_os_name: Some("Ubuntu 24.04 LTS".into()),
            num_vcpus: Some(2),
            memsize_mb: Some(2048),
            power_state: PowerState::NotRunning,
            ip_address: None,
            tools_state: None,
            environment: Environment::Lab,
            protected: false,
            tags: vec![],
            last_seen_at: None,
        }
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        assert!(VmFilter::default().matches(&vm("web01")));
    }

    #[test]
    fn text_matches_name_path_os_ip_and_tags_without_case() {
        let mut web = vm("web01");
        web.ip_address = Some("192.0.2.10".into());
        web.tags = vec!["Frontend".into()];
        for text in ["WEB", r"c:\vms", "ubuntu 24", "192.0.2.10", "frontend"] {
            let f = VmFilter {
                text: text.into(),
                ..Default::default()
            };
            assert!(f.matches(&web), "{text}");
        }
        let miss = VmFilter {
            text: "db".into(),
            ..Default::default()
        };
        assert!(!miss.matches(&web));
    }

    #[test]
    fn fields_are_and_values_are_or() {
        let mut web = vm("web01");
        web.tags = vec!["lab-a".into()];
        web.power_state = PowerState::Running;

        let tag_or = VmFilter {
            tags: vec!["lab-b".into(), "LAB-A".into()],
            ..Default::default()
        };
        assert!(tag_or.matches(&web));

        let tag_and_state = VmFilter {
            tags: vec!["lab-a".into()],
            power_states: vec![PowerState::NotRunning, PowerState::Suspended],
            ..Default::default()
        };
        assert!(!tag_and_state.matches(&web), "right tag, wrong state");

        let env = VmFilter {
            environments: vec![Environment::Prod],
            ..Default::default()
        };
        assert!(!env.matches(&web));

        let protected = VmFilter {
            protected: Some(true),
            ..Default::default()
        };
        assert!(!protected.matches(&web));
        web.protected = true;
        assert!(protected.matches(&web));
    }

    #[test]
    fn the_hypervisor_filter_picks_vmware_or_virtualbox_vms() {
        let web = vm("web01");
        let vbox = VmRecord {
            vmx_path: "3f0c1a2b-1111-4222-8333-444455556666".into(),
            hypervisor: Hypervisor::VirtualBox,
            config_path: Some(r"D:\VirtualBox VMs\db01\db01.vbox".into()),
            ..vm("db01")
        };
        let only = |h: Hypervisor| VmFilter {
            hypervisors: vec![h],
            ..Default::default()
        };
        assert!(only(Hypervisor::Vmware).matches(&web));
        assert!(!only(Hypervisor::Vmware).matches(&vbox));
        assert!(only(Hypervisor::VirtualBox).matches(&vbox));
        let both = VmFilter {
            hypervisors: Hypervisor::ALL.to_vec(),
            ..Default::default()
        };
        assert!(both.matches(&web) && both.matches(&vbox));
        let by_file = VmFilter {
            text: "virtualbox vms\\db01".into(),
            ..Default::default()
        };
        assert!(by_file.matches(&vbox), "the .vbox path counts as text");
        let parsed: VmFilter = serde_json::from_str(r#"{"hypervisors":["virtualbox"]}"#).unwrap();
        assert_eq!(parsed.hypervisors, [Hypervisor::VirtualBox]);
    }

    #[test]
    fn a_label_change_names_the_vms_only_when_their_labels_differed() {
        let unlabelled = |name: &str| VmRecord {
            environment: Environment::None,
            ..vm(name)
        };
        assert_eq!(
            label_change(&[unlabelled("a"), unlabelled("b")], Environment::Prod),
            "label: none -> prod"
        );
        assert_eq!(
            label_change(&[unlabelled("a"), vm("lab01"), unlabelled("b")], Environment::Prod),
            "label: none -> prod (a, b); lab -> prod (lab01)"
        );
    }

    #[test]
    fn filters_round_trip_through_json_and_default_missing_fields() {
        let f: VmFilter = serde_json::from_str(r#"{"tags":["lab"],"powerStates":["not_running"]}"#).unwrap();
        assert_eq!(f.tags, ["lab"]);
        assert_eq!(f.power_states, [PowerState::NotRunning]);
        assert_eq!(f.text, "");
        assert_eq!(
            serde_json::from_str::<VmFilter>(&serde_json::to_string(&f).unwrap()).unwrap(),
            f
        );
    }
}
