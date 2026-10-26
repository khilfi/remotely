//! Impact preview (AP-02): what each VM target looks like right now, shown in the approval dialog.
//! Container targets (CT-01, CT-02) come from [`crate::containers::Containers::impact`]: each container's
//! state, image and uptime, what uses an image or volume, and what a prune removes.
//!
//! Reads only, and none needs a guest login: `vmrun list` for the power state (the .vmx tells a
//! suspended VM from one that is off), the first line of the VM's `vmware.log` for how long it has
//! been running, and its .vmsd for the snapshot count. A VirtualBox VM (VM-18) answers all three
//! through `showvminfo` (its state, when that state began, its snapshots) and its .vbox file (snapshot
//! times). VM-04, VM-21, VM-24: for a snapshot or VM delete, the linked clones that depend on what it would delete
//! ([`crate::linked_clones`]). Users logged in to the guest need a guest login, and other dependent VMs need lab
//! blueprints (VM-08, v2); neither is shown yet.

use std::path::Path;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::adapters::containers::ContainerState;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors, RunningVms};
use crate::command_bus::Command;
use crate::containers::Containers;
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::host_networks::HostNetworks;
use crate::linked_clones::{Blocked, LinkedClones, SnapshotClones};
use crate::snapshots;
use crate::store::Store;
use crate::vm_settings::{VmChangePreview, VmEditor};

/// One VM target as it is now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetImpact {
    /// [`TargetRef::key`] of the target, to match it with the request's targets.
    pub target: String,
    pub power_state: PowerState,
    /// When the running VM's process started (its power-on or resume), RFC 3339 UTC.
    pub running_since: Option<String>,
    pub uptime_secs: Option<u64>,
    pub snapshot_count: Option<usize>,
    /// Snapshots older than [`snapshots::OLD_AFTER_DAYS`] days.
    pub old_snapshot_count: Option<usize>,
    /// What could not be read, so a gap in the preview is never silent.
    pub notes: Vec<String>,
    /// CT-01, CT-02: for a container target, what it is now (the VM fields are empty then).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerImpact>,
    /// VM-04, VM-21, VM-24: for a snapshot or VM delete, the linked clones that depend on what it would delete, by
    /// snapshot. Such a VM is refused ([`crate::linked_clones`]).
    pub linked_clones: Vec<SnapshotClones>,
}

/// CT-01, CT-02: one container, image or volume target as it is now, or what a pull or prune on a host
/// does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerImpact {
    /// `container`, `image`, `volume` or `engine`.
    pub kind: String,
    pub name: String,
    pub state: Option<ContainerState>,
    /// The engine's words, e.g. "Up 2 hours (healthy)": the uptime.
    pub status: Option<String>,
    pub image: Option<String>,
    pub ports: Vec<String>,
    pub size_bytes: Option<u64>,
    /// Containers that use the image or volume, with their state.
    pub used_by: Vec<String>,
    /// What a prune or a volume removal deletes (at most 50 listed).
    pub removes: Vec<String>,
}

impl ContainerImpact {
    pub fn empty(kind: &str, name: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            name: name.to_owned(),
            state: None,
            status: None,
            image: None,
            ports: Vec::new(),
            size_bytes: None,
            used_by: Vec::new(),
            removes: Vec::new(),
        }
    }
}

pub struct ImpactPreviewer {
    store: Store,
    hypervisors: Hypervisors,
    /// CT-01, CT-02: container targets.
    containers: Option<Containers>,
    /// VM-23, VM-24: what a VM settings or lifecycle change does to each VM.
    editor: VmEditor,
    /// VM-11: port forwards.
    networks: Option<HostNetworks>,
    /// VM-04, VM-21, VM-24: the linked clones a delete would break.
    linked_clones: LinkedClones,
}

impl ImpactPreviewer {
    pub fn new(store: Store, hypervisors: Hypervisors) -> Self {
        Self {
            editor: VmEditor::new(hypervisors.clone(), store.clone()),
            linked_clones: LinkedClones::new(hypervisors.clone()),
            store,
            hypervisors,
            containers: None,
            networks: None,
        }
    }

    /// VM-04, VM-21, VM-24: for a snapshot or VM delete, each VM target it must not touch because linked clones depend
    /// on what it would delete (or that could not be checked). Empty for other commands. Reads only.
    pub async fn linked_clones(&self, command: &Command, targets: &[Target]) -> Vec<Blocked> {
        self.linked_clones.blocked(command, targets).await
    }

    /// VM-23, VM-24: for a VM settings or lifecycle command, what it changes on each VM, the files that go,
    /// and why a VM would be refused. `None` for other commands. Reads only.
    pub async fn vm_change(&self, command: &Command, targets: &[Target]) -> Option<VmChangePreview> {
        self.editor.preview(command, targets).await
    }

    /// CT-01, CT-02: container targets are previewed by the containers service.
    pub fn with_containers(mut self, containers: Containers) -> Self {
        self.containers = Some(containers);
        self
    }

    /// VM-11: port forwards are previewed by the host networks service.
    pub fn with_host_networks(mut self, networks: HostNetworks) -> Self {
        self.networks = Some(networks);
        self
    }

    /// VM-11: why a command can't run on this PC at all, before anything is asked.
    pub fn refusal(&self, command: &Command) -> Option<String> {
        self.networks.as_ref()?.refusal(command)
    }

    /// VM-11: what a port forward's approval says (who can reach it, whose address, the VMs on the network).
    pub async fn network_warnings(&self, ctx: &Context, command: &Command) -> Vec<String> {
        match &self.networks {
            Some(networks) => networks.warnings(ctx, command).await,
            None => Vec::new(),
        }
    }

    /// The preview for a command's targets: VMs here, container targets by the containers service.
    /// VM-21: for a deploy, what it makes and the free-space check on its folder's drive. `None` for other
    /// commands. Reads only.
    pub async fn deploy(
        &self,
        command: &Command,
        host: &dyn crate::adapters::host_counters::HostCounters,
    ) -> Option<crate::deploy::preview::DeployPreview> {
        let Command::Deploy { spec, .. } = command else {
            return None;
        };
        Some(crate::deploy::preview::preview(spec, &self.hypervisors, host).await)
    }

    pub async fn preview_for(&self, ctx: &Context, command: &Command, targets: &[Target]) -> Vec<TargetImpact> {
        let mut out = self.preview(ctx, targets).await;
        if let (Some(containers), Command::Container { op, .. }) = (&self.containers, command) {
            out.extend(containers.impact(ctx, targets, Some(op)).await);
        }
        out
    }

    /// One entry per VM target, in order. Other kinds of target have nothing to preview yet.
    pub async fn preview(&self, ctx: &Context, targets: &[Target]) -> Vec<TargetImpact> {
        let vms: Vec<&str> = targets
            .iter()
            .filter_map(|t| match &t.target {
                TargetRef::Vm { vmx_path } => Some(vmx_path.as_str()),
                _ => None,
            })
            .collect();
        if vms.is_empty() {
            return Vec::new();
        }
        let running = if vms.iter().any(|key| Hypervisor::of_key(key) == Hypervisor::Vmware) {
            Some(self.hypervisors.running().await)
        } else {
            None
        };
        let now = OffsetDateTime::now_utc();
        let mut out = Vec::with_capacity(vms.len());
        for key in vms {
            let impact = match Hypervisor::of_key(key) {
                Hypervisor::Vmware => self.one_vmware(ctx, key, running.as_ref(), now).await,
                Hypervisor::VirtualBox => self.one_virtualbox(key, now).await,
            };
            out.push(impact);
        }
        out
    }

    async fn one_vmware(
        &self,
        ctx: &Context,
        vmx_path: &str,
        running: Option<&RunningVms>,
        now: OffsetDateTime,
    ) -> TargetImpact {
        let vmware = self.hypervisors.vmware();
        let vmx = Path::new(vmx_path);
        let mut notes = Vec::new();
        let stored = match self.store.find_vm(ctx, vmx_path).await {
            Ok(vm) => vm.map(|vm| vm.power_state).unwrap_or_default(),
            Err(err) => {
                notes.push(format!("Could not read the inventory: {err}"));
                PowerState::Unknown
            }
        };
        let listed = running.map(|r| (r.contains(vmx_path), &r.vmware));
        let power_state = match listed {
            // vmrun cannot see a pause; the app's own pause jobs can.
            Some((Some(true), _)) => {
                if stored == PowerState::Paused {
                    PowerState::Paused
                } else {
                    PowerState::Running
                }
            }
            Some((Some(false), _)) => match vmware.read_vmx(vmx).await {
                Ok(info) if info.suspended => PowerState::Suspended,
                Ok(_) => PowerState::NotRunning,
                Err(err) => {
                    notes.push(format!("Could not read the .vmx: {err}"));
                    PowerState::NotRunning
                }
            },
            Some((None, Err(err))) => {
                notes.push(format!(
                    "State from the last refresh; Workstation could not be asked: {err}"
                ));
                stored
            }
            _ => stored,
        };

        let (mut running_since, mut uptime_secs) = (None, None);
        if power_state.is_on() {
            match vmware.running_since(vmx).await {
                Ok(Some(since)) => {
                    running_since = since.format(&Rfc3339).ok();
                    uptime_secs = u64::try_from((now - since).whole_seconds()).ok();
                }
                Ok(None) => notes.push("Uptime unknown: the VM has no vmware.log".into()),
                Err(err) => notes.push(format!("Uptime unknown: could not read vmware.log: {err}")),
            }
        }

        let (snapshot_count, old_snapshot_count) = self.snapshot_counts(vmx_path, now, &mut notes).await;
        TargetImpact {
            target: vmx_path.to_owned(),
            power_state,
            running_since,
            uptime_secs,
            snapshot_count,
            old_snapshot_count,
            notes,
            container: None,
            linked_clones: Vec::new(),
        }
    }

    /// VM-18: `showvminfo` gives the state and when it began; VirtualBox sees a pause itself.
    async fn one_virtualbox(&self, uuid: &str, now: OffsetDateTime) -> TargetImpact {
        let mut notes = Vec::new();
        let (power_state, since) = match self.hypervisors.virtualbox().vm_info(uuid).await {
            Ok(info) => (info.power_state(), info.running_since()),
            Err(err) => {
                notes.push(format!("VirtualBox could not be asked about the VM: {err}"));
                (PowerState::Unknown, None)
            }
        };
        let (mut running_since, mut uptime_secs) = (None, None);
        if let Some(since) = since {
            running_since = since.format(&Rfc3339).ok();
            uptime_secs = u64::try_from((now - since).whole_seconds()).ok();
        } else if power_state.is_on() {
            notes.push("Uptime unknown: VirtualBox did not say when the VM started".into());
        }
        let (snapshot_count, old_snapshot_count) = self.snapshot_counts(uuid, now, &mut notes).await;
        TargetImpact {
            target: uuid.to_owned(),
            power_state,
            running_since,
            uptime_secs,
            snapshot_count,
            old_snapshot_count,
            notes,
            container: None,
            linked_clones: Vec::new(),
        }
    }

    async fn snapshot_counts(
        &self,
        key: &str,
        now: OffsetDateTime,
        notes: &mut Vec<String>,
    ) -> (Option<usize>, Option<usize>) {
        match self.hypervisors.snapshots(key).await {
            Ok(tree) => {
                let counts = snapshots::counts(&tree, now);
                (Some(counts.total), Some(counts.old))
            }
            Err(err) => {
                notes.push(format!("Could not read the snapshot list: {err}"));
                (None, None)
            }
        }
    }
}
