//! Impact preview (AP-02): what each VM target looks like right now, shown in the approval dialog.
//!
//! Reads only, and none needs a guest login: `vmrun list` for the power state (the .vmx tells a
//! suspended VM from one that is off), the first line of the VM's `vmware.log` for how long it has
//! been running, and its .vmsd for the snapshot count. A VirtualBox VM (VM-18) answers all three
//! through `showvminfo` (its state, when that state began, its snapshots) and its .vbox file (snapshot
//! times). Users logged in to the guest need a guest login, and dependent VMs need lab blueprints
//! (VM-08, v2); neither is shown yet.

use std::path::Path;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::adapters::hypervisor::{Hypervisor, Hypervisors, RunningVms};
use crate::domain::{Context, PowerState, Target, TargetRef};
use crate::snapshots;
use crate::store::Store;

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
}

pub struct ImpactPreviewer {
    store: Store,
    hypervisors: Hypervisors,
}

impl ImpactPreviewer {
    pub fn new(store: Store, hypervisors: Hypervisors) -> Self {
        Self { store, hypervisors }
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
