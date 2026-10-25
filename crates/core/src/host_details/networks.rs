//! QL-21: each VM's network adapters for the topology map, from R3's settings model ([`VirtualNic`]: the
//! connection and the network's name). Reads only, like the rest of host details.
//!
//! What was read before (stored with the VM's hardware, MO-13) is used as it is, so opening the map reads no
//! file and starts no VBoxManage for a VM whose hardware is known; only a VM never read before is read now. A
//! Refresh (`fresh`) reads every VM again, a few at a time, each with the hardware read's time limit, and keeps
//! what was read before for a VM whose files can't be read. R4's host networks join the map on the UI side,
//! keyed by the same network names.

use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::HostDetails;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::{VirtualNic, VmHardware};
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};

/// VMs read at once on a Refresh.
pub const NETWORK_READS_AT_ONCE: usize = 4;

/// One VM's adapters.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmNetworks {
    pub vm_id: String,
    /// The VM's key (`TargetRef::Vm`).
    pub vmx_path: String,
    pub hypervisor: Hypervisor,
    pub nics: Vec<VirtualNic>,
    /// When they were read; None when they never could be.
    pub collected_at: Option<String>,
    /// What was read before: the files could not be read now, or nothing asked for a fresh read.
    pub stored: bool,
    /// Why the files could not be read now.
    pub problem: Option<String>,
}

impl HostDetails {
    /// QL-21: the network adapters of every VM in the inventory (see the module docs).
    pub async fn vm_networks(&self, ctx: &Context, fresh: bool) -> Result<Vec<VmNetworks>> {
        let store = &self.inner.store;
        let vms = store.list_vms(ctx).await?;
        let mut stored = store.all_vm_specs(ctx).await?;
        let mut out = Vec::with_capacity(vms.len());
        let mut reads = JoinSet::new();
        let at_once = Arc::new(Semaphore::new(NETWORK_READS_AT_ONCE));
        let timeout = self.inner.collector.tuning().vm_timeout;
        for (index, vm) in vms.iter().enumerate() {
            let known = stored
                .remove(&vm.id)
                .and_then(|s| Some((serde_json::from_str::<VmHardware>(&s.specs).ok()?, s.collected_at)));
            out.push(VmNetworks {
                vm_id: vm.id.clone(),
                vmx_path: vm.vmx_path.clone(),
                hypervisor: vm.hypervisor,
                nics: known.as_ref().map(|(h, _)| h.nics.clone()).unwrap_or_default(),
                collected_at: known.as_ref().map(|(_, at)| at.clone()),
                stored: known.is_some(),
                problem: None,
            });
            if known.is_some() && !fresh {
                continue;
            }
            let hypervisors = self.inner.hypervisors.clone();
            let at_once = Arc::clone(&at_once);
            let (key, name) = (vm.vmx_path.clone(), vm.display_name.clone());
            reads.spawn(async move {
                let _turn = at_once.acquire_owned().await;
                let read = tokio::time::timeout(timeout, hypervisors.hardware(&key))
                    .await
                    .unwrap_or_else(|_| {
                        Err(CoreError::Timeout {
                            command: format!("reading {name}'s hardware"),
                            seconds: timeout.as_secs(),
                        })
                    });
                (index, read)
            });
        }
        while let Some(done) = reads.join_next().await {
            let Ok((index, read)) = done else { continue };
            let Some(entry) = out.get_mut(index) else { continue };
            match read {
                Ok(hardware) => {
                    let at = now_rfc3339();
                    // Kept like the details panel keeps it, so the map and the System tab agree.
                    if let Ok(json) = serde_json::to_string(&hardware) {
                        store.put_vm_specs(ctx, &entry.vm_id, &json, &at).await?;
                    }
                    entry.nics = hardware.nics;
                    entry.collected_at = Some(at);
                    entry.stored = false;
                }
                Err(err) => entry.problem = Some(err.to_string()),
            }
        }
        Ok(out)
    }
}
