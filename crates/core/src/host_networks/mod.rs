//! VM-11: the hypervisors' host networks, the VMs on each, and their NAT port forwards.
//!
//! Reads skip the bus ([`HostNetworks::report`]): Workstation's vmnets (`vmrun listHostNetworks`) with a NAT vmnet's
//! forwards (`listPortForwardings`, or `vmnetnat.conf` when its lines can't be read), VirtualBox's host-only
//! interfaces, NAT networks with their rules, and each VM's NAT adapter rules. The VMs on each network come from
//! each VM's network adapters as R3's settings model reads them, through QL-21's read for the topology map
//! ([`HostDetails::vm_networks`]: read now and stored, so the app reads a VM's adapters one way); a VM whose files
//! can't be read now shows with what was read before. [`HostNetworks::networks_only`] is the networks alone, without
//! VMs or forwards: the map's network nodes (QL-21 joins them to its VMs' adapters by network name) and the
//! palette's search.
//!
//! Changes are [`crate::command_bus::Command::HostNetwork`] on the bus (High: a forward reaches every VM on the
//! network), carried out by [`apply`] from the job runner. A network target counts as Prod when a VM on it is
//! labelled Prod (from the stored adapters, so resolving one reads no VM). Workstation's NAT forwards need
//! administrator rights, which Remotely never asks for: a change is refused before it is asked
//! ([`HostNetworks::refusal`]) unless the app itself runs elevated.

pub mod ops;

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::Serialize;

use crate::adapters::host_networks::{
    self as net, ForwardProtocol, VboxHostOnlyIf, VboxNatNetwork, VboxRule, Vmnet, VmnetForward, VmnetKind,
};
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::vm_hardware::{VirtualNic, VmHardware};
use crate::command_bus::Command;
use crate::domain::{now_rfc3339, Context, Environment, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::host_details::HostDetails;
use crate::store::{Store, VmRecord};

pub use ops::{ForwardPlace, HostNetworkOp, NatForward};

/// A list or `showvminfo`.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Adding or removing one forward.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// A VM on a network, as the networks view lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkVm {
    /// The VM's key.
    pub vmx_path: String,
    pub name: String,
    pub power_state: PowerState,
    pub environment: Environment,
    pub protected: bool,
    /// Its adapter on this network: `ethernet0`, `nic2`.
    pub adapter: String,
    /// Its guest's addresses on this network, when known (a forward's guest address).
    pub ips: Vec<String>,
}

/// A Workstation vmnet with its VMs and, for a NAT vmnet, its forwards.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmnetView {
    pub network: Vmnet,
    /// What the bus takes for its forwards.
    pub target: TargetRef,
    pub vms: Vec<NetworkVm>,
    pub forwards: Vec<VmnetForward>,
    /// A NAT vmnet's forwards could not be read.
    pub forwards_problem: Option<String>,
}

/// Workstation's side of the report.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmwareNetworks {
    /// vmrun was found.
    pub available: bool,
    pub problem: Option<String>,
    /// Why forwards can't be changed from this app (not running as administrator).
    pub forwards_refused: Option<String>,
    pub networks: Vec<VmnetView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOnlyView {
    pub iface: VboxHostOnlyIf,
    pub vms: Vec<NetworkVm>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NatNetworkView {
    pub network: VboxNatNetwork,
    pub target: TargetRef,
    pub vms: Vec<NetworkVm>,
}

/// A bridged adapter or internal network VirtualBox VMs are on (nothing to set there here).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherNetworkView {
    /// `bridged` or `intnet`.
    pub kind: String,
    pub name: String,
    pub vms: Vec<NetworkVm>,
}

/// A VirtualBox VM's NAT adapter and its rules.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmNatView {
    /// The VM, with `adapter` naming the NAT adapter (`nic1`).
    pub vm: NetworkVm,
    pub slot: u32,
    pub rules: Vec<VboxRule>,
    pub problem: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualBoxNetworks {
    /// VBoxManage was found.
    pub available: bool,
    pub problem: Option<String>,
    pub host_only: Vec<HostOnlyView>,
    pub nat_networks: Vec<NatNetworkView>,
    pub other: Vec<OtherNetworkView>,
    pub vm_nat: Vec<VmNatView>,
}

/// VM-11: both hypervisors' host networks.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostNetworksReport {
    pub vmware: VmwareNetworks,
    pub virtualbox: VirtualBoxNetworks,
    /// VMs whose adapters could not be read now; what was read before is shown for them.
    pub stale_vms: Vec<String>,
    pub read_at: String,
}

/// A VM and its adapters, as read now or before.
#[derive(Debug, Clone)]
struct VmAdapters {
    vm: VmRecord,
    nics: Vec<VirtualNic>,
    ips: Vec<String>,
    /// Read before, not now.
    stale: bool,
}

/// What network a Workstation adapter is on: `nat` is the NAT vmnet (`vmnet8`), `hostonly` vmnet1, `bridged`
/// vmnet0, `custom (VMnet2)` vmnet2.
pub fn vmnet_of(nic: &VirtualNic, nat_vmnet: &str) -> Option<String> {
    let connection = nic.connection.as_deref()?.to_ascii_lowercase();
    match connection.as_str() {
        "nat" => Some(nat_vmnet.to_owned()),
        "hostonly" => Some("vmnet1".to_owned()),
        "bridged" => Some("vmnet0".to_owned()),
        c if c.starts_with("custom") => nic
            .network_name
            .as_deref()
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| !n.is_empty()),
        _ => None,
    }
}

/// Whether `ip` is in `base`/`mask`.
fn in_subnet(ip: &str, base: &str, mask: &str) -> bool {
    match (
        ip.parse::<Ipv4Addr>(),
        base.parse::<Ipv4Addr>(),
        mask.parse::<Ipv4Addr>(),
    ) {
        (Ok(ip), Ok(base), Ok(mask)) => {
            let mask = u32::from(mask);
            u32::from(ip) & mask == u32::from(base) & mask
        }
        _ => false,
    }
}

fn network_vm(entry: &VmAdapters, adapter: &str, ips: Vec<String>) -> NetworkVm {
    NetworkVm {
        vmx_path: entry.vm.vmx_path.clone(),
        name: entry.vm.display_name.clone(),
        power_state: entry.vm.power_state,
        environment: entry.vm.environment,
        protected: entry.vm.protected,
        adapter: adapter.to_owned(),
        ips,
    }
}

/// The NAT vmnet's name: the first NAT vmnet listed, else vmnet8.
fn nat_vmnet(vmnets: &[Vmnet]) -> String {
    vmnets
        .iter()
        .find(|n| n.kind == VmnetKind::Nat)
        .map_or_else(|| "vmnet8".to_owned(), |n| n.name.clone())
}

/// Workstation's vmnets with their VMs: the listed ones in order, then any a VM is on that the list leaves out
/// (vmnet0, bridged, isn't listed).
fn vmware_views(vmnets: Vec<Vmnet>, vms: &[VmAdapters]) -> Vec<VmnetView> {
    let nat = nat_vmnet(&vmnets);
    let mut views: Vec<VmnetView> = vmnets
        .into_iter()
        .map(|network| VmnetView {
            target: TargetRef::Network {
                hypervisor: Hypervisor::Vmware,
                name: network.name.clone(),
            },
            network,
            vms: Vec::new(),
            forwards: Vec::new(),
            forwards_problem: None,
        })
        .collect();
    for entry in vms.iter().filter(|e| e.vm.hypervisor == Hypervisor::Vmware) {
        for nic in &entry.nics {
            let Some(name) = vmnet_of(nic, &nat) else {
                continue;
            };
            let index = match views.iter().position(|v| v.network.name == name) {
                Some(index) => index,
                None => {
                    let number = name.trim_start_matches("vmnet").parse().unwrap_or(0);
                    views.push(VmnetView {
                        target: TargetRef::Network {
                            hypervisor: Hypervisor::Vmware,
                            name: name.clone(),
                        },
                        network: Vmnet {
                            index: number,
                            name: name.clone(),
                            kind: if number == 0 {
                                VmnetKind::Bridged
                            } else {
                                VmnetKind::Other(String::new())
                            },
                            dhcp: None,
                            subnet: None,
                            mask: None,
                        },
                        vms: Vec::new(),
                        forwards: Vec::new(),
                        forwards_problem: None,
                    });
                    views.len() - 1
                }
            };
            let view = &mut views[index];
            let ips = entry
                .ips
                .iter()
                .filter(|ip| view.network.contains(ip) == Some(true))
                .cloned()
                .collect();
            view.vms.push(network_vm(entry, &nic.slot, ips));
        }
    }
    views.sort_by_key(|v| v.network.index);
    views
}

/// VirtualBox's networks with their VMs.
fn virtualbox_views(
    host_only: Vec<VboxHostOnlyIf>,
    nat_networks: Vec<VboxNatNetwork>,
    vms: &[VmAdapters],
) -> (Vec<HostOnlyView>, Vec<NatNetworkView>, Vec<OtherNetworkView>) {
    let mut host_only: Vec<HostOnlyView> = host_only
        .into_iter()
        .map(|iface| HostOnlyView { iface, vms: Vec::new() })
        .collect();
    let mut nat: Vec<NatNetworkView> = nat_networks
        .into_iter()
        .map(|network| NatNetworkView {
            target: TargetRef::Network {
                hypervisor: Hypervisor::VirtualBox,
                name: network.name.clone(),
            },
            network,
            vms: Vec::new(),
        })
        .collect();
    let mut other: BTreeMap<(String, String), Vec<NetworkVm>> = BTreeMap::new();
    for entry in vms.iter().filter(|e| e.vm.hypervisor == Hypervisor::VirtualBox) {
        for nic in &entry.nics {
            let attachment = nic.connection.as_deref().unwrap_or_default().to_ascii_lowercase();
            let Some(name) = nic.network_name.clone().filter(|n| !n.is_empty()) else {
                continue;
            };
            match attachment.as_str() {
                "hostonly" => {
                    if let Some(view) = host_only.iter_mut().find(|v| v.iface.name.eq_ignore_ascii_case(&name)) {
                        let ips = match (&view.iface.ip, &view.iface.mask) {
                            (Some(base), Some(mask)) => entry
                                .ips
                                .iter()
                                .filter(|ip| in_subnet(ip, base, mask))
                                .cloned()
                                .collect(),
                            _ => Vec::new(),
                        };
                        view.vms.push(network_vm(entry, &nic.slot, ips));
                    } else {
                        other.entry(("hostonly".into(), name)).or_default().push(network_vm(
                            entry,
                            &nic.slot,
                            Vec::new(),
                        ));
                    }
                }
                "natnetwork" => {
                    if let Some(view) = nat.iter_mut().find(|v| v.network.name == name) {
                        let ips = entry
                            .ips
                            .iter()
                            .filter(|ip| view.network.contains(ip) == Some(true))
                            .cloned()
                            .collect();
                        view.vms.push(network_vm(entry, &nic.slot, ips));
                    } else {
                        other.entry(("natnetwork".into(), name)).or_default().push(network_vm(
                            entry,
                            &nic.slot,
                            Vec::new(),
                        ));
                    }
                }
                "bridged" | "intnet" => {
                    other
                        .entry((attachment.clone(), name))
                        .or_default()
                        .push(network_vm(entry, &nic.slot, Vec::new()))
                }
                _ => {}
            }
        }
    }
    let other = other
        .into_iter()
        .map(|((kind, name), vms)| OtherNetworkView { kind, name, vms })
        .collect();
    (host_only, nat, other)
}

/// The adapters a VM's stored facts list.
fn stored_adapters(vm: &VmRecord, specs: Option<&str>) -> Option<VmAdapters> {
    let hardware: VmHardware = serde_json::from_str(specs?).ok()?;
    Some(adapters_of(vm.clone(), hardware.nics, hardware.guest_ips, true))
}

fn adapters_of(vm: VmRecord, nics: Vec<VirtualNic>, mut ips: Vec<String>, stale: bool) -> VmAdapters {
    if let Some(ip) = &vm.ip_address {
        if !ips.contains(ip) {
            ips.push(ip.clone());
        }
    }
    VmAdapters { vm, nics, ips, stale }
}

/// Workstation's lists, read before the VMs' adapters are known.
struct VmwareLists {
    side: VmwareNetworks,
    vmnets: Vec<Vmnet>,
    /// Each NAT vmnet's forwards, and why they could not all be read.
    forwards: BTreeMap<String, (Vec<VmnetForward>, Option<String>)>,
}

impl VmwareLists {
    fn with_vms(self, vms: &[VmAdapters]) -> VmwareNetworks {
        let mut side = self.side;
        if !side.available {
            return side;
        }
        let mut forwards = self.forwards;
        side.networks = vmware_views(self.vmnets, vms);
        for view in side.networks.iter_mut() {
            if let Some((list, problem)) = forwards.remove(&view.network.name) {
                view.forwards = list;
                view.forwards_problem = problem;
            }
        }
        side
    }
}

/// VirtualBox's lists, read before the VMs' adapters are known.
struct VirtualBoxLists {
    side: VirtualBoxNetworks,
    host_only: Vec<VboxHostOnlyIf>,
    nat_networks: Vec<VboxNatNetwork>,
}

/// VM-11: host networks, read on demand; changes through the bus.
#[derive(Clone)]
pub struct HostNetworks {
    store: Store,
    hypervisors: Hypervisors,
    /// QL-21's read of the VMs' adapters.
    details: HostDetails,
}

impl HostNetworks {
    pub fn new(store: Store, hypervisors: Hypervisors, details: HostDetails) -> Self {
        Self {
            store,
            hypervisors,
            details,
        }
    }

    /// VM-11: both hypervisors' networks, the VMs on each and their forwards, read now. A hypervisor that isn't
    /// installed has nothing; one that fails says why, and the other is still read.
    pub async fn report(&self, ctx: &Context) -> Result<HostNetworksReport> {
        // The VMs' adapters and the tools' lists don't depend on each other: read them at once (vmrun alone takes
        // seconds a call).
        let (vms, vmware, virtualbox) = tokio::join!(
            self.read_adapters(ctx),
            self.vmware_lists(true),
            self.virtualbox_lists()
        );
        let vms = vms?;
        let stale_vms = vms
            .iter()
            .filter(|e| e.stale)
            .map(|e| e.vm.display_name.clone())
            .collect();
        Ok(HostNetworksReport {
            vmware: vmware.with_vms(&vms),
            virtualbox: self.virtualbox_side(virtualbox, &vms).await,
            stale_vms,
            read_at: now_rfc3339(),
        })
    }

    /// VM-11, QL-21: the networks alone (`vmrun listHostNetworks` and VBoxManage's two lists), with no VMs on them
    /// and no forwards: no VM's files are read and no VBoxManage runs per VM. The topology map's network nodes, which
    /// it joins to the adapters QL-21 read by network name, and the palette's search.
    pub async fn networks_only(&self) -> HostNetworksReport {
        let (vmware, virtualbox) = tokio::join!(self.vmware_lists(false), self.virtualbox_lists());
        HostNetworksReport {
            vmware: vmware.with_vms(&[]),
            virtualbox: self.virtualbox_side(virtualbox, &[]).await,
            stale_vms: Vec::new(),
            read_at: now_rfc3339(),
        }
    }

    /// Workstation's vmnets and, with `forwards`, each NAT vmnet's forwards.
    async fn vmware_lists(&self, forwards: bool) -> VmwareLists {
        let vmware = self.hypervisors.vmware();
        let listed = vmware
            .vmrun_host(vec!["listHostNetworks".into()], READ_TIMEOUT)
            .await
            .and_then(|out| net::parse_host_networks(&out));
        let mut lists = VmwareLists {
            side: VmwareNetworks {
                available: true,
                forwards_refused: vmware.nat_refusal(),
                ..Default::default()
            },
            vmnets: Vec::new(),
            forwards: BTreeMap::new(),
        };
        match listed {
            Ok(vmnets) => lists.vmnets = vmnets,
            Err(CoreError::VmrunNotFound) => lists.side.available = false,
            Err(err) => lists.side.problem = Some(err.to_string()),
        }
        for vmnet in lists.vmnets.iter().filter(|n| forwards && n.kind == VmnetKind::Nat) {
            let read = vmnet_forwards(&self.hypervisors, &vmnet.name)
                .await
                .unwrap_or_else(|err| (Vec::new(), Some(err.to_string())));
            lists.forwards.insert(vmnet.name.clone(), read);
        }
        lists
    }

    /// VirtualBox's host-only interfaces and NAT networks.
    async fn virtualbox_lists(&self) -> VirtualBoxLists {
        let vbox = self.hypervisors.virtualbox();
        let mut lists = VirtualBoxLists {
            side: VirtualBoxNetworks {
                available: true,
                ..Default::default()
            },
            host_only: Vec::new(),
            nat_networks: Vec::new(),
        };
        match vbox
            .vboxmanage_host(vec!["list".into(), "hostonlyifs".into()], READ_TIMEOUT)
            .await
        {
            Ok(out) => lists.host_only = net::parse_hostonly_ifs(&out),
            Err(CoreError::VboxManageNotFound) => {
                lists.side.available = false;
                return lists;
            }
            Err(err) => lists.side.problem = Some(err.to_string()),
        }
        match vbox
            .vboxmanage_host(vec!["list".into(), "--long".into(), "natnets".into()], READ_TIMEOUT)
            .await
        {
            Ok(out) => lists.nat_networks = net::parse_natnets(&out),
            Err(err) => {
                lists.side.problem.get_or_insert(err.to_string());
            }
        }
        lists
    }

    /// VirtualBox's side: its networks with their VMs, and each VM's NAT adapter rules.
    async fn virtualbox_side(&self, lists: VirtualBoxLists, vms: &[VmAdapters]) -> VirtualBoxNetworks {
        let mut side = lists.side;
        if !side.available {
            return side;
        }
        let (host_only, nat, other) = virtualbox_views(lists.host_only, lists.nat_networks, vms);
        side.host_only = host_only;
        side.nat_networks = nat;
        side.other = other;
        for entry in vms.iter().filter(|e| e.vm.hypervisor == Hypervisor::VirtualBox) {
            let nat_slots: Vec<(u32, &VirtualNic)> = entry
                .nics
                .iter()
                .filter(|n| n.connection.as_deref().is_some_and(|c| c.eq_ignore_ascii_case("nat")))
                .filter_map(|n| Some((n.slot.trim_start_matches("nic").parse().ok()?, n)))
                .collect();
            if nat_slots.is_empty() {
                continue;
            }
            let rules = vm_rules(&self.hypervisors, &entry.vm.vmx_path).await;
            for (slot, nic) in nat_slots {
                let (rules, problem) = match &rules {
                    Ok(all) => (
                        all.iter().filter(|r| r.slot == slot).map(|r| r.rule.clone()).collect(),
                        None,
                    ),
                    Err(err) => (Vec::new(), Some(err.to_string())),
                };
                side.vm_nat.push(VmNatView {
                    vm: network_vm(entry, &nic.slot, Vec::new()),
                    slot,
                    rules,
                    problem,
                });
            }
        }
        side
    }

    /// Every VM's adapters from QL-21's read ([`HostDetails::vm_networks`], fresh: read now, a few at a time, and
    /// stored; what was stored for a VM whose files can't be read now). A VM never read is left out.
    async fn read_adapters(&self, ctx: &Context) -> Result<Vec<VmAdapters>> {
        let read = self.details.vm_networks(ctx, true).await?;
        let mut vms: HashMap<String, VmRecord> = self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| (vm.id.clone(), vm))
            .collect();
        Ok(read
            .into_iter()
            .filter(|n| n.collected_at.is_some())
            .filter_map(|n| {
                let vm = vms.remove(&n.vm_id)?;
                Some(adapters_of(vm, n.nics, n.guest_ips, n.problem.is_some()))
            })
            .collect())
    }

    /// Every VM's adapters as last stored (resolving a network target reads no VM). FD-02: the workspace's VMs,
    /// or with `everywhere` every workspace's (a network is this PC's: a change there reaches all of them).
    async fn stored(&self, ctx: &Context, everywhere: bool) -> Result<Vec<VmAdapters>> {
        let workspaces = if everywhere {
            self.store
                .list_workspaces(ctx.user_id)
                .await?
                .into_iter()
                .map(|w| Context {
                    workspace_id: w.id,
                    user_id: ctx.user_id,
                })
                .collect()
        } else {
            vec![*ctx]
        };
        let mut out = Vec::new();
        for ws in &workspaces {
            for vm in self.store.list_vms(ws).await? {
                let stored = self.store.vm_specs(ws, &vm.id).await?;
                if let Some(entry) = stored_adapters(&vm, stored.as_ref().map(|s| s.specs.as_str())) {
                    out.push(entry);
                }
            }
        }
        Ok(out)
    }

    /// The VMs on a network target, from the stored adapters (FD-02: every workspace's with `everywhere`).
    async fn vms_on(
        &self,
        ctx: &Context,
        hypervisor: Hypervisor,
        name: &str,
        everywhere: bool,
    ) -> Result<Vec<NetworkVm>> {
        let vms = self.stored(ctx, everywhere).await?;
        Ok(match hypervisor {
            Hypervisor::Vmware => {
                // Which vmnet `nat` adapters are on: the listed NAT vmnet, else vmnet8.
                let listed = self
                    .hypervisors
                    .vmware()
                    .vmrun_host(vec!["listHostNetworks".into()], READ_TIMEOUT)
                    .await
                    .and_then(|out| net::parse_host_networks(&out))
                    .unwrap_or_default();
                let nat = nat_vmnet(&listed);
                let mut on = Vec::new();
                for entry in vms.iter().filter(|e| e.vm.hypervisor == Hypervisor::Vmware) {
                    for nic in &entry.nics {
                        if vmnet_of(nic, &nat).is_some_and(|n| n.eq_ignore_ascii_case(name)) {
                            on.push(network_vm(entry, &nic.slot, entry.ips.clone()));
                        }
                    }
                }
                on
            }
            Hypervisor::VirtualBox => {
                let mut on = Vec::new();
                for entry in vms.iter().filter(|e| e.vm.hypervisor == Hypervisor::VirtualBox) {
                    for nic in &entry.nics {
                        let natnet = nic
                            .connection
                            .as_deref()
                            .is_some_and(|c| c.eq_ignore_ascii_case("natnetwork"));
                        if natnet && nic.network_name.as_deref() == Some(name) {
                            on.push(network_vm(entry, &nic.slot, entry.ips.clone()));
                        }
                    }
                }
                on
            }
        })
    }

    /// VM-11: a network target for the policy engine: Prod when a VM on it is labelled Prod (AP-01, the Prod rule).
    /// FD-02: a VM of any workspace counts (none is named): the change reaches every VM on the network.
    pub async fn target(&self, ctx: &Context, target: &TargetRef) -> Result<Target> {
        let TargetRef::Network { hypervisor, name } = target else {
            return Err(CoreError::UnknownTarget(target.key()));
        };
        let vms = self.vms_on(ctx, *hypervisor, name, true).await?;
        let prod = vms.iter().any(|v| v.environment == Environment::Prod);
        let label = match hypervisor {
            Hypervisor::Vmware => format!("{name} (Workstation)"),
            Hypervisor::VirtualBox => format!("NAT network {name} (VirtualBox)"),
        };
        Ok(Target {
            target: target.clone(),
            name: label,
            environment: if prod { Environment::Prod } else { Environment::None },
            protected: false,
        })
    }

    /// VM-11: why the command can't run on this PC at all, before anything is asked: Workstation's forwards need
    /// administrator rights.
    pub fn refusal(&self, command: &Command) -> Option<String> {
        let Command::HostNetwork { targets, op } = command else {
            return None;
        };
        match ops::place(targets, op.forward()).ok()? {
            ForwardPlace::Vmnet(_) => self.hypervisors.vmware().nat_refusal(),
            _ => None,
        }
    }

    /// VM-11: what the approval says about a forward: who can reach it, which VM the guest address is, and the
    /// VMs on the network.
    pub async fn warnings(&self, ctx: &Context, command: &Command) -> Vec<String> {
        let Command::HostNetwork { targets, op } = command else {
            return Vec::new();
        };
        let forward = op.forward();
        let Ok(place) = ops::place(targets, forward) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let adding = matches!(op, HostNetworkOp::AddForward { .. });
        let every_address = match place {
            ForwardPlace::Vmnet(_) => true,
            _ => forward
                .host_ip
                .as_deref()
                .is_none_or(|ip| !ip.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())),
        };
        if adding && every_address {
            let target = format!(
                "{}:{}",
                forward.guest_ip.as_deref().unwrap_or("the guest"),
                forward.guest_port
            );
            let who = if matches!(place, ForwardPlace::Vmnet(_)) {
                "Workstation listens on every address of this PC"
            } else if forward.host_ip.is_none() {
                "It listens on every address of this PC"
            } else {
                "It listens on a network address of this PC"
            };
            out.push(format!(
                "{who}, so other computers that can reach this PC on {} port {} reach {target} through it",
                forward.protocol.as_str(),
                forward.host_port
            ));
        }
        if !adding {
            out.push(format!("Connections through {} stop", forward.describe()));
        }
        let (hypervisor, name) = match place {
            ForwardPlace::Vmnet(name) => (Hypervisor::Vmware, name),
            ForwardPlace::NatNetwork(name) => (Hypervisor::VirtualBox, name),
            ForwardPlace::VboxVm(..) => return out,
        };
        let vms = match self.vms_on(ctx, hypervisor, name, true).await {
            Ok(vms) => vms,
            Err(err) => {
                tracing::debug!(error = %err, "could not read the VMs on a network for an approval");
                return out;
            }
        };
        // FD-02: the workspace's own VMs are named; the others on the network are only counted.
        let mine: std::collections::HashSet<String> = match self.store.list_vms(ctx).await {
            Ok(list) => list.into_iter().map(|vm| vm.vmx_path.to_lowercase()).collect(),
            Err(_) => std::collections::HashSet::new(),
        };
        let is_mine = |vm: &NetworkVm| mine.contains(&vm.vmx_path.to_lowercase());
        if let Some(ip) = forward.guest_ip.as_deref() {
            let owner = vms.iter().find(|v| v.ips.iter().any(|i| i == ip));
            out.push(match owner {
                Some(vm) if is_mine(vm) => format!("{ip} is {}'s address on {name}", vm.name),
                Some(_) => format!("{ip} is the address of a VM outside this workspace on {name}"),
                None => format!("No VM Remotely knows on {name} has the address {ip}"),
            });
        }
        let mut names: Vec<&str> = vms.iter().filter(|v| is_mine(v)).map(|v| v.name.as_str()).collect();
        names.dedup();
        let mut others: Vec<&str> = vms
            .iter()
            .filter(|v| !is_mine(v))
            .map(|v| v.vmx_path.as_str())
            .collect();
        others.sort_unstable();
        others.dedup();
        if !names.is_empty() || !others.is_empty() {
            let shown: Vec<&str> = names.iter().take(8).copied().collect();
            let more = names.len().saturating_sub(shown.len());
            let mut list = if more > 0 {
                format!("{}, and {more} more", shown.join(", "))
            } else {
                shown.join(", ")
            };
            match (others.len(), list.is_empty()) {
                (0, _) => {}
                (n, true) => list = format!("{n} outside this workspace"),
                (n, false) => list = format!("{list}; and {n} outside this workspace"),
            }
            out.push(format!("VMs on {name}: {list}"));
        }
        out
    }
}

/// A NAT vmnet's forwards: `listPortForwardings`, or `vmnetnat.conf` when some of its lines can't be read. The
/// second value says when neither could be read in full.
async fn vmnet_forwards(hypervisors: &Hypervisors, vmnet: &str) -> Result<(Vec<VmnetForward>, Option<String>)> {
    let vmware = hypervisors.vmware();
    let out = vmware
        .vmrun_host(vec!["listPortForwardings".into(), vmnet.into()], READ_TIMEOUT)
        .await?;
    let (total, forwards) = net::parse_port_forwardings(&out)?;
    if forwards.len() >= total {
        return Ok((forwards, None));
    }
    match vmware.nat_conf().await {
        Ok(Some(text)) => {
            let (device, from_conf) = net::parse_nat_conf(&text);
            if device.as_deref().is_none_or(|d| d.eq_ignore_ascii_case(vmnet)) && from_conf.len() >= total {
                return Ok((from_conf, None));
            }
            Ok((
                forwards,
                Some(format!(
                    "vmrun listed {total} forwards and Remotely could read {}; {} doesn't list them all either",
                    from_conf.len().min(total),
                    net::VMNET_NAT_CONF
                )),
            ))
        }
        Ok(None) | Err(_) => Ok((
            forwards,
            Some(format!(
                "vmrun listed {total} forwards in a form Remotely could only partly read"
            )),
        )),
    }
}

/// A VirtualBox VM's NAT rules, by adapter.
async fn vm_rules(hypervisors: &Hypervisors, uuid: &str) -> Result<Vec<net::VboxVmRule>> {
    let pairs = net::showvminfo_pairs(hypervisors.virtualbox().as_ref(), uuid, READ_TIMEOUT).await?;
    Ok(net::vm_rules(&pairs))
}

fn refused(message: String) -> CoreError {
    CoreError::HostNetworkRefused(message)
}

fn same_port(a: &VmnetForward, protocol: ForwardProtocol, port: u16) -> bool {
    a.protocol == protocol && a.host_port == port
}

/// VM-11: adds or removes the forward. Only the job runner calls this, after the bus. Each change is checked
/// against what the hypervisor lists now: a Workstation forward on a host port in use would replace the one
/// there, so it is refused; a removal must find the forward the approval named.
pub(crate) async fn apply(hypervisors: &Hypervisors, targets: &[TargetRef], op: &HostNetworkOp) -> Result<String> {
    let forward = op.forward();
    let adding = matches!(op, HostNetworkOp::AddForward { .. });
    let verb = if adding { "added" } else { "removed" };
    match ops::place(targets, forward)? {
        ForwardPlace::Vmnet(vmnet) => {
            let vmware = hypervisors.vmware();
            if let Some(why) = vmware.nat_refusal() {
                return Err(refused(why));
            }
            let out = vmware.vmrun_host(vec!["listHostNetworks".into()], READ_TIMEOUT).await?;
            let listed = net::parse_host_networks(&out)?;
            let Some(network) = listed.iter().find(|n| n.name.eq_ignore_ascii_case(vmnet)) else {
                return Err(refused(format!(
                    "{vmnet} is not one of Workstation's networks any more"
                )));
            };
            if network.kind != VmnetKind::Nat {
                return Err(refused(format!(
                    "{vmnet} is not a NAT network, and port forwards are for NAT networks"
                )));
            }
            let (current, _) = vmnet_forwards(hypervisors, &network.name).await?;
            let wanted = forward.vmnet();
            let there = current.iter().find(|f| same_port(f, wanted.protocol, wanted.host_port));
            let args = if adding {
                if let Some(there) = there {
                    return Err(refused(format!(
                        "{} port {} on {vmnet} already goes to {}:{}; remove that forward first",
                        wanted.protocol.as_str(),
                        wanted.host_port,
                        there.guest_ip,
                        there.guest_port
                    )));
                }
                net::set_forward_args(&network.name, &wanted)
            } else {
                if there.is_none() {
                    return Err(refused(format!(
                        "{vmnet} has no forward on {} port {} any more",
                        wanted.protocol.as_str(),
                        wanted.host_port
                    )));
                }
                net::delete_forward_args(&network.name, wanted.protocol, wanted.host_port)
            };
            vmware.vmrun_host(args, CHANGE_TIMEOUT).await?;
            Ok(format!("{verb} {} on {vmnet}", forward.describe()))
        }
        ForwardPlace::NatNetwork(name) => {
            let vbox = hypervisors.virtualbox();
            let out = vbox
                .vboxmanage_host(vec!["list".into(), "--long".into(), "natnets".into()], READ_TIMEOUT)
                .await?;
            let Some(network) = net::parse_natnets(&out).into_iter().find(|n| n.name == name) else {
                return Err(refused(format!("VirtualBox has no NAT network '{name}' any more")));
            };
            let rule = forward.vbox();
            let taken = network.forwards.iter().find(|r| r.name == rule.name);
            if adding {
                if taken.is_some() {
                    return Err(refused(format!("'{name}' already has a rule named '{}'", rule.name)));
                }
                if let Some(other) = network
                    .forwards
                    .iter()
                    .find(|r| r.protocol == rule.protocol && r.host_port == rule.host_port && r.host_ip == rule.host_ip)
                {
                    return Err(refused(format!(
                        "the rule '{}' on '{name}' already listens on {} port {}",
                        other.name,
                        rule.protocol.as_str(),
                        rule.host_port
                    )));
                }
            } else if taken.is_none() {
                return Err(refused(format!("'{name}' has no rule named '{}' any more", rule.name)));
            }
            vbox.vboxmanage_host(net::natnet_rule_args(name, &rule, !adding), CHANGE_TIMEOUT)
                .await?;
            Ok(format!("{verb} {} on the NAT network '{name}'", forward.describe()))
        }
        ForwardPlace::VboxVm(uuid, slot) => {
            let vbox = hypervisors.virtualbox();
            let info = vbox.vm_info(uuid).await?;
            let nat = info
                .nics
                .iter()
                .any(|n| n.slot == slot && n.attachment.eq_ignore_ascii_case("nat"));
            if !nat {
                return Err(refused(format!(
                    "adapter {slot} of {} is not attached to NAT, so it has no port forwarding rules",
                    info.name
                )));
            }
            let state = info.power_state();
            if state == PowerState::Suspended {
                return Err(refused(format!(
                    "VirtualBox doesn't change a suspended VM's settings: start {} or discard its saved state first",
                    info.name
                )));
            }
            let rule = forward.vbox();
            let rules = vm_rules(hypervisors, uuid).await?;
            let mine: Vec<&VboxRule> = rules.iter().filter(|r| r.slot == slot).map(|r| &r.rule).collect();
            let taken = rules.iter().any(|r| r.rule.name == rule.name);
            if adding {
                if taken {
                    return Err(refused(format!(
                        "{} already has a NAT rule named '{}'",
                        info.name, rule.name
                    )));
                }
                if let Some(other) = mine
                    .iter()
                    .find(|r| r.protocol == rule.protocol && r.host_port == rule.host_port && r.host_ip == rule.host_ip)
                {
                    return Err(refused(format!(
                        "the rule '{}' of {} already listens on {} port {}",
                        other.name,
                        info.name,
                        rule.protocol.as_str(),
                        rule.host_port
                    )));
                }
            } else if !mine.iter().any(|r| r.name == rule.name) {
                return Err(refused(format!(
                    "adapter {slot} of {} has no rule named '{}' any more",
                    info.name, rule.name
                )));
            }
            let args = net::vm_rule_args(uuid, slot, &rule, state.is_on(), !adding);
            vbox.vboxmanage_host(args, CHANGE_TIMEOUT).await?;
            let how = if state.is_on() { " (applied while it runs)" } else { "" };
            Ok(format!(
                "{verb} {} on {}'s NAT adapter {slot}{how}",
                forward.describe(),
                info.name
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(slot: &str, connection: &str, name: Option<&str>) -> VirtualNic {
        VirtualNic {
            slot: slot.into(),
            connection: Some(connection.into()),
            network_name: name.map(String::from),
            ..Default::default()
        }
    }

    fn vm(name: &str, hypervisor: Hypervisor, nics: Vec<VirtualNic>, ips: &[&str]) -> VmAdapters {
        VmAdapters {
            vm: VmRecord {
                id: name.into(),
                vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
                hypervisor,
                config_path: None,
                display_name: name.into(),
                guest_os: None,
                guest_os_name: None,
                num_vcpus: None,
                memsize_mb: None,
                power_state: PowerState::Running,
                ip_address: None,
                tools_state: None,
                environment: Environment::None,
                protected: false,
                tags: vec![],
                last_seen_at: None,
            },
            nics,
            ips: ips.iter().map(|s| (*s).to_owned()).collect(),
            stale: false,
        }
    }

    fn vmnet(index: u32, kind: VmnetKind, subnet: &str) -> Vmnet {
        Vmnet {
            index,
            name: format!("vmnet{index}"),
            kind,
            dhcp: Some(true),
            subnet: Some(subnet.into()),
            mask: Some("255.255.255.0".into()),
        }
    }

    #[test]
    fn workstation_adapters_map_to_their_vmnets() {
        assert_eq!(
            vmnet_of(&nic("ethernet0", "nat", None), "vmnet8").as_deref(),
            Some("vmnet8")
        );
        assert_eq!(
            vmnet_of(&nic("ethernet0", "hostonly", None), "vmnet8").as_deref(),
            Some("vmnet1")
        );
        assert_eq!(
            vmnet_of(&nic("ethernet0", "bridged", None), "vmnet8").as_deref(),
            Some("vmnet0")
        );
        assert_eq!(
            vmnet_of(&nic("ethernet1", "custom (VMnet2)", Some("VMnet2")), "vmnet8").as_deref(),
            Some("vmnet2")
        );
        assert_eq!(vmnet_of(&nic("ethernet1", "custom", None), "vmnet8"), None);
        assert_eq!(vmnet_of(&nic("ethernet1", "pvn", None), "vmnet8"), None);
    }

    #[test]
    fn vmware_views_put_each_vm_on_its_networks_with_the_addresses_there() {
        let vms = vec![
            vm(
                "web01",
                Hypervisor::Vmware,
                vec![nic("ethernet0", "nat", None), nic("ethernet1", "bridged", None)],
                &["203.0.113.10", "192.0.2.50"],
            ),
            vm(
                "db01",
                Hypervisor::Vmware,
                vec![nic("ethernet0", "custom (VMnet2)", Some("VMnet2"))],
                &[],
            ),
            vm("vbox01", Hypervisor::VirtualBox, vec![nic("nic1", "nat", None)], &[]),
        ];
        let views = vmware_views(
            vec![
                vmnet(1, VmnetKind::HostOnly, "198.51.100.0"),
                vmnet(8, VmnetKind::Nat, "203.0.113.0"),
            ],
            &vms,
        );
        let names: Vec<&str> = views.iter().map(|v| v.network.name.as_str()).collect();
        assert_eq!(
            names,
            ["vmnet0", "vmnet1", "vmnet2", "vmnet8"],
            "unlisted vmnets a VM is on are added"
        );
        let nat = views.iter().find(|v| v.network.name == "vmnet8").unwrap();
        assert_eq!(nat.vms.len(), 1);
        assert_eq!(nat.vms[0].ips, ["203.0.113.10"], "only the address in vmnet8's subnet");
        assert_eq!(views[0].network.kind, VmnetKind::Bridged);
        assert!(views[1].vms.is_empty());
        assert_eq!(views[2].vms[0].name, "db01");
    }

    #[test]
    fn virtualbox_views_match_adapters_by_network_name() {
        let vms = vec![
            vm(
                "lab01",
                Hypervisor::VirtualBox,
                vec![
                    nic("nic1", "natnetwork", Some("lab-net")),
                    nic("nic2", "hostonly", Some("VirtualBox Host-Only Ethernet Adapter")),
                    nic("nic3", "intnet", Some("backend")),
                    nic("nic4", "nat", None),
                ],
                &["198.51.100.5", "192.0.2.20"],
            ),
            vm(
                "lab02",
                Hypervisor::VirtualBox,
                vec![nic("nic1", "natnetwork", Some("gone-net"))],
                &[],
            ),
        ];
        let (host_only, nat, other) = virtualbox_views(
            vec![VboxHostOnlyIf {
                name: "VirtualBox Host-Only Ethernet Adapter".into(),
                ip: Some("192.0.2.1".into()),
                mask: Some("255.255.255.0".into()),
                ..Default::default()
            }],
            vec![VboxNatNetwork {
                name: "lab-net".into(),
                network: Some("198.51.100.0/24".into()),
                ..Default::default()
            }],
            &vms,
        );
        assert_eq!(host_only[0].vms[0].ips, ["192.0.2.20"]);
        assert_eq!(nat[0].vms[0].ips, ["198.51.100.5"]);
        assert_eq!(nat[0].vms[0].adapter, "nic1");
        let kinds: Vec<(&str, &str)> = other.iter().map(|o| (o.kind.as_str(), o.name.as_str())).collect();
        assert_eq!(kinds, [("intnet", "backend"), ("natnetwork", "gone-net")]);
    }

    #[test]
    fn subnets_compare_by_mask() {
        assert!(in_subnet("192.0.2.200", "192.0.2.0", "255.255.255.0"));
        assert!(!in_subnet("192.0.3.1", "192.0.2.0", "255.255.255.0"));
        assert!(!in_subnet("not an ip", "192.0.2.0", "255.255.255.0"));
    }
}
