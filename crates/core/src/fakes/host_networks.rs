//! VM-11, VM-16, VM-25 (R4): the fakes' host networks and the VirtualBox paths the insight and waste finder read.
//!
//! [`VmwareNetworks`] answers `vmrun listHostNetworks`, `listPortForwardings`, `setPortForwarding` and
//! `deletePortForwarding` the way vmrun does (errors included), and can print forwards in a form the parser can't
//! read, so the `vmnetnat.conf` fallback is used. Changing forwards needs [`VmwareNetworks::set_admin`], as on a PC
//! where Remotely isn't elevated. [`VboxNetworks`] answers `list hostonlyifs`, `list --long natnets`, `list
//! systemproperties`, `showvminfo --machinereadable` (adapters, NAT rules, files) and the NAT rule changes, with
//! VirtualBox's own refusals (a name taken or missing, `modifyvm` on a running VM, `controlvm` on one that isn't).
//! Both record each call in their fake's calls as `host <args>`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::{FakeVirtualBox, FakeVmware};
use crate::adapters::host_networks::{
    parse_network_rule, parse_vm_rule, ForwardProtocol, VboxHostOnlyIf, VboxNatNetwork, VboxRule, VboxVmRule, Vmnet,
    VmnetForward, VmnetKind,
};
use crate::domain::PowerState;
use crate::error::{CoreError, Result};
use crate::locks;

/// Workstation's vmnets and NAT forwards in memory.
#[derive(Default)]
pub struct VmwareNetworks {
    vmnets: Mutex<Vec<Vmnet>>,
    forwards: Mutex<HashMap<String, Vec<VmnetForward>>>,
    admin: AtomicBool,
    /// `listPortForwardings` prints lines the parser can't read; `vmnetnat.conf` has the forwards.
    conf_only: AtomicBool,
    default_folder: Mutex<Option<PathBuf>>,
}

fn vmrun_failed(command: &str, message: &str) -> CoreError {
    CoreError::Vmrun {
        command: command.to_owned(),
        message: message.to_owned(),
    }
}

fn kind_text(kind: &VmnetKind) -> &str {
    match kind {
        VmnetKind::HostOnly => "hostOnly",
        VmnetKind::Nat => "nat",
        VmnetKind::Bridged => "bridged",
        VmnetKind::Other(text) => text,
    }
}

impl VmwareNetworks {
    pub(super) fn add_vmnet(&self, vmnet: Vmnet) {
        locks::lock(&self.vmnets).push(vmnet);
    }

    pub(super) fn add_forward(&self, vmnet: &str, forward: VmnetForward) {
        locks::lock(&self.forwards)
            .entry(vmnet.to_owned())
            .or_default()
            .push(forward);
    }

    /// Remotely runs as administrator (or not): Workstation's forwards can be changed.
    pub fn set_admin(&self, admin: bool) {
        self.admin.store(admin, Ordering::SeqCst);
    }

    pub(super) fn set_conf_only(&self, on: bool) {
        self.conf_only.store(on, Ordering::SeqCst);
    }

    pub(super) fn set_default_folder(&self, folder: PathBuf) {
        *locks::lock(&self.default_folder) = Some(folder);
    }

    pub(super) fn default_folder(&self) -> Option<PathBuf> {
        locks::lock(&self.default_folder).clone()
    }

    /// A vmnet's forwards now.
    pub fn forwards(&self, vmnet: &str) -> Vec<VmnetForward> {
        locks::lock(&self.forwards).get(vmnet).cloned().unwrap_or_default()
    }

    pub(super) fn admin(&self) -> bool {
        self.admin.load(Ordering::SeqCst)
    }

    fn vmnet(&self, name: &str) -> Option<Vmnet> {
        locks::lock(&self.vmnets).iter().find(|n| n.name == name).cloned()
    }

    fn nat_vmnet(&self, name: &str, command: &str) -> Result<()> {
        match self.vmnet(name) {
            None => Err(vmrun_failed(command, "Invalid host network")),
            Some(n) if n.kind != VmnetKind::Nat => Err(vmrun_failed(command, "Host network type is not nat")),
            Some(_) => Ok(()),
        }
    }

    /// `vmnetnat.conf` as Workstation writes it, when the forwards are only readable there.
    pub(super) fn nat_conf(&self) -> Option<String> {
        if !self.conf_only.load(Ordering::SeqCst) {
            return None;
        }
        let nat = locks::lock(&self.vmnets).iter().find(|n| n.kind == VmnetKind::Nat).cloned()?;
        let forwards = self.forwards(&nat.name);
        let mut text = format!(
            "# Windows NAT configuration file\n[host]\nip = 203.0.113.2/24\ndevice = {}\n\n[incomingtcp]\n# SSH\n#8889 = 203.0.113.128:22\n",
            nat.name.replace("vmnet", "VMnet")
        );
        for f in forwards.iter().filter(|f| f.protocol == ForwardProtocol::Tcp) {
            text.push_str(&format!("{} = {}:{}\n", f.host_port, f.guest_ip, f.guest_port));
        }
        text.push_str("\n[incomingudp]\n");
        for f in forwards.iter().filter(|f| f.protocol == ForwardProtocol::Udp) {
            text.push_str(&format!("{} = {}:{}\n", f.host_port, f.guest_ip, f.guest_port));
        }
        Some(text)
    }

    /// One vmrun call.
    pub(super) fn vmrun(&self, args: &[String]) -> Result<String> {
        let verb = args.first().map(String::as_str).unwrap_or_default();
        match (verb, &args[1.min(args.len())..]) {
            ("listHostNetworks", _) => {
                let nets = locks::lock(&self.vmnets).clone();
                let mut out = format!(
                    "Total host networks: {}\r\nINDEX  NAME         TYPE         DHCP         SUBNET           MASK\r\n",
                    nets.len()
                );
                for n in nets {
                    out.push_str(&format!(
                        "{:<6} {:<12} {:<12} {:<12} {:<16} {}\r\n",
                        n.index,
                        n.name,
                        kind_text(&n.kind),
                        n.dhcp.unwrap_or(false),
                        n.subnet.as_deref().unwrap_or("empty"),
                        n.mask.as_deref().unwrap_or("empty"),
                    ));
                }
                Ok(out)
            }
            ("listPortForwardings", [vmnet]) => {
                self.nat_vmnet(vmnet, verb)?;
                let forwards = self.forwards(vmnet);
                let mut out = format!("Total port forwardings: {}\r\n", forwards.len());
                for (i, f) in forwards.iter().enumerate() {
                    if self.conf_only.load(Ordering::SeqCst) {
                        out.push_str(&format!("{i}: <unreadable>\r\n"));
                    } else {
                        let description = f.description.as_deref().map(|d| format!(" \"{d}\"")).unwrap_or_default();
                        out.push_str(&format!(
                            "{i}: {} {} -> {}:{}{description}\r\n",
                            f.protocol.as_str(),
                            f.host_port,
                            f.guest_ip,
                            f.guest_port
                        ));
                    }
                }
                Ok(out)
            }
            ("setPortForwarding", [vmnet, protocol, host_port, guest_ip, guest_port, rest @ ..]) => {
                self.nat_vmnet(vmnet, verb)?;
                if !self.admin() {
                    return Err(vmrun_failed(verb, "Insufficient permissions"));
                }
                let forward = VmnetForward {
                    protocol: ForwardProtocol::parse(protocol).ok_or_else(|| vmrun_failed(verb, "Invalid protocol"))?,
                    host_port: host_port.parse().map_err(|_| vmrun_failed(verb, "Invalid port"))?,
                    guest_ip: guest_ip.clone(),
                    guest_port: guest_port.parse().map_err(|_| vmrun_failed(verb, "Invalid port"))?,
                    description: rest.first().cloned(),
                };
                let mut all = locks::lock(&self.forwards);
                let list = all.entry(vmnet.clone()).or_default();
                // "Add or update": the one on that host port is replaced.
                list.retain(|f| !(f.protocol == forward.protocol && f.host_port == forward.host_port));
                list.push(forward);
                Ok(String::new())
            }
            ("deletePortForwarding", [vmnet, protocol, host_port]) => {
                self.nat_vmnet(vmnet, verb)?;
                if !self.admin() {
                    return Err(vmrun_failed(verb, "Insufficient permissions"));
                }
                let protocol = ForwardProtocol::parse(protocol).ok_or_else(|| vmrun_failed(verb, "Invalid protocol"))?;
                let port: u16 = host_port.parse().map_err(|_| vmrun_failed(verb, "Invalid port"))?;
                let mut all = locks::lock(&self.forwards);
                let list = all.entry(vmnet.clone()).or_default();
                let before = list.len();
                list.retain(|f| !(f.protocol == protocol && f.host_port == port));
                if list.len() == before {
                    return Err(vmrun_failed(verb, "Port forwarding not found"));
                }
                Ok(String::new())
            }
            _ => Err(vmrun_failed(verb, "Unknown command")),
        }
    }
}

/// VirtualBox's host networks, NAT rules and VM paths in memory.
#[derive(Default)]
pub struct VboxNetworks {
    host_only: Mutex<Vec<VboxHostOnlyIf>>,
    nat_networks: Mutex<Vec<VboxNatNetwork>>,
    vm_rules: Mutex<HashMap<String, Vec<VboxVmRule>>>,
    machine_folder: Mutex<Option<PathBuf>>,
}

fn vbox_failed(command: &str, message: &str) -> CoreError {
    CoreError::VboxManage {
        command: command.to_owned(),
        message: message.to_owned(),
    }
}

/// A value as `--machinereadable` quotes it: `"` and `\` escaped.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

impl VboxNetworks {
    pub(super) fn add_host_only(&self, iface: VboxHostOnlyIf) {
        locks::lock(&self.host_only).push(iface);
    }

    pub(super) fn add_nat_network(&self, network: VboxNatNetwork) {
        locks::lock(&self.nat_networks).push(network);
    }

    pub(super) fn add_vm_rule(&self, uuid: &str, slot: u32, rule: VboxRule) {
        locks::lock(&self.vm_rules)
            .entry(uuid.to_owned())
            .or_default()
            .push(VboxVmRule { slot, rule });
    }

    pub(super) fn set_machine_folder(&self, folder: PathBuf) {
        *locks::lock(&self.machine_folder) = Some(folder);
    }

    /// A NAT network's rules now.
    pub fn nat_rules(&self, network: &str) -> Vec<VboxRule> {
        locks::lock(&self.nat_networks)
            .iter()
            .find(|n| n.name == network)
            .map(|n| n.forwards.clone())
            .unwrap_or_default()
    }

    /// A VM's NAT rules now.
    pub fn vm_rules(&self, uuid: &str) -> Vec<VboxVmRule> {
        locks::lock(&self.vm_rules).get(uuid).cloned().unwrap_or_default()
    }

    fn change_vm_rules(&self, uuid: &str, slot: u32, args: &[String], command: &str) -> Result<String> {
        let mut all = locks::lock(&self.vm_rules);
        let rules = all.entry(uuid.to_owned()).or_default();
        match args {
            [delete, name] if delete == "delete" => {
                let before = rules.len();
                rules.retain(|r| !(r.slot == slot && &r.rule.name == name));
                if rules.len() == before {
                    return Err(vbox_failed(command, "Code E_INVALIDARG (0x80070057) (extended info not available)"));
                }
            }
            [rule] => {
                let rule = parse_vm_rule(rule).ok_or_else(|| vbox_failed(command, "Invalid NAT rule"))?;
                if rules.iter().any(|r| r.rule.name == rule.name) {
                    return Err(vbox_failed(command, "A NAT rule of this name already exists"));
                }
                rules.push(VboxVmRule { slot, rule });
            }
            _ => return Err(vbox_failed(command, "Invalid arguments")),
        }
        Ok(String::new())
    }

    /// `showvminfo <uuid> --machinereadable`: the files and adapters, each adapter's NAT rules after its keys.
    fn showvminfo(&self, fake: &FakeVirtualBox, uuid: &str) -> Result<String> {
        let vm = fake
            .find(uuid)
            .ok_or_else(|| vbox_failed("showvminfo", &format!("Could not find a registered machine named '{uuid}'")))?;
        let mut out = format!("name={}\nUUID={}\n", quoted(&vm.name), quoted(&vm.uuid));
        let folder = vm.config_file.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        if let Some(cfg) = &vm.config_file {
            out.push_str(&format!("CfgFile={}\n", quoted(&cfg.display().to_string())));
        }
        if let Some(folder) = &folder {
            out.push_str(&format!("SnapFldr={}\n", quoted(&folder.join("Snapshots").display().to_string())));
            out.push_str(&format!("LogFldr={}\n", quoted(&folder.join("Logs").display().to_string())));
        }
        out.push_str(&format!("VMState={}\n", quoted(&vm.state)));
        if vm.power_state() == PowerState::Suspended {
            if let Some(folder) = &folder {
                // VirtualBox prints this one without escapes.
                out.push_str(&format!(
                    "VMStateFile=\"{}\"\n",
                    folder.join("Snapshots").join("saved.sav").display()
                ));
            }
        }
        let rules = self.vm_rules(uuid);
        for nic in &vm.nics {
            let n = nic.slot;
            if nic.attachment == "nat" {
                out.push_str(&format!("natnet{n}=\"nat\"\n"));
            }
            if let Some(mac) = &nic.mac {
                out.push_str(&format!("macaddress{n}=\"{mac}\"\n"));
            }
            out.push_str(&format!("nic{n}=\"{}\"\n", nic.attachment));
            for (i, r) in rules.iter().filter(|r| r.slot == n).enumerate() {
                out.push_str(&format!("Forwarding({i})={}\n", quoted(&r.rule.vm_form())));
            }
        }
        Ok(out)
    }

    /// One VBoxManage call.
    pub(super) fn vboxmanage(&self, fake: &FakeVirtualBox, args: &[String]) -> Result<String> {
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["list", "hostonlyifs"] => Ok(locks::lock(&self.host_only)
                .iter()
                .map(|i| {
                    format!(
                        "Name:            {}\nGUID:            00000000-0000-4000-8000-000000000001\nDHCP:            {}\n\
                         IPAddress:       {}\nNetworkMask:     {}\nStatus:          {}\n\n",
                        i.name,
                        if i.dhcp == Some(true) { "Enabled" } else { "Disabled" },
                        i.ip.as_deref().unwrap_or(""),
                        i.mask.as_deref().unwrap_or(""),
                        i.status.as_deref().unwrap_or("Up"),
                    )
                })
                .collect()),
            ["list", "--long", "natnets"] => Ok(locks::lock(&self.nat_networks)
                .iter()
                .map(|n| {
                    let yes = |b: Option<bool>| if b == Some(true) { "Yes" } else { "No" };
                    let mut block = format!(
                        "Name:         {}\nEnabled:      {}\nNetwork:      {}\nGateway:      {}\nDHCP Server:  {}\nIPv6:         No\n",
                        n.name,
                        yes(n.enabled),
                        n.network.as_deref().unwrap_or(""),
                        n.gateway.as_deref().unwrap_or(""),
                        yes(n.dhcp),
                    );
                    if !n.forwards.is_empty() {
                        block.push_str("Port-forwarding (ipv4)\n");
                        for r in &n.forwards {
                            block.push_str(&format!("        {}\n", r.network_form()));
                        }
                    }
                    block.push_str("loopback mappings (ipv4)\n        127.0.0.1=2\n\n");
                    block
                })
                .collect()),
            ["list", "systemproperties"] => Ok(match &*locks::lock(&self.machine_folder) {
                Some(folder) => format!("API version:  7_2\nDefault machine folder:          {}\n", folder.display()),
                None => "API version:  7_2\nDefault machine folder:\n".to_owned(),
            }),
            ["showvminfo", uuid, "--machinereadable"] => self.showvminfo(fake, uuid),
            ["natnetwork", "modify", "--netname", network, "--port-forward-4", rest @ ..] => {
                let mut nets = locks::lock(&self.nat_networks);
                let Some(net) = nets.iter_mut().find(|n| n.name == *network) else {
                    return Err(vbox_failed("natnetwork", "Failed to find the NAT network"));
                };
                match rest {
                    ["delete", name] => {
                        let before = net.forwards.len();
                        net.forwards.retain(|r| r.name != *name);
                        if net.forwards.len() == before {
                            return Err(vbox_failed("natnetwork", "Failed to delete pf"));
                        }
                    }
                    [rule] => {
                        let rule = parse_network_rule(rule).ok_or_else(|| vbox_failed("natnetwork", "Invalid rule"))?;
                        if net.forwards.iter().any(|r| r.name == rule.name) {
                            return Err(vbox_failed("natnetwork", "A NAT rule of this name already exists"));
                        }
                        net.forwards.push(rule);
                    }
                    _ => return Err(vbox_failed("natnetwork", "Invalid arguments")),
                }
                Ok(String::new())
            }
            ["modifyvm", uuid, natpf, rest @ ..] if natpf.starts_with("--natpf") => {
                let vm = fake.find(uuid).ok_or_else(|| vbox_failed("modifyvm", "Could not find the machine"))?;
                if vm.power_state().is_on() {
                    return Err(vbox_failed(
                        "modifyvm",
                        &format!("The machine '{}' is already locked for a session (or being unlocked)", vm.name),
                    ));
                }
                let slot: u32 = natpf[7..].parse().map_err(|_| vbox_failed("modifyvm", "Invalid adapter"))?;
                let rest: Vec<String> = rest.iter().map(|s| (*s).to_owned()).collect();
                self.change_vm_rules(uuid, slot, &rest, "modifyvm")
            }
            ["controlvm", uuid, natpf, rest @ ..] if natpf.starts_with("natpf") => {
                let vm = fake.find(uuid).ok_or_else(|| vbox_failed("controlvm", "Could not find the machine"))?;
                if !vm.power_state().is_on() {
                    return Err(vbox_failed(
                        "controlvm",
                        &format!("Machine '{}' is not currently running.", vm.name),
                    ));
                }
                let slot: u32 = natpf[5..].parse().map_err(|_| vbox_failed("controlvm", "Invalid adapter"))?;
                let rest: Vec<String> = rest.iter().map(|s| (*s).to_owned()).collect();
                self.change_vm_rules(uuid, slot, &rest, "controlvm")
            }
            _ => Err(vbox_failed(args.first().map_or("", String::as_str), "Unknown subcommand")),
        }
    }
}

impl FakeVmware {
    /// VM-11: a vmnet `vmrun listHostNetworks` lists.
    pub fn with_vmnet(self, index: u32, kind: VmnetKind, subnet: &str) -> Self {
        self.networks.add_vmnet(Vmnet {
            index,
            name: format!("vmnet{index}"),
            kind,
            dhcp: Some(true),
            subnet: Some(subnet.to_owned()),
            mask: Some("255.255.255.0".to_owned()),
        });
        self
    }

    /// VM-11: Workstation's usual networks: vmnet1 host-only on 192.0.2.0/24 and vmnet8 NAT on 203.0.113.0/24.
    pub fn with_default_networks(self) -> Self {
        self.with_vmnet(1, VmnetKind::HostOnly, "192.0.2.0")
            .with_vmnet(8, VmnetKind::Nat, "203.0.113.0")
    }

    /// VM-11: a NAT forward on a vmnet.
    pub fn with_forward(self, vmnet: &str, forward: VmnetForward) -> Self {
        self.networks.add_forward(vmnet, forward);
        self
    }

    /// VM-11: Remotely runs as administrator, so Workstation's forwards can change.
    pub fn as_admin(self) -> Self {
        self.networks.set_admin(true);
        self
    }

    /// VM-11: `listPortForwardings` prints lines Remotely can't read; `vmnetnat.conf` has the forwards.
    pub fn with_forwards_in_conf_only(self) -> Self {
        self.networks.set_conf_only(true);
        self
    }

    /// VM-16: Workstation's default VM folder (`prefvmx.defaultVMPath`).
    pub fn with_default_vm_folder(self, folder: impl Into<PathBuf>) -> Self {
        self.networks.set_default_folder(folder.into());
        self
    }

    /// VM-11: the fake's vmnets and forwards.
    pub fn networks(&self) -> &VmwareNetworks {
        &self.networks
    }

    pub(super) fn vmrun_host_call(&self, args: Vec<OsString>) -> Result<String> {
        self.vmrun()?;
        let args: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let result = self.networks.vmrun(&args);
        if !args.first().is_some_and(|v| v.starts_with("list")) {
            self.record(format!("host {}", args.join(" ")));
        }
        result
    }
}

impl FakeVirtualBox {
    /// VM-11: a host-only interface `list hostonlyifs` lists.
    pub fn with_host_only(self, name: &str, ip: &str) -> Self {
        self.networks.add_host_only(VboxHostOnlyIf {
            name: name.to_owned(),
            ip: Some(ip.to_owned()),
            mask: Some("255.255.255.0".to_owned()),
            dhcp: Some(false),
            status: Some("Up".to_owned()),
        });
        self
    }

    /// VM-11: a NAT network `list --long natnets` lists, on `network` (CIDR).
    pub fn with_nat_network(self, name: &str, network: &str) -> Self {
        self.networks.add_nat_network(VboxNatNetwork {
            name: name.to_owned(),
            enabled: Some(true),
            network: Some(network.to_owned()),
            gateway: None,
            dhcp: Some(true),
            ipv6: Some(false),
            forwards: Vec::new(),
        });
        self
    }

    /// VM-11: a NAT rule on a VM's adapter.
    pub fn with_vm_rule(self, uuid: &str, slot: u32, rule: VboxRule) -> Self {
        self.networks.add_vm_rule(uuid, slot, rule);
        self
    }

    /// VM-16: VirtualBox's default machine folder (`list systemproperties`).
    pub fn with_machine_folder(self, folder: impl Into<PathBuf>) -> Self {
        self.networks.set_machine_folder(folder.into());
        self
    }

    /// VM-11: the fake's host networks and NAT rules.
    pub fn networks(&self) -> &VboxNetworks {
        &self.networks
    }

    pub(super) fn vboxmanage_host_call(&self, args: Vec<String>) -> Result<String> {
        self.installed()?;
        let result = self.networks.vboxmanage(self, &args);
        let reads = matches!(args.first().map(String::as_str), Some("list" | "showvminfo"));
        if !reads {
            self.record(format!("host {}", args.join(" ")));
        }
        result
    }
}
