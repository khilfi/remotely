//! VM-11: the hypervisors' host networks and NAT port forwards, as their tools print them.
//!
//! Workstation: `vmrun -T ws listHostNetworks` lists the vmnets (index, name, type, DHCP, subnet, mask);
//! `listPortForwardings <vmnet>` a NAT vmnet's forwards; `setPortForwarding <vmnet> <tcp|udp> <host port>
//! <guest ip> <guest port> [description]` adds one, or replaces the one on that host port, and
//! `deletePortForwarding <vmnet> <tcp|udp> <host port>` removes one. Workstation keeps them in
//! `C:\ProgramData\VMware\vmnetnat.conf` (`[incomingtcp]`, `[incomingudp]`: `<host port> = <guest ip>:<guest
//! port>`), which only administrators can change and everyone can read. On Windows it has one NAT network
//! (`[host] device = VMnet8`). Remotely never runs as administrator, so it changes them only when the app
//! itself was started elevated ([`process_elevated`]).
//!
//! VirtualBox: `list hostonlyifs` (blocks of `Key: value`; `list hostonlynets` is macOS only), `list --long
//! natnets` (each NAT network with its `Port-forwarding (ipv4)` rules, `name:proto:[host ip]:host
//! port:[guest ip]:guest port`), a VM's NAT rules in `showvminfo --machinereadable` (`Forwarding(N)="name,proto,
//! host ip,host port,guest ip,guest port"` after the keys of the adapter they belong to: the key doesn't name
//! the adapter), `natnetwork modify --netname <n> --port-forward-4 <rule>` and `... --port-forward-4 delete
//! <name>`, `modifyvm <uuid> --natpfN <rule>` (VM off) and `controlvm <uuid> natpfN <rule>` (running; kept
//! after power-off), with `delete <name>` to remove. A rule name that is taken, or missing on delete, is an
//! error. None of these need administrator rights.
//!
//! Everything here is pure: parsers and argument builders. [`crate::host_networks`] runs them through the
//! adapters.

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// Workstation's NAT settings, readable by every user.
pub const VMNET_NAT_CONF: &str = r"C:\ProgramData\VMware\vmnetnat.conf";
/// A9: the NAT settings file is a few KB; a larger one is not read.
pub const MAX_NAT_CONF_BYTES: u64 = 256 * 1024;
/// The longest description or rule name Remotely writes.
pub const MAX_RULE_NAME: usize = 64;

/// TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    Tcp,
    Udp,
}

impl ForwardProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardProtocol::Tcp => "tcp",
            ForwardProtocol::Udp => "udp",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(ForwardProtocol::Tcp),
            "udp" => Some(ForwardProtocol::Udp),
            _ => None,
        }
    }
}

/// What kind of vmnet: Workstation's `TYPE` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VmnetKind {
    HostOnly,
    Nat,
    Bridged,
    /// A type this version doesn't know, as printed.
    Other(String),
}

impl VmnetKind {
    fn parse(text: &str) -> Self {
        match text.to_ascii_lowercase().as_str() {
            "hostonly" => VmnetKind::HostOnly,
            "nat" => VmnetKind::Nat,
            "bridged" => VmnetKind::Bridged,
            _ => VmnetKind::Other(text.to_owned()),
        }
    }
}

/// One of Workstation's virtual networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vmnet {
    /// 1 for vmnet1.
    pub index: u32,
    /// `vmnet8`, lower case as vmrun prints it.
    pub name: String,
    pub kind: VmnetKind,
    pub dhcp: Option<bool>,
    pub subnet: Option<String>,
    pub mask: Option<String>,
}

impl Vmnet {
    /// Whether `ip` is in the vmnet's subnet, when both are known.
    pub fn contains(&self, ip: &str) -> Option<bool> {
        let subnet: Ipv4Addr = self.subnet.as_deref()?.parse().ok()?;
        let mask: Ipv4Addr = self.mask.as_deref()?.parse().ok()?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let mask = u32::from(mask);
        Some(u32::from(ip) & mask == u32::from(subnet) & mask)
    }
}

/// A Workstation NAT port forward: connections to this PC's `host_port` (on every address) go to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmnetForward {
    pub protocol: ForwardProtocol,
    pub host_port: u16,
    pub guest_ip: String,
    pub guest_port: u16,
    pub description: Option<String>,
}

/// A VirtualBox host-only interface (`list hostonlyifs`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VboxHostOnlyIf {
    /// What `--hostonlyadapterN` names, e.g. "VirtualBox Host-Only Ethernet Adapter".
    pub name: String,
    pub ip: Option<String>,
    pub mask: Option<String>,
    pub dhcp: Option<bool>,
    /// `Up` or `Down`.
    pub status: Option<String>,
}

/// A VirtualBox port forwarding rule: a NAT network's (`--port-forward-4`) or a VM's NAT adapter's (`--natpfN`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VboxRule {
    pub name: String,
    pub protocol: ForwardProtocol,
    /// `None`: every address of this PC.
    pub host_ip: Option<String>,
    pub host_port: u16,
    /// `None` (a VM's rule only): the address the guest got from VirtualBox's DHCP.
    pub guest_ip: Option<String>,
    pub guest_port: u16,
}

impl VboxRule {
    /// `name,tcp,127.0.0.1,8080,,80`: what `--natpfN` takes.
    pub fn vm_form(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.name,
            self.protocol.as_str(),
            self.host_ip.as_deref().unwrap_or(""),
            self.host_port,
            self.guest_ip.as_deref().unwrap_or(""),
            self.guest_port
        )
    }

    /// `name:tcp:[127.0.0.1]:8080:[10.0.2.4]:80`: what `--port-forward-4` takes.
    pub fn network_form(&self) -> String {
        format!(
            "{}:{}:[{}]:{}:[{}]:{}",
            self.name,
            self.protocol.as_str(),
            self.host_ip.as_deref().unwrap_or(""),
            self.host_port,
            self.guest_ip.as_deref().unwrap_or(""),
            self.guest_port
        )
    }
}

/// A VirtualBox NAT network (`list --long natnets`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VboxNatNetwork {
    pub name: String,
    pub enabled: Option<bool>,
    /// `10.0.2.0/24`.
    pub network: Option<String>,
    pub gateway: Option<String>,
    pub dhcp: Option<bool>,
    pub ipv6: Option<bool>,
    /// IPv4 port forwarding rules. IPv6 rules are left out.
    pub forwards: Vec<VboxRule>,
}

impl VboxNatNetwork {
    /// Whether `ip` is in the network's CIDR, when both are known.
    pub fn contains(&self, ip: &str) -> Option<bool> {
        let (base, bits) = self.network.as_deref()?.split_once('/')?;
        let base: Ipv4Addr = base.parse().ok()?;
        let bits: u32 = bits.parse().ok().filter(|b| *b <= 32)?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Some(u32::from(ip) & mask == u32::from(base) & mask)
    }
}

/// One NAT rule of a VirtualBox VM, with the adapter (1 to 8) it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VboxVmRule {
    pub slot: u32,
    pub rule: VboxRule,
}

/// Where a VirtualBox VM keeps its files, from `showvminfo --machinereadable`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VboxVmPaths {
    /// `CfgFile`: the .vbox.
    pub config_file: Option<PathBuf>,
    /// `LogFldr`: `VBox.log` and `VBox.log.N`.
    pub log_folder: Option<PathBuf>,
    /// `SnapFldr`: differencing images and saved states.
    pub snapshot_folder: Option<PathBuf>,
    /// `VMStateFile`: a saved (suspended) VM's state. VirtualBox prints this one without escaping its backslashes.
    pub state_file: Option<PathBuf>,
    /// `VMState`.
    pub state: Option<String>,
    /// `VMStateChangeTime`, as printed (UTC without an offset).
    pub state_changed: Option<String>,
}

// ---- Workstation ----

/// `vmrun listHostNetworks`: the table after the `INDEX NAME TYPE ...` header. Missing columns are `None`.
pub fn parse_host_networks(out: &str) -> Result<Vec<Vmnet>> {
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    if !lines.clone().any(|l| l.starts_with("Total host networks:")) {
        return Err(CoreError::Vmrun {
            command: "listHostNetworks".into(),
            message: format!("unexpected output: {}", first_line(out)),
        });
    }
    let mut networks = Vec::new();
    let mut in_table = false;
    for line in lines.by_ref() {
        if line.to_ascii_uppercase().starts_with("INDEX") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(index), Some(name)) = (cols.first().and_then(|i| i.parse().ok()), cols.get(1)) else {
            continue;
        };
        let text = |i: usize| {
            cols.get(i)
                .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("empty"))
                .map(|v| (*v).to_owned())
        };
        networks.push(Vmnet {
            index,
            name: name.to_ascii_lowercase(),
            kind: cols
                .get(2)
                .map_or(VmnetKind::Other(String::new()), |k| VmnetKind::parse(k)),
            dhcp: cols.get(3).and_then(|d| truthy(d)),
            subnet: text(4),
            mask: text(5),
        });
    }
    Ok(networks)
}

/// `vmrun listPortForwardings <vmnet>`: `Total port forwardings: N`, then one forward a line. The lines are read
/// loosely (the protocol, the host port, the guest's `ip:port`, and the rest as the description, in any order),
/// since their layout was not seen on a PC with forwards. `Ok((total, forwards))`; fewer forwards than the total
/// means some lines could not be read, and the caller reads `vmnetnat.conf` instead ([`parse_nat_conf`]).
pub fn parse_port_forwardings(out: &str) -> Result<(usize, Vec<VmnetForward>)> {
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    let total = lines
        .by_ref()
        .find_map(|l| l.strip_prefix("Total port forwardings:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .ok_or_else(|| CoreError::Vmrun {
            command: "listPortForwardings".into(),
            message: format!("unexpected output: {}", first_line(out)),
        })?;
    let forwards = lines.filter_map(parse_forward_line).collect();
    Ok((total, forwards))
}

/// One line of `listPortForwardings`, read loosely: `tcp 8080 192.0.2.10:80 web`, `0: tcp 8080 -> 192.0.2.10:80
/// "web"`, `8080 (tcp) => 192.0.2.10:80`...
fn parse_forward_line(line: &str) -> Option<VmnetForward> {
    let mut protocol = None;
    let mut host_port = None;
    let mut guest = None;
    let mut description: Vec<&str> = Vec::new();
    let mut first = true;
    for word in line.split_whitespace() {
        let bare = word.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '"' | '\''));
        let index = first && word.ends_with(':') && word[..word.len() - 1].chars().all(|c| c.is_ascii_digit());
        first = false;
        if index || matches!(bare, "->" | "=>" | "-" | "=" | "") {
            continue;
        }
        if protocol.is_none() {
            if let Some(p) = ForwardProtocol::parse(bare) {
                protocol = Some(p);
                continue;
            }
        }
        if guest.is_none() {
            if let Some(endpoint) = parse_endpoint(bare) {
                guest = Some(endpoint);
                continue;
            }
        }
        if host_port.is_none() {
            if let Some(port) = parse_port(bare) {
                host_port = Some(port);
                continue;
            }
        }
        description.push(word);
    }
    let (guest_ip, guest_port) = guest?;
    let description = description.join(" ");
    let description = description
        .trim_matches(|c: char| matches!(c, '"' | '\'' | ' '))
        .to_owned();
    Some(VmnetForward {
        protocol: protocol?,
        host_port: host_port?,
        guest_ip,
        guest_port,
        description: (!description.is_empty()).then_some(description),
    })
}

/// `vmnetnat.conf`: the vmnet it serves (`[host] device = VMnet8`, lower case) and its forwards
/// (`[incomingtcp]` and `[incomingudp]`, `<host port> = <guest ip>:<guest port>`). Comments and other sections
/// are left out.
pub fn parse_nat_conf(text: &str) -> (Option<String>, Vec<VmnetForward>) {
    let mut section = String::new();
    let mut device = None;
    let mut forwards = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match section.as_str() {
            "host" if key.eq_ignore_ascii_case("device") => device = Some(value.to_ascii_lowercase()),
            "incomingtcp" | "incomingudp" => {
                let protocol = if section == "incomingtcp" {
                    ForwardProtocol::Tcp
                } else {
                    ForwardProtocol::Udp
                };
                let (Some(host_port), Some((guest_ip, guest_port))) = (parse_port(key), parse_endpoint(value)) else {
                    continue;
                };
                forwards.push(VmnetForward {
                    protocol,
                    host_port,
                    guest_ip,
                    guest_port,
                    description: None,
                });
            }
            _ => {}
        }
    }
    (device, forwards)
}

/// `setPortForwarding <vmnet> <protocol> <host port> <guest ip> <guest port> [description]`.
pub fn set_forward_args(vmnet: &str, forward: &VmnetForward) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "setPortForwarding".into(),
        vmnet.into(),
        forward.protocol.as_str().into(),
        forward.host_port.to_string().into(),
        forward.guest_ip.clone().into(),
        forward.guest_port.to_string().into(),
    ];
    if let Some(description) = forward.description.as_deref().filter(|d| !d.is_empty()) {
        args.push(description.into());
    }
    args
}

/// `deletePortForwarding <vmnet> <protocol> <host port>`.
pub fn delete_forward_args(vmnet: &str, protocol: ForwardProtocol, host_port: u16) -> Vec<OsString> {
    vec![
        "deletePortForwarding".into(),
        vmnet.into(),
        protocol.as_str().into(),
        host_port.to_string().into(),
    ]
}

// ---- VirtualBox ----

/// Blocks of `Key: value` lines separated by blank lines (`list hostonlyifs`, `list bridgedifs`).
fn key_value_blocks(out: &str) -> Vec<Vec<(String, String)>> {
    let mut blocks = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for line in out.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            current.push((key.trim().to_owned(), value.trim().to_owned()));
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

fn value<'a>(block: &'a [(String, String)], key: &str) -> Option<&'a str> {
    block
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// `list hostonlyifs`.
pub fn parse_hostonly_ifs(out: &str) -> Vec<VboxHostOnlyIf> {
    key_value_blocks(out)
        .into_iter()
        .filter_map(|block| {
            Some(VboxHostOnlyIf {
                name: value(&block, "Name")?.to_owned(),
                ip: value(&block, "IPAddress").map(str::to_owned),
                mask: value(&block, "NetworkMask").map(str::to_owned),
                dhcp: value(&block, "DHCP").and_then(truthy),
                status: value(&block, "Status").map(str::to_owned),
            })
        })
        .collect()
}

/// `list --long natnets`. VirtualBox 7 starts each network with `Name:`, 6.1 with `NetworkName:`. The rules are
/// the indented lines after `Port-forwarding (ipv4)`.
pub fn parse_natnets(out: &str) -> Vec<VboxNatNetwork> {
    let mut networks: Vec<VboxNatNetwork> = Vec::new();
    // Which indented list the next lines belong to: IPv4 rules, or something else (IPv6 rules, loopback mappings).
    let mut in_rules = false;
    for raw in out.lines() {
        let line = raw.trim();
        if line.is_empty() {
            in_rules = false;
            continue;
        }
        let indented = raw.starts_with([' ', '\t']);
        if indented {
            if in_rules {
                if let (Some(network), Some(rule)) = (networks.last_mut(), parse_network_rule(line)) {
                    network.forwards.push(rule);
                }
            }
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("port-forwarding (ipv4)") {
            in_rules = true;
            continue;
        }
        if lower.starts_with("port-forwarding") || lower.starts_with("loopback mappings") {
            in_rules = false;
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let (key, val) = (key.trim(), val.trim());
        if key.eq_ignore_ascii_case("Name") || key.eq_ignore_ascii_case("NetworkName") {
            networks.push(VboxNatNetwork {
                name: val.to_owned(),
                ..Default::default()
            });
            in_rules = false;
            continue;
        }
        let Some(network) = networks.last_mut() else {
            continue;
        };
        let text = (!val.is_empty()).then(|| val.to_owned());
        match key.to_ascii_lowercase().as_str() {
            "enabled" => network.enabled = truthy(val),
            "network" => network.network = text,
            "gateway" => network.gateway = text,
            "dhcp server" | "dhcp enabled" => network.dhcp = truthy(val),
            "ipv6" | "ipv6 enabled" => network.ipv6 = truthy(val),
            _ => {}
        }
    }
    networks
}

/// `name:proto:[host ip]:host port:[guest ip]:guest port` (a NAT network's rule as `list --long natnets` prints it).
pub fn parse_network_rule(text: &str) -> Option<VboxRule> {
    let (name, rest) = text.split_once(':')?;
    let (protocol, rest) = rest.split_once(':')?;
    let (host_ip, rest) = bracketed(rest)?;
    let (host_port, rest) = rest.strip_prefix(':')?.split_once(':')?;
    let (guest_ip, rest) = bracketed(rest)?;
    let guest_port = rest.strip_prefix(':')?;
    Some(VboxRule {
        name: name.trim().to_owned(),
        protocol: ForwardProtocol::parse(protocol)?,
        host_ip: non_empty(host_ip),
        host_port: parse_port(host_port)?,
        guest_ip: non_empty(guest_ip),
        guest_port: parse_port(guest_port)?,
    })
}

/// `[text]rest` -> (`text`, `rest`).
fn bracketed(text: &str) -> Option<(&str, &str)> {
    let inner = text.strip_prefix('[')?;
    let end = inner.find(']')?;
    Some((&inner[..end], &inner[end + 1..]))
}

/// `name,proto,host ip,host port,guest ip,guest port` (a VM's rule, `Forwarding(N)` in `showvminfo`). Read from
/// the right, so a name holding a comma still reads.
pub fn parse_vm_rule(text: &str) -> Option<VboxRule> {
    let mut parts: Vec<&str> = text.rsplitn(6, ',').collect();
    if parts.len() != 6 {
        return None;
    }
    parts.reverse();
    Some(VboxRule {
        name: parts[0].trim().to_owned(),
        protocol: ForwardProtocol::parse(parts[1])?,
        host_ip: non_empty(parts[2]),
        host_port: parse_port(parts[3])?,
        guest_ip: non_empty(parts[4]),
        guest_port: parse_port(parts[5])?,
    })
}

/// A VM's NAT rules from `showvminfo --machinereadable` pairs (in order): each `Forwarding(N)` belongs to the
/// adapter whose keys (`natnetN`, `nicN`, `macaddressN`...) came last before it.
pub fn vm_rules(pairs: &[(String, String)]) -> Vec<VboxVmRule> {
    const ADAPTER_KEYS: [&str; 7] = [
        "natnet",
        "nic",
        "nictype",
        "nicspeed",
        "macaddress",
        "cableconnected",
        "hostonlyadapter",
    ];
    let mut slot = None;
    let mut rules = Vec::new();
    for (key, value) in pairs {
        if key.starts_with("Forwarding(") {
            if let (Some(slot), Some(rule)) = (slot, parse_vm_rule(value)) {
                rules.push(VboxVmRule { slot, rule });
            }
            continue;
        }
        let digits = key.trim_start_matches(|c: char| !c.is_ascii_digit());
        let stem = &key[..key.len() - digits.len()];
        if ADAPTER_KEYS.contains(&stem) {
            if let Ok(n) = digits.parse::<u32>() {
                slot = Some(n);
            }
        }
    }
    rules
}

/// Where the VM keeps its files, from `showvminfo --machinereadable` pairs.
pub fn vm_paths(pairs: &[(String, String)]) -> VboxVmPaths {
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    VboxVmPaths {
        config_file: get("CfgFile").map(PathBuf::from),
        log_folder: get("LogFldr").map(PathBuf::from),
        snapshot_folder: get("SnapFldr").map(PathBuf::from),
        state_file: get("VMStateFile").map(PathBuf::from),
        state: get("VMState"),
        state_changed: get("VMStateChangeTime"),
    }
}

/// VirtualBox's answer when another client holds or is taking a VM's session lock (a second `showvminfo` on the same
/// VM at the same moment fails with one of these): worth asking again in a moment.
pub fn vbox_busy(err: &CoreError) -> bool {
    let CoreError::VboxManage { message, .. } = err else {
        return false;
    };
    let message = message.to_ascii_lowercase();
    ["lock request pending", "session is not locked", "object is not ready"]
        .iter()
        .any(|m| message.contains(m))
}

/// Waits before asking a busy VirtualBox again.
const BUSY_RETRIES: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(300),
    std::time::Duration::from_millis(800),
    std::time::Duration::from_millis(1500),
];

/// `showvminfo <uuid> --machinereadable` as `key=value` pairs, asked again (up to three times) while VirtualBox says
/// another client has the VM's session lock.
pub async fn showvminfo_pairs(
    vbox: &dyn crate::adapters::virtualbox::VirtualBoxAdapter,
    uuid: &str,
    timeout: std::time::Duration,
) -> Result<Vec<(String, String)>> {
    let args = || vec!["showvminfo".to_owned(), uuid.to_owned(), "--machinereadable".to_owned()];
    let mut waits = BUSY_RETRIES.iter();
    loop {
        match vbox.vboxmanage_host(args(), timeout).await {
            Ok(out) => return Ok(crate::adapters::virtualbox::parse_machine_readable(&out)),
            Err(err) if vbox_busy(&err) => match waits.next() {
                Some(wait) => tokio::time::sleep(*wait).await,
                None => return Err(err),
            },
            Err(err) => return Err(err),
        }
    }
}

/// `natnetwork modify --netname <name> --port-forward-4 <rule>` (or `delete <rule name>`).
pub fn natnet_rule_args(network: &str, rule: &VboxRule, delete: bool) -> Vec<String> {
    let mut args = vec![
        "natnetwork".to_owned(),
        "modify".to_owned(),
        "--netname".to_owned(),
        network.to_owned(),
        "--port-forward-4".to_owned(),
    ];
    if delete {
        args.push("delete".to_owned());
        args.push(rule.name.clone());
    } else {
        args.push(rule.network_form());
    }
    args
}

/// `modifyvm <uuid> --natpfN <rule>` while the VM is off, `controlvm <uuid> natpfN <rule>` while it runs (or
/// `delete <rule name>`).
pub fn vm_rule_args(uuid: &str, slot: u32, rule: &VboxRule, running: bool, delete: bool) -> Vec<String> {
    let mut args = if running {
        vec!["controlvm".to_owned(), uuid.to_owned(), format!("natpf{slot}")]
    } else {
        vec!["modifyvm".to_owned(), uuid.to_owned(), format!("--natpf{slot}")]
    };
    if delete {
        args.push("delete".to_owned());
        args.push(rule.name.clone());
    } else {
        args.push(rule.vm_form());
    }
    args
}

// ---- Shared ----

/// `192.0.2.10:80` -> (`192.0.2.10`, 80).
fn parse_endpoint(text: &str) -> Option<(String, u16)> {
    let (ip, port) = text.rsplit_once(':')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    Some((ip.to_string(), parse_port(port)?))
}

/// 1 to 65535.
fn parse_port(text: &str) -> Option<u16> {
    text.trim().parse::<u16>().ok().filter(|p| *p > 0)
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn truthy(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "enabled" | "on" | "1" => Some(true),
        "false" | "no" | "disabled" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn first_line(out: &str) -> &str {
    out.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("nothing")
}

/// VM-11: whether this process runs elevated (as administrator). Workstation's NAT forwards need it.
#[cfg(windows)]
pub fn process_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle of this process needs no closing; the token handle is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut written = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size passed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    };
    // SAFETY: opened above.
    let _ = unsafe { CloseHandle(token) };
    read.is_ok() && elevation.TokenIsElevated != 0
}

#[cfg(not(windows))]
pub fn process_elevated() -> bool {
    false
}

/// VM-11: why Workstation's NAT port forwards can't be changed from this app, or `None` when they can.
pub fn nat_refusal(elevated: bool) -> Option<String> {
    (!elevated).then(|| {
        format!(
            "Workstation keeps its NAT port forwards in {VMNET_NAT_CONF}, which only administrators can change, and \
             Remotely never asks to run as administrator. Change them in Workstation's Virtual Network Editor (Edit, \
             Virtual Network Editor, Change Settings), or start Remotely with Run as administrator"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures: the layout of the tools' output on Workstation 26 and VirtualBox 7.2, with reserved addresses only.

    const HOST_NETWORKS: &str = "Total host networks: 3\r\n\
        INDEX  NAME         TYPE         DHCP         SUBNET           MASK\r\n\
        1      vmnet1       hostOnly     true         192.0.2.0        255.255.255.0   \r\n\
        2      vmnet2       hostOnly     false        198.51.100.0     255.255.255.0   \r\n\
        8      vmnet8       nat          true         203.0.113.0      255.255.255.0\r\n";

    #[test]
    fn reads_the_vmnets() {
        let nets = parse_host_networks(HOST_NETWORKS).unwrap();
        assert_eq!(nets.len(), 3);
        assert_eq!(
            nets[2],
            Vmnet {
                index: 8,
                name: "vmnet8".into(),
                kind: VmnetKind::Nat,
                dhcp: Some(true),
                subnet: Some("203.0.113.0".into()),
                mask: Some("255.255.255.0".into()),
            }
        );
        assert_eq!(nets[0].kind, VmnetKind::HostOnly);
        assert_eq!(nets[1].dhcp, Some(false));
        assert_eq!(nets[2].contains("203.0.113.40"), Some(true));
        assert_eq!(nets[2].contains("192.0.2.40"), Some(false));
    }

    #[test]
    fn a_bridged_vmnet_without_a_subnet_and_an_unknown_type_still_read() {
        let out =
            "Total host networks: 2\nINDEX  NAME  TYPE  DHCP  SUBNET  MASK\n0  vmnet0  bridged  false  empty  empty\n\
                   9  vmnet9  futureKind\n";
        let nets = parse_host_networks(out).unwrap();
        assert_eq!(nets[0].kind, VmnetKind::Bridged);
        assert_eq!(nets[0].subnet, None);
        assert_eq!(nets[1].kind, VmnetKind::Other("futureKind".into()));
        assert_eq!(nets[1].dhcp, None);
        assert!(parse_host_networks("Error: something broke").is_err());
        assert!(parse_host_networks("Total host networks: 0\r\n").unwrap().is_empty());
    }

    #[test]
    fn reads_port_forwardings_loosely() {
        let (total, none) = parse_port_forwardings("Total port forwardings: 0\r\n").unwrap();
        assert_eq!((total, none.len()), (0, 0));
        let out = "Total port forwardings: 4\r\n\
                   0: tcp 8080 -> 203.0.113.10:80 \"web site\"\r\n\
                   udp  5353  203.0.113.11:53\r\n\
                   2222 (tcp) => 203.0.113.12:22 ssh\r\n\
                   something vmrun may print that is not a forward\r\n";
        let (total, forwards) = parse_port_forwardings(out).unwrap();
        assert_eq!(total, 4);
        assert_eq!(forwards.len(), 3, "{forwards:?}");
        assert_eq!(
            forwards[0],
            VmnetForward {
                protocol: ForwardProtocol::Tcp,
                host_port: 8080,
                guest_ip: "203.0.113.10".into(),
                guest_port: 80,
                description: Some("web site".into()),
            }
        );
        assert_eq!(forwards[1].protocol, ForwardProtocol::Udp);
        assert_eq!(forwards[1].description, None);
        assert_eq!((forwards[2].host_port, forwards[2].guest_port), (2222, 22));
        assert_eq!(forwards[2].description.as_deref(), Some("ssh"));
        assert!(parse_port_forwardings("Error: Host network type is not nat").is_err());
    }

    #[test]
    fn reads_the_nat_conf_forwards_and_skips_comments() {
        let conf = "# Windows NAT configuration file\n[host]\nip = 203.0.113.2/24\ndevice = VMnet8\n\n\
                    [incomingtcp]\n# SSH\n#8889 = 203.0.113.128:22\n8080 = 203.0.113.10:80\n2222 = 203.0.113.12:22\n\
                    [incomingudp]\n#6000 = 203.0.113.128:6001\n5353 = 203.0.113.11:53\nbad = 203.0.113.11:53\n\
                    [PrivilegedTCP]\nautodetect = 1\n";
        let (device, forwards) = parse_nat_conf(conf);
        assert_eq!(device.as_deref(), Some("vmnet8"));
        assert_eq!(forwards.len(), 3);
        assert_eq!(forwards[0].host_port, 8080);
        assert_eq!(forwards[2].protocol, ForwardProtocol::Udp);
        assert_eq!(forwards[2].guest_ip, "203.0.113.11");
    }

    #[test]
    fn builds_vmrun_forward_arguments() {
        let forward = VmnetForward {
            protocol: ForwardProtocol::Tcp,
            host_port: 8080,
            guest_ip: "203.0.113.10".into(),
            guest_port: 80,
            description: Some("web site".into()),
        };
        let args: Vec<String> = set_forward_args("vmnet8", &forward)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "setPortForwarding",
                "vmnet8",
                "tcp",
                "8080",
                "203.0.113.10",
                "80",
                "web site"
            ]
        );
        let args: Vec<String> = delete_forward_args("vmnet8", ForwardProtocol::Udp, 53)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["deletePortForwarding", "vmnet8", "udp", "53"]);
    }

    const HOSTONLY_IFS: &str = "Name:            VirtualBox Host-Only Ethernet Adapter\r\n\
        GUID:            00000000-0000-4000-8000-000000000001\r\n\
        DHCP:            Disabled\r\n\
        IPAddress:       192.0.2.1\r\n\
        NetworkMask:     255.255.255.0\r\n\
        IPV6Address:     fe80::1\r\n\
        IPV6NetworkMaskPrefixLength: 64\r\n\
        HardwareAddress: 0a:00:27:00:00:01\r\n\
        MediumType:      Ethernet\r\n\
        Wireless:        No\r\n\
        Status:          Up\r\n\
        VBoxNetworkName: HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter\r\n\
        \r\n\
        Name:            VirtualBox Host-Only Ethernet Adapter #2\r\n\
        DHCP:            Enabled\r\n\
        IPAddress:       198.51.100.1\r\n\
        NetworkMask:     255.255.255.0\r\n\
        Status:          Down\r\n\r\n";

    #[test]
    fn reads_host_only_interfaces() {
        let ifs = parse_hostonly_ifs(HOSTONLY_IFS);
        assert_eq!(ifs.len(), 2);
        assert_eq!(
            ifs[0],
            VboxHostOnlyIf {
                name: "VirtualBox Host-Only Ethernet Adapter".into(),
                ip: Some("192.0.2.1".into()),
                mask: Some("255.255.255.0".into()),
                dhcp: Some(false),
                status: Some("Up".into()),
            }
        );
        assert_eq!(ifs[1].name, "VirtualBox Host-Only Ethernet Adapter #2");
        assert_eq!(ifs[1].dhcp, Some(true));
        assert!(parse_hostonly_ifs("").is_empty());
    }

    const NATNETS_LONG: &str = "Name:         lab-net\r\n\
        Enabled:      Yes\r\n\
        Network:      198.51.100.0/24\r\n\
        Gateway:      198.51.100.1\r\n\
        DHCP Server:  Yes\r\n\
        IPv6:         No\r\n\
        IPv6 Prefix:  fd17:625c:f037:2::/64\r\n\
        IPv6 Default: No\r\n\
        Port-forwarding (ipv4)\r\n\
        \x20       it udp:udp:[127.0.0.1]:47053:[198.51.100.6]:53\r\n\
        \x20       ssh:tcp:[]:2222:[198.51.100.5]:22\r\n\
        loopback mappings (ipv4)\r\n\
        \x20       127.0.0.1=2\r\n\
        \r\n\
        Name:         empty-net\r\n\
        Enabled:      No\r\n\
        Network:      203.0.113.0/24\r\n\
        Gateway:      203.0.113.1\r\n\
        DHCP Server:  No\r\n\
        IPv6:         No\r\n\r\n";

    #[test]
    fn reads_nat_networks_with_their_rules() {
        let nets = parse_natnets(NATNETS_LONG);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].name, "lab-net");
        assert_eq!(nets[0].enabled, Some(true));
        assert_eq!(nets[0].network.as_deref(), Some("198.51.100.0/24"));
        assert_eq!(nets[0].dhcp, Some(true));
        assert_eq!(nets[0].forwards.len(), 2, "loopback mappings are not rules");
        assert_eq!(
            nets[0].forwards[0],
            VboxRule {
                name: "it udp".into(),
                protocol: ForwardProtocol::Udp,
                host_ip: Some("127.0.0.1".into()),
                host_port: 47053,
                guest_ip: Some("198.51.100.6".into()),
                guest_port: 53,
            }
        );
        assert_eq!(nets[0].forwards[1].host_ip, None);
        assert_eq!(nets[1].enabled, Some(false));
        assert!(nets[1].forwards.is_empty());
        assert_eq!(nets[0].contains("198.51.100.77"), Some(true));
        assert_eq!(nets[0].contains("203.0.113.77"), Some(false));
        // VirtualBox 6.1 named each network with NetworkName:.
        let old =
            parse_natnets("NetworkName:    old-net\nIP:             198.51.100.1\nNetwork:        198.51.100.0/24\n");
        assert_eq!(old[0].name, "old-net");
    }

    #[test]
    fn rules_round_trip_through_both_forms() {
        let rule = VboxRule {
            name: "web".into(),
            protocol: ForwardProtocol::Tcp,
            host_ip: Some("127.0.0.1".into()),
            host_port: 8080,
            guest_ip: None,
            guest_port: 80,
        };
        assert_eq!(rule.vm_form(), "web,tcp,127.0.0.1,8080,,80");
        assert_eq!(parse_vm_rule(&rule.vm_form()), Some(rule.clone()));
        assert_eq!(rule.network_form(), "web:tcp:[127.0.0.1]:8080:[]:80");
        assert_eq!(parse_network_rule(&rule.network_form()), Some(rule));
        assert_eq!(parse_vm_rule("only,three,parts"), None);
        assert_eq!(parse_vm_rule("x,sctp,,1,,2"), None);
        assert_eq!(parse_network_rule("x:tcp:127.0.0.1:1:[]:2"), None);
    }

    #[test]
    fn a_vms_rules_belong_to_the_adapter_before_them() {
        let out = "UUID=\"00000000-0000-4000-8000-0000000000aa\"\n\
            LogFldr=\"C:\\\\VMs\\\\db01\\\\Logs\"\n\
            CfgFile=\"C:\\\\VMs\\\\db01\\\\db01.vbox\"\n\
            SnapFldr=\"C:\\\\VMs\\\\db01\\\\Snapshots\"\n\
            VMState=\"saved\"\n\
            VMStateChangeTime=\"2026-10-25T13:40:18.686000000\"\n\
            VMStateFile=\"C:\\VMs\\db01\\Snapshots\\2026-10-25T13-40-17-814880400Z.sav\"\n\
            natnet1=\"nat\"\nmacaddress1=\"080027000001\"\ncableconnected1=\"on\"\nnic1=\"nat\"\nnictype1=\"82540EM\"\n\
            nicspeed1=\"0\"\n\
            Forwarding(0)=\"it web,tcp,127.0.0.1,47180,192.0.2.15,80\"\n\
            Forwarding(1)=\"ssh,tcp,,2222,,22\"\n\
            hostonlyadapter2=\"VirtualBox Host-Only Ethernet Adapter\"\nmacaddress2=\"080027000002\"\nnic2=\"hostonly\"\n\
            natnet3=\"nat\"\nmacaddress3=\"080027000003\"\nnic3=\"nat\"\n\
            Forwarding(0)=\"dns,udp,,5353,,53\"\n\
            nic4=\"none\"\n";
        let pairs = crate::adapters::virtualbox::parse_machine_readable(out);
        let rules = vm_rules(&pairs);
        assert_eq!(rules.len(), 3);
        assert_eq!((rules[0].slot, rules[0].rule.name.as_str()), (1, "it web"));
        assert_eq!(rules[1].rule.host_ip, None);
        assert_eq!((rules[2].slot, rules[2].rule.protocol), (3, ForwardProtocol::Udp));
        let paths = vm_paths(&pairs);
        assert_eq!(paths.log_folder, Some(PathBuf::from(r"C:\VMs\db01\Logs")));
        assert_eq!(paths.snapshot_folder, Some(PathBuf::from(r"C:\VMs\db01\Snapshots")));
        assert_eq!(
            paths.state_file,
            Some(PathBuf::from(
                r"C:\VMs\db01\Snapshots\2026-10-25T13-40-17-814880400Z.sav"
            )),
            "printed without escapes"
        );
        assert_eq!(paths.state.as_deref(), Some("saved"));
    }

    #[test]
    fn builds_vboxmanage_rule_arguments() {
        let rule = VboxRule {
            name: "ssh".into(),
            protocol: ForwardProtocol::Tcp,
            host_ip: None,
            host_port: 2222,
            guest_ip: Some("198.51.100.5".into()),
            guest_port: 22,
        };
        assert_eq!(
            natnet_rule_args("lab-net", &rule, false),
            [
                "natnetwork",
                "modify",
                "--netname",
                "lab-net",
                "--port-forward-4",
                "ssh:tcp:[]:2222:[198.51.100.5]:22"
            ]
        );
        assert_eq!(
            natnet_rule_args("lab-net", &rule, true),
            [
                "natnetwork",
                "modify",
                "--netname",
                "lab-net",
                "--port-forward-4",
                "delete",
                "ssh"
            ]
        );
        assert_eq!(
            vm_rule_args("u-1", 1, &rule, false, false),
            ["modifyvm", "u-1", "--natpf1", "ssh,tcp,,2222,198.51.100.5,22"]
        );
        assert_eq!(
            vm_rule_args("u-1", 2, &rule, true, true),
            ["controlvm", "u-1", "natpf2", "delete", "ssh"]
        );
    }

    fn vbox_error(message: &str) -> CoreError {
        CoreError::VboxManage {
            command: "showvminfo".into(),
            message: message.into(),
        }
    }

    #[test]
    fn a_vm_locked_by_another_client_is_busy_and_other_errors_are_not() {
        assert!(vbox_busy(&vbox_error(
            "The machine 'lab01' already has a lock request pending"
        )));
        assert!(vbox_busy(&vbox_error(
            "The session is not locked (session state: Unlocked)"
        )));
        assert!(vbox_busy(&vbox_error("The object is not ready")));
        assert!(!vbox_busy(&vbox_error("Could not find a registered machine named 'x'")));
        assert!(!vbox_busy(&CoreError::VboxManageNotFound));
    }

    /// VirtualBox that is busy for the first `busy` calls, then answers.
    struct BusyThenReady {
        busy: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::adapters::virtualbox::VirtualBoxAdapter for BusyThenReady {
        fn tool_path(&self) -> Option<PathBuf> {
            None
        }
        async fn list_vms(&self) -> Result<Vec<crate::adapters::virtualbox::VboxListedVm>> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn list_running(&self) -> Result<Vec<String>> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn vm_info(&self, _: &str) -> Result<crate::adapters::virtualbox::VboxVmInfo> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn guest_properties(&self, _: &str) -> Result<crate::adapters::virtualbox::GuestProperties> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn power(&self, _: &str, _: crate::command_bus::PowerOp) -> Result<()> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn snapshot(&self, _: &str, _: &crate::command_bus::SnapshotOp) -> Result<()> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn snapshots(&self, _: &str) -> Result<crate::adapters::vmware::SnapshotTree> {
            Err(CoreError::VboxManageNotFound)
        }
        async fn vboxmanage_host(&self, _: Vec<String>, _: std::time::Duration) -> Result<String> {
            let left = self.busy.load(std::sync::atomic::Ordering::SeqCst);
            if left > 0 {
                self.busy.store(left - 1, std::sync::atomic::Ordering::SeqCst);
                return Err(vbox_error("The machine 'lab01' already has a lock request pending"));
            }
            Ok("LogFldr=\"C:\\\\VMs\\\\lab01\\\\Logs\"\n".into())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn showvminfo_is_asked_again_while_virtualbox_is_busy() {
        let twice = BusyThenReady {
            busy: std::sync::atomic::AtomicUsize::new(2),
        };
        let pairs = showvminfo_pairs(&twice, "u-1", std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(vm_paths(&pairs).log_folder, Some(PathBuf::from(r"C:\VMs\lab01\Logs")));
        let always = BusyThenReady {
            busy: std::sync::atomic::AtomicUsize::new(10),
        };
        let err = showvminfo_pairs(&always, "u-1", std::time::Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(vbox_busy(&err), "gives up after three more tries");
    }

    #[test]
    fn the_nat_refusal_names_the_file_and_the_way_out() {
        assert_eq!(nat_refusal(true), None);
        let why = nat_refusal(false).unwrap();
        assert!(
            why.contains("vmnetnat.conf") && why.contains("Virtual Network Editor"),
            "{why}"
        );
    }
}
