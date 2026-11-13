//! VM-32 (0.8.0 G6): address pools: static IPv4 addresses for unattended deploys, per network of one hypervisor and per
//! workspace (rule 8: every call takes the ctx it acts in, every row carries its workspace).
//!
//! * A pool is the user's own data, like the catalogue: adding, changing and deleting one is audited
//!   (`address_pool_changed`, no approval tier) and refused by the read-only lock ([`Change::AddressPools`]). Nothing here
//!   touches a VM, so it skips the command bus. Pools are not in the trash and not in FD-07 exports: they describe this
//!   PC's networks, and their leases the VMs made here.
//! * [`check_pool`] checks what the editor sends: IPv4 only; first and last in one subnet of the prefix (/8 to /30),
//!   neither its network nor its broadcast address, at most [`MAX_RANGE`] addresses; the gateway in that subnet; at most
//!   [`MAX_DNS`] DNS servers; a network the hypervisor has, which this PC has an adapter on (never VirtualBox's NAT, NAT
//!   networks or internal networks); a VirtualBox host-only pool names its adapter.
//! * This PC's networks are the PC's, whatever workspace uses them. [`resolve_network`] turns a pool's network into the
//!   network of this PC it is, through VM-11's host network report ([`HostNetworks`]): Workstation's NAT is whichever
//!   vmnet the Virtual Network Editor made NAT (vmnet8 unless moved), its host-only network vmnet1, bridged networks the
//!   PC's LAN on either hypervisor, a VirtualBox host-only adapter itself. Two pools of a workspace never share an address
//!   on one network; pools of two workspaces may (Workstation's NAT has one subnet per PC), but a lease is one per network
//!   and address across workspaces, so an address one workspace holds is never handed out by another ("held in another
//!   workspace", saying nothing more of it).
//! * An address is handed out only when nothing is there: one ICMP echo ([`PING_TIMEOUT`]) and one ARP request through
//!   the toolbox's [`NetworkTools`], [`PINGS_AT_ONCE`] addresses at a time. A reply, or "unreachable" from the address
//!   itself, or an ARP answer (a Windows guest drops pings but answers ARP) means in use; an address that couldn't be
//!   checked is skipped and counted. Both only mean something on a subnet this PC has an adapter on, so pick and claim
//!   refuse a pool whose subnet no adapter of this PC is on: a ping would leave through another network.
//! * The deploy (G6) asks [`AddressPools::pick`] for a preview (kept [`PICK_FRESH`], so the dialog's checks don't ping
//!   the range each time), then at each VM's step [`AddressPools::claim`]s the address (a row of its own: of two claims
//!   of one address, one wins; a claim dropped mid-check, a cancel, takes its row away), [`AddressPools::assign`]s it to
//!   the VM once it is made, or [`AddressPools::release`]s it; [`AddressPools::release_job_claims`] lets go of whatever a
//!   job claimed and didn't assign. A claim whose job isn't open any more counts as free at once. The lease stays the
//!   VM's until Remotely deletes the VM (VM-24's delete, a stack teardown too: `Store::free_vm_leases`). A VM deleted
//!   outside Remotely leaves its lease, which the user can free by hand ([`AddressPools::free`], audited) once no
//!   workspace lists the VM.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::host_networks::VmnetKind;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::net_tools::{Echo, EchoRequest, NetworkTools};
use crate::catalog::templates::{check_network, hypervisor_label, Network};
use crate::domain::{Context, UserId};
use crate::error::{CoreError, Result};
use crate::host_networks::{HostNetworks, HostNetworksReport};
use crate::locks;
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};
use crate::untrusted::is_format_char;

/// Pools one workspace keeps.
pub const MAX_POOLS: usize = 100;
/// The longest name, in characters.
pub const MAX_NAME_CHARS: usize = 60;
/// The longest VirtualBox host-only adapter name, in characters.
pub const MAX_ADAPTER_CHARS: usize = 128;
/// The most addresses one pool spans.
pub const MAX_RANGE: u32 = 4096;
/// DNS servers a pool gives its VMs.
pub const MAX_DNS: usize = 3;
pub const MAX_NOTES: usize = 1000;
/// The widest and the narrowest subnet a pool may be in.
pub const MIN_PREFIX: u8 = 8;
pub const MAX_PREFIX: u8 = 30;
/// How long one ping waits for its answer.
pub const PING_TIMEOUT: Duration = Duration::from_secs(1);
/// Addresses checked at once while looking for free ones.
pub const PINGS_AT_ONCE: usize = 8;
/// How long a pick's answer is given again for the same pool, count and exclusions (the Deploy dialog checks after each
/// change; a claim checks the address again anyway). Any change to a pool or a lease forgets them.
pub const PICK_FRESH: Duration = Duration::from_secs(5);
/// How long VM-11's networks are trusted before they are read again (vmrun takes seconds).
pub const FACTS_FRESH: Duration = Duration::from_secs(60);
/// A claim without a VM older than this was left by a deploy that never ended (the app stopped mid-deploy).
pub const STALE_CLAIM_DAYS: i64 = 1;

/// Every bridged network: this PC's LAN, whichever hypervisor bridges to it.
const BRIDGED_KEY: &str = "bridged";
const EVENT: &str = "address_pool_changed";

/// What the editor sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPoolInput {
    pub name: String,
    pub hypervisor: Hypervisor,
    pub network: Network,
    /// VirtualBox host-only: the adapter's name (what `--hostonlyadapterN` takes). Ignored for every other network.
    #[serde(default)]
    pub host_adapter: Option<String>,
    /// Dotted IPv4, as typed.
    pub first_ip: String,
    pub last_ip: String,
    pub prefix: u8,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default, rename = "dnsServers")]
    pub dns: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// A pool's settings once checked, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSpec {
    pub name: String,
    pub hypervisor: Hypervisor,
    pub network: Network,
    /// VirtualBox host-only only.
    pub host_adapter: Option<String>,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub notes: Option<String>,
}

impl PoolSpec {
    /// Addresses in the range.
    pub fn size(&self) -> u32 {
        u32::from(self.last) - u32::from(self.first) + 1
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(self.first)..=u32::from(self.last)).contains(&u32::from(ip))
    }

    /// The gateway and the DNS servers: never handed out.
    pub fn reserved(&self) -> HashSet<Ipv4Addr> {
        self.gateway.iter().chain(self.dns.iter()).copied().collect()
    }

    /// Addresses the pool can hand out: the range without the gateway and DNS servers in it.
    pub fn usable(&self) -> u32 {
        let reserved = self.reserved().into_iter().filter(|ip| self.contains(*ip)).count();
        self.size().saturating_sub(u32::try_from(reserved).unwrap_or(0))
    }

    /// "NAT", "host-only adapter 'vboxnet0'".
    fn network_text(&self) -> String {
        match (&self.network, &self.host_adapter) {
            (Network::HostOnly, Some(adapter)) => format!("host-only adapter '{adapter}'"),
            (network, _) => network.describe(),
        }
    }

    /// "Workstation, NAT, 192.0.2.10 to 192.0.2.50 /24, gateway 192.0.2.1, DNS 192.0.2.53", for the audit log.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "{}, {}, {} to {} /{}",
            hypervisor_label(self.hypervisor),
            self.network_text(),
            self.first,
            self.last,
            self.prefix
        );
        if let Some(gateway) = self.gateway {
            out.push_str(&format!(", gateway {gateway}"));
        }
        if !self.dns.is_empty() {
            let dns: Vec<String> = self.dns.iter().map(Ipv4Addr::to_string).collect();
            out.push_str(&format!(", DNS {}", dns.join(" ")));
        }
        out
    }
}

/// A stored pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolRow {
    pub id: Uuid,
    pub spec: PoolSpec,
    /// The network of this PC it resolved to when last used.
    pub network_key: String,
    pub created_at: String,
    pub updated_at: String,
}

/// One pool, as the Templates page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPool {
    pub id: Uuid,
    pub name: String,
    pub hypervisor: Hypervisor,
    pub network: Network,
    pub host_adapter: Option<String>,
    pub first_ip: Ipv4Addr,
    pub last_ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    #[serde(rename = "dnsServers")]
    pub dns: Vec<Ipv4Addr>,
    pub notes: Option<String>,
    /// Addresses in the range.
    pub size: u32,
    /// Addresses it can hand out: the range without the gateway and DNS servers.
    pub usable: u32,
    /// Held by this pool: assigned to a VM, or claimed by a deploy now.
    pub used: u32,
    /// Addresses of the range another workspace holds on the same network (nothing more is said of them).
    pub held_elsewhere: u32,
    /// `usable - used - held_elsewhere`. Whether something answers on them is checked only when one is picked.
    pub free: u32,
    pub created_at: String,
    pub updated_at: String,
}

impl AddressPool {
    fn of(row: PoolRow, used: u32, held_elsewhere: u32) -> Self {
        let usable = row.spec.usable();
        Self {
            id: row.id,
            size: row.spec.size(),
            usable,
            used,
            held_elsewhere,
            free: usable.saturating_sub(used).saturating_sub(held_elsewhere),
            name: row.spec.name,
            hypervisor: row.spec.hypervisor,
            network: row.spec.network,
            host_adapter: row.spec.host_adapter,
            first_ip: row.spec.first,
            last_ip: row.spec.last,
            prefix: row.spec.prefix,
            gateway: row.spec.gateway,
            dns: row.spec.dns,
            notes: row.spec.notes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Whether a lease is a deploy's claim or a VM's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    /// A deploy job is making the VM.
    Claimed,
    /// The VM was made: the address is its until it is deleted.
    Assigned,
}

impl LeaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseState::Claimed => "claimed",
            LeaseState::Assigned => "assigned",
        }
    }
}

/// One taken address of a pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressLease {
    pub pool_id: Uuid,
    pub ip: Ipv4Addr,
    /// The VM's key, once it was made.
    pub vm_key: Option<String>,
    pub vm_name: String,
    /// The deploy job that claimed it.
    pub job_id: Option<Uuid>,
    pub state: LeaseState,
    pub created_at: String,
    /// The address can be freed by hand ([`AddressPools::free`]): no workspace lists its VM (deleted outside Remotely,
    /// or taken out of every workspace), or its claim's deploy isn't running (such a claim holds nothing).
    pub can_free: bool,
}

/// An address for a new VM: what its install config's `{{ip}}` and network settings get.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolAddress {
    pub pool_id: Uuid,
    pub pool_name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    #[serde(rename = "dnsServers")]
    pub dns: Vec<Ipv4Addr>,
}

impl PoolAddress {
    fn of(pool: &PoolRow, ip: Ipv4Addr) -> Self {
        Self {
            pool_id: pool.id,
            pool_name: pool.spec.name.clone(),
            ip,
            prefix: pool.spec.prefix,
            gateway: pool.spec.gateway,
            dns: pool.spec.dns.clone(),
        }
    }
}

/// What VM-11's host network report says about this PC's networks, as pools need it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkFacts {
    /// Workstation's NAT vmnet (`vmnet8` unless the Virtual Network Editor moved it), when vmrun lists one.
    pub vmware_nat: Option<String>,
    /// Workstation's listed vmnets, lower case, with their subnets when known.
    pub vmnets: Vec<(String, Option<(Ipv4Addr, u8)>)>,
    /// VBoxManage was found and asked.
    pub virtualbox: bool,
    /// VirtualBox's host-only adapters with their subnets when known.
    pub host_only: Vec<(String, Option<(Ipv4Addr, u8)>)>,
}

/// A subnet from an address and a dotted mask (contiguous only).
fn subnet_of(address: Option<&str>, mask: Option<&str>) -> Option<(Ipv4Addr, u8)> {
    let address: Ipv4Addr = address?.trim().parse().ok()?;
    let bits = u32::from(mask?.trim().parse::<Ipv4Addr>().ok()?);
    let prefix = bits.count_ones();
    if prefix == 0 || bits.leading_ones() != prefix {
        return None;
    }
    Some((Ipv4Addr::from(u32::from(address) & bits), u8::try_from(prefix).ok()?))
}

impl NetworkFacts {
    pub fn of(report: &HostNetworksReport) -> Self {
        let vmnets = report
            .vmware
            .networks
            .iter()
            .map(|v| {
                (
                    v.network.name.to_ascii_lowercase(),
                    subnet_of(v.network.subnet.as_deref(), v.network.mask.as_deref()),
                )
            })
            .collect();
        let vmware_nat = report
            .vmware
            .networks
            .iter()
            .find(|v| v.network.kind == VmnetKind::Nat)
            .map(|v| v.network.name.to_ascii_lowercase());
        let host_only = report
            .virtualbox
            .host_only
            .iter()
            .map(|h| {
                (
                    h.iface.name.clone(),
                    subnet_of(h.iface.ip.as_deref(), h.iface.mask.as_deref()),
                )
            })
            .collect();
        Self {
            vmware_nat,
            vmnets,
            virtualbox: report.virtualbox.available,
            host_only,
        }
    }
}

/// The network of this PC a pool's network is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNetwork {
    /// The same for every name of one network, in every workspace: `bridged`, `vmware:vmnet8`,
    /// `virtualbox:hostonly:<adapter>`.
    pub key: String,
    /// "NAT (vmnet8)", for messages.
    pub label: String,
    /// The subnet the hypervisor gives it, when it says.
    pub subnet: Option<(Ipv4Addr, u8)>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// The subnet mask of a prefix (1 to 32).
fn mask(prefix: u8) -> u32 {
    u32::MAX << (32 - u32::from(prefix.clamp(1, 32)))
}

fn no_host_adapter(network: &Network) -> String {
    format!(
        "This PC has no adapter on VirtualBox's {}, so Remotely can't check which addresses are free there (a ping \
         would leave through another network): give the pool a host-only adapter or a bridged network.",
        match network {
            Network::Nat => "NAT (each VM's network of its own)".to_owned(),
            other => other.describe(),
        }
    )
}

/// The network of this PC that `network` of `hypervisor` is (with VirtualBox's host-only `host_adapter`), from VM-11's
/// report. Pure, so it is tested without a hypervisor.
pub fn resolve_network(
    hypervisor: Hypervisor,
    network: &Network,
    host_adapter: Option<&str>,
    facts: &NetworkFacts,
) -> Result<ResolvedNetwork> {
    let vmnet = |name: String, label: String| {
        let subnet = facts.vmnets.iter().find(|(n, _)| *n == name).and_then(|(_, s)| *s);
        ResolvedNetwork {
            key: format!("vmware:{name}"),
            label,
            subnet,
        }
    };
    match (hypervisor, network) {
        (_, Network::Bridged) | (Hypervisor::Vmware, Network::Vmnet { number: 0 }) => Ok(ResolvedNetwork {
            key: BRIDGED_KEY.to_owned(),
            label: "bridged (this PC's network)".to_owned(),
            subnet: None,
        }),
        (Hypervisor::Vmware, Network::Nat) => {
            let name = facts.vmware_nat.clone().unwrap_or_else(|| "vmnet8".to_owned());
            Ok(vmnet(name.clone(), format!("NAT ({name})")))
        }
        (Hypervisor::Vmware, Network::HostOnly) => Ok(vmnet("vmnet1".to_owned(), "host-only (vmnet1)".to_owned())),
        (Hypervisor::Vmware, Network::Vmnet { number }) => {
            let name = format!("vmnet{number}");
            let label = if facts.vmware_nat.as_deref() == Some(name.as_str()) {
                format!("NAT ({name})")
            } else {
                name.clone()
            };
            Ok(vmnet(name, label))
        }
        (Hypervisor::VirtualBox, Network::HostOnly) => {
            let Some(adapter) = host_adapter.map(str::trim).filter(|a| !a.is_empty()) else {
                return invalid("Pick VirtualBox's host-only adapter the pool is on.");
            };
            let listed = facts.host_only.iter().find(|(n, _)| n.eq_ignore_ascii_case(adapter));
            if facts.virtualbox && listed.is_none() {
                return invalid(format!("VirtualBox has no host-only adapter named '{adapter}'."));
            }
            Ok(ResolvedNetwork {
                key: format!("virtualbox:hostonly:{}", adapter.to_lowercase()),
                label: format!("host-only adapter '{adapter}'"),
                subnet: listed.and_then(|(_, s)| *s),
            })
        }
        (Hypervisor::VirtualBox, other @ (Network::Nat | Network::NatNetwork { .. } | Network::Internal { .. })) => {
            invalid(no_host_adapter(other))
        }
        (hypervisor, other) => invalid(format!(
            "The network {} isn't {}'s.",
            other.describe(),
            hypervisor_label(hypervisor)
        )),
    }
}

/// A name as kept: trimmed, one line, no control or invisible formatting character.
pub fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("Give the address pool a name.");
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return invalid(format!(
            "An address pool's name can be at most {MAX_NAME_CHARS} characters."
        ));
    }
    if name
        .chars()
        .any(|c| c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return invalid("An address pool's name can't hold line breaks, tabs or invisible characters.");
    }
    Ok(name.to_owned())
}

/// Two names are one when they are the same without letter case (beyond ASCII too, as the editor folds them).
pub fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

fn clean_adapter(adapter: Option<&str>) -> Result<String> {
    let Some(adapter) = adapter.map(str::trim).filter(|a| !a.is_empty()) else {
        return invalid("Pick VirtualBox's host-only adapter the pool is on.");
    };
    if adapter.chars().count() > MAX_ADAPTER_CHARS {
        return invalid(format!(
            "An adapter's name can be at most {MAX_ADAPTER_CHARS} characters."
        ));
    }
    if adapter.chars().any(|c| c.is_control() || is_format_char(c)) {
        return invalid("An adapter's name can't hold control or invisible characters.");
    }
    Ok(adapter.to_owned())
}

fn clean_notes(notes: Option<&str>) -> Result<Option<String>> {
    let Some(notes) = notes.map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(None);
    };
    if notes.chars().count() > MAX_NOTES {
        return invalid(format!("Notes can be at most {MAX_NOTES} characters."));
    }
    let notes = notes.replace("\r\n", "\n");
    if notes
        .chars()
        .any(|c| (c.is_control() && c != '\n' && c != '\t') || is_format_char(c))
    {
        return invalid("Notes can't hold control or invisible characters.");
    }
    Ok(Some(notes))
}

/// An IPv4 address a VM can have, a gateway or a DNS server: not in 0.0.0.0/8, loopback, link-local, multicast,
/// reserved or the broadcast address.
pub fn parse_ip(what: &str, text: &str) -> Result<Ipv4Addr> {
    let text = text.trim();
    if text.is_empty() {
        return invalid(format!("Give the {what}."));
    }
    let Ok(ip) = text.parse::<Ipv4Addr>() else {
        if text.parse::<Ipv6Addr>().is_ok() {
            return invalid(format!("The {what} is an IPv6 address: address pools are IPv4 only."));
        }
        return invalid(format!(
            "The {what} '{text}' isn't an IPv4 address, such as 192.0.2.10."
        ));
    };
    let first = ip.octets()[0];
    if first == 0 || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || first >= 240 {
        return invalid(format!("The {what} {ip} can't be used on a network."));
    }
    Ok(ip)
}

/// Checks and tidies what the editor sends. Whether the network is there and two pools overlap is the service's
/// business ([`resolve_network`]).
pub fn check_pool(input: &AddressPoolInput) -> Result<PoolSpec> {
    let name = clean_name(&input.name)?;
    let network = check_network(&input.network)?;
    if let Some(only) = network.only_on() {
        if only != input.hypervisor {
            return invalid(format!(
                "The network {} is {}'s; pick one {} has.",
                network.describe(),
                hypervisor_label(only),
                hypervisor_label(input.hypervisor)
            ));
        }
    }
    let host_adapter = match (input.hypervisor, &network) {
        (Hypervisor::VirtualBox, Network::HostOnly) => Some(clean_adapter(input.host_adapter.as_deref())?),
        (Hypervisor::VirtualBox, Network::Nat | Network::NatNetwork { .. } | Network::Internal { .. }) => {
            return invalid(no_host_adapter(&network));
        }
        _ => None,
    };
    let prefix = input.prefix;
    if !(MIN_PREFIX..=MAX_PREFIX).contains(&prefix) {
        return invalid(format!("The prefix length is /{MIN_PREFIX} to /{MAX_PREFIX}."));
    }
    let first = parse_ip("first address", &input.first_ip)?;
    let last = parse_ip("last address", &input.last_ip)?;
    let (from, to) = (u32::from(first), u32::from(last));
    if from > to {
        return invalid(format!("The first address {first} comes after the last {last}."));
    }
    let mask = mask(prefix);
    let subnet = from & mask;
    if to & mask != subnet {
        return invalid(format!(
            "{first} and {last} are in different /{prefix} subnets: a pool is one subnet."
        ));
    }
    let network_address = Ipv4Addr::from(subnet);
    let broadcast = Ipv4Addr::from(subnet | !mask);
    if first == network_address {
        return invalid(format!(
            "{first} is the subnet's own address ({first}/{prefix}): start at {} or later.",
            Ipv4Addr::from(subnet + 1)
        ));
    }
    if last == broadcast {
        return invalid(format!(
            "{last} is the subnet's broadcast address: end at {} or earlier.",
            Ipv4Addr::from((subnet | !mask) - 1)
        ));
    }
    if to - from + 1 > MAX_RANGE {
        return invalid(format!(
            "A pool spans at most {MAX_RANGE} addresses; {first} to {last} is {}.",
            to - from + 1
        ));
    }
    let gateway = match input.gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
        None => None,
        Some(text) => {
            let gateway = parse_ip("gateway", text)?;
            let at = u32::from(gateway);
            if at & mask != subnet || gateway == network_address || gateway == broadcast {
                return invalid(format!(
                    "The gateway {gateway} isn't an address of {network_address}/{prefix}, the pool's subnet."
                ));
            }
            Some(gateway)
        }
    };
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    for text in input.dns.iter().map(|d| d.trim()).filter(|d| !d.is_empty()) {
        let server = parse_ip("DNS server", text)?;
        if server == network_address || server == broadcast {
            return invalid(format!(
                "The DNS server {server} is the subnet's own or broadcast address, which no server has."
            ));
        }
        if !dns.contains(&server) {
            dns.push(server);
        }
    }
    if dns.len() > MAX_DNS {
        return invalid(format!("A pool gives its VMs at most {MAX_DNS} DNS servers."));
    }
    Ok(PoolSpec {
        name,
        hypervisor: input.hypervisor,
        network,
        host_adapter,
        first,
        last,
        prefix,
        gateway,
        dns,
        notes: clean_notes(input.notes.as_deref())?,
    })
}

/// Refuses a range outside the subnet the hypervisor gives the network.
fn check_in_subnet(spec: &PoolSpec, resolved: &ResolvedNetwork) -> Result<()> {
    let Some((base, bits)) = resolved.subnet else {
        return Ok(());
    };
    let m = mask(bits);
    let inside = |ip: Ipv4Addr| u32::from(ip) & m == u32::from(base) & m;
    if inside(spec.first) && inside(spec.last) {
        Ok(())
    } else {
        invalid(format!(
            "{} is on {base}/{bits}: the pool's range must be in that subnet.",
            resolved.label
        ))
    }
}

fn overlaps(a: &PoolSpec, b: &PoolSpec) -> bool {
    u32::from(a.first) <= u32::from(b.last) && u32::from(b.first) <= u32::from(a.last)
}

/// "web-1, web-2 and 3 more".
fn names_of(leases: &[AddressLease]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for lease in leases {
        if !names.contains(&lease.vm_name.as_str()) {
            names.push(&lease.vm_name);
        }
    }
    let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
    if names.len() > 5 {
        format!("{shown} and {} more", names.len() - 5)
    } else {
        shown
    }
}

/// A claim that holds nothing: no VM, and its deploy isn't running.
fn stale(lease: &AddressLease) -> bool {
    lease.state == LeaseState::Claimed && lease.can_free
}

/// What one address's check found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Probe {
    /// Nothing answered a ping or ARP.
    Free,
    /// Something is there.
    InUse,
    /// Remotely couldn't check it.
    Unknown(String),
}

/// One ping and one ARP request to `ip`, at once.
async fn probe(tools: &Arc<dyn NetworkTools>, ip: Ipv4Addr) -> Probe {
    let (echo, arp) = tokio::join!(
        tools.echo(EchoRequest {
            to: IpAddr::V4(ip),
            ttl: 128,
            size: 32,
            timeout: PING_TIMEOUT,
        }),
        tools.arp(ip),
    );
    let echo_in_use = match &echo {
        Ok(Echo::Reply { .. }) => true,
        // "Protocol unreachable" and the like from the address itself: a host is there.
        Ok(Echo::Unreachable { from: Some(from), .. }) => *from == IpAddr::V4(ip),
        _ => false,
    };
    if echo_in_use || matches!(arp, Ok(Some(true))) {
        return Probe::InUse;
    }
    if let Err(err) = echo {
        return Probe::Unknown(err.to_string());
    }
    if let Err(err) = arp {
        return Probe::Unknown(err.to_string());
    }
    Probe::Free
}

/// A claim's row while it is checked: dropped before [`ClaimGuard::keep`] (the job's cancel drops the claim's future
/// wherever it waits), it deletes the row on the runtime, so no claim outlives its check.
struct ClaimGuard {
    store: Store,
    ctx: Context,
    pool_id: Uuid,
    ip: Ipv4Addr,
    job_id: Uuid,
    armed: bool,
}

impl ClaimGuard {
    fn keep(mut self) {
        self.armed = false;
    }

    async fn undo(mut self) -> Result<()> {
        self.armed = false;
        self.store
            .delete_address_claim(&self.ctx, self.pool_id, self.ip, self.job_id)
            .await
            .map(drop)
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (store, ctx, pool_id, ip, job_id) = (self.store.clone(), self.ctx, self.pool_id, self.ip, self.job_id);
        runtime.spawn(async move {
            if let Err(err) = store.delete_address_claim(&ctx, pool_id, ip, job_id).await {
                tracing::warn!(error = %err, "a cancelled address claim couldn't be taken back");
            }
        });
    }
}

type PickKey = (Uuid, usize, Vec<Ipv4Addr>);

#[derive(Debug, Clone)]
enum Picked {
    Found(Vec<PoolAddress>),
    TooFew(String),
}

/// Address pools of the shown workspace (`Core.address_pools`), and the deploy's claims on them.
#[derive(Clone)]
pub struct AddressPools {
    store: Store,
    tools: Arc<dyn NetworkTools>,
    /// VM-11's networks, for which network of this PC a pool is on. Without them, Workstation's NAT is vmnet8 and
    /// VirtualBox's adapters aren't checked.
    networks: Option<HostNetworks>,
    facts: Arc<tokio::sync::Mutex<Option<(Instant, NetworkFacts)>>>,
    picks: Arc<Mutex<HashMap<PickKey, (Instant, Picked)>>>,
}

impl AddressPools {
    pub fn new(store: Store, tools: Arc<dyn NetworkTools>) -> Self {
        Self {
            store,
            tools,
            networks: None,
            facts: Arc::new(tokio::sync::Mutex::new(None)),
            picks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolves pools' networks through VM-11's host network report.
    pub fn with_networks(mut self, networks: HostNetworks) -> Self {
        self.networks = Some(networks);
        self
    }

    /// VM-11's networks, read again when `fresh` or older than [`FACTS_FRESH`].
    async fn facts(&self, fresh: bool) -> NetworkFacts {
        let Some(networks) = &self.networks else {
            return NetworkFacts::default();
        };
        let mut cached = self.facts.lock().await;
        if let (false, Some((at, facts))) = (fresh, cached.as_ref()) {
            if at.elapsed() < FACTS_FRESH {
                return facts.clone();
            }
        }
        let facts = NetworkFacts::of(&networks.networks_only().await);
        *cached = Some((Instant::now(), facts.clone()));
        facts
    }

    fn forget_picks(&self) {
        locks::lock(&self.picks).clear();
    }

    fn cached_pick(&self, key: &PickKey) -> Option<Result<Vec<PoolAddress>>> {
        let mut picks = locks::lock(&self.picks);
        picks.retain(|_, (at, _)| at.elapsed() < PICK_FRESH);
        picks.get(key).map(|(_, picked)| match picked {
            Picked::Found(found) => Ok(found.clone()),
            Picked::TooFew(message) => Err(CoreError::InvalidInput(message.clone())),
        })
    }

    fn remember_pick(&self, key: PickKey, picked: Picked) {
        locks::lock(&self.picks).insert(key, (Instant::now(), picked));
    }

    async fn row(&self, ctx: &Context, id: Uuid) -> Result<PoolRow> {
        self.store
            .get_address_pool(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("address pool {id}")))
    }

    /// The network of this PC the pool is on now; its saved key follows when the network moved.
    async fn resolve_row(&self, ctx: &Context, row: &PoolRow) -> Result<ResolvedNetwork> {
        let facts = self.facts(false).await;
        let spec = &row.spec;
        let resolved = resolve_network(spec.hypervisor, &spec.network, spec.host_adapter.as_deref(), &facts)?;
        if !resolved.key.eq_ignore_ascii_case(&row.network_key) {
            self.store.set_address_pool_key(ctx, row.id, &resolved.key).await?;
        }
        Ok(resolved)
    }

    /// Refuses a pool whose subnet no adapter of this PC is on: a ping or ARP would mean nothing there.
    async fn on_link(&self, spec: &PoolSpec, resolved: &ResolvedNetwork) -> Result<()> {
        let adapters =
            self.tools.adapters().await.map_err(|err| {
                CoreError::Network(format!("Remotely couldn't read this PC's network adapters: {err}"))
            })?;
        let on = adapters
            .iter()
            .filter(|a| a.up && !a.loopback)
            .flat_map(|a| a.addresses.iter())
            .any(|a| match a.address {
                IpAddr::V4(own) if a.prefix > 0 => {
                    let m = mask(a.prefix);
                    let base = u32::from(own) & m;
                    u32::from(spec.first) & m == base && u32::from(spec.last) & m == base
                }
                _ => false,
            });
        if on {
            return Ok(());
        }
        let subnet = Ipv4Addr::from(u32::from(spec.first) & mask(spec.prefix));
        invalid(format!(
            "This PC has no network adapter on {subnet}/{}, the subnet of '{}', so Remotely can't check which of its \
             addresses are free (a ping would leave through another network). Turn on this PC's adapter for {}, or \
             connect this PC to that network.",
            spec.prefix, spec.name, resolved.label
        ))
    }

    async fn views(&self, ctx: &Context, rows: Vec<PoolRow>) -> Result<Vec<AddressPool>> {
        let counts = self.store.address_lease_counts(ctx).await?;
        let elsewhere = self.store.leases_elsewhere(ctx).await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let used = counts.get(&row.id).copied().unwrap_or(0);
                let held = elsewhere
                    .iter()
                    .filter(|(key, ip)| key.eq_ignore_ascii_case(&row.network_key) && row.spec.contains(*ip))
                    .count();
                AddressPool::of(row, used, u32::try_from(held).unwrap_or(u32::MAX))
            })
            .collect())
    }

    /// The workspace's pools by name, each with how many of its addresses are taken.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<AddressPool>> {
        let rows = self.store.list_address_pools(ctx).await?;
        self.views(ctx, rows).await
    }

    /// One pool, with its counts.
    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<AddressPool> {
        let row = self.row(ctx, id).await?;
        let mut views = self.views(ctx, vec![row]).await?;
        views
            .pop()
            .ok_or_else(|| CoreError::UnknownTarget(format!("address pool {id}")))
    }

    /// The pool's taken addresses in this workspace, in address order.
    pub async fn leases(&self, ctx: &Context, pool_id: Uuid) -> Result<Vec<AddressLease>> {
        self.row(ctx, pool_id).await?;
        self.store.address_leases(ctx, Some(pool_id)).await
    }

    /// The pools a VM on `network` of `hypervisor` can take an address from, by name. A VirtualBox host-only deploy
    /// gets none here: it names its adapter ([`AddressPools::pools_for_adapter`]).
    pub async fn pools_for(
        &self,
        ctx: &Context,
        hypervisor: Hypervisor,
        network: &Network,
    ) -> Result<Vec<AddressPool>> {
        self.pools_for_adapter(ctx, hypervisor, network, None).await
    }

    /// The pools a VM on `network` of `hypervisor`, with VirtualBox's `host_adapter` (the deploy's), can take an
    /// address from, by name: those on the same network of this PC (Workstation's NAT and its vmnet are one).
    pub async fn pools_for_adapter(
        &self,
        ctx: &Context,
        hypervisor: Hypervisor,
        network: &Network,
        host_adapter: Option<&str>,
    ) -> Result<Vec<AddressPool>> {
        let facts = self.facts(false).await;
        let Ok(wanted) = resolve_network(hypervisor, network, host_adapter, &facts) else {
            return Ok(Vec::new());
        };
        let rows: Vec<PoolRow> = self
            .store
            .list_address_pools(ctx)
            .await?
            .into_iter()
            .filter(|row| {
                let spec = &row.spec;
                spec.hypervisor == hypervisor
                    && resolve_network(spec.hypervisor, &spec.network, spec.host_adapter.as_deref(), &facts)
                        .is_ok_and(|r| r.key.eq_ignore_ascii_case(&wanted.key))
            })
            .collect();
        self.views(ctx, rows).await
    }

    /// Refuses a second pool of the name, and one sharing an address with another of the workspace on the same network
    /// of this PC.
    async fn check_overlap(
        &self,
        ctx: &Context,
        spec: &PoolSpec,
        key: &str,
        facts: &NetworkFacts,
        except: Option<Uuid>,
    ) -> Result<()> {
        let pools = self.store.list_address_pools(ctx).await?;
        if pools.len() >= MAX_POOLS && except.is_none() {
            return invalid(format!(
                "A workspace keeps at most {MAX_POOLS} address pools; delete one first."
            ));
        }
        for other in pools.iter().filter(|p| Some(p.id) != except) {
            if same_name(&other.spec.name, &spec.name) {
                return invalid(format!("There is an address pool named '{}' already.", other.spec.name));
            }
            let other_key = resolve_network(
                other.spec.hypervisor,
                &other.spec.network,
                other.spec.host_adapter.as_deref(),
                facts,
            )
            .map_or_else(|_| other.network_key.clone(), |r| r.key);
            if other_key.eq_ignore_ascii_case(key) && overlaps(&other.spec, spec) {
                return invalid(format!(
                    "{} to {} overlaps '{}' ({} to {}) on the same network: two pools would hand out one address.",
                    spec.first, spec.last, other.spec.name, other.spec.first, other.spec.last
                ));
            }
        }
        Ok(())
    }

    /// Checks a pool against this PC's networks: the network of this PC it is, the subnet the hypervisor gives it,
    /// and the workspace's other pools.
    async fn place(&self, ctx: &Context, spec: &PoolSpec, except: Option<Uuid>) -> Result<ResolvedNetwork> {
        let facts = self.facts(true).await;
        let resolved = resolve_network(spec.hypervisor, &spec.network, spec.host_adapter.as_deref(), &facts)?;
        check_in_subnet(spec, &resolved)?;
        self.check_overlap(ctx, spec, &resolved.key, &facts, except).await?;
        Ok(resolved)
    }

    /// Adds a pool. Audited; refused while presenting with the lock on.
    pub async fn add(&self, ctx: &Context, input: AddressPoolInput) -> Result<AddressPool> {
        self.store.read_only().check(Change::AddressPools)?;
        let spec = check_pool(&input)?;
        let resolved = self.place(ctx, &spec, None).await?;
        let row = self.store.insert_address_pool(ctx, &spec, &resolved.key).await?;
        self.audit(ctx, &format!("Added address pool '{}'", spec.name), &spec.describe())
            .await?;
        self.forget_picks();
        self.get(ctx, row.id).await
    }

    /// Changes a pool. A range, gateway or DNS server that would take an address a VM holds is refused, and so is
    /// another hypervisor or network while VMs hold addresses. Audited; an unchanged pool writes nothing.
    pub async fn update(&self, ctx: &Context, id: Uuid, input: AddressPoolInput) -> Result<AddressPool> {
        self.store.read_only().check(Change::AddressPools)?;
        let spec = check_pool(&input)?;
        let before = self.row(ctx, id).await?;
        if before.spec == spec {
            return self.get(ctx, id).await;
        }
        let resolved = self.place(ctx, &spec, Some(id)).await?;
        let leases = self.store.address_leases(ctx, Some(id)).await?;
        let (gone, held): (Vec<AddressLease>, Vec<AddressLease>) = leases.into_iter().partition(stale);
        let moved = before.spec.hypervisor != spec.hypervisor
            || before.spec.network != spec.network
            || before.spec.host_adapter != spec.host_adapter;
        if !held.is_empty() && moved {
            return invalid(format!(
                "VMs hold addresses from '{}' ({}), so its hypervisor and network stay as they are.",
                before.spec.name,
                names_of(&held)
            ));
        }
        let outside: Vec<&AddressLease> = held.iter().filter(|l| !spec.contains(l.ip)).collect();
        if let Some(first) = outside.first() {
            return invalid(format!(
                "{} is {}'s and would fall outside the new range: keep it in the range{}.",
                first.ip,
                first.vm_name,
                if outside.len() > 1 {
                    format!(" (and {} more)", outside.len() - 1)
                } else {
                    String::new()
                }
            ));
        }
        let reserved = spec.reserved();
        if let Some(taken) = held.iter().find(|l| reserved.contains(&l.ip)) {
            return invalid(format!(
                "{} is {}'s, so it can't be the gateway or a DNS server.",
                taken.ip, taken.vm_name
            ));
        }
        // Claims of deploys that ended hold nothing; they go with the change.
        for lease in &gone {
            self.store.delete_address_lease(ctx, id, lease.ip).await?;
        }
        self.store.update_address_pool(ctx, id, &spec, &resolved.key).await?;
        let detail = if before.spec.describe() == spec.describe() {
            spec.describe()
        } else {
            format!("was {}; now {}", before.spec.describe(), spec.describe())
        };
        let action = if before.spec.name == spec.name {
            format!("Changed address pool '{}'", spec.name)
        } else {
            format!("Changed address pool '{}' (was '{}')", spec.name, before.spec.name)
        };
        self.audit(ctx, &action, &detail).await?;
        self.forget_picks();
        self.get(ctx, id).await
    }

    /// Deletes a pool, refused while a VM holds one of its addresses or a running deploy claims one. Audited.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::AddressPools)?;
        let row = self.row(ctx, id).await?;
        let leases = self.store.address_leases(ctx, Some(id)).await?;
        let (gone, held): (Vec<AddressLease>, Vec<AddressLease>) = leases.into_iter().partition(stale);
        if !held.is_empty() {
            let assigned: Vec<AddressLease> = held
                .iter()
                .filter(|l| l.state == LeaseState::Assigned)
                .cloned()
                .collect();
            return invalid(if assigned.is_empty() {
                format!(
                    "A deploy is taking addresses from '{}' ({}); delete it once the deploy ended.",
                    row.spec.name,
                    names_of(&held)
                )
            } else {
                format!(
                    "VMs hold addresses from '{}': {}. Delete those VMs first, or free the address of one that is gone.",
                    row.spec.name,
                    names_of(&assigned)
                )
            });
        }
        for lease in &gone {
            self.store.delete_address_lease(ctx, id, lease.ip).await?;
        }
        if !self.store.delete_address_pool(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("address pool {id}")));
        }
        self.forget_picks();
        self.audit(
            ctx,
            &format!("Deleted address pool '{}'", row.spec.name),
            &row.spec.describe(),
        )
        .await
    }

    /// Frees an address by hand: one whose VM no workspace lists, or whose deploy isn't running (the lease says so,
    /// `can_free`). Audited; refused while presenting with the lock on.
    pub async fn free(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr) -> Result<()> {
        self.store.read_only().check(Change::AddressPools)?;
        let row = self.row(ctx, pool_id).await?;
        let leases = self.store.address_leases(ctx, Some(pool_id)).await?;
        let Some(lease) = leases.iter().find(|l| l.ip == ip) else {
            return invalid(format!("{ip} isn't taken in '{}'.", row.spec.name));
        };
        if !lease.can_free {
            return invalid(match lease.state {
                LeaseState::Assigned => format!(
                    "{ip} is {}'s, which is still on the VMs page: deleting the VM frees it.",
                    lease.vm_name
                ),
                LeaseState::Claimed => format!("A deploy is making {} with {ip} now.", lease.vm_name),
            });
        }
        self.store.delete_address_lease(ctx, pool_id, ip).await?;
        self.forget_picks();
        self.audit(
            ctx,
            &format!("Freed an address of address pool '{}'", row.spec.name),
            &format!("{ip}, which was {}'s ({})", lease.vm_name, lease.state.as_str()),
        )
        .await
    }

    /// The next `count` addresses of the pool free now, lowest first: not held on its network in any workspace, not
    /// the gateway or a DNS server, not in `exclude`, and nothing answering a ping or ARP. Reserves nothing (a preview:
    /// the deploy claims each at its run), and the same question gets the same answer for [`PICK_FRESH`]. Fewer than
    /// `count` free: an error saying how many were, and why the others weren't.
    pub async fn pick(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        count: usize,
        exclude: &[Ipv4Addr],
    ) -> Result<Vec<PoolAddress>> {
        let pool = self.row(ctx, pool_id).await?;
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut excluded = exclude.to_vec();
        excluded.sort_unstable();
        excluded.dedup();
        let key: PickKey = (pool_id, count, excluded);
        if let Some(cached) = self.cached_pick(&key) {
            return cached;
        }
        let resolved = self.resolve_row(ctx, &pool).await?;
        self.on_link(&pool.spec, &resolved).await?;
        let here = ctx.workspace_id.to_string();
        let mut held_here: HashSet<Ipv4Addr> = HashSet::new();
        let mut held_elsewhere: HashSet<Ipv4Addr> = HashSet::new();
        for held in self.store.held_addresses(&resolved.key, pool_id).await? {
            if held.workspace_id == here {
                held_here.insert(held.ip);
            } else {
                held_elsewhere.insert(held.ip);
            }
        }
        let reserved = pool.spec.reserved();
        let in_range = |set: &HashSet<Ipv4Addr>| set.iter().filter(|ip| pool.spec.contains(**ip)).count();
        let (taken_here, taken_elsewhere) = (in_range(&held_here), in_range(&held_elsewhere));
        let elsewhere_note = match taken_elsewhere {
            0 => String::new(),
            1 => " (1 of them is held in another workspace)".to_owned(),
            n => format!(" ({n} of them are held in another workspace)"),
        };
        let candidates: Vec<Ipv4Addr> = (u32::from(pool.spec.first)..=u32::from(pool.spec.last))
            .map(Ipv4Addr::from)
            .filter(|ip| {
                !held_here.contains(ip) && !held_elsewhere.contains(ip) && !reserved.contains(ip) && !key.2.contains(ip)
            })
            .collect();
        let name = &pool.spec.name;
        if candidates.len() < count {
            let message = format!(
                "'{name}' has {} of its {} addresses not taken{elsewhere_note}; {count} were asked for.",
                candidates.len(),
                pool.spec.usable()
            );
            self.remember_pick(key, Picked::TooFew(message.clone()));
            return invalid(message);
        }
        let mut free: Vec<Ipv4Addr> = Vec::with_capacity(count);
        let (mut answering, mut unchecked) = (0usize, 0usize);
        for batch in candidates.chunks(PINGS_AT_ONCE) {
            let mut checks = tokio::task::JoinSet::new();
            for ip in batch.iter().copied() {
                let tools = Arc::clone(&self.tools);
                checks.spawn(async move { (ip, probe(&tools, ip).await) });
            }
            let mut found: Vec<(Ipv4Addr, Probe)> = Vec::with_capacity(batch.len());
            while let Some(done) = checks.join_next().await {
                match done {
                    Ok(result) => found.push(result),
                    Err(err) => tracing::warn!(error = %err, "an address check stopped"),
                }
            }
            found.sort_by_key(|(ip, _)| u32::from(*ip));
            unchecked += batch.len() - found.len();
            for (ip, result) in found {
                match result {
                    Probe::Free if free.len() < count => free.push(ip),
                    Probe::Free => {}
                    Probe::InUse => answering += 1,
                    Probe::Unknown(why) => {
                        tracing::warn!(%why, "an address of a pool couldn't be checked; it is skipped");
                        unchecked += 1;
                    }
                }
            }
            if free.len() >= count {
                let found: Vec<PoolAddress> = free.into_iter().map(|ip| PoolAddress::of(&pool, ip)).collect();
                self.remember_pick(key, Picked::Found(found.clone()));
                return Ok(found);
            }
        }
        let message = format!(
            "Only {} of the {count} addresses asked for are free in '{name}' now: {} of its {} addresses are \
             taken{elsewhere_note}, and something answers on {answering} more{}.",
            free.len(),
            taken_here + taken_elsewhere,
            pool.spec.usable(),
            match unchecked {
                0 => String::new(),
                n => format!(", and {n} couldn't be checked"),
            }
        );
        self.remember_pick(key, Picked::TooFew(message.clone()));
        invalid(message)
    }

    /// At a deploy job's run: records `ip` as `vm_name`'s (claimed, by `job_id`), refusing an address that isn't the
    /// pool's to give, is held on its network since (in this workspace or another), or where something answers now
    /// (the claim is then undone; dropped mid-check, its row goes too). The address with the pool's prefix, gateway and
    /// DNS servers.
    pub async fn claim(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        ip: Ipv4Addr,
        vm_name: &str,
        job_id: Uuid,
    ) -> Result<PoolAddress> {
        let pool = self.row(ctx, pool_id).await?;
        let name = &pool.spec.name;
        if !pool.spec.contains(ip) {
            return invalid(format!(
                "{ip} isn't in '{name}' ({} to {}).",
                pool.spec.first, pool.spec.last
            ));
        }
        if pool.spec.reserved().contains(&ip) {
            return invalid(format!("{ip} is '{name}''s gateway or DNS server, so no VM gets it."));
        }
        let resolved = self.resolve_row(ctx, &pool).await?;
        self.on_link(&pool.spec, &resolved).await?;
        // A claim whose deploy ended holds nothing.
        self.store.clear_stale_claims(&resolved.key, pool_id, ip).await?;
        if !self
            .store
            .insert_address_claim(ctx, pool_id, &resolved.key, ip, vm_name, job_id)
            .await?
        {
            let here = ctx.workspace_id.to_string();
            return invalid(match self.store.lease_holder(&resolved.key, pool_id, ip).await? {
                Some((workspace, holder)) if workspace == here => {
                    format!("{ip} of '{name}' went to '{holder}' since it was picked.")
                }
                Some(_) => format!(
                    "{ip} is held in another workspace on the same network, so '{vm_name}' doesn't get it. Pick \
                     another address."
                ),
                None => format!("{ip} of '{name}' was taken since it was picked."),
            });
        }
        self.forget_picks();
        let guard = ClaimGuard {
            store: self.store.clone(),
            ctx: *ctx,
            pool_id,
            ip,
            job_id,
            armed: true,
        };
        // The pool may have changed while the row went in.
        let now = match self.row(ctx, pool_id).await {
            Ok(now) => now,
            Err(err) => {
                guard.undo().await?;
                return Err(err);
            }
        };
        if !now.spec.contains(ip) || now.spec.reserved().contains(&ip) {
            guard.undo().await?;
            return invalid(format!("'{name}' changed: {ip} isn't one it hands out any more."));
        }
        match probe(&self.tools, ip).await {
            Probe::Free => {
                guard.keep();
                Ok(PoolAddress::of(&now, ip))
            }
            Probe::InUse => {
                guard.undo().await?;
                invalid(format!(
                    "Something on the network answers on {ip} now, so '{vm_name}' doesn't get it. Pick another address."
                ))
            }
            Probe::Unknown(why) => {
                guard.undo().await?;
                Err(CoreError::Network(format!(
                    "Remotely couldn't check that {ip} is free, so '{vm_name}' doesn't get it: {why}"
                )))
            }
        }
    }

    /// Once the VM is made: `job_id`'s claim of the address is the VM's (`vm_key`) until it is deleted. Refused for an
    /// address the job didn't claim, or one assigned already.
    pub async fn assign(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr, job_id: Uuid, vm_key: &str) -> Result<()> {
        if self
            .store
            .assign_address_lease(ctx, pool_id, ip, job_id, vm_key)
            .await?
        {
            self.forget_picks();
            Ok(())
        } else {
            invalid(format!(
                "{ip} isn't claimed by that deploy in that address pool, so it can't be the VM's."
            ))
        }
    }

    /// A step that failed before its VM was made: `job_id`'s claim of the address goes. Nothing else's.
    pub async fn release(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr, job_id: Uuid) -> Result<()> {
        self.store.delete_address_claim(ctx, pool_id, ip, job_id).await?;
        self.forget_picks();
        Ok(())
    }

    /// Everything `job_id` claimed and didn't assign to a VM goes back (a step's error or cancel, the job's end). How
    /// many went.
    pub async fn release_job_claims(&self, ctx: &Context, job_id: Uuid) -> Result<u64> {
        let gone = self.store.release_job_claims(ctx, job_id).await?;
        if gone > 0 {
            self.forget_picks();
        }
        Ok(gone)
    }

    /// Of `ips`, those held now on the pool's network, in this workspace or another: assigned to a VM, or claimed by a
    /// deploy that is running (not `except_job`). For the approval of a deploy whose preview picked them.
    pub async fn held_now(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        ips: &[Ipv4Addr],
        except_job: Option<Uuid>,
    ) -> Result<Vec<Ipv4Addr>> {
        let pool = self.row(ctx, pool_id).await?;
        let held: HashSet<Ipv4Addr> = self
            .store
            .held_addresses(&pool.network_key, pool_id)
            .await?
            .into_iter()
            .filter(|h| except_job.is_none() || h.job_id != except_job)
            .map(|h| h.ip)
            .collect();
        Ok(ips.iter().copied().filter(|ip| held.contains(ip)).collect())
    }

    /// Claims without a VM older than [`STALE_CLAIM_DAYS`] whose deploy isn't running: left by a deploy the app
    /// stopped in the middle of. (They count as free already; this deletes their rows.) How many went.
    pub async fn release_stale_claims(&self, ctx: &Context) -> Result<u64> {
        let before = time::OffsetDateTime::now_utc() - time::Duration::days(STALE_CLAIM_DAYS);
        let before = before
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let gone = self.store.release_stale_address_claims(ctx, &before).await?;
        if gone > 0 {
            tracing::info!(gone, "address claims left by deploys that never ended were released");
            self.forget_picks();
        }
        Ok(gone)
    }

    /// [`AddressPools::release_stale_claims`] in each of the user's workspaces, shown or not (at start).
    pub async fn release_stale_claims_everywhere(&self, user: UserId) -> Result<u64> {
        let mut gone = 0;
        for workspace in self.store.list_workspaces(user).await? {
            let ctx = Context {
                workspace_id: workspace.id,
                user_id: user,
            };
            gone += self.release_stale_claims(&ctx).await?;
        }
        Ok(gone)
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: EVENT,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail).filter(|d| !d.is_empty()),
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> AddressPoolInput {
        AddressPoolInput {
            name: " lab ".into(),
            hypervisor: Hypervisor::Vmware,
            network: Network::Nat,
            host_adapter: Some("ignored".into()),
            first_ip: "192.0.2.10".into(),
            last_ip: "192.0.2.50".into(),
            prefix: 24,
            gateway: Some("192.0.2.1".into()),
            dns: vec![
                "192.0.2.53".into(),
                " ".into(),
                "192.0.2.53".into(),
                "198.51.100.53".into(),
            ],
            notes: Some("  ".into()),
        }
    }

    fn refused(change: impl FnOnce(&mut AddressPoolInput), says: &str) {
        let mut bad = input();
        change(&mut bad);
        let err = check_pool(&bad).expect_err("refused").to_string();
        assert!(err.contains(says), "{err}");
    }

    #[test]
    fn a_pool_is_checked_and_tidied() {
        let spec = check_pool(&input()).unwrap();
        assert_eq!(spec.name, "lab");
        assert_eq!(
            spec.host_adapter, None,
            "only a VirtualBox host-only pool names an adapter"
        );
        assert_eq!(spec.first, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(
            spec.dns,
            [Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(198, 51, 100, 53)]
        );
        assert_eq!(spec.notes, None);
        assert_eq!(spec.size(), 41);
        assert_eq!(spec.usable(), 41, "the gateway and DNS servers are outside the range");
        assert_eq!(
            spec.describe(),
            "Workstation, NAT, 192.0.2.10 to 192.0.2.50 /24, gateway 192.0.2.1, DNS 192.0.2.53 198.51.100.53"
        );
        let mut inside = input();
        inside.gateway = Some("192.0.2.10".into());
        assert_eq!(check_pool(&inside).unwrap().usable(), 40);
    }

    #[test]
    fn ranges_are_one_ipv4_subnet_without_its_own_or_broadcast_address() {
        refused(|i| i.first_ip = "2001:db8::1".into(), "IPv4 only");
        refused(|i| i.first_ip = "192.0.2".into(), "isn't an IPv4 address");
        refused(|i| i.last_ip = String::new(), "Give the last address");
        refused(|i| i.first_ip = "192.0.2.60".into(), "comes after");
        refused(
            |i| {
                i.prefix = 25;
                i.first_ip = "192.0.2.100".into();
                i.last_ip = "192.0.2.200".into();
                i.gateway = None;
            },
            "different /25 subnets",
        );
        refused(|i| i.first_ip = "192.0.2.0".into(), "subnet's own address");
        refused(|i| i.last_ip = "192.0.2.255".into(), "broadcast address");
        refused(|i| i.prefix = 7, "/8 to /30");
        refused(|i| i.prefix = 31, "/8 to /30");
        refused(
            |i| {
                i.prefix = 16;
                i.first_ip = "198.18.0.1".into();
                i.last_ip = "198.18.16.1".into();
                i.gateway = None;
            },
            "at most 4096",
        );
        refused(|i| i.first_ip = "127.0.0.1".into(), "can't be used");
        refused(|i| i.first_ip = "169.254.0.10".into(), "can't be used");
        refused(
            |i| {
                i.prefix = 8;
                i.first_ip = "0.0.0.5".into();
                i.last_ip = "0.0.0.9".into();
                i.gateway = None;
            },
            "can't be used",
        );
        refused(|i| i.dns = vec!["224.0.0.1".into()], "can't be used");
        // /30: two addresses, between the subnet's own and its broadcast.
        let mut small = input();
        small.prefix = 30;
        small.first_ip = "203.0.113.5".into();
        small.last_ip = "203.0.113.6".into();
        small.gateway = None;
        assert_eq!(check_pool(&small).unwrap().size(), 2);
        // 4096 exactly is fine.
        let mut big = input();
        big.prefix = 16;
        big.first_ip = "198.18.0.1".into();
        big.last_ip = "198.18.16.0".into();
        big.gateway = None;
        assert_eq!(check_pool(&big).unwrap().size(), MAX_RANGE);
    }

    #[test]
    fn gateway_dns_names_and_networks_are_checked() {
        refused(
            |i| i.gateway = Some("198.51.100.1".into()),
            "isn't an address of 192.0.2.0/24",
        );
        refused(|i| i.gateway = Some("192.0.2.255".into()), "isn't an address of");
        refused(
            |i| {
                i.dns = vec![
                    "192.0.2.1".into(),
                    "192.0.2.2".into(),
                    "192.0.2.3".into(),
                    "192.0.2.4".into(),
                ]
            },
            "at most 3 DNS servers",
        );
        refused(|i| i.dns = vec!["192.0.2.255".into()], "own or broadcast address");
        refused(|i| i.dns = vec!["192.0.2.0".into()], "own or broadcast address");
        refused(|i| i.name = "  ".into(), "Give the address pool a name");
        refused(|i| i.name = "a\tb".into(), "invisible");
        refused(|i| i.name = "lab\u{202E}".into(), "invisible");
        refused(|i| i.name = "x".repeat(MAX_NAME_CHARS + 1), "at most 60");
        refused(|i| i.network = Network::Vmnet { number: 20 }, "vmnet0 to vmnet19");
        refused(
            |i| i.network = Network::NatNetwork { name: "lab".into() },
            "is VirtualBox's",
        );
        refused(
            |i| {
                i.hypervisor = Hypervisor::VirtualBox;
                i.network = Network::Vmnet { number: 2 };
            },
            "is Workstation's",
        );
        refused(|i| i.notes = Some("a\u{0}b".into()), "invisible");
        assert!(same_name("Läb", "LÄB"), "beyond ASCII, as the editor folds names");
    }

    #[test]
    fn virtualbox_pools_name_their_host_only_adapter_and_never_sit_where_this_pc_has_none() {
        let vbox = |network: Network, adapter: Option<&str>| {
            let mut i = input();
            i.hypervisor = Hypervisor::VirtualBox;
            i.network = network;
            i.host_adapter = adapter.map(str::to_owned);
            check_pool(&i)
        };
        let spec = vbox(Network::HostOnly, Some("  vboxnet0 ")).unwrap();
        assert_eq!(spec.host_adapter.as_deref(), Some("vboxnet0"));
        assert!(spec.describe().contains("host-only adapter 'vboxnet0'"));
        let err = vbox(Network::HostOnly, None).unwrap_err().to_string();
        assert!(err.contains("Pick VirtualBox's host-only adapter"), "{err}");
        for network in [
            Network::Nat,
            Network::NatNetwork { name: "lab".into() },
            Network::Internal { name: "lab".into() },
        ] {
            let err = vbox(network, None).unwrap_err().to_string();
            assert!(err.contains("This PC has no adapter on VirtualBox's"), "{err}");
        }
        assert_eq!(vbox(Network::Bridged, Some("x")).unwrap().host_adapter, None);
    }

    fn facts() -> NetworkFacts {
        NetworkFacts {
            vmware_nat: Some("vmnet3".into()),
            vmnets: vec![
                ("vmnet1".into(), Some((Ipv4Addr::new(198, 51, 100, 0), 24))),
                ("vmnet3".into(), Some((Ipv4Addr::new(192, 0, 2, 0), 24))),
            ],
            virtualbox: true,
            host_only: vec![("vboxnet0".into(), Some((Ipv4Addr::new(203, 0, 113, 0), 24)))],
        }
    }

    #[test]
    fn one_network_of_this_pc_has_one_key_whatever_it_is_called() {
        let facts = facts();
        let key = |hv: Hypervisor, network: Network, adapter: Option<&str>| {
            resolve_network(hv, &network, adapter, &facts).map(|r| r.key)
        };
        // The Virtual Network Editor made vmnet3 the NAT network.
        assert_eq!(key(Hypervisor::Vmware, Network::Nat, None).unwrap(), "vmware:vmnet3");
        assert_eq!(
            key(Hypervisor::Vmware, Network::Vmnet { number: 3 }, None).unwrap(),
            "vmware:vmnet3"
        );
        assert_eq!(
            key(Hypervisor::Vmware, Network::Vmnet { number: 8 }, None).unwrap(),
            "vmware:vmnet8"
        );
        assert_eq!(
            key(Hypervisor::Vmware, Network::HostOnly, None).unwrap(),
            "vmware:vmnet1"
        );
        assert_eq!(
            key(Hypervisor::Vmware, Network::Vmnet { number: 1 }, None).unwrap(),
            "vmware:vmnet1"
        );
        // Bridged is this PC's LAN, whichever hypervisor bridges to it.
        assert_eq!(
            key(Hypervisor::Vmware, Network::Vmnet { number: 0 }, None).unwrap(),
            BRIDGED_KEY
        );
        assert_eq!(key(Hypervisor::Vmware, Network::Bridged, None).unwrap(), BRIDGED_KEY);
        assert_eq!(
            key(Hypervisor::VirtualBox, Network::Bridged, None).unwrap(),
            BRIDGED_KEY
        );
        assert_eq!(
            key(Hypervisor::VirtualBox, Network::HostOnly, Some("VBoxNet0")).unwrap(),
            "virtualbox:hostonly:vboxnet0"
        );
        assert!(key(Hypervisor::VirtualBox, Network::HostOnly, Some("vboxnet9"))
            .unwrap_err()
            .to_string()
            .contains("no host-only adapter named 'vboxnet9'"));
        assert!(key(Hypervisor::VirtualBox, Network::HostOnly, None).is_err());
        assert!(key(Hypervisor::VirtualBox, Network::Nat, None).is_err());
        // Without Workstation's list, its NAT is vmnet8.
        let none = NetworkFacts::default();
        assert_eq!(
            resolve_network(Hypervisor::Vmware, &Network::Nat, None, &none)
                .unwrap()
                .key,
            "vmware:vmnet8"
        );
        // The subnet the hypervisor gives a network bounds the pool's range.
        let nat = resolve_network(Hypervisor::Vmware, &Network::Nat, None, &facts).unwrap();
        let mut spec = check_pool(&input()).unwrap();
        assert!(check_in_subnet(&spec, &nat).is_ok());
        spec.first = Ipv4Addr::new(198, 51, 100, 10);
        spec.last = Ipv4Addr::new(198, 51, 100, 20);
        let err = check_in_subnet(&spec, &nat).unwrap_err().to_string();
        assert!(err.contains("NAT (vmnet3) is on 192.0.2.0/24"), "{err}");
    }

    #[test]
    fn subnets_come_from_contiguous_masks_only() {
        assert_eq!(
            subnet_of(Some("192.0.2.1"), Some("255.255.255.0")),
            Some((Ipv4Addr::new(192, 0, 2, 0), 24))
        );
        assert_eq!(subnet_of(Some("192.0.2.1"), Some("255.0.255.0")), None);
        assert_eq!(subnet_of(None, Some("255.255.255.0")), None);
    }

    #[test]
    fn overlaps_are_ranges_sharing_an_address() {
        let a = check_pool(&input()).unwrap();
        let mut b = a.clone();
        assert!(overlaps(&a, &b));
        b.first = Ipv4Addr::new(192, 0, 2, 51);
        b.last = Ipv4Addr::new(192, 0, 2, 60);
        assert!(!overlaps(&a, &b));
    }
}
