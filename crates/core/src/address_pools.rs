//! VM-32 (0.8.0 G6): address pools: static IPv4 addresses for unattended deploys, per network of one hypervisor and per
//! workspace (rule 8: every call takes the ctx it acts in, every row carries its workspace).
//!
//! * A pool is the user's own data, like the catalogue: adding, changing and deleting one is audited
//!   (`address_pool_changed`, no approval tier) and refused by the read-only lock ([`Change::AddressPools`]). Nothing here
//!   touches a VM, so it skips the command bus. Pools are not in the trash and not in FD-07 exports: they describe this
//!   PC's networks, and their leases the VMs made here.
//! * [`check_pool`] checks what the editor sends: IPv4 only; first and last in one subnet of the prefix (/8 to /30),
//!   neither its network nor its broadcast address, at most [`MAX_RANGE`] addresses; the gateway in that subnet; at most
//!   [`MAX_DNS`] DNS servers; a network the hypervisor has. Two pools of a workspace never share an address on one
//!   network (bridged networks are this PC's LAN whichever hypervisor bridges to it).
//! * An address is handed out only when nothing answers on it: one ICMP echo through the toolbox's
//!   [`NetworkTools`] ([`PING_TIMEOUT`], [`PINGS_AT_ONCE`] at a time). A host whose firewall drops pings looks free, which
//!   is why a deploy's claim pings again just before the VM is made, and why leases are kept: the pool never hands out an
//!   address it gave a VM.
//! * The deploy (G6) asks [`AddressPools::pick`] for a preview, then at each VM's step [`AddressPools::claim`]s the
//!   address (a row of its own: of two claims of one address, one wins), [`AddressPools::assign`]s it to the VM once it
//!   is made, or [`AddressPools::release`]s it when the step failed. The lease stays the VM's until Remotely deletes the
//!   VM (VM-24's delete, a stack teardown too: `Store::free_vm_leases`). A claim left by a restart mid-deploy goes after
//!   a day ([`AddressPools::release_stale_claims`], at start). A VM deleted outside Remotely leaves its lease, which the
//!   user can free by hand ([`AddressPools::free`], audited) once the VM is gone from the VMs page.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::net_tools::{Echo, EchoRequest, NetworkTools};
use crate::catalog::templates::{check_network, hypervisor_label, Network};
use crate::domain::{Context, UserId};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};
use crate::untrusted::is_format_char;

/// Pools one workspace keeps.
pub const MAX_POOLS: usize = 100;
/// The longest name, in characters.
pub const MAX_NAME_CHARS: usize = 60;
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
/// Pings sent at once while looking for free addresses.
pub const PINGS_AT_ONCE: usize = 8;
/// A claim without a VM older than this was left by a deploy that never ended (the app stopped mid-deploy).
pub const STALE_CLAIM_DAYS: i64 = 1;

const EVENT: &str = "address_pool_changed";

/// What the editor sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPoolInput {
    pub name: String,
    pub hypervisor: Hypervisor,
    pub network: Network,
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

    /// "Workstation, NAT, 192.0.2.10 to 192.0.2.50 /24, gateway 192.0.2.1, DNS 192.0.2.53", for the audit log.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "{}, {}, {} to {} /{}",
            hypervisor_label(self.hypervisor),
            self.network.describe(),
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
    /// Leased: assigned to a VM, or claimed by a deploy now.
    pub used: u32,
    /// `usable - used`: not leased. Whether something answers on them is checked only when one is picked.
    pub free: u32,
    pub created_at: String,
    pub updated_at: String,
}

impl AddressPool {
    fn of(row: PoolRow, used: u32) -> Self {
        let usable = row.spec.usable();
        Self {
            id: row.id,
            size: row.spec.size(),
            usable,
            used,
            free: usable.saturating_sub(used),
            name: row.spec.name,
            hypervisor: row.spec.hypervisor,
            network: row.spec.network,
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
    /// The address can be freed by hand ([`AddressPools::free`]): its VM is gone from this workspace's VMs (deleted
    /// outside Remotely, or taken out of the workspace), or its claim's deploy isn't running.
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

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// The subnet mask of `prefix` (8 to 30).
fn mask(prefix: u8) -> u32 {
    u32::MAX << (32 - u32::from(prefix.clamp(1, 32)))
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

/// An IPv4 address a VM can have, a gateway or a DNS server: not 0.0.0.0, loopback, link-local, multicast, reserved
/// or the broadcast address.
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
    if ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || first >= 240 {
        return invalid(format!("The {what} {ip} can't be used on a network."));
    }
    Ok(ip)
}

/// Checks and tidies what the editor sends. Whether two pools overlap is the service's business.
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
        first,
        last,
        prefix,
        gateway,
        dns,
        notes: clean_notes(input.notes.as_deref())?,
    })
}

/// Whether two pools' VMs would meet on one network: the same network of one hypervisor, or bridged networks (this
/// PC's LAN, whichever hypervisor bridges to it).
fn same_network(a: &PoolSpec, b: &PoolSpec) -> bool {
    (a.network == Network::Bridged && b.network == Network::Bridged)
        || (a.hypervisor == b.hypervisor && a.network == b.network)
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

/// Address pools of the shown workspace (`Core.address_pools`), and the deploy's claims on them.
#[derive(Clone)]
pub struct AddressPools {
    store: Store,
    tools: Arc<dyn NetworkTools>,
}

impl AddressPools {
    pub fn new(store: Store, tools: Arc<dyn NetworkTools>) -> Self {
        Self { store, tools }
    }

    async fn row(&self, ctx: &Context, id: Uuid) -> Result<PoolRow> {
        self.store
            .get_address_pool(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("address pool {id}")))
    }

    /// The workspace's pools by name, each with how many of its addresses are taken.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<AddressPool>> {
        let counts = self.store.address_lease_counts(ctx).await?;
        Ok(self
            .store
            .list_address_pools(ctx)
            .await?
            .into_iter()
            .map(|row| {
                let used = counts.get(&row.id).copied().unwrap_or(0);
                AddressPool::of(row, used)
            })
            .collect())
    }

    /// One pool, with its counts.
    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<AddressPool> {
        let row = self.row(ctx, id).await?;
        let used = self.store.address_leases(ctx, Some(id)).await?.len();
        Ok(AddressPool::of(row, u32::try_from(used).unwrap_or(u32::MAX)))
    }

    /// The pool's taken addresses, in address order.
    pub async fn leases(&self, ctx: &Context, pool_id: Uuid) -> Result<Vec<AddressLease>> {
        self.row(ctx, pool_id).await?;
        self.store.address_leases(ctx, Some(pool_id)).await
    }

    /// The pools a VM on `network` of `hypervisor` can take an address from, by name.
    pub async fn pools_for(
        &self,
        ctx: &Context,
        hypervisor: Hypervisor,
        network: &Network,
    ) -> Result<Vec<AddressPool>> {
        let Ok(network) = check_network(network) else {
            return Ok(Vec::new());
        };
        Ok(self
            .list(ctx)
            .await?
            .into_iter()
            .filter(|p| p.hypervisor == hypervisor && p.network == network)
            .collect())
    }

    /// Refuses a pool sharing an address with another of the workspace on the same network.
    async fn check_overlap(&self, ctx: &Context, spec: &PoolSpec, except: Option<Uuid>) -> Result<()> {
        let pools = self.store.list_address_pools(ctx).await?;
        if pools.len() >= MAX_POOLS && except.is_none() {
            return invalid(format!(
                "A workspace keeps at most {MAX_POOLS} address pools; delete one first."
            ));
        }
        for other in pools.iter().filter(|p| Some(p.id) != except) {
            if other.spec.name.eq_ignore_ascii_case(&spec.name) {
                return invalid(format!("There is an address pool named '{}' already.", other.spec.name));
            }
            if same_network(&other.spec, spec) && overlaps(&other.spec, spec) {
                return invalid(format!(
                    "{} to {} overlaps '{}' ({} to {}) on the same network: two pools would hand out one address.",
                    spec.first, spec.last, other.spec.name, other.spec.first, other.spec.last
                ));
            }
        }
        Ok(())
    }

    /// Adds a pool. Audited; refused while presenting with the lock on.
    pub async fn add(&self, ctx: &Context, input: AddressPoolInput) -> Result<AddressPool> {
        self.store.read_only().check(Change::AddressPools)?;
        let spec = check_pool(&input)?;
        self.check_overlap(ctx, &spec, None).await?;
        let row = self.store.insert_address_pool(ctx, &spec).await?;
        self.audit(ctx, &format!("Added address pool '{}'", spec.name), &spec.describe())
            .await?;
        Ok(AddressPool::of(row, 0))
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
        self.check_overlap(ctx, &spec, Some(id)).await?;
        let leases = self.store.address_leases(ctx, Some(id)).await?;
        if !leases.is_empty() && (before.spec.hypervisor != spec.hypervisor || before.spec.network != spec.network) {
            return invalid(format!(
                "VMs hold addresses from '{}' ({}), so its hypervisor and network stay as they are.",
                before.spec.name,
                names_of(&leases)
            ));
        }
        let outside: Vec<AddressLease> = leases.iter().filter(|l| !spec.contains(l.ip)).cloned().collect();
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
        if let Some(taken) = leases.iter().find(|l| reserved.contains(&l.ip)) {
            return invalid(format!(
                "{} is {}'s, so it can't be the gateway or a DNS server.",
                taken.ip, taken.vm_name
            ));
        }
        self.store.update_address_pool(ctx, id, &spec).await?;
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
        self.get(ctx, id).await
    }

    /// Deletes a pool, refused while a VM holds one of its addresses or a deploy claims one. Audited.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::AddressPools)?;
        let row = self.row(ctx, id).await?;
        let leases = self.store.address_leases(ctx, Some(id)).await?;
        if !leases.is_empty() {
            let held: Vec<AddressLease> = leases
                .iter()
                .filter(|l| l.state == LeaseState::Assigned)
                .cloned()
                .collect();
            return invalid(if held.is_empty() {
                format!(
                    "A deploy is taking addresses from '{}' ({}); delete it once the deploy ended.",
                    row.spec.name,
                    names_of(&leases)
                )
            } else {
                format!(
                    "VMs hold addresses from '{}': {}. Delete those VMs first, or free the address of one that is gone.",
                    row.spec.name,
                    names_of(&held)
                )
            });
        }
        if !self.store.delete_address_pool(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("address pool {id}")));
        }
        self.audit(
            ctx,
            &format!("Deleted address pool '{}'", row.spec.name),
            &row.spec.describe(),
        )
        .await
    }

    /// Frees an address by hand: one whose VM is gone from the workspace's VMs, or whose deploy isn't running (the
    /// lease says so, `can_free`). Audited; refused while presenting with the lock on.
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
        self.audit(
            ctx,
            &format!("Freed an address of address pool '{}'", row.spec.name),
            &format!("{ip}, which was {}'s ({})", lease.vm_name, lease.state.as_str()),
        )
        .await
    }

    /// Whether something answers a ping at `ip` now.
    async fn answers(tools: &Arc<dyn NetworkTools>, ip: Ipv4Addr) -> Result<bool> {
        let echo = tools
            .echo(EchoRequest {
                to: IpAddr::V4(ip),
                ttl: 128,
                size: 32,
                timeout: PING_TIMEOUT,
            })
            .await
            .map_err(|err| CoreError::Network(format!("Remotely couldn't ping {ip} to check it is free: {err}")))?;
        Ok(matches!(echo, Echo::Reply { .. }))
    }

    /// The next `count` addresses of the pool free now, lowest first: not leased, not the gateway or a DNS server, not
    /// in `exclude`, and no answer to a ping. Reserves nothing (a preview: the deploy claims each at its run). Fewer
    /// than `count` free: an error saying how many were.
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
        let leased: HashSet<Ipv4Addr> = self
            .store
            .address_leases(ctx, Some(pool_id))
            .await?
            .into_iter()
            .map(|l| l.ip)
            .collect();
        let reserved = pool.spec.reserved();
        let candidates: Vec<Ipv4Addr> = (u32::from(pool.spec.first)..=u32::from(pool.spec.last))
            .map(Ipv4Addr::from)
            .filter(|ip| !leased.contains(ip) && !reserved.contains(ip) && !exclude.contains(ip))
            .collect();
        let name = &pool.spec.name;
        if candidates.len() < count {
            return invalid(format!(
                "'{name}' has {} of its {} addresses not taken; {count} were asked for.",
                candidates.len(),
                pool.spec.usable()
            ));
        }
        let mut free: Vec<Ipv4Addr> = Vec::with_capacity(count);
        let mut answering = 0usize;
        for batch in candidates.chunks(PINGS_AT_ONCE) {
            let mut pings = tokio::task::JoinSet::new();
            for ip in batch.iter().copied() {
                let tools = Arc::clone(&self.tools);
                pings.spawn(async move { (ip, Self::answers(&tools, ip).await) });
            }
            let mut found: Vec<(Ipv4Addr, bool)> = Vec::with_capacity(batch.len());
            while let Some(done) = pings.join_next().await {
                let (ip, answer) =
                    done.map_err(|err| CoreError::Network(format!("a ping to check an address failed: {err}")))?;
                found.push((ip, answer?));
            }
            found.sort_by_key(|(ip, _)| u32::from(*ip));
            for (ip, answers) in found {
                if answers {
                    answering += 1;
                } else if free.len() < count {
                    free.push(ip);
                }
            }
            if free.len() >= count {
                return Ok(free.into_iter().map(|ip| PoolAddress::of(&pool, ip)).collect());
            }
        }
        invalid(format!(
            "Only {} of the {count} addresses asked for are free in '{name}' now: {} of its {} addresses are taken, \
             and something answers on {answering} more.",
            free.len(),
            leased.len(),
            pool.spec.usable()
        ))
    }

    /// At a deploy job's run: records `ip` as `vm_name`'s (claimed, by `job_id`), refusing an address that isn't the
    /// pool's to give, was leased since, or answers a ping now (the claim is then undone). The address with the pool's
    /// prefix, gateway and DNS servers.
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
        if !self
            .store
            .insert_address_claim(ctx, pool_id, ip, vm_name, job_id)
            .await?
        {
            let holder = self
                .store
                .address_leases(ctx, Some(pool_id))
                .await?
                .into_iter()
                .find(|l| l.ip == ip)
                .map_or_else(|| "another VM".to_owned(), |l| format!("'{}'", l.vm_name));
            return invalid(format!("{ip} of '{name}' went to {holder} since it was picked."));
        }
        // The pool may have changed while the row went in.
        let now = match self.row(ctx, pool_id).await {
            Ok(now) => now,
            Err(err) => {
                self.store.delete_address_claim(ctx, pool_id, ip, job_id).await?;
                return Err(err);
            }
        };
        if !now.spec.contains(ip) || now.spec.reserved().contains(&ip) {
            self.store.delete_address_claim(ctx, pool_id, ip, job_id).await?;
            return invalid(format!("'{name}' changed: {ip} isn't one it hands out any more."));
        }
        match Self::answers(&self.tools, ip).await {
            Ok(false) => Ok(PoolAddress::of(&now, ip)),
            Ok(true) => {
                self.store.delete_address_claim(ctx, pool_id, ip, job_id).await?;
                invalid(format!(
                    "Something on the network answers on {ip} now, so '{vm_name}' doesn't get it. Pick another address."
                ))
            }
            Err(err) => {
                self.store.delete_address_claim(ctx, pool_id, ip, job_id).await?;
                Err(err)
            }
        }
    }

    /// Once the VM is made: the claimed address is the VM's (`vm_key`) until it is deleted.
    pub async fn assign(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr, vm_key: &str) -> Result<()> {
        if self.store.assign_address_lease(ctx, pool_id, ip, vm_key).await? {
            Ok(())
        } else {
            invalid(format!(
                "{ip} wasn't claimed in that address pool, so it can't be the VM's."
            ))
        }
    }

    /// A step that failed: its claim (or assignment) goes, so the address is free again.
    pub async fn release(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr) -> Result<()> {
        self.store.delete_address_lease(ctx, pool_id, ip).await.map(drop)
    }

    /// Claims without a VM older than [`STALE_CLAIM_DAYS`] whose deploy isn't running: left by a deploy the app
    /// stopped in the middle of. Called at start for each workspace. How many went.
    pub async fn release_stale_claims(&self, ctx: &Context) -> Result<u64> {
        let before = time::OffsetDateTime::now_utc() - time::Duration::days(STALE_CLAIM_DAYS);
        let before = before
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let gone = self.store.release_stale_address_claims(ctx, &before).await?;
        if gone > 0 {
            tracing::info!(gone, "address claims left by deploys that never ended were released");
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
        refused(|i| i.last_ip = "192.0.3.20".into(), "different /24 subnets");
        refused(|i| i.first_ip = "192.0.2.0".into(), "subnet's own address");
        refused(|i| i.last_ip = "192.0.2.255".into(), "broadcast address");
        refused(|i| i.prefix = 7, "/8 to /30");
        refused(|i| i.prefix = 31, "/8 to /30");
        refused(
            |i| {
                i.prefix = 16;
                i.first_ip = "198.51.0.1".into();
                i.last_ip = "198.51.16.1".into();
                i.gateway = None;
            },
            "at most 4096",
        );
        refused(|i| i.first_ip = "127.0.0.1".into(), "can't be used");
        refused(|i| i.first_ip = "169.254.0.10".into(), "can't be used");
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
        big.first_ip = "198.51.0.1".into();
        big.last_ip = "198.51.16.0".into();
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
        refused(|i| i.name = "  ".into(), "Give the address pool a name");
        refused(|i| i.name = "a\tb".into(), "invisible");
        refused(|i| i.name = "lab\u{202E}".into(), "invisible");
        refused(|i| i.name = "x".repeat(MAX_NAME_CHARS + 1), "at most 60");
        refused(|i| i.network = Network::Vmnet { number: 20 }, "vmnet0 to vmnet19");
        refused(
            |i| {
                i.network = Network::NatNetwork { name: "lab".into() };
            },
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
    }

    #[test]
    fn bridged_pools_meet_whichever_hypervisor_bridges() {
        let a = check_pool(&input()).unwrap();
        let mut b = a.clone();
        b.hypervisor = Hypervisor::VirtualBox;
        assert!(
            !same_network(&a, &b),
            "NAT networks of two hypervisors are two networks"
        );
        let mut a_bridged = a.clone();
        a_bridged.network = Network::Bridged;
        b.network = Network::Bridged;
        assert!(same_network(&a_bridged, &b));
        assert!(overlaps(&a, &b));
        b.first = Ipv4Addr::new(192, 0, 2, 51);
        b.last = Ipv4Addr::new(192, 0, 2, 60);
        assert!(!overlaps(&a, &b));
    }
}
