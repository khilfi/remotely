//! FD-05: the workspace's inventory as sheets: VMs (MO-13's hardware), hosts (every saved session, with an SSH or WinRM host's
//! MO-13 facts and MO-14's listening ports and pending updates), networks (VM-11), health checks (MO-08), and on request
//! each host's installed packages. Built from what is stored; "Read again first" reads the SSH and WinRM hosts now, a few at a
//! time, through [`HostDetails::inventory_read`] (the login guard's parks and caps), and keeps what was stored for a host
//! that can't be read. Reads only: nothing here changes a host or a VM.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::table::{clean, col, Cell, Column, Sheet};
use super::ReportClock;
use crate::adapters::host_networks::VmnetKind;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::VmHardware;
use crate::checks::RunResult;
use crate::domain::{Context, Environment, PowerState};
use crate::error::{CoreError, Result};
use crate::host_details::admin::{ListeningPort, UpdatesReport};
use crate::host_details::linux::HostSpecs;
use crate::host_details::packages::PackagesReport;
use crate::host_details::windows::ListeningPort as WindowsPort;
use crate::host_details::{HostDetails, InventoryReads};
use crate::host_networks::{HostNetworks, NetworkVm};
use crate::sessions::{SessionFolder, SessionKind, SessionRecord};
use crate::store::{Store, VmRecord};
use crate::toolbox::ProbeTarget;

/// What the inventory reads now, besides what is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InventoryOptions {
    /// Read the SSH and WinRM hosts again first: their facts (stored, like a Refresh) and listening ports.
    pub read_again: bool,
    /// Also each host's pending updates (dnf may take a minute a host).
    pub updates: bool,
    /// Also each host's installed packages (a Packages sheet, and a count per host).
    pub packages: bool,
}

impl InventoryOptions {
    /// Updates and packages are read on the same connection as the facts, so asking for either reads the hosts.
    pub fn reads_hosts(self) -> bool {
        self.read_again || self.updates || self.packages
    }
}

/// Hosts read at once.
pub const READS_AT_ONCE: usize = 4;
/// One host's reads, all together, at most (a dnf metadata refresh included).
pub const HOST_READ_LIMIT: Duration = Duration::from_secs(240);

/// How far "Read again first" got: hosts done (read or not) of those asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadProgress {
    pub done: usize,
    pub total: usize,
}

/// Stops and follows an export's host reads: the dialog's Cancel (or the window reloading) cancels `cancel`, which
/// ends every read at once, waiting ones included, and the export makes no file; `progress` hears of each host done.
#[derive(Clone, Default)]
pub struct ReadControl {
    pub cancel: CancellationToken,
    progress: Option<Arc<dyn Fn(ReadProgress) + Send + Sync>>,
}

impl ReadControl {
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel, progress: None }
    }

    pub fn with_progress(mut self, progress: impl Fn(ReadProgress) + Send + Sync + 'static) -> Self {
        self.progress = Some(Arc::new(progress));
        self
    }

    fn report(&self, progress: ReadProgress) {
        if let Some(report) = &self.progress {
            report(progress);
        }
    }

    /// `Cancelled` once the export was cancelled.
    pub fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            Err(CoreError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// How the reads went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadSummary {
    /// SSH and WinRM hosts asked.
    pub asked: usize,
    /// Read now (facts or ports).
    pub read: usize,
    /// "web01: the vault is locked" for each host not read, or read only in part.
    pub problems: Vec<String>,
}

/// Everything the inventory found, as sheets, with what the handover pack draws its diagram from.
#[derive(Debug, Clone)]
pub struct InventoryData {
    pub vms: Sheet,
    pub hosts: Sheet,
    pub networks: Sheet,
    pub checks: Sheet,
    /// With [`InventoryOptions::packages`].
    pub packages: Option<Sheet>,
    pub read: Option<ReadSummary>,
    /// What couldn't be read (a hypervisor's networks...).
    pub notes: Vec<String>,
    pub vm_records: Vec<VmRecord>,
    pub sessions: Vec<SessionRecord>,
    /// Each VM's adapters as stored, by VM key, for the topology.
    pub nics: HashMap<String, (Hypervisor, Vec<crate::adapters::vm_hardware::VirtualNic>)>,
}

impl InventoryData {
    /// The sheets in the workbook's order.
    pub fn sheets(&self) -> Vec<&Sheet> {
        let mut out = vec![&self.vms, &self.hosts, &self.networks, &self.checks];
        if let Some(p) = &self.packages {
            out.push(p);
        }
        out
    }
}

pub const VM_COLUMNS: [Column; 18] = [
    col("Name", 24.0),
    col("Hypervisor", 12.0),
    col("State", 11.0),
    col("Guest OS", 26.0),
    col("vCPU", 6.0),
    col("RAM (GB)", 9.0),
    col("Disks", 34.0),
    col("Disk size (GB)", 13.0),
    col("Addresses", 18.0),
    col("MAC addresses", 20.0),
    col("Networks", 26.0),
    col("Firmware", 9.0),
    col("Folder", 40.0),
    col("Environment", 12.0),
    col("Protected", 10.0),
    col("Tags", 20.0),
    col("Sessions", 20.0),
    col("Hardware read", 17.0),
];

pub const HOST_COLUMNS: [Column; 33] = [
    col("Name", 22.0),
    col("Kind", 10.0),
    col("Host", 22.0),
    col("Port", 6.0),
    col("User", 12.0),
    col("Folder", 20.0),
    col("Environment", 12.0),
    col("Protected", 10.0),
    col("Tags", 18.0),
    col("Jump host", 16.0),
    col("VM", 16.0),
    col("Last address", 16.0),
    col("Host name", 18.0),
    // F4: a Windows host's adapters (Linux facts have none).
    col("Addresses", 24.0),
    col("MAC addresses", 20.0),
    col("OS", 24.0),
    col("Kernel or build", 22.0),
    col("Architecture", 12.0),
    col("CPU", 30.0),
    col("vCPUs", 7.0),
    col("RAM (GB)", 9.0),
    col("Disks", 28.0),
    col("File systems", 34.0),
    col("Virtualization", 13.0),
    // F4: a Windows host's domain (or workgroup) and its manufacturer and model.
    col("Domain or workgroup", 18.0),
    col("Hardware", 24.0),
    col("Booted", 17.0),
    col("Listening ports", 34.0),
    col("Pending updates", 10.0),
    col("Security updates", 10.0),
    col("Packages", 10.0),
    col("Facts read", 17.0),
    col("Read now", 30.0),
];

pub const NETWORK_COLUMNS: [Column; 8] = [
    col("Hypervisor", 12.0),
    col("Network", 30.0),
    col("Type", 14.0),
    col("Subnet", 18.0),
    col("DHCP", 7.0),
    col("Gateway or address", 18.0),
    col("VMs", 30.0),
    col("Port forwards", 40.0),
];

pub const CHECK_COLUMNS: [Column; 10] = [
    col("Name", 24.0),
    col("Checks", 30.0),
    col("Target", 22.0),
    col("Every", 12.0),
    col("Paused", 8.0),
    col("Last result", 11.0),
    col("Last run", 17.0),
    col("Detail", 34.0),
    col("Uptime 24 h (%)", 12.0),
    col("Uptime 7 days (%)", 12.0),
];

pub const PACKAGE_COLUMNS: [Column; 4] = [
    col("Host", 22.0),
    col("Package", 34.0),
    col("Version", 26.0),
    col("Architecture", 12.0),
];

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn gib(bytes: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let b = bytes as f64;
    b / GIB
}

fn gb_text(bytes: u64) -> String {
    let g = gib(bytes);
    if g >= 10.0 {
        format!("{g:.0} GB")
    } else {
        format!("{g:.1} GB")
    }
}

fn environment(env: Environment) -> Cell {
    match env {
        Environment::None => Cell::Empty,
        Environment::Lab => Cell::text("Lab"),
        Environment::Staging => Cell::text("Staging"),
        Environment::Prod => Cell::text("Prod"),
    }
}

fn power(state: PowerState) -> &'static str {
    match state {
        PowerState::Running => "Running",
        PowerState::NotRunning => "Off",
        PowerState::Suspended => "Suspended",
        PowerState::Paused => "Paused",
        PowerState::Unknown => "Unknown",
    }
}

fn hypervisor(h: Hypervisor) -> &'static str {
    match h {
        Hypervisor::Vmware => "Workstation",
        Hypervisor::VirtualBox => "VirtualBox",
    }
}

fn kind(kind: &SessionKind) -> &'static str {
    match kind {
        SessionKind::Ssh => "SSH",
        SessionKind::Rdp(_) => "RDP",
        SessionKind::Vnc(_) => "VNC",
        SessionKind::Telnet(_) => "Telnet",
        SessionKind::Serial(_) => "Serial",
        SessionKind::Winrm(_) => "WinRM",
    }
}

/// `Customer / Web tier`.
pub fn folder_path(folder: Option<Uuid>, folders: &HashMap<Uuid, &SessionFolder>) -> String {
    let mut names = Vec::new();
    let mut next = folder;
    while let Some(id) = next {
        let Some(f) = folders.get(&id) else { break };
        if names.len() > 64 {
            break;
        }
        names.push(f.name.as_str());
        next = f.parent_id;
    }
    names.reverse();
    names.join(" / ")
}

/// A host's listening ports in one cell: `tcp 22 (sshd); udp 53`, each port once.
fn ports_text(ports: &[ListeningPort]) -> String {
    let mut seen = BTreeSet::new();
    let mut parts = Vec::new();
    for p in ports {
        if !seen.insert((p.protocol.clone(), p.port)) {
            continue;
        }
        let who = if p.processes.is_empty() {
            String::new()
        } else {
            format!(" ({})", p.processes.join(", "))
        };
        parts.push(format!("{} {}{who}", p.protocol, p.port));
        if parts.len() >= 60 {
            parts.push("…".into());
            break;
        }
    }
    parts.join("; ")
}

/// F4: a Windows host's listening TCP ports in one cell: `tcp 3389 (svchost); tcp 5986 (System)`, each port once.
fn windows_ports_text(ports: &[WindowsPort]) -> String {
    let mut seen = BTreeSet::new();
    let mut parts = Vec::new();
    for p in ports {
        if !seen.insert(p.port) {
            continue;
        }
        let who = p.process.as_deref().map(|w| format!(" ({w})")).unwrap_or_default();
        parts.push(format!("tcp {}{who}", p.port));
        if parts.len() >= 60 {
            parts.push("…".into());
            break;
        }
    }
    parts.join("; ")
}

/// One host's sheet row.
struct HostFacts<'a> {
    specs: Option<(HostSpecs, String)>,
    ports: Option<&'a [ListeningPort]>,
    updates: Option<&'a UpdatesReport>,
    packages: Option<&'a PackagesReport>,
    read_now: String,
}

fn host_row(
    s: &SessionRecord,
    facts: &HostFacts<'_>,
    names: &HashMap<Uuid, String>,
    folders: &HashMap<Uuid, &SessionFolder>,
    vm_names: &HashMap<&str, &str>,
    clock: &ReportClock,
) -> Vec<Cell> {
    let specs = facts.specs.as_ref().map(|(s, _)| s);
    let disks = specs.map(|sp| {
        sp.disks
            .iter()
            .filter(|d| d.kind == "disk")
            .map(|d| match d.size_bytes {
                Some(size) => format!("{} {}", d.name, gb_text(size)),
                None => d.name.clone(),
            })
            .collect::<Vec<_>>()
            .join("; ")
    });
    let filesystems = specs.map(|sp| {
        sp.filesystems
            .iter()
            .take(20)
            .map(|f| format!("{} {} ({:.0}% used)", f.mount, gb_text(f.size_bytes), f.used_pct))
            .collect::<Vec<_>>()
            .join("; ")
    });
    let booted = specs.and_then(|sp| {
        let (_, at) = facts.specs.as_ref()?;
        match sp.uptime_secs {
            Some(up) => clock.before(at, up),
            // F4: Windows says when it booted.
            None => sp.windows.as_ref()?.last_boot.as_deref().map(|b| clock.at(b)),
        }
    });
    // F4: a Windows host's adapters, domain and hardware.
    let addresses = specs.map(|sp| {
        let mut all: Vec<&str> = Vec::new();
        for a in sp.adapters.iter().flat_map(|a| &a.addresses) {
            if !all.contains(&a.as_str()) {
                all.push(a);
            }
        }
        all.join(", ")
    });
    let macs = specs.map(|sp| {
        sp.adapters
            .iter()
            .filter_map(|a| a.mac.as_deref().map(|m| format!("{} {m}", a.name)))
            .collect::<Vec<_>>()
            .join("; ")
    });
    let windows = specs.and_then(|sp| sp.windows.as_ref());
    let domain = windows.and_then(|w| match (w.part_of_domain, &w.domain, &w.workgroup) {
        (Some(true), Some(domain), _) => Some(domain.clone()),
        (_, _, Some(group)) => Some(format!("{group} (workgroup)")),
        (_, Some(domain), None) => Some(domain.clone()),
        _ => None,
    });
    let hardware = windows.and_then(|w| match (&w.manufacturer, &w.model) {
        (Some(m), Some(model)) => Some(format!("{m} {model}")),
        (Some(one), None) | (None, Some(one)) => Some(one.clone()),
        (None, None) => None,
    });
    // MO-14's ports for a Linux host read now; a Windows host's are in its facts.
    let ports = match facts.ports {
        Some(ports) => Some(ports_text(ports)),
        None => specs
            .filter(|sp| !sp.listening.is_empty())
            .map(|sp| windows_ports_text(&sp.listening)),
    };
    vec![
        Cell::text(&s.name),
        Cell::text(kind(&s.kind)),
        Cell::text(&s.host),
        Cell::int(s.port),
        Cell::opt_text(s.username.as_deref()),
        Cell::text(folder_path(s.folder_id, folders)),
        environment(s.environment),
        Cell::yes_no(s.protected),
        Cell::text(s.tags.join(", ")),
        Cell::opt_text(s.jump_session_id.and_then(|j| names.get(&j))),
        Cell::opt_text(s.vm_id.as_deref().and_then(|v| vm_names.get(v).copied())),
        Cell::opt_text(s.last_ip.as_deref()),
        Cell::opt_text(
            specs
                .and_then(|sp| sp.hostname.clone())
                .or_else(|| s.last_hostname.clone()),
        ),
        Cell::opt_text(addresses),
        Cell::opt_text(macs),
        Cell::opt_text(specs.and_then(HostSpecs::os_name)),
        Cell::opt_text(specs.and_then(|sp| sp.kernel.clone())),
        Cell::opt_text(specs.and_then(|sp| sp.architecture.clone())),
        Cell::opt_text(specs.and_then(|sp| sp.cpu.model.clone())),
        Cell::opt_int(specs.and_then(|sp| sp.cpu.logical_cpus)),
        Cell::opt_number(specs.and_then(|sp| sp.memory.total_bytes).map(gib)),
        Cell::opt_text(disks),
        Cell::opt_text(filesystems),
        Cell::opt_text(specs.and_then(|sp| sp.virtualization.clone())),
        Cell::opt_text(domain),
        Cell::opt_text(hardware),
        Cell::opt_text(booted),
        Cell::opt_text(ports),
        Cell::opt_int(facts.updates.filter(|u| u.manager.is_some()).map(|u| u.packages.len())),
        Cell::opt_int(facts.updates.filter(|u| u.manager.is_some()).map(|u| u.security_count)),
        Cell::opt_int(facts.packages.filter(|p| p.database.is_some()).map(|p| p.count)),
        Cell::opt_text(facts.specs.as_ref().map(|(_, at)| clock.at(at))),
        Cell::text(&facts.read_now),
    ]
}

fn vm_row(
    vm: &VmRecord,
    hardware: Option<&(VmHardware, String)>,
    sessions: &[String],
    clock: &ReportClock,
) -> Vec<Cell> {
    let hw = hardware.map(|(h, _)| h);
    let disks = hw.map(|h| {
        h.disks
            .iter()
            .map(|d| {
                let size = d.provisioned_bytes.map(gb_text).unwrap_or_default();
                let thin = match d.thin {
                    Some(true) => " thin",
                    Some(false) => " thick",
                    None => "",
                };
                format!("{} {size}{thin}", d.slot).trim().to_owned()
            })
            .collect::<Vec<_>>()
            .join("; ")
    });
    let disk_total: Option<u64> = hw.and_then(|h| {
        let sizes: Vec<u64> = h.disks.iter().filter_map(|d| d.provisioned_bytes).collect();
        (!sizes.is_empty()).then(|| sizes.iter().sum())
    });
    let mut addresses: Vec<String> = Vec::new();
    if let Some(ip) = &vm.ip_address {
        addresses.push(ip.clone());
    }
    for ip in hw.map(|h| h.guest_ips.as_slice()).unwrap_or(&[]) {
        if !addresses.contains(ip) {
            addresses.push(ip.clone());
        }
    }
    let macs = hw.map(|h| {
        h.nics
            .iter()
            .filter_map(|n| n.mac.clone())
            .collect::<Vec<_>>()
            .join(", ")
    });
    let networks = hw.map(|h| {
        h.nics
            .iter()
            .map(|n| {
                let what = super::topology::network_key(vm.hypervisor, n).map(|(_, label, _)| label);
                format!("{}: {}", n.slot, what.unwrap_or_else(|| "not connected".into()))
            })
            .collect::<Vec<_>>()
            .join("; ")
    });
    vec![
        Cell::text(&vm.display_name),
        Cell::text(hypervisor(vm.hypervisor)),
        Cell::text(power(vm.power_state)),
        Cell::opt_text(
            hw.and_then(|h| h.guest_os_name.clone())
                .or_else(|| vm.guest_os_name.clone())
                .or_else(|| vm.guest_os.clone()),
        ),
        Cell::opt_int(hw.and_then(|h| h.vcpus).or(vm.num_vcpus)),
        Cell::opt_number(
            hw.and_then(|h| h.memory_mb)
                .or(vm.memsize_mb)
                .map(|mb| f64::from(mb) / 1024.0),
        ),
        Cell::opt_text(disks),
        Cell::opt_number(disk_total.map(gib)),
        Cell::text(addresses.join(", ")),
        Cell::opt_text(macs),
        Cell::opt_text(networks),
        Cell::opt_text(hw.and_then(|h| h.firmware.clone())),
        Cell::opt_text(vm.folder().map(|f| f.display().to_string())),
        environment(vm.environment),
        Cell::yes_no(vm.protected),
        Cell::text(vm.tags.join(", ")),
        Cell::text(sessions.join(", ")),
        Cell::opt_text(hardware.map(|(_, at)| clock.at(at))),
    ]
}

fn vms_on(vms: &[NetworkVm]) -> String {
    vms.iter()
        .map(|v| {
            if v.ips.is_empty() {
                v.name.clone()
            } else {
                format!("{} ({})", v.name, v.ips.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn yes_no(value: Option<bool>) -> Cell {
    value.map_or(Cell::Empty, Cell::yes_no)
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// VM-11's networks as rows; a report that can't be read at all is a note, and the sheet stays empty. Rule 8: the
/// networks are this PC's, shared by every workspace, so only those a VM of this workspace is on go in, and of their
/// forwards only those to a VM of this workspace (by its address, `vm_ips`); the rest are counted in a note.
async fn network_sheet(
    networks: &HostNetworks,
    ctx: &Context,
    vm_ips: &HashSet<String>,
    notes: &mut Vec<String>,
) -> Sheet {
    let mut sheet = Sheet::new("networks", "Networks", &NETWORK_COLUMNS);
    let report = match networks.report(ctx).await {
        Ok(report) => report,
        Err(err) => {
            notes.push(format!("The host networks could not be read: {err}"));
            return sheet;
        }
    };
    for problem in [&report.vmware.problem, &report.virtualbox.problem]
        .into_iter()
        .flatten()
    {
        notes.push(format!("Host networks: {problem}"));
    }
    // The report's VMs are this workspace's, with the addresses they have on each network.
    let mut ips = vm_ips.clone();
    let on = report
        .vmware
        .networks
        .iter()
        .flat_map(|v| &v.vms)
        .chain(report.virtualbox.host_only.iter().flat_map(|h| &h.vms))
        .chain(report.virtualbox.nat_networks.iter().flat_map(|n| &n.vms))
        .chain(report.virtualbox.other.iter().flat_map(|o| &o.vms));
    for vm in on {
        ips.extend(vm.ips.iter().cloned());
    }
    let mut networks_out = 0;
    let mut forwards_out = 0;
    for v in &report.vmware.networks {
        if v.vms.is_empty() {
            networks_out += 1;
            forwards_out += v.forwards.len();
            continue;
        }
        let kind = match &v.network.kind {
            VmnetKind::HostOnly => "Host-only".to_owned(),
            VmnetKind::Nat => "NAT".to_owned(),
            VmnetKind::Bridged => "Bridged".to_owned(),
            VmnetKind::Other(other) => other.clone(),
        };
        let subnet = match (&v.network.subnet, &v.network.mask) {
            (Some(s), Some(m)) => format!("{s} / {m}"),
            (Some(s), None) => s.clone(),
            _ => String::new(),
        };
        let (mine, others): (Vec<_>, Vec<_>) = v.forwards.iter().partition(|f| ips.contains(&f.guest_ip));
        forwards_out += others.len();
        let forwards = mine
            .iter()
            .map(|f| {
                format!(
                    "{} {} → {}:{}",
                    f.protocol.as_str(),
                    f.host_port,
                    f.guest_ip,
                    f.guest_port
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        sheet.push(vec![
            Cell::text("Workstation"),
            Cell::text(&v.network.name),
            Cell::text(kind),
            Cell::text(subnet),
            yes_no(v.network.dhcp),
            Cell::Empty,
            Cell::text(vms_on(&v.vms)),
            Cell::text(forwards),
        ]);
    }
    let vbox = &report.virtualbox;
    for h in &vbox.host_only {
        if h.vms.is_empty() {
            networks_out += 1;
            continue;
        }
        let subnet = match (&h.iface.ip, &h.iface.mask) {
            (Some(ip), Some(m)) => format!("{ip} / {m}"),
            (Some(ip), None) => ip.clone(),
            _ => String::new(),
        };
        sheet.push(vec![
            Cell::text("VirtualBox"),
            Cell::text(&h.iface.name),
            Cell::text("Host-only"),
            Cell::text(subnet),
            yes_no(h.iface.dhcp),
            Cell::opt_text(h.iface.status.as_deref()),
            Cell::text(vms_on(&h.vms)),
            Cell::Empty,
        ]);
    }
    for n in &vbox.nat_networks {
        if n.vms.is_empty() {
            networks_out += 1;
            forwards_out += n.network.forwards.len();
            continue;
        }
        // A rule without a guest address can't be told to lead to this workspace's VM.
        let (mine, others): (Vec<_>, Vec<_>) = n
            .network
            .forwards
            .iter()
            .partition(|r| r.guest_ip.as_ref().is_some_and(|ip| ips.contains(ip)));
        forwards_out += others.len();
        let rules = mine
            .iter()
            .map(|r| {
                format!(
                    "{} {} {} → {}:{}",
                    r.name,
                    r.protocol.as_str(),
                    r.host_port,
                    r.guest_ip.as_deref().unwrap_or("DHCP"),
                    r.guest_port
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        sheet.push(vec![
            Cell::text("VirtualBox"),
            Cell::text(&n.network.name),
            Cell::text("NAT network"),
            Cell::opt_text(n.network.network.as_deref()),
            yes_no(n.network.dhcp),
            Cell::opt_text(n.network.gateway.as_deref()),
            Cell::text(vms_on(&n.vms)),
            Cell::text(rules),
        ]);
    }
    for o in &vbox.other {
        if o.vms.is_empty() {
            networks_out += 1;
            continue;
        }
        let kind = match o.kind.as_str() {
            "bridged" => "Bridged",
            "intnet" => "Internal",
            other => other,
        };
        sheet.push(vec![
            Cell::text("VirtualBox"),
            Cell::text(&o.name),
            Cell::text(kind),
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::text(vms_on(&o.vms)),
            Cell::Empty,
        ]);
    }
    for v in &vbox.vm_nat {
        if v.rules.is_empty() {
            continue;
        }
        let rules = v
            .rules
            .iter()
            .map(|r| format!("{} {} {} → {}", r.name, r.protocol.as_str(), r.host_port, r.guest_port))
            .collect::<Vec<_>>()
            .join("; ");
        sheet.push(vec![
            Cell::text("VirtualBox"),
            Cell::text(format!("{} NAT ({})", v.vm.name, v.vm.adapter)),
            Cell::text("NAT"),
            Cell::Empty,
            Cell::Empty,
            Cell::Empty,
            Cell::text(&v.vm.name),
            Cell::text(rules),
        ]);
    }
    let left_out = match (networks_out, forwards_out) {
        (0, 0) => None,
        (n, 0) => Some(format!("{} no VM of this workspace is on", plural(n, "network"))),
        (0, f) => Some(format!("{} to VMs outside this workspace", plural(f, "port forward"))),
        (n, f) => Some(format!(
            "{} no VM of this workspace is on, and {} to VMs outside it,",
            plural(n, "network"),
            plural(f, "port forward")
        )),
    };
    if let Some(what) = left_out {
        notes.push(format!("Networks: {what} left out."));
    }
    sheet
}

/// MO-08's checks, with each one's last run and uptime over the last day and week.
async fn check_sheet(
    store: &Store,
    ctx: &Context,
    now_ms: i64,
    session_names: &HashMap<Uuid, String>,
    vm_names: &HashMap<&str, &str>,
    clock: &ReportClock,
) -> Result<Sheet> {
    let mut sheet = Sheet::new("checks", "Checks", &CHECK_COLUMNS);
    let checks = store.list_checks(ctx).await?;
    if checks.is_empty() {
        return Ok(sheet);
    }
    let day: HashMap<Uuid, Option<f64>> = store
        .check_uptime(ctx, now_ms - 86_400_000, now_ms + 1)
        .await?
        .into_iter()
        .map(|u| (u.check_id, u.uptime))
        .collect();
    let week: HashMap<Uuid, Option<f64>> = store
        .check_uptime(ctx, now_ms - 7 * 86_400_000, now_ms + 1)
        .await?
        .into_iter()
        .map(|u| (u.check_id, u.uptime))
        .collect();
    for check in checks {
        let target = match &check.target {
            ProbeTarget::Address { host } => host.clone(),
            ProbeTarget::Session { session_id } => session_names
                .get(session_id)
                .cloned()
                .unwrap_or_else(|| "a deleted session".into()),
            ProbeTarget::Vm { vm_key } => vm_names
                .get(vm_key.as_str())
                .map_or_else(|| "a VM not in this workspace".into(), |n| (*n).to_owned()),
        };
        let last = store.check_results(ctx, check.id, 0, 1).await?.into_iter().next();
        let result = last.as_ref().map(|r| match r.result {
            RunResult::Up => "Up",
            RunResult::Down => "Down",
            RunResult::Unknown => "Unknown",
        });
        sheet.push(vec![
            Cell::text(&check.name),
            Cell::text(check.spec.describe()),
            Cell::text(target),
            Cell::text(crate::checks::spec::every_text(check.interval_secs)),
            Cell::yes_no(check.paused),
            Cell::opt_text(result),
            Cell::opt_text(last.as_ref().map(|r| clock.at_ms(r.at))),
            Cell::opt_text(last.as_ref().map(|r| r.detail.as_str())),
            Cell::opt_number(day.get(&check.id).copied().flatten()),
            Cell::opt_number(week.get(&check.id).copied().flatten()),
        ]);
    }
    Ok(sheet)
}

/// The sessions "Read again first" reads: SSH hosts, and F4's Windows hosts over WinRM (their facts only).
fn read_again(kind: &SessionKind) -> bool {
    kind.is_ssh() || kind.is_winrm()
}

/// What a host read gave, kept until its row is made.
#[derive(Default)]
struct Fresh {
    specs: Option<(HostSpecs, String)>,
    ports: Option<Vec<ListeningPort>>,
    updates: Option<UpdatesReport>,
    packages: Option<PackagesReport>,
    read_now: String,
    /// F4: a Windows host (its updates and packages are not read).
    windows: bool,
}

/// Reads the SSH and WinRM hosts now, [`READS_AT_ONCE`] at a time, until `control` is cancelled (then `Cancelled`).
async fn read_hosts(
    details: &HostDetails,
    ctx: &Context,
    sessions: &[SessionRecord],
    options: InventoryOptions,
    control: &ReadControl,
) -> Result<(HashMap<Uuid, Fresh>, ReadSummary)> {
    let reads = InventoryReads {
        updates: options.updates,
        packages: options.packages,
    };
    let at_once = Arc::new(Semaphore::new(READS_AT_ONCE));
    let mut jobs = JoinSet::new();
    let mut summary = ReadSummary::default();
    for s in sessions.iter().filter(|s| read_again(&s.kind)) {
        summary.asked += 1;
        let (details, ctx, at_once, id, name) = (details.clone(), *ctx, Arc::clone(&at_once), s.id, s.name.clone());
        let cancel = control.cancel.clone();
        jobs.spawn(async move {
            let read = tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                read = async {
                    let _turn = at_once.acquire_owned().await;
                    tokio::time::timeout(HOST_READ_LIMIT, details.inventory_read(&ctx, id, reads)).await
                } => Some(read),
            };
            // Remotely's own connection for this goes now, not minutes later (a cancelled read's too).
            details.release(id).await;
            (id, name, read)
        });
    }
    let total = summary.asked;
    let mut done_count = 0;
    control.report(ReadProgress { done: 0, total });
    let mut out = HashMap::new();
    while let Some(done) = jobs.join_next().await {
        let Ok((id, name, read)) = done else { continue };
        done_count += 1;
        control.report(ReadProgress {
            done: done_count,
            total,
        });
        let Some(read) = read else { continue };
        let mut fresh = Fresh::default();
        match read {
            Err(_) => {
                fresh.read_now = format!("Not read: it took over {} s", HOST_READ_LIMIT.as_secs());
                summary.problems.push(format!("{}: {}", clean(&name), fresh.read_now));
            }
            Ok(Err(err)) => {
                fresh.read_now = format!("Not read: {err}");
                summary.problems.push(format!("{}: {err}", clean(&name)));
            }
            Ok(Ok(read)) => {
                if read.specs.is_some() || read.ports.is_some() {
                    summary.read += 1;
                }
                fresh.read_now = if read.problems.is_empty() {
                    "Read now".into()
                } else {
                    summary
                        .problems
                        .push(format!("{}: {}", clean(&name), read.problems.join("; ")));
                    format!("Read in part: {}", read.problems.join("; "))
                };
                fresh.specs = read.specs.map(|s| (s.specs, s.collected_at));
                fresh.ports = read.ports;
                fresh.updates = read.updates;
                fresh.packages = read.packages;
                fresh.windows = read.windows;
            }
        }
        out.insert(id, fresh);
    }
    control.check()?;
    summary.problems.sort();
    Ok((out, summary))
}

/// What the inventory reads from.
pub struct Sources<'a> {
    pub store: &'a Store,
    pub details: &'a HostDetails,
    pub networks: &'a HostNetworks,
}

/// Builds the inventory of the workspace `ctx` names (rule 8: every read takes this ctx). `Cancelled` once `control`
/// is.
pub async fn collect(
    sources: &Sources<'_>,
    ctx: &Context,
    options: InventoryOptions,
    clock: &ReportClock,
    now_ms: i64,
    control: &ReadControl,
) -> Result<InventoryData> {
    let store = sources.store;
    let vms = store.list_vms(ctx).await?;
    let sessions = store.list_sessions(ctx).await?;
    let folders = store.list_session_folders(ctx).await?;
    let folder_by_id: HashMap<Uuid, &SessionFolder> = folders.iter().map(|f| (f.id, f)).collect();
    let session_names: HashMap<Uuid, String> = sessions.iter().map(|s| (s.id, s.name.clone())).collect();
    let vm_names: HashMap<&str, &str> = vms
        .iter()
        .flat_map(|v| {
            [
                (v.id.as_str(), v.display_name.as_str()),
                (v.vmx_path.as_str(), v.display_name.as_str()),
            ]
        })
        .collect();
    let mut notes = Vec::new();

    let (mut fresh, read) = if options.reads_hosts() {
        let (fresh, summary) = read_hosts(sources.details, ctx, &sessions, options, control).await?;
        (fresh, Some(summary))
    } else {
        (HashMap::new(), None)
    };
    // F4: updates and packages are Linux reads; the Windows hosts read now are said to be left out of them.
    let windows_read = fresh.values().filter(|f| f.windows).count();
    if windows_read > 0 && (options.updates || options.packages) {
        let what = match (options.updates, options.packages) {
            (true, true) => "Pending updates and installed packages are",
            (true, false) => "Pending updates are",
            _ => "Installed packages are",
        };
        let hosts = if windows_read == 1 {
            "1 Windows host".to_owned()
        } else {
            format!("{windows_read} Windows hosts")
        };
        notes.push(format!(
            "{what} read from Linux hosts only, so {hosts} has none in the file."
        ));
    }

    // VMs, with their stored hardware. A VM never read is read now from its files (QL-21's read, stored as the
    // details panel stores it); "Read again first" reads every VM's again.
    let vm_read = tokio::select! {
        biased;
        () = control.cancel.cancelled() => return Err(CoreError::Cancelled),
        read = sources.details.vm_networks(ctx, options.read_again) => read,
    };
    if let Err(err) = vm_read {
        notes.push(format!("The VMs' hardware could not be read: {err}"));
    }
    let mut stored_hw = store.all_vm_specs(ctx).await?;
    let mut by_vm: HashMap<&str, Vec<String>> = HashMap::new();
    for s in &sessions {
        if let Some(vm) = s.vm_id.as_deref() {
            by_vm.entry(vm).or_default().push(s.name.clone());
        }
    }
    let mut vm_sheet = Sheet::new("vms", "VMs", &VM_COLUMNS);
    let mut nics = HashMap::new();
    // Rule 8: the addresses of this workspace's VMs, which the networks' forwards are kept by.
    let mut vm_ips: HashSet<String> = HashSet::new();
    for vm in &vms {
        let hw = stored_hw
            .remove(&vm.id)
            .and_then(|s| Some((serde_json::from_str::<VmHardware>(&s.specs).ok()?, s.collected_at)));
        vm_ips.extend(vm.ip_address.iter().cloned());
        if let Some((h, _)) = &hw {
            nics.insert(vm.vmx_path.clone(), (vm.hypervisor, h.nics.clone()));
            vm_ips.extend(h.guest_ips.iter().cloned());
        }
        let linked = by_vm.get(vm.id.as_str()).cloned().unwrap_or_default();
        vm_sheet.push(vm_row(vm, hw.as_ref(), &linked, clock));
    }

    // Hosts: every session; an SSH or WinRM host's facts as read now, else as stored.
    let mut stored_specs = store.all_session_specs(ctx).await?;
    let mut host_sheet = Sheet::new("hosts", "Hosts", &HOST_COLUMNS);
    let mut package_sheet = options
        .packages
        .then(|| Sheet::new("packages", "Packages", &PACKAGE_COLUMNS));
    for s in &sessions {
        let fresh = fresh.remove(&s.id).unwrap_or_default();
        let stored = stored_specs
            .remove(&s.id)
            .and_then(|st| Some((serde_json::from_str::<HostSpecs>(&st.specs).ok()?, st.collected_at)));
        let read_now = if !read_again(&s.kind) {
            String::new()
        } else if options.reads_hosts() {
            fresh.read_now.clone()
        } else {
            "Stored facts".to_owned()
        };
        let facts = HostFacts {
            specs: fresh.specs.clone().or(stored),
            ports: fresh.ports.as_deref(),
            updates: fresh.updates.as_ref(),
            packages: fresh.packages.as_ref(),
            read_now,
        };
        host_sheet.push(host_row(s, &facts, &session_names, &folder_by_id, &vm_names, clock));
        if let (Some(sheet), Some(packages)) = (package_sheet.as_mut(), fresh.packages.as_ref()) {
            for p in &packages.packages {
                sheet.push(vec![
                    Cell::text(&s.name),
                    Cell::text(&p.name),
                    Cell::text(&p.version),
                    Cell::text(&p.arch),
                ]);
            }
            if packages.count > packages.packages.len() {
                notes.push(format!(
                    "{}: {} packages are installed; the list holds the first {}.",
                    clean(&s.name),
                    packages.count,
                    packages.packages.len()
                ));
            }
        }
    }

    let networks = tokio::select! {
        biased;
        () = control.cancel.cancelled() => return Err(CoreError::Cancelled),
        sheet = network_sheet(sources.networks, ctx, &vm_ips, &mut notes) => sheet,
    };
    let checks = check_sheet(store, ctx, now_ms, &session_names, &vm_names, clock).await?;
    Ok(InventoryData {
        vms: vm_sheet,
        hosts: host_sheet,
        networks,
        checks,
        packages: package_sheet,
        read,
        notes,
        vm_records: vms,
        sessions,
        nics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_listed_once_each() {
        let port = |proto: &str, port: u16, who: &[&str]| ListeningPort {
            protocol: proto.into(),
            ip: "0.0.0.0".into(),
            port,
            interface: None,
            processes: who.iter().map(|w| (*w).to_owned()).collect(),
            pids: Vec::new(),
        };
        let text = ports_text(&[
            port("tcp", 22, &["sshd"]),
            port("tcp", 22, &["sshd"]),
            port("udp", 53, &[]),
        ]);
        assert_eq!(text, "tcp 22 (sshd); udp 53");
    }

    #[test]
    fn sizes_and_folders_read_plainly() {
        assert_eq!(gb_text(40 * 1024 * 1024 * 1024), "40 GB");
        assert_eq!(gb_text(1024 * 1024 * 512), "0.5 GB");
        let a = SessionFolder {
            id: Uuid::new_v4(),
            parent_id: None,
            name: "Customer".into(),
            sort_order: 0,
            defaults: Default::default(),
        };
        let b = SessionFolder {
            id: Uuid::new_v4(),
            parent_id: Some(a.id),
            name: "Web".into(),
            sort_order: 0,
            defaults: Default::default(),
        };
        let map: HashMap<Uuid, &SessionFolder> = [(a.id, &a), (b.id, &b)].into();
        assert_eq!(folder_path(Some(b.id), &map), "Customer / Web");
        assert_eq!(folder_path(None, &map), "");
    }
}
