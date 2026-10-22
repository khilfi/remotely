//! MO-14: admin details of a Linux host, read on demand: services (running and failed), listening
//! ports, logged-in users, the last boot, top processes, and pending updates. Pure parsers, tested
//! against what real hosts print; [`super::HostDetails`] runs the scripts.
//!
//! Every command only reads, as the login user: no sudo. `ss` and `netstat` name another user's
//! processes only for root, so ports may come without process names; `ps` and `who` name users, and
//! `who` the address each logged in from. Process command lines are never read (only the program
//! name), since a command line can hold a password.

use serde::{Deserialize, Serialize};

use super::linux::sections;
use crate::adapters::network::ip_literal;

/// One exec for everything but pending updates. Without systemd, OpenRC's `rc-status` or SysV's
/// `service --status-all` list services instead. Boots and shutdowns come from the latest 200 entries of
/// the login record (`last -x`), filtered here: naming them on the command line (`last reboot shutdown`)
/// would read like a shutdown to the policy engine's dangerous-command rule.
pub const ADMIN_SCRIPT: &str =
    "echo @@running; systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null; \
echo @@failed; systemctl list-units --type=service --state=failed --no-pager --no-legend --plain 2>/dev/null; \
echo @@other-init; type systemctl >/dev/null 2>&1 || rc-status 2>/dev/null || service --status-all 2>&1; \
echo @@ports; ss -tulpnH 2>/dev/null || ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null; \
echo @@who; who; \
echo @@who-boot; who -b; \
echo @@uptime; cat /proc/uptime; \
echo @@last; last -x -F -n 200 2>/dev/null; \
echo @@ps; ps -eo pid,user,pcpu,pmem,rss,etime,comm 2>/dev/null";

/// Pending updates, from apt's lists as they are (no `apt update`: that needs root and changes them)
/// or dnf, which refreshes its metadata first when it is old: that can take a minute or more.
pub const UPDATES_SCRIPT: &str =
    "echo @@apt; type apt >/dev/null 2>&1 && echo present && apt list --upgradable 2>/dev/null; \
echo @@apt-lists; stat -c %Y /var/cache/apt/pkgcache.bin 2>/dev/null; \
echo @@dnf; type dnf >/dev/null 2>&1 && echo present && dnf check-update -q 2>/dev/null; \
echo @@dnf-status $?";

pub const MAX_OUTPUT: usize = 1024 * 1024;

/// Processes listed per table.
pub const TOP_PROCESSES: usize = 10;

/// Boots and shutdowns listed at most.
pub const MAX_BOOTS: usize = 10;

/// How a host's services were listed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceManager {
    Systemd,
    OpenRc,
    SysV,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceState {
    Running,
    Failed,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// `nginx.service` (systemd) or `nginx`.
    pub name: String,
    pub description: Option<String>,
    pub state: ServiceState,
    /// systemd's sub-state, e.g. `running`, `failed`, `exited`.
    pub sub: Option<String>,
}

/// A socket listening for connections (TCP) or packets (UDP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListeningPort {
    /// `tcp` or `udp` (IPv4 and IPv6 alike).
    pub protocol: String,
    /// The address it listens on: `0.0.0.0`, `::`, `127.0.0.1`, `*`, or one of the host's.
    pub ip: String,
    pub port: u16,
    /// `%lo` in `127.0.0.53%lo:53`: bound to one interface.
    pub interface: Option<String>,
    /// Program names; empty when the login user can't see them (another user's process, not root).
    pub processes: Vec<String>,
    pub pids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggedInUser {
    pub user: String,
    /// `pts/0`, `tty1`, `:0`.
    pub terminal: String,
    /// When, as `who` printed it.
    pub since: String,
    /// Where from, when it was an IP address.
    pub ip: Option<String>,
    /// Where from, when it was a host name (or a tmux or screen session).
    pub host: Option<String>,
}

/// One line of `last -x reboot shutdown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootEvent {
    /// `reboot` or `shutdown`.
    pub kind: String,
    pub kernel: Option<String>,
    /// From when to when, as `last` printed it, e.g. `Sat Oct 18 08:12:03 2026 - still running`.
    pub when: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub user: String,
    /// CPU time over the process's life as a share of one CPU, as `ps` counts it (not right now).
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub rss_bytes: u64,
    /// How long it has run, in seconds.
    pub elapsed_secs: Option<u64>,
    /// The program name only, never its arguments.
    pub command: String,
}

/// What [`ADMIN_SCRIPT`] found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDetails {
    pub service_manager: ServiceManager,
    pub running: Vec<Service>,
    pub failed: Vec<Service>,
    /// Without systemd: the services the init system lists as stopped or unknown.
    pub other_services: Vec<Service>,
    pub ports: Vec<ListeningPort>,
    /// Some ports have no process: their owner is another user, so only root sees it.
    pub ports_need_root: bool,
    pub users: Vec<LoggedInUser>,
    /// `who -b`, e.g. `2026-10-18 08:12`.
    pub boot_text: Option<String>,
    pub uptime_secs: Option<u64>,
    pub boots: Vec<BootEvent>,
    pub process_count: usize,
    pub top_cpu: Vec<ProcessInfo>,
    pub top_memory: Vec<ProcessInfo>,
    /// The host answered, but not like Linux.
    pub not_linux: bool,
}

/// Parses everything [`ADMIN_SCRIPT`] printed.
pub fn parse(output: &str) -> AdminDetails {
    let parts = sections(output);
    let part = |name: &str| parts.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let mut details = AdminDetails::default();
    let running = parse_systemctl(part("running"));
    let failed = parse_systemctl(part("failed"));
    if !running.is_empty() || !failed.is_empty() {
        details.service_manager = ServiceManager::Systemd;
        details.running = running;
        details.failed = failed;
    } else {
        let (manager, services) = parse_other_init(part("other-init"));
        details.service_manager = manager;
        for service in services {
            match service.state {
                ServiceState::Running => details.running.push(service),
                ServiceState::Failed => details.failed.push(service),
                _ => details.other_services.push(service),
            }
        }
    }
    details.ports = parse_ports(part("ports"));
    details.ports_need_root = details.ports.iter().any(|p| p.processes.is_empty());
    details.users = parse_who(part("who"));
    details.boot_text = part("who-boot").iter().find_map(|l| {
        let line = l.trim();
        line.strip_prefix("system boot").map(|rest| rest.trim().to_owned())
    });
    details.uptime_secs = part("uptime")
        .first()
        .and_then(|l| l.split_whitespace().next())
        .and_then(|u| u.parse::<f64>().ok())
        .filter(|u| *u >= 0.0)
        .map(|u| u as u64);
    details.boots = parse_last(part("last"));
    let processes = parse_ps(part("ps"));
    details.process_count = processes.len();
    details.top_cpu = top(&processes, |a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
    details.top_memory = top(&processes, |a, b| b.rss_bytes.cmp(&a.rss_bytes));
    details.not_linux = details.uptime_secs.is_none() && processes.is_empty() && details.running.is_empty();
    details
}

fn top(
    processes: &[ProcessInfo],
    order: impl Fn(&ProcessInfo, &ProcessInfo) -> std::cmp::Ordering,
) -> Vec<ProcessInfo> {
    let mut sorted = processes.to_vec();
    sorted.sort_by(|a, b| order(a, b).then(a.pid.cmp(&b.pid)));
    sorted.truncate(TOP_PROCESSES);
    sorted
}

/// `systemctl list-units --plain --no-legend`: `UNIT LOAD ACTIVE SUB DESCRIPTION...`. Without
/// `--plain` (old systemd ignores nothing, but a bullet may lead a failed unit) the `●` is dropped.
pub fn parse_systemctl(lines: &[&str]) -> Vec<Service> {
    lines
        .iter()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches(['●', '*', '○']).trim();
            let mut words = line.split_whitespace();
            let name = words.next()?;
            if !name.contains('.') {
                return None;
            }
            let _load = words.next()?;
            let active = words.next()?;
            let sub = words.next()?;
            let description: Vec<&str> = words.collect();
            let state = match (active, sub) {
                ("failed", _) | (_, "failed") => ServiceState::Failed,
                ("active", "running") => ServiceState::Running,
                ("inactive", _) => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };
            Some(Service {
                name: name.to_owned(),
                description: Some(description.join(" ")).filter(|d| !d.is_empty()),
                state,
                sub: Some(sub.to_owned()),
            })
        })
        .collect()
}

/// OpenRC's `rc-status` (` sshd   [  started  ]` under `Runlevel:` headings) or `service --status-all`
/// (Debian's ` [ + ]  cron`, or RHEL 6's `crond (pid  1520) is running...`).
pub fn parse_other_init(lines: &[&str]) -> (ServiceManager, Vec<Service>) {
    let mut services: Vec<Service> = Vec::new();
    let mut manager = ServiceManager::Unknown;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("Runlevel:") {
            if trimmed.contains("Runlevel:") {
                manager = ServiceManager::OpenRc;
            }
            continue;
        }
        let service = if let Some(rest) = trimmed.strip_prefix('[') {
            // Debian: `[ + ]  cron`
            let Some((mark, name)) = rest.split_once(']') else {
                continue;
            };
            manager = ServiceManager::SysV;
            let state = match mark.trim() {
                "+" => ServiceState::Running,
                "-" => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };
            Service {
                name: name.trim().to_owned(),
                description: None,
                state,
                sub: None,
            }
        } else if trimmed.ends_with(']') && trimmed.contains('[') {
            // OpenRC: `sshd    [  started  ]`
            let open = trimmed.rfind('[').unwrap_or(0);
            let status = trimmed[open + 1..trimmed.len() - 1].trim().to_ascii_lowercase();
            if manager == ServiceManager::Unknown {
                manager = ServiceManager::OpenRc;
            }
            let state = match status.as_str() {
                "started" => ServiceState::Running,
                "crashed" => ServiceState::Failed,
                "stopped" => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };
            Service {
                name: trimmed[..open].trim().to_owned(),
                description: None,
                state,
                sub: Some(status),
            }
        } else if let Some(at) = [" (pid", " is ", " dead"].iter().filter_map(|w| trimmed.find(w)).min() {
            // RHEL 6: `crond (pid  1520) is running...`, `nginx is stopped`, `iptables: Firewall is not
            // running.`, `httpd dead but pid file exists`.
            manager = ServiceManager::SysV;
            let name = trimmed[..at].trim();
            let name = name.split_once(':').map_or(name, |(n, _)| n).trim().to_owned();
            let lower = trimmed.to_ascii_lowercase();
            let state = if lower.contains("dead") || lower.contains("failed") {
                ServiceState::Failed
            } else if lower.contains("not running") || lower.contains("stopped") {
                ServiceState::Stopped
            } else if lower.contains("running") {
                ServiceState::Running
            } else {
                ServiceState::Unknown
            };
            Service {
                name,
                description: None,
                state,
                sub: None,
            }
        } else {
            continue;
        };
        if !service.name.is_empty() && !services.iter().any(|s| s.name == service.name) {
            services.push(service);
        }
    }
    (manager, services)
}

/// `0.0.0.0:22`, `[::]:22`, `*:80`, `127.0.0.53%lo:53`, netstat's `:::22`. Returns the address, the
/// interface and the port.
fn split_address(text: &str) -> Option<(String, Option<String>, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let (host, interface) = match host.split_once('%') {
        Some((h, i)) => (h, Some(i.to_owned())),
        None => (host, None),
    };
    let host = if host.is_empty() { "::" } else { host };
    Some((host.to_owned(), interface, port))
}

/// Program names and pids in ss's `users:(("nginx",pid=2201,fd=6),("nginx",pid=2200,fd=6))` (old ss:
/// `users:(("sshd",1001,3))`) or netstat's `1001/sshd`.
fn process_names(text: &str) -> (Vec<String>, Vec<u32>) {
    let mut names = Vec::new();
    let mut pids = Vec::new();
    if let Some(users) = text.find("users:(") {
        let mut rest = &text[users + 7..];
        while let Some(open) = rest.find("(\"") {
            let after = &rest[open + 2..];
            let Some(close) = after.find('"') else {
                break;
            };
            let name = after[..close].to_owned();
            let fields = &after[close + 1..];
            let end = fields.find(')').unwrap_or(fields.len());
            let pid = fields[..end]
                .split(',')
                .map(|f| f.trim().trim_start_matches("pid="))
                .find_map(|f| f.parse::<u32>().ok());
            if !names.contains(&name) {
                names.push(name);
            }
            if let Some(pid) = pid.filter(|p| !pids.contains(p)) {
                pids.push(pid);
            }
            rest = &fields[end..];
        }
    } else if let Some((pid, name)) = text.trim().split_once('/') {
        if let Ok(pid) = pid.parse::<u32>() {
            names.push(name.trim().to_owned());
            pids.push(pid);
        }
    }
    (names, pids)
}

/// `ss -tulpn` (with or without its header) or `netstat -tulpn`. One entry per protocol, address and
/// port; sorted by port.
pub fn parse_ports(lines: &[&str]) -> Vec<ListeningPort> {
    let mut ports: Vec<ListeningPort> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = words.first() else {
            continue;
        };
        let (protocol, local, rest) = match *first {
            // ss: Netid State Recv-Q Send-Q Local Peer [Process]
            "tcp" | "udp" if words.len() >= 6 && !words[1].chars().all(|c| c.is_ascii_digit()) => {
                if words[0] == "tcp" && words[1] != "LISTEN" {
                    continue;
                }
                (words[0], words[4], words[6..].join(" "))
            }
            // netstat: Proto Recv-Q Send-Q Local Foreign [State] PID/Program
            "tcp" | "tcp6" | "udp" | "udp6" if words.len() >= 5 => {
                let tcp = words[0].starts_with("tcp");
                if tcp && words.get(5) != Some(&"LISTEN") {
                    continue;
                }
                let program = if tcp { words.get(6) } else { words.get(5) };
                (
                    words[0].trim_end_matches('6'),
                    words[3],
                    program.map(|p| p.to_string()).unwrap_or_default(),
                )
            }
            _ => continue,
        };
        let Some((ip, interface, port)) = split_address(local) else {
            continue;
        };
        let (names, pids) = process_names(&rest);
        match ports
            .iter_mut()
            .find(|p| p.protocol == protocol && p.ip == ip && p.port == port)
        {
            Some(existing) => {
                for name in names {
                    if !existing.processes.contains(&name) {
                        existing.processes.push(name);
                    }
                }
                existing.pids.extend(pids);
            }
            None => ports.push(ListeningPort {
                protocol: protocol.to_owned(),
                ip,
                port,
                interface,
                processes: names,
                pids,
            }),
        }
    }
    ports.sort_by(|a, b| (a.port, &a.protocol, &a.ip).cmp(&(b.port, &b.protocol, &b.ip)));
    ports
}

/// `who`: `alice    pts/0        2026-10-22 09:14 (192.0.2.50)`. The time's format follows the host's
/// locale, so it is kept as printed.
pub fn parse_who(lines: &[&str]) -> Vec<LoggedInUser> {
    lines
        .iter()
        .filter_map(|line| {
            let line = line.trim_end();
            let mut words = line.split_whitespace();
            let user = words.next()?.to_owned();
            let terminal = words.next()?.to_owned();
            let after_tty = line
                .find(&terminal)
                .map(|at| &line[at + terminal.len()..])
                .unwrap_or("");
            let (since, from) = match after_tty.find(" (") {
                Some(open) if after_tty.ends_with(')') => (
                    after_tty[..open].trim(),
                    Some(&after_tty[open + 2..after_tty.len() - 1]),
                ),
                _ => (after_tty.trim(), None),
            };
            let (ip, host) = match from.map(str::trim).filter(|f| !f.is_empty()) {
                Some(from) if ip_literal(from).is_some() => (Some(from.to_owned()), None),
                Some(from) => (None, Some(from.to_owned())),
                None => (None, None),
            };
            Some(LoggedInUser {
                user,
                terminal,
                since: since.to_owned(),
                ip,
                host,
            })
        })
        .collect()
}

/// The reboot and shutdown lines of `last -x -F` (newest first), at most [`MAX_BOOTS`]:
/// `reboot   system boot  6.8.0-45-generic Sat Oct 18 08:12:03 2026   still running`.
pub fn parse_last(lines: &[&str]) -> Vec<BootEvent> {
    lines
        .iter()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let kind = *words.first()?;
            if !matches!(kind, "reboot" | "shutdown") || words.len() < 5 || words[1] != "system" {
                return None;
            }
            Some(BootEvent {
                kind: kind.to_owned(),
                kernel: Some(words[3].to_owned()),
                when: words[4..].join(" "),
            })
        })
        .take(MAX_BOOTS)
        .collect()
}

/// `ps -eo etime`: `[[dd-]hh:]mm:ss`.
pub fn parse_elapsed(text: &str) -> Option<u64> {
    let (days, clock) = match text.split_once('-') {
        Some((d, rest)) => (d.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let parts: Vec<u64> = clock.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let secs = match parts.as_slice() {
        [m, s] => m * 60 + s,
        [h, m, s] => h * 3600 + m * 60 + s,
        _ => return None,
    };
    Some(days * 86_400 + secs)
}

/// `ps -eo pid,user,pcpu,pmem,rss,etime,comm`; the command is the rest of the line (it may hold spaces).
pub fn parse_ps(lines: &[&str]) -> Vec<ProcessInfo> {
    lines
        .iter()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 7 {
                return None;
            }
            Some(ProcessInfo {
                pid: words[0].parse().ok()?,
                user: words[1].to_owned(),
                cpu_pct: words[2].parse().ok()?,
                mem_pct: words[3].parse().ok()?,
                rss_bytes: words[4].parse::<u64>().ok()?.saturating_mul(1024),
                elapsed_secs: parse_elapsed(words[5]),
                command: words[6..].join(" "),
            })
        })
        .collect()
}

/// One package with a newer version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdate {
    pub name: String,
    pub version: String,
    /// The installed version (apt says it).
    pub current: Option<String>,
    /// Where it comes from: `noble-updates`, `baseos`...
    pub source: String,
    /// apt: it comes from a security pocket.
    pub security: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PackageManager {
    Apt,
    Dnf,
}

/// What [`UPDATES_SCRIPT`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatesReport {
    pub manager: Option<PackageManager>,
    pub packages: Vec<PendingUpdate>,
    pub security_count: usize,
    /// apt: when its package lists were last refreshed (`apt update`), as Unix seconds.
    pub lists_refreshed_unix: Option<i64>,
    /// dnf could not check (no network, a broken repository).
    pub error: Option<String>,
}

/// Parses everything [`UPDATES_SCRIPT`] printed.
pub fn parse_updates(output: &str) -> UpdatesReport {
    let parts = sections(output);
    let part = |name: &str| parts.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let mut report = UpdatesReport::default();
    let apt = part("apt");
    let dnf = part("dnf");
    if apt.first().is_some_and(|l| l.trim() == "present") {
        report.manager = Some(PackageManager::Apt);
        report.packages = apt[1..].iter().filter_map(|l| parse_apt_line(l)).collect();
        report.lists_refreshed_unix = part("apt-lists").iter().find_map(|l| l.trim().parse::<i64>().ok());
    } else if dnf.first().is_some_and(|l| l.trim() == "present") {
        report.manager = Some(PackageManager::Dnf);
        report.packages = parse_dnf(&dnf[1..]);
        // `echo @@dnf-status $?` puts the status on the marker line itself.
        let status = output
            .lines()
            .find_map(|l| l.trim().strip_prefix("@@dnf-status").map(|s| s.trim().to_owned()));
        if status.as_deref() == Some("1") {
            report.error = Some(
                "dnf could not check for updates: a repository could not be reached, or its metadata is broken".into(),
            );
        }
    }
    report.security_count = report.packages.iter().filter(|p| p.security).count();
    report
}

/// `bash/noble-updates 5.2.21-2ubuntu4.1 amd64 [upgradable from: 5.2.21-2ubuntu4]`.
fn parse_apt_line(line: &str) -> Option<PendingUpdate> {
    let line = line.trim();
    if line.starts_with("Listing") || line.is_empty() {
        return None;
    }
    let mut words = line.split_whitespace();
    let (name, source) = words.next()?.split_once('/')?;
    let version = words.next()?.to_owned();
    let current = line
        .find("[upgradable from:")
        .map(|at| line[at + 17..].trim_end_matches(']').trim().to_owned());
    Some(PendingUpdate {
        name: name.to_owned(),
        version,
        current,
        security: source.split(',').any(|s| s.ends_with("-security")),
        source: source.to_owned(),
    })
}

/// `dnf check-update -q`: `name.arch  version  repository` lines, then maybe "Obsoleting Packages".
fn parse_dnf(lines: &[&str]) -> Vec<PendingUpdate> {
    let mut out = Vec::new();
    for line in lines {
        if line.trim_start().starts_with("Obsoleting") || line.trim_start().starts_with("Security:") {
            break;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() != 3 || !words[0].contains('.') {
            continue;
        }
        out.push(PendingUpdate {
            name: words[0].to_owned(),
            version: words[1].to_owned(),
            current: None,
            source: words[2].to_owned(),
            security: false,
        });
    }
    out
}

/// Test data: what real hosts print for [`ADMIN_SCRIPT`] and [`UPDATES_SCRIPT`].
#[cfg(any(test, feature = "fakes"))]
pub mod samples {
    pub const SYSTEMCTL_RUNNING: &str = "accounts-daemon.service          loaded active running Accounts Service
cron.service                     loaded active running Regular background program processing daemon
dbus.service                     loaded active running D-Bus System Message Bus
nginx.service                    loaded active running A high performance web server and a reverse proxy server
ssh.service                      loaded active running OpenBSD Secure Shell server
";

    pub const SYSTEMCTL_FAILED: &str = "● postgresql@16-main.service loaded failed failed PostgreSQL Cluster 16-main
";

    pub const SS: &str = "udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=1001,fd=3))
tcp   LISTEN 0      511                *:80              *:*    users:((\"nginx\",pid=2201,fd=6),(\"nginx\",pid=2200,fd=6))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:((\"sshd\",pid=1001,fd=4))
tcp   LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*
";

    pub const WHO: &str = "alice    pts/0        2026-10-22 09:14 (192.0.2.50)
bob      pts/1        2026-10-22 10:01 (tmux(1234).%0)
root     tty1         2026-10-20 08:00
carol    pts/2        Oct 22 09:30 (laptop.example.com)
";

    pub const LAST: &str = "alice    pts/0        192.0.2.50       Wed Oct 22 09:14:02 2026   still logged in
runlevel (to lvl 5)   6.8.0-45-generic Sat Oct 18 08:12:10 2026   still running
reboot   system boot  6.8.0-45-generic Sat Oct 18 08:12:03 2026   still running
shutdown system down  6.8.0-45-generic Sat Oct 18 08:11:40 2026 - Sat Oct 18 08:12:03 2026  (00:00)
bob      pts/1        198.51.100.7     Fri Oct 17 16:00:00 2026 - Fri Oct 17 17:30:00 2026  (01:30)
reboot   system boot  6.8.0-41-generic Mon Oct  6 07:00:00 2026 - Sat Oct 18 08:11:40 2026 (12+01:11)

wtmp begins Mon Sep  1 10:00:00 2026
";

    pub const PS: &str = "    PID USER     %CPU %MEM   RSS     ELAPSED COMMAND
      1 root      0.0  0.1 12345  3-02:01:00 systemd
   1001 root      0.0  0.0  8000  3-02:00:59 sshd
   2200 www-data 12.5  1.2 98765    01:23:45 nginx
   3000 alice    99.0 25.3 2097152      05:12 java
   3100 bob       3.0  2.0 163840      00:42 tmux: server
";

    pub const APT: &str = "present
Listing...
bash/noble-updates 5.2.21-2ubuntu4.1 amd64 [upgradable from: 5.2.21-2ubuntu4]
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
";

    pub const DNF: &str = "present

bash.x86_64                    5.1.8-9.el9                  baseos
openssl.x86_64                 1:3.0.7-28.el9_4             baseos
nginx.x86_64                   1:1.20.1-16.el9_4.1          appstream
Obsoleting Packages
grub2-tools.x86_64             1:2.06-80.el9                baseos
";

    /// What an Ubuntu host prints for the whole admin script, as alice (not root).
    pub fn ubuntu() -> String {
        format!(
            "@@running\n{SYSTEMCTL_RUNNING}@@failed\n{SYSTEMCTL_FAILED}@@other-init\n@@ports\n{SS}@@who\n{WHO}@@who-boot\n         system boot  2026-10-18 08:12\n@@uptime\n273600.52 1000000.10\n@@last\n{LAST}@@ps\n{PS}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::samples::*;
    use super::*;
    use crate::policy::{ActionKind, PolicyEngine, PolicyRules};

    #[test]
    fn every_command_only_reads() {
        let policy = PolicyEngine::new(PolicyRules::default()).unwrap();
        for script in [ADMIN_SCRIPT, UPDATES_SCRIPT] {
            assert_eq!(policy.classify_script(script), ActionKind::ExecReadOnly, "{script}");
            for part in script.split(';') {
                assert_eq!(policy.classify_script(part), ActionKind::ExecReadOnly, "{part}");
            }
        }
        // What the panel offers to copy is a change, never run from here.
        for fix in ["sudo systemctl restart nginx.service", "kill 3000", "sudo apt upgrade"] {
            assert_ne!(policy.classify_script(fix), ActionKind::ExecReadOnly, "{fix}");
        }
    }

    #[test]
    fn reads_an_ubuntu_host_end_to_end() {
        let details = parse(&ubuntu());
        assert_eq!(details.service_manager, ServiceManager::Systemd);
        let running: Vec<&str> = details.running.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            running,
            [
                "accounts-daemon.service",
                "cron.service",
                "dbus.service",
                "nginx.service",
                "ssh.service"
            ]
        );
        assert_eq!(
            details.running[4].description.as_deref(),
            Some("OpenBSD Secure Shell server")
        );
        assert_eq!(details.failed.len(), 1);
        assert_eq!(
            details.failed[0].name, "postgresql@16-main.service",
            "the bullet dropped"
        );
        assert_eq!(details.failed[0].state, ServiceState::Failed);

        type PortRow<'a> = (&'a str, &'a str, u16, Option<&'a str>, Vec<&'a str>);
        let ports: Vec<PortRow> = details
            .ports
            .iter()
            .map(|p| {
                (
                    p.protocol.as_str(),
                    p.ip.as_str(),
                    p.port,
                    p.interface.as_deref(),
                    p.processes.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            ports,
            [
                ("tcp", "0.0.0.0", 22, None, vec!["sshd"]),
                ("tcp", "::", 22, None, vec!["sshd"]),
                ("tcp", "127.0.0.53", 53, Some("lo"), vec![]),
                ("udp", "127.0.0.53", 53, Some("lo"), vec![]),
                ("udp", "0.0.0.0", 68, None, vec![]),
                ("tcp", "*", 80, None, vec!["nginx"]),
                ("tcp", "127.0.0.1", 5432, None, vec![]),
            ]
        );
        assert_eq!(details.ports[5].pids, [2201, 2200]);
        assert!(details.ports_need_root, "postgres and resolved belong to other users");

        type UserRow<'a> = (&'a str, &'a str, &'a str, Option<&'a str>, Option<&'a str>);
        let users: Vec<UserRow> = details
            .users
            .iter()
            .map(|u| {
                (
                    u.user.as_str(),
                    u.terminal.as_str(),
                    u.since.as_str(),
                    u.ip.as_deref(),
                    u.host.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            users,
            [
                ("alice", "pts/0", "2026-10-22 09:14", Some("192.0.2.50"), None),
                ("bob", "pts/1", "2026-10-22 10:01", None, Some("tmux(1234).%0")),
                ("root", "tty1", "2026-10-20 08:00", None, None),
                ("carol", "pts/2", "Oct 22 09:30", None, Some("laptop.example.com")),
            ]
        );
        assert_eq!(details.boot_text.as_deref(), Some("2026-10-18 08:12"));
        assert_eq!(details.uptime_secs, Some(273_600));
        assert_eq!(details.boots.len(), 3, "not logins, run levels or the wtmp line");
        assert_eq!(details.boots[0].when, "Sat Oct 18 08:12:03 2026 still running");
        assert_eq!(details.boots[2].kernel.as_deref(), Some("6.8.0-41-generic"));

        assert_eq!(details.process_count, 5);
        let by_cpu: Vec<&str> = details.top_cpu.iter().map(|p| p.command.as_str()).collect();
        assert_eq!(by_cpu, ["java", "nginx", "tmux: server", "systemd", "sshd"]);
        let by_memory: Vec<u32> = details.top_memory.iter().map(|p| p.pid).collect();
        assert_eq!(by_memory, [3000, 3100, 2200, 1, 1001]);
        assert_eq!(details.top_cpu[0].rss_bytes, 2_097_152 * 1024);
        assert_eq!(details.top_cpu[0].elapsed_secs, Some(312));
        assert!(!details.not_linux);
    }

    #[test]
    fn services_without_systemd() {
        let rc = "Runlevel: default\n sshd                                                              [  started  ]\n crond                                                             [  started  ]\n nginx                                                             [  crashed  ]\nDynamic Runlevel: hotplugged\nDynamic Runlevel: needed/wanted\n sysfs                                                             [  started  ]\n";
        let details = parse(&format!("@@running\n@@failed\n@@other-init\n{rc}@@ps\n"));
        assert_eq!(details.service_manager, ServiceManager::OpenRc);
        let running: Vec<&str> = details.running.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(running, ["sshd", "crond", "sysfs"]);
        assert_eq!(details.failed[0].name, "nginx");

        let debian = " [ + ]  cron\n [ - ]  nginx\n [ ? ]  hwclock.sh\n";
        let (manager, services) = parse_other_init(&debian.lines().collect::<Vec<_>>());
        assert_eq!(manager, ServiceManager::SysV);
        let states: Vec<(&str, ServiceState)> = services.iter().map(|s| (s.name.as_str(), s.state)).collect();
        assert_eq!(
            states,
            [
                ("cron", ServiceState::Running),
                ("nginx", ServiceState::Stopped),
                ("hwclock.sh", ServiceState::Unknown)
            ]
        );

        let rhel6 = "crond (pid  1520) is running...\niptables: Firewall is not running.\nnginx is stopped\nhttpd dead but pid file exists\n";
        let (manager, services) = parse_other_init(&rhel6.lines().collect::<Vec<_>>());
        assert_eq!(manager, ServiceManager::SysV);
        let states: Vec<(&str, ServiceState)> = services.iter().map(|s| (s.name.as_str(), s.state)).collect();
        assert_eq!(
            states,
            [
                ("crond", ServiceState::Running),
                ("iptables", ServiceState::Stopped),
                ("nginx", ServiceState::Stopped),
                ("httpd", ServiceState::Failed),
            ]
        );
    }

    #[test]
    fn old_ss_with_a_header_and_netstat() {
        let old = "Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port\ntcp    LISTEN     0      128          *:22                       *:*                   users:((\"sshd\",1001,3))\ntcp    ESTAB      0      0      192.0.2.10:22          192.0.2.50:51234\n";
        let ports = parse_ports(&old.lines().collect::<Vec<_>>());
        assert_eq!(ports.len(), 1, "the header and an established connection left out");
        assert_eq!((ports[0].ip.as_str(), ports[0].port), ("*", 22));
        assert_eq!(ports[0].processes, ["sshd"]);
        assert_eq!(ports[0].pids, [1001]);

        let netstat = "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1001/sshd\ntcp6       0      0 :::22                   :::*                    LISTEN      1001/sshd\ntcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -\nudp        0      0 0.0.0.0:68              0.0.0.0:*                           -\n";
        let ports = parse_ports(&netstat.lines().collect::<Vec<_>>());
        let summary: Vec<(&str, &str, u16, usize)> = ports
            .iter()
            .map(|p| (p.protocol.as_str(), p.ip.as_str(), p.port, p.processes.len()))
            .collect();
        assert_eq!(
            summary,
            [
                ("tcp", "0.0.0.0", 22, 1),
                ("tcp", "::", 22, 1),
                ("udp", "0.0.0.0", 68, 0),
                ("tcp", "127.0.0.1", 631, 0)
            ]
        );
    }

    #[test]
    fn elapsed_times_read_like_ps_prints_them() {
        assert_eq!(parse_elapsed("05:12"), Some(312));
        assert_eq!(parse_elapsed("01:23:45"), Some(5025));
        assert_eq!(parse_elapsed("3-02:01:00"), Some(3 * 86_400 + 7260));
        assert_eq!(parse_elapsed("soon"), None);
    }

    #[test]
    fn pending_updates_from_apt_and_dnf() {
        let apt = parse_updates(&format!("@@apt\n{APT}@@apt-lists\n1792600000\n@@dnf\n@@dnf-status 1\n"));
        assert_eq!(apt.manager, Some(PackageManager::Apt));
        assert_eq!(apt.packages.len(), 2);
        assert_eq!(apt.packages[0].name, "bash");
        assert_eq!(apt.packages[0].current.as_deref(), Some("5.2.21-2ubuntu4"));
        assert!(apt.packages[1].security);
        assert_eq!(apt.security_count, 1);
        assert_eq!(apt.lists_refreshed_unix, Some(1_792_600_000));
        assert_eq!(apt.error, None, "dnf's status doesn't count on an apt host");

        let dnf = parse_updates(&format!("@@apt\n@@apt-lists\n@@dnf\n{DNF}@@dnf-status 100\n"));
        assert_eq!(dnf.manager, Some(PackageManager::Dnf));
        let names: Vec<&str> = dnf.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["bash.x86_64", "openssl.x86_64", "nginx.x86_64"],
            "not the obsoleted list"
        );
        assert_eq!(dnf.error, None);
        let broken = parse_updates("@@apt\n@@apt-lists\n@@dnf\npresent\n@@dnf-status 1\n");
        assert!(broken.error.is_some());
        let neither = parse_updates("@@apt\n@@apt-lists\n@@dnf\n@@dnf-status 1\n");
        assert_eq!(neither.manager, None);
    }
}
