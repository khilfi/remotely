//! MO-13: what a Linux host says about its OS and hardware, read in one exec and parsed here. Pure
//! functions, tested against what real distributions print.
//!
//! The script uses plain commands, `;`, `||` and redirections only, so any `sh` runs it; every part
//! classifies as read-only under the default policy rules (`tests::every_command_only_reads`). Each
//! part follows a marker line, and a part that is missing or fails leaves its fields empty.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One exec on the host. `LC_ALL=C` keeps lscpu's labels and df's header in English. `df -l` leaves
/// network mounts out (a dead one can hang df); busybox df has no `-T` or `-B1`, so it falls back to
/// `-kP`. Old lsblk (util-linux before 2.27, e.g. RHEL 7) has no JSON: `-P` prints `KEY="value"` pairs.
pub const SPECS_SCRIPT: &str = "echo @@os-release; cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null; \
echo @@redhat-release; cat /etc/redhat-release 2>/dev/null; \
echo @@uname; uname -srm; \
echo @@hostname; hostname; \
echo @@cpu; LC_ALL=C lscpu 2>/dev/null || cat /proc/cpuinfo; \
echo @@meminfo; cat /proc/meminfo; \
echo @@swaps; cat /proc/swaps 2>/dev/null; \
echo @@lsblk; lsblk -J -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,ROTA,TRAN 2>/dev/null || lsblk -P -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL 2>/dev/null; \
echo @@df; LC_ALL=C df -PT -B1 -l 2>/dev/null || LC_ALL=C df -kP -l 2>/dev/null; \
echo @@virt; systemd-detect-virt 2>/dev/null; \
echo @@uptime; cat /proc/uptime";

/// Output kept from the script. A host with hundreds of disks prints a few hundred kilobytes.
pub const MAX_OUTPUT: usize = 512 * 1024;

/// A host's OS and hardware.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HostSpecs {
    pub os: OsInfo,
    /// `uname -s`: "Linux"; anything else is not a Linux host.
    pub system: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
    pub hostname: Option<String>,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub swaps: Vec<SwapArea>,
    pub disks: Vec<BlockDevice>,
    pub filesystems: Vec<Filesystem>,
    /// `systemd-detect-virt`, or lscpu's hypervisor vendor: "vmware", "kvm", "oracle", "microsoft",
    /// "none" (bare metal)...
    pub virtualization: Option<String>,
    pub uptime_secs: Option<u64>,
}

impl HostSpecs {
    /// Nothing a Linux host would print (a network device, a Windows host).
    pub fn is_empty(&self) -> bool {
        self.os.pretty_name.is_none()
            && self.kernel.is_none()
            && self.memory.total_bytes.is_none()
            && self.cpu.logical_cpus.is_none()
    }

    /// "Ubuntu 24.04.1 LTS", or the name and version, or the kernel's system name.
    pub fn os_name(&self) -> Option<String> {
        self.os
            .pretty_name
            .clone()
            .or_else(|| match (&self.os.name, &self.os.version) {
                (Some(name), Some(version)) => Some(format!("{name} {version}")),
                (Some(name), None) => Some(name.clone()),
                _ => None,
            })
            .or_else(|| self.system.clone())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OsInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub version_id: Option<String>,
    pub id: Option<String>,
    pub id_like: Option<String>,
    pub pretty_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub vendor: Option<String>,
    /// Logical CPUs (threads) the kernel sees.
    pub logical_cpus: Option<u32>,
    pub sockets: Option<u32>,
    pub cores_per_socket: Option<u32>,
    pub threads_per_core: Option<u32>,
    pub max_mhz: Option<f64>,
}

impl CpuInfo {
    /// Physical cores, when sockets and cores per socket are known.
    pub fn cores(&self) -> Option<u32> {
        Some(self.sockets?.saturating_mul(self.cores_per_socket?))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MemoryInfo {
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
}

/// A swap file or partition, from /proc/swaps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SwapArea {
    pub path: String,
    /// `file` or `partition`.
    pub kind: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
}

/// A block device from lsblk: a disk, a partition, an LVM volume, a RAID or crypt device...
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BlockDevice {
    pub name: String,
    /// lsblk's TYPE: `disk`, `part`, `lvm`, `raid1`, `crypt`, `rom`, `mpath`...
    pub kind: String,
    pub size_bytes: Option<u64>,
    pub fstype: Option<String>,
    pub mountpoint: Option<String>,
    pub model: Option<String>,
    pub rotational: Option<bool>,
    /// `sata`, `nvme`, `spi`, `iscsi`, `usb`...
    pub transport: Option<String>,
    /// 0 for a disk, 1 for its partitions, 2 for what sits on those.
    pub depth: u32,
}

/// A mounted local filesystem, from df.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Filesystem {
    /// The device, e.g. `/dev/mapper/vg-root`.
    pub source: String,
    pub fstype: Option<String>,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    /// Used of what is usable (used + available), as df counts it.
    pub used_pct: f64,
    pub mount: String,
}

/// The script's output split at its markers.
pub fn sections(output: &str) -> BTreeMap<String, Vec<&str>> {
    let mut out: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(name) = trimmed.trim().strip_prefix("@@") {
            let name = name.split_whitespace().next().unwrap_or("").to_owned();
            out.entry(name.clone()).or_default();
            current = Some(name);
        } else if let Some(name) = &current {
            out.entry(name.clone()).or_default().push(trimmed);
        }
    }
    out
}

/// Parses everything [`SPECS_SCRIPT`] printed.
pub fn parse(output: &str) -> HostSpecs {
    let parts = sections(output);
    let part = |name: &str| parts.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let mut specs = HostSpecs {
        os: parse_os_release(part("os-release")),
        ..HostSpecs::default()
    };
    if specs.os.pretty_name.is_none() {
        // CentOS and RHEL 6 have no os-release.
        specs.os.pretty_name = part("redhat-release")
            .iter()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .map(str::to_owned);
    }
    if let Some(line) = part("uname").iter().map(|l| l.trim()).find(|l| !l.is_empty()) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() >= 3 {
            specs.system = Some(words[0].to_owned());
            specs.kernel = Some(words[1].to_owned());
            specs.architecture = Some(words[words.len() - 1].to_owned());
        }
    }
    specs.hostname = part("hostname")
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .filter(|h| crate::adapters::remote::parse_hostname(h, Some(0)).is_some())
        .map(str::to_owned);
    let cpu_lines = part("cpu");
    let (cpu, hypervisor) = if cpu_lines.iter().any(|l| l.starts_with("processor")) {
        (parse_cpuinfo(cpu_lines), None)
    } else {
        parse_lscpu(cpu_lines)
    };
    specs.cpu = cpu;
    specs.memory = parse_meminfo(part("meminfo"));
    specs.swaps = parse_swaps(part("swaps"));
    specs.disks = parse_lsblk(&part("lsblk").join("\n"));
    specs.filesystems = parse_df(part("df"));
    specs.virtualization = part("virt")
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .map(str::to_owned)
        .or(hypervisor.map(|h| h.to_lowercase()));
    specs.uptime_secs = part("uptime")
        .first()
        .and_then(|l| l.split_whitespace().next())
        .and_then(|u| u.parse::<f64>().ok())
        .filter(|u| *u >= 0.0)
        .map(|u| u as u64);
    specs
}

/// `/etc/os-release`: `KEY=value` lines, values maybe quoted with `"` or `'` and escaped with `\`.
pub fn parse_os_release(lines: &[&str]) -> OsInfo {
    let mut os = OsInfo::default();
    for line in lines {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(raw.trim());
        let value = Some(value).filter(|v| !v.is_empty());
        match key.trim() {
            "NAME" => os.name = value,
            "VERSION" => os.version = value,
            "VERSION_ID" => os.version_id = value,
            "ID" => os.id = value,
            "ID_LIKE" => os.id_like = value,
            "PRETTY_NAME" => os.pretty_name = value,
            _ => {}
        }
    }
    os
}

fn unquote(raw: &str) -> String {
    let mut chars = raw.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => {
            let mut out = String::new();
            let mut escaped = false;
            for c in chars {
                if escaped {
                    out.push(c);
                    escaped = false;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                } else if c == q {
                    break;
                } else {
                    out.push(c);
                }
            }
            out
        }
        _ => raw.to_owned(),
    }
}

/// `lscpu` (any util-linux: flat labels, or the indented groups of 2.37 and later). Returns the CPU
/// and lscpu's "Hypervisor vendor", when it names one.
pub fn parse_lscpu(lines: &[&str]) -> (CpuInfo, Option<String>) {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty() {
            fields.entry(key.trim().to_owned()).or_insert_with(|| value.to_owned());
        }
    }
    let number = |key: &str| fields.get(key).and_then(|v| v.parse::<u32>().ok());
    let cpu = CpuInfo {
        model: fields.get("Model name").cloned(),
        vendor: fields.get("Vendor ID").cloned(),
        logical_cpus: number("CPU(s)"),
        // ARM servers count clusters, not sockets ("Socket(s): -").
        sockets: number("Socket(s)").or_else(|| number("Cluster(s)")),
        cores_per_socket: number("Core(s) per socket").or_else(|| number("Core(s) per cluster")),
        threads_per_core: number("Thread(s) per core"),
        max_mhz: fields
            .get("CPU max MHz")
            .or_else(|| fields.get("CPU MHz"))
            .and_then(|v| v.parse::<f64>().ok()),
    };
    (cpu, fields.get("Hypervisor vendor").cloned())
}

/// /proc/cpuinfo, where lscpu is missing: logical CPUs are `processor` entries, sockets the distinct
/// `physical id`s, cores the distinct (`physical id`, `core id`) pairs.
pub fn parse_cpuinfo(lines: &[&str]) -> CpuInfo {
    let mut logical = 0u32;
    let mut model = None;
    let mut vendor = None;
    let mut sockets = std::collections::BTreeSet::new();
    let mut cores = std::collections::BTreeSet::new();
    let mut physical: Option<String> = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "processor" => {
                logical += 1;
                physical = None;
            }
            "model name" | "Model" | "cpu model" if model.is_none() && !value.is_empty() => {
                model = Some(value.to_owned());
            }
            "vendor_id" if vendor.is_none() => vendor = Some(value.to_owned()),
            "physical id" => {
                sockets.insert(value.to_owned());
                physical = Some(value.to_owned());
            }
            "core id" => {
                cores.insert((physical.clone().unwrap_or_default(), value.to_owned()));
            }
            _ => {}
        }
    }
    let sockets_n = u32::try_from(sockets.len()).ok().filter(|n| *n > 0);
    let cores_n = u32::try_from(cores.len()).ok().filter(|n| *n > 0);
    CpuInfo {
        model,
        vendor,
        logical_cpus: (logical > 0).then_some(logical),
        sockets: sockets_n,
        cores_per_socket: sockets_n.zip(cores_n).map(|(s, c)| (c / s).max(1)),
        threads_per_core: cores_n.filter(|_| logical > 0).map(|c| (logical / c).max(1)),
        max_mhz: None,
    }
}

/// MemTotal, MemAvailable (or free + buffers + cached before kernel 3.14), SwapTotal and SwapFree.
pub fn parse_meminfo(lines: &[&str]) -> MemoryInfo {
    let kb = |key: &str| -> Option<u64> {
        lines.iter().find_map(|line| {
            let rest = line.strip_prefix(key)?.strip_prefix(':')?;
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            Some(value.saturating_mul(1024))
        })
    };
    MemoryInfo {
        total_bytes: kb("MemTotal"),
        available_bytes: kb("MemAvailable")
            .or_else(|| Some(kb("MemFree")? + kb("Buffers").unwrap_or(0) + kb("Cached").unwrap_or(0))),
        swap_total_bytes: kb("SwapTotal"),
        swap_free_bytes: kb("SwapFree"),
    }
}

/// /proc/swaps: `Filename Type Size Used Priority`, sizes in KiB. A name may hold spaces, so the
/// four numbers and the type are read from the end.
pub fn parse_swaps(lines: &[&str]) -> Vec<SwapArea> {
    lines
        .iter()
        .filter(|l| !l.trim_start().starts_with("Filename"))
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 5 {
                return None;
            }
            let n = words.len();
            let size: u64 = words[n - 3].parse().ok()?;
            let used: u64 = words[n - 2].parse().ok()?;
            Some(SwapArea {
                path: words[..n - 4].join(" "),
                kind: words[n - 4].to_owned(),
                size_bytes: size.saturating_mul(1024),
                used_bytes: used.saturating_mul(1024),
            })
        })
        .collect()
}

/// Devices that aren't storage: snap images, RAM disks.
fn skip_device(kind: &str) -> bool {
    matches!(kind, "loop" | "ram")
}

/// `lsblk -J` (sizes as numbers from util-linux 2.33, as strings before; `rota` as a boolean or "0"/"1")
/// or `lsblk -P` (`NAME="sda" TYPE="disk" ...`, one device a line, parents before children).
pub fn parse_lsblk(text: &str) -> Vec<BlockDevice> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let Ok(json) = serde_json::from_str::<Value>(trimmed) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(devices) = json.get("blockdevices").and_then(Value::as_array) {
            for device in devices {
                walk_json(device, 0, &mut out);
            }
        }
        return out;
    }
    trimmed
        .lines()
        .filter_map(|line| {
            let pairs = parse_pairs(line);
            let name = pairs.get("NAME")?.clone();
            let kind = pairs.get("TYPE").cloned().unwrap_or_default();
            if skip_device(&kind) {
                return None;
            }
            // -P keeps no tree: disks first, then partitions, then what sits on them.
            let depth = match kind.as_str() {
                "disk" | "rom" | "mpath" => 0,
                "part" => 1,
                _ => 2,
            };
            Some(BlockDevice {
                name,
                size_bytes: pairs.get("SIZE").and_then(|s| s.parse().ok()),
                fstype: pairs.get("FSTYPE").cloned().filter(|v| !v.is_empty()),
                mountpoint: pairs.get("MOUNTPOINT").cloned().filter(|v| !v.is_empty()),
                model: pairs
                    .get("MODEL")
                    .map(|m| m.trim().to_owned())
                    .filter(|v| !v.is_empty()),
                kind,
                depth,
                ..BlockDevice::default()
            })
        })
        .collect()
}

fn json_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn walk_json(device: &Value, depth: u32, out: &mut Vec<BlockDevice>) {
    let kind = json_text(device.get("type")).unwrap_or_default();
    if skip_device(&kind) {
        return;
    }
    let rotational = match device.get("rota") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match s.as_str() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        },
        Some(Value::Number(n)) => n.as_u64().map(|n| n == 1),
        _ => None,
    };
    // util-linux 2.37 and later can print `mountpoints` (a list) instead.
    let mountpoint = json_text(device.get("mountpoint")).or_else(|| {
        device
            .get("mountpoints")
            .and_then(Value::as_array)
            .and_then(|all| all.iter().find_map(|m| json_text(Some(m))))
    });
    out.push(BlockDevice {
        name: json_text(device.get("name")).unwrap_or_default(),
        size_bytes: json_text(device.get("size")).and_then(|s| s.parse().ok()),
        fstype: json_text(device.get("fstype")),
        mountpoint,
        model: json_text(device.get("model")),
        rotational,
        transport: json_text(device.get("tran")),
        kind,
        depth,
    });
    if let Some(children) = device.get("children").and_then(Value::as_array) {
        for child in children {
            walk_json(child, depth + 1, out);
        }
    }
}

/// `KEY="value"` pairs of `lsblk -P`, with lsblk's `\xHH` escapes undone.
fn parse_pairs(line: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = line.trim();
    while let Some(eq) = rest.find("=\"") {
        let key = rest[..eq].trim().to_owned();
        let after = &rest[eq + 2..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.insert(key, unescape_hex(&after[..end]));
        rest = &after[end + 1..];
    }
    out
}

fn unescape_hex(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\\x") {
        out.push_str(&rest[..at]);
        let hex = rest.get(at + 2..at + 4);
        match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
            Some(byte) => {
                out.push(char::from(byte));
                rest = &rest[at + 4..];
            }
            None => {
                out.push_str("\\x");
                rest = &rest[at + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Memory, pseudo and snap filesystems: not where data runs out.
fn pseudo_filesystem(source: &str, fstype: Option<&str>) -> bool {
    let pseudo_type = fstype.is_some_and(|t| {
        matches!(
            t,
            "tmpfs"
                | "devtmpfs"
                | "overlay"
                | "squashfs"
                | "efivarfs"
                | "proc"
                | "sysfs"
                | "cgroup"
                | "cgroup2"
                | "devpts"
                | "ramfs"
                | "autofs"
                | "nsfs"
                | "tracefs"
                | "fuse.lxcfs"
                | "fuse.snapfuse"
        )
    });
    pseudo_type
        || ["tmpfs", "devtmpfs", "udev", "overlay", "none", "shm", "run", "efivarfs"].contains(&source)
        || source.starts_with("/dev/loop")
}

/// `df -PT -B1` (`Filesystem Type 1-blocks Used Available Capacity Mounted on`) or `df -kP`
/// (no type, 1024-byte blocks). The mount point is the rest of the line, so it may hold spaces.
pub fn parse_df(lines: &[&str]) -> Vec<Filesystem> {
    let Some(header_at) = lines.iter().position(|l| l.trim_start().starts_with("Filesystem")) else {
        return Vec::new();
    };
    let header = lines[header_at];
    let typed = header.split_whitespace().nth(1) == Some("Type");
    let block = header
        .split_whitespace()
        .find_map(|w| w.strip_suffix("-blocks"))
        .and_then(|b| b.parse::<u64>().ok())
        .unwrap_or(1024);
    let numbers_at = if typed { 2 } else { 1 };
    let mut out = Vec::new();
    for line in &lines[header_at + 1..] {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() < numbers_at + 5 {
            continue;
        }
        let fstype = typed.then(|| words[1].to_owned());
        if pseudo_filesystem(words[0], fstype.as_deref()) {
            continue;
        }
        let (Ok(size), Ok(used), Ok(available)) = (
            words[numbers_at].parse::<u64>(),
            words[numbers_at + 1].parse::<u64>(),
            words[numbers_at + 2].parse::<u64>(),
        ) else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let usable = used + available;
        out.push(Filesystem {
            source: words[0].to_owned(),
            fstype,
            size_bytes: size.saturating_mul(block),
            used_bytes: used.saturating_mul(block),
            available_bytes: available.saturating_mul(block),
            used_pct: if usable == 0 {
                0.0
            } else {
                used as f64 * 100.0 / usable as f64
            },
            mount: words[numbers_at + 4..].join(" "),
        });
    }
    out
}

/// Test data: what real hosts print for [`SPECS_SCRIPT`].
#[cfg(any(test, feature = "fakes"))]
pub mod samples {
    pub const OS_RELEASE_UBUNTU: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
"#;

    pub const OS_RELEASE_RHEL: &str = r#"NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"
"#;

    pub const OS_RELEASE_DEBIAN: &str = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
"#;

    /// util-linux 2.39 (Ubuntu 24.04) on a VMware VM: indented groups.
    pub const LSCPU_NEW: &str = "Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          45 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   4
  On-line CPU(s) list:    0-3
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz
    CPU family:           6
    Model:                85
    Thread(s) per core:   1
    Core(s) per socket:   2
    Socket(s):            2
    Stepping:             7
    BogoMIPS:             5999.99
    Flags:                fpu vme de pse tsc msr pae mce cx8 apic
Virtualization features:
  Hypervisor vendor:      VMware
  Virtualization type:    full
Caches (sum of all):
  L1d:                    128 KiB (4 instances)
NUMA:
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-3
";

    /// util-linux 2.23 (RHEL 7) on KVM: flat labels.
    pub const LSCPU_OLD: &str = "Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                8
On-line CPU(s) list:   0-7
Thread(s) per core:    2
Core(s) per socket:    4
Socket(s):             1
NUMA node(s):          1
Vendor ID:             GenuineIntel
CPU family:            6
Model:                 85
Model name:            Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz
Stepping:              4
CPU MHz:               2194.843
BogoMIPS:              4389.68
Hypervisor vendor:     KVM
Virtualization type:   full
L1d cache:             32K
";

    /// util-linux 2.38 on an ARM server: clusters instead of sockets.
    pub const LSCPU_ARM: &str = "Architecture:           aarch64
  CPU op-mode(s):       32-bit, 64-bit
  Byte Order:           Little Endian
CPU(s):                 2
  On-line CPU(s) list:  0,1
Vendor ID:              ARM
  Model name:           Neoverse-N1
    Model:              1
    Thread(s) per core: 1
    Core(s) per cluster: 2
    Socket(s):          -
    Cluster(s):         1
";

    pub const CPUINFO: &str = "processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model name\t: Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz
physical id\t: 0
siblings\t: 4
core id\t\t: 0
cpu cores\t: 2

processor\t: 1
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz
physical id\t: 0
core id\t\t: 0

processor\t: 2
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz
physical id\t: 0
core id\t\t: 1

processor\t: 3
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz
physical id\t: 0
core id\t\t: 1
";

    pub const MEMINFO: &str = "MemTotal:        8131116 kB
MemFree:          912340 kB
MemAvailable:    5226784 kB
Buffers:          210044 kB
Cached:          3812345 kB
SwapCached:            0 kB
SwapTotal:       4194300 kB
SwapFree:        4094300 kB
";

    pub const SWAPS: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority
/swap.img                               file\t\t4194300\t\t100000\t\t-2
";

    /// util-linux 2.39: numbers and booleans; an LVM volume under a partition; snaps and a CD.
    pub const LSBLK_JSON: &str = r#"{
   "blockdevices": [
      {
         "name": "loop0",
         "type": "loop",
         "size": 67108864,
         "fstype": "squashfs",
         "mountpoint": "/snap/core20/2318",
         "model": null,
         "rota": false,
         "tran": null
      },{
         "name": "sda",
         "type": "disk",
         "size": 42949672960,
         "fstype": null,
         "mountpoint": null,
         "model": "VMware Virtual S",
         "rota": true,
         "tran": "spi",
         "children": [
            {
               "name": "sda1",
               "type": "part",
               "size": 1048576,
               "fstype": null,
               "mountpoint": null,
               "model": null,
               "rota": true,
               "tran": null
            },{
               "name": "sda2",
               "type": "part",
               "size": 2147483648,
               "fstype": "ext4",
               "mountpoint": "/boot",
               "model": null,
               "rota": true,
               "tran": null
            },{
               "name": "sda3",
               "type": "part",
               "size": 40800092160,
               "fstype": "LVM2_member",
               "mountpoint": null,
               "model": null,
               "rota": true,
               "tran": null,
               "children": [
                  {
                     "name": "ubuntu--vg-ubuntu--lv",
                     "type": "lvm",
                     "size": 20396900352,
                     "fstype": "ext4",
                     "mountpoint": "/",
                     "model": null,
                     "rota": true,
                     "tran": null
                  }
               ]
            }
         ]
      },{
         "name": "sr0",
         "type": "rom",
         "size": 2133391360,
         "fstype": "iso9660",
         "mountpoint": null,
         "model": "VMware SATA CD01",
         "rota": true,
         "tran": "sata"
      }
   ]
}
"#;

    /// util-linux 2.31 (Ubuntu 18.04): sizes and `rota` as strings.
    pub const LSBLK_JSON_OLD: &str = r#"{
   "blockdevices": [
      {"name": "vda", "type": "disk", "size": "21474836480", "fstype": null, "mountpoint": null, "model": null, "rota": "1", "tran": null,
         "children": [
            {"name": "vda1", "type": "part", "size": "21473787904", "fstype": "ext4", "mountpoint": "/", "model": null, "rota": "1", "tran": null}
         ]
      }
   ]
}
"#;

    /// util-linux 2.23 (RHEL 7): no JSON, `KEY="value"` pairs.
    pub const LSBLK_PAIRS: &str = r#"NAME="sda" TYPE="disk" SIZE="21474836480" FSTYPE="" MOUNTPOINT="" MODEL="Virtual\x20disk    "
NAME="sda1" TYPE="part" SIZE="1073741824" FSTYPE="xfs" MOUNTPOINT="/boot" MODEL=""
NAME="sda2" TYPE="part" SIZE="20400046080" FSTYPE="LVM2_member" MOUNTPOINT="" MODEL=""
NAME="centos-root" TYPE="lvm" SIZE="18249416704" FSTYPE="xfs" MOUNTPOINT="/" MODEL=""
NAME="centos-swap" TYPE="lvm" SIZE="2147483648" FSTYPE="swap" MOUNTPOINT="[SWAP]" MODEL=""
NAME="sr0" TYPE="rom" SIZE="1073741312" FSTYPE="" MOUNTPOINT="" MODEL="VMware IDE CDR10"
"#;

    pub const DF_TYPED: &str =
        "Filesystem                        Type         1-blocks        Used    Available Capacity Mounted on
tmpfs                             tmpfs       402817024     1638400    401178624       1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv ext4      20365004800  9870442496   9435787264      52% /
/dev/sda2                         ext4       1969250304   189370368   1662332928      11% /boot
/dev/sdb1                         xfs      107317563392 96585807053  10731756339      91% /var/lib/my data
/dev/loop0                        squashfs     67108864    67108864            0     100% /snap/core20/2318
";

    /// busybox df: no type, 1024-byte blocks.
    pub const DF_BUSYBOX: &str = "Filesystem           1024-blocks    Used Available Capacity Mounted on
/dev/root              7864320  1048576   6815744  13% /
tmpfs                   102400        0    102400   0% /dev/shm
";

    /// What an Ubuntu VM prints for the whole script.
    pub fn ubuntu() -> String {
        format!(
            "@@os-release\n{OS_RELEASE_UBUNTU}@@redhat-release\n@@uname\nLinux 6.8.0-45-generic x86_64\n@@hostname\nweb01\n@@cpu\n{LSCPU_NEW}@@meminfo\n{MEMINFO}@@swaps\n{SWAPS}@@lsblk\n{LSBLK_JSON}@@df\n{DF_TYPED}@@virt\nvmware\n@@uptime\n273600.52 1000000.10\n"
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
        assert_eq!(policy.classify_script(SPECS_SCRIPT), ActionKind::ExecReadOnly);
        for part in SPECS_SCRIPT.split(';') {
            assert_eq!(policy.classify_script(part), ActionKind::ExecReadOnly, "{part}");
        }
    }

    #[test]
    fn reads_an_ubuntu_host_end_to_end() {
        let specs = parse(&ubuntu());
        assert_eq!(specs.os_name().as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(specs.os.id.as_deref(), Some("ubuntu"));
        assert_eq!(specs.os.version_id.as_deref(), Some("24.04"));
        assert_eq!(specs.system.as_deref(), Some("Linux"));
        assert_eq!(specs.kernel.as_deref(), Some("6.8.0-45-generic"));
        assert_eq!(specs.architecture.as_deref(), Some("x86_64"));
        assert_eq!(specs.hostname.as_deref(), Some("web01"));
        assert_eq!(
            specs.cpu.model.as_deref(),
            Some("Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz")
        );
        assert_eq!(
            (
                specs.cpu.logical_cpus,
                specs.cpu.sockets,
                specs.cpu.cores_per_socket,
                specs.cpu.threads_per_core
            ),
            (Some(4), Some(2), Some(2), Some(1))
        );
        assert_eq!(specs.cpu.cores(), Some(4));
        assert_eq!(specs.memory.total_bytes, Some(8_131_116 * 1024));
        assert_eq!(specs.memory.available_bytes, Some(5_226_784 * 1024));
        assert_eq!(specs.memory.swap_total_bytes, Some(4_194_300 * 1024));
        assert_eq!(specs.memory.swap_free_bytes, Some(4_094_300 * 1024));
        assert_eq!(
            specs.swaps,
            [SwapArea {
                path: "/swap.img".into(),
                kind: "file".into(),
                size_bytes: 4_194_300 * 1024,
                used_bytes: 100_000 * 1024
            }]
        );
        let disks: Vec<(&str, &str, u32, Option<&str>)> = specs
            .disks
            .iter()
            .map(|d| (d.name.as_str(), d.kind.as_str(), d.depth, d.mountpoint.as_deref()))
            .collect();
        assert_eq!(
            disks,
            [
                ("sda", "disk", 0, None),
                ("sda1", "part", 1, None),
                ("sda2", "part", 1, Some("/boot")),
                ("sda3", "part", 1, None),
                ("ubuntu--vg-ubuntu--lv", "lvm", 2, Some("/")),
                ("sr0", "rom", 0, None),
            ],
            "no snap loop devices"
        );
        assert_eq!(specs.disks[0].size_bytes, Some(42_949_672_960));
        assert_eq!(specs.disks[0].model.as_deref(), Some("VMware Virtual S"));
        assert_eq!(specs.disks[0].rotational, Some(true));
        assert_eq!(specs.disks[0].transport.as_deref(), Some("spi"));
        let mounts: Vec<(&str, Option<&str>, u64)> = specs
            .filesystems
            .iter()
            .map(|f| {
                (
                    f.mount.as_str(),
                    f.fstype.as_deref(),
                    (f.used_pct * 10.0).round() as u64,
                )
            })
            .collect();
        assert_eq!(
            mounts,
            [
                ("/", Some("ext4"), 511),
                ("/boot", Some("ext4"), 102),
                ("/var/lib/my data", Some("xfs"), 900),
            ],
            "no tmpfs or snaps; mount points with spaces"
        );
        assert_eq!(specs.filesystems[0].size_bytes, 20_365_004_800);
        assert_eq!(specs.virtualization.as_deref(), Some("vmware"));
        assert_eq!(specs.uptime_secs, Some(273_600));
        assert!(!specs.is_empty());
        // Stored as JSON and read back.
        let json = serde_json::to_string(&specs).unwrap();
        assert_eq!(serde_json::from_str::<HostSpecs>(&json).unwrap(), specs);
    }

    #[test]
    fn os_release_reads_rhel_debian_and_old_redhat_release() {
        let lines = |t: &str| t.lines().map(str::to_owned).collect::<Vec<_>>();
        let rhel = lines(OS_RELEASE_RHEL);
        let rhel = parse_os_release(&rhel.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(rhel.pretty_name.as_deref(), Some("Red Hat Enterprise Linux 9.4 (Plow)"));
        assert_eq!(
            (rhel.id.as_deref(), rhel.version_id.as_deref()),
            (Some("rhel"), Some("9.4"))
        );
        let debian = lines(OS_RELEASE_DEBIAN);
        let debian = parse_os_release(&debian.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(debian.pretty_name.as_deref(), Some("Debian GNU/Linux 12 (bookworm)"));
        assert_eq!(debian.version.as_deref(), Some("12 (bookworm)"));
        let quoted = parse_os_release(&[r#"PRETTY_NAME='Alpine Linux v3.20'"#, r#"NAME="My \"Linux\"""#]);
        assert_eq!(quoted.pretty_name.as_deref(), Some("Alpine Linux v3.20"));
        assert_eq!(quoted.name.as_deref(), Some(r#"My "Linux""#));

        let centos6 = parse("@@os-release\n@@redhat-release\nCentOS release 6.10 (Final)\n@@uname\nLinux 2.6.32-754.el6.x86_64 x86_64\n");
        assert_eq!(centos6.os_name().as_deref(), Some("CentOS release 6.10 (Final)"));
        assert_eq!(centos6.kernel.as_deref(), Some("2.6.32-754.el6.x86_64"));
    }

    #[test]
    fn lscpu_old_new_and_arm_and_cpuinfo_without_lscpu() {
        let lines = |t: &'static str| t.lines().collect::<Vec<_>>();
        let (old, hypervisor) = parse_lscpu(&lines(LSCPU_OLD));
        assert_eq!(
            (
                old.logical_cpus,
                old.sockets,
                old.cores_per_socket,
                old.threads_per_core
            ),
            (Some(8), Some(1), Some(4), Some(2))
        );
        assert_eq!(old.model.as_deref(), Some("Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz"));
        assert_eq!(old.max_mhz, Some(2194.843));
        assert_eq!(hypervisor.as_deref(), Some("KVM"));
        let (arm, none) = parse_lscpu(&lines(LSCPU_ARM));
        assert_eq!(arm.model.as_deref(), Some("Neoverse-N1"));
        assert_eq!(
            (arm.sockets, arm.cores_per_socket, arm.cores()),
            (Some(1), Some(2), Some(2))
        );
        assert_eq!(none, None);

        let cpu = parse_cpuinfo(&lines(CPUINFO));
        assert_eq!(cpu.model.as_deref(), Some("Intel(R) Xeon(R) E5-2680 v4 @ 2.40GHz"));
        assert_eq!(
            (
                cpu.logical_cpus,
                cpu.sockets,
                cpu.cores_per_socket,
                cpu.threads_per_core
            ),
            (Some(4), Some(1), Some(2), Some(2))
        );
        // The script falls back to /proc/cpuinfo; the parser tells which it got, and KVM from lscpu
        // stands in for systemd-detect-virt.
        let fallback = parse(&format!("@@cpu\n{CPUINFO}@@virt\n"));
        assert_eq!(fallback.cpu.logical_cpus, Some(4));
        let kvm = parse(&format!("@@cpu\n{LSCPU_OLD}@@virt\n"));
        assert_eq!(kvm.virtualization.as_deref(), Some("kvm"));
    }

    #[test]
    fn lsblk_without_json_and_with_string_numbers() {
        let pairs = parse_lsblk(LSBLK_PAIRS);
        let summary: Vec<(&str, u32, Option<&str>, Option<&str>)> = pairs
            .iter()
            .map(|d| (d.name.as_str(), d.depth, d.fstype.as_deref(), d.mountpoint.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                ("sda", 0, None, None),
                ("sda1", 1, Some("xfs"), Some("/boot")),
                ("sda2", 1, Some("LVM2_member"), None),
                ("centos-root", 2, Some("xfs"), Some("/")),
                ("centos-swap", 2, Some("swap"), Some("[SWAP]")),
                ("sr0", 0, None, None),
            ]
        );
        assert_eq!(
            pairs[0].model.as_deref(),
            Some("Virtual disk"),
            "\\x20 undone, padding trimmed"
        );
        assert_eq!(pairs[0].size_bytes, Some(21_474_836_480));

        let old = parse_lsblk(LSBLK_JSON_OLD);
        assert_eq!(old.len(), 2);
        assert_eq!(old[0].size_bytes, Some(21_474_836_480));
        assert_eq!(old[0].rotational, Some(true));
        assert_eq!(old[1].mountpoint.as_deref(), Some("/"));
        assert!(parse_lsblk("").is_empty());
        assert!(parse_lsblk("{ not json").is_empty());
    }

    #[test]
    fn df_with_and_without_types() {
        let busybox = parse_df(&DF_BUSYBOX.lines().collect::<Vec<_>>());
        assert_eq!(busybox.len(), 1, "tmpfs left out");
        assert_eq!(busybox[0].mount, "/");
        assert_eq!(busybox[0].fstype, None);
        assert_eq!(busybox[0].size_bytes, 7_864_320 * 1024);
        assert!(parse_df(&["no header here"]).is_empty());
    }

    #[test]
    fn a_host_that_is_not_linux_reads_as_empty() {
        let specs = parse("@@os-release\n@@redhat-release\n@@uname\n@@hostname\n% Invalid input\n@@cpu\n@@meminfo\n@@lsblk\n@@df\n@@virt\n@@uptime\n");
        assert!(specs.is_empty());
        assert_eq!(specs.hostname, None, "not a host name");
        assert!(parse("").is_empty());
    }
}
