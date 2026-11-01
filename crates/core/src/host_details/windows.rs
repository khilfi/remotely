//! MO-13 for Windows hosts: what a host reached over WinRM says about itself through CIM (and the build's update
//! number from the registry), read in one PowerShell run and parsed here into the same [`HostSpecs`] a Linux host's
//! facts fill, with the Windows-only parts beside them ([`WindowsInfo`], [`NetAdapter`], [`ListeningPort`]) for the
//! System tab and F6's inventory.
//!
//! Every statement only reads: `Get-CimInstance`, `Get-ItemProperty`, `Get-Process`, `Get-NetTCPConnection` and the
//! pipeline's `ForEach-Object`, `Sort-Object` and `Select-Object` (`assert_only_reads`, run on each script in the tests).

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::linux::{sections, BlockDevice, CpuInfo, Filesystem, HostSpecs, MemoryInfo, OsInfo, SwapArea};

/// One run over WinRM. `$ErrorActionPreference` keeps a class a host lacks from printing errors into the facts.
pub const FACTS_SCRIPT: &str = "# remotely:host-facts
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$cv = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
'@@os'
'caption=' + $os.Caption
'version=' + $os.Version
'build=' + $os.BuildNumber
'ubr=' + $cv.UBR
'display=' + $cv.DisplayVersion
'edition=' + $cv.EditionID
'arch=' + $os.OSArchitecture
'boot=' + $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
'uptime=' + [long]((Get-Date) - $os.LastBootUpTime).TotalSeconds
'@@system'
'name=' + $cs.Name
'dnsname=' + $cs.DNSHostName
'domain=' + $cs.Domain
'partofdomain=' + $cs.PartOfDomain
'workgroup=' + $cs.Workgroup
'manufacturer=' + $cs.Manufacturer
'model=' + $cs.Model
'@@memory'
'total_kb=' + $os.TotalVisibleMemorySize
'free_kb=' + $os.FreePhysicalMemory
'pagetotal_kb=' + $os.SizeStoredInPagingFiles
'pagefree_kb=' + $os.FreeSpaceInPagingFiles
'@@cpu'
Get-CimInstance -ClassName Win32_Processor | ForEach-Object { 'cpu=' + $_.NumberOfCores + '|' + $_.NumberOfLogicalProcessors + '|' + $_.MaxClockSpeed + '|' + $_.Manufacturer + '|' + $_.Name }
'@@pagefile'
Get-CimInstance -ClassName Win32_PageFileUsage | ForEach-Object { 'page=' + $_.AllocatedBaseSize + '|' + $_.CurrentUsage + '|' + $_.Name }
'@@disks'
Get-CimInstance -ClassName Win32_DiskDrive | ForEach-Object { 'disk=' + $_.Index + '|' + $_.Size + '|' + $_.InterfaceType + '|' + $_.MediaType + '|' + $_.Model }
'@@volumes'
Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { 'vol=' + $_.DeviceID + '|' + $_.FileSystem + '|' + $_.Size + '|' + $_.FreeSpace + '|' + $_.VolumeName }
'@@adapters'
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { 'nic=' + $_.MACAddress + '|' + ($_.IPAddress -join ',') + '|' + ($_.IPSubnet -join ',') + '|' + ($_.DefaultIPGateway -join ',') + '|' + ($_.DNSServerSearchOrder -join ',') + '|' + $_.DHCPEnabled + '|' + $_.Description }
'@@listening'
$names = @{}; Get-Process | ForEach-Object { $names[[string]$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Listen | Sort-Object -Property LocalPort, LocalAddress | Select-Object -First 200 | ForEach-Object { 'tcp=' + $_.LocalPort + '|' + $_.OwningProcess + '|' + $names[[string]$_.OwningProcess] + '|' + $_.LocalAddress }
'@@end'";

/// Output kept from the script: a host with many adapters and ports prints tens of KB.
pub const MAX_OUTPUT: usize = 256 * 1024;
const MAX_ITEMS: usize = 256;

/// What only a Windows host says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WindowsInfo {
    /// The edition's id: `ServerDatacenter`, `Professional`...
    pub edition: Option<String>,
    /// `23H2`, `21H2`.
    pub display_version: Option<String>,
    /// The build with its update number: `20348.2340`.
    pub build: Option<String>,
    /// The domain it is joined to, or its workgroup.
    pub domain: Option<String>,
    pub part_of_domain: Option<bool>,
    pub workgroup: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// When it last started (UTC, RFC 3339).
    pub last_boot: Option<String>,
}

/// A network adapter with its MAC and addresses (an IP-enabled adapter's configuration).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetAdapter {
    pub name: String,
    pub mac: Option<String>,
    /// `192.0.2.10/24`, `fe80::1/64`.
    pub addresses: Vec<String>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dhcp: Option<bool>,
}

/// A TCP port the host listens on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListeningPort {
    pub port: u16,
    pub address: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

fn clean(text: &str, max: usize) -> Option<String> {
    let text: String = text
        .trim()
        .chars()
        .filter(|c| !c.is_control() && !crate::untrusted::is_format_char(*c))
        .take(max)
        .collect();
    (!text.is_empty()).then_some(text)
}

fn list(text: &str) -> Vec<String> {
    text.split(',').filter_map(|v| clean(v, 64)).take(32).collect()
}

/// A prefix length from a dotted mask (`255.255.255.0` -> 24), or the number IPv6 gives as it is.
fn prefix(mask: &str) -> Option<u32> {
    let mask = mask.trim();
    if let Ok(bits) = mask.parse::<u32>() {
        return (bits <= 128).then_some(bits);
    }
    let ip: std::net::Ipv4Addr = mask.parse().ok()?;
    let value = u32::from(ip);
    (value.leading_ones() + value.trailing_zeros() == 32).then(|| value.leading_ones())
}

/// `vmware`, `microsoft`, `oracle`, `kvm`... from the maker and model, as systemd-detect-virt names them.
fn virtualization(manufacturer: Option<&str>, model: Option<&str>) -> Option<String> {
    let both = format!("{} {}", manufacturer.unwrap_or(""), model.unwrap_or("")).to_lowercase();
    let found = if both.contains("vmware") {
        "vmware"
    } else if both.contains("virtualbox") || both.contains("innotek") {
        "oracle"
    } else if both.contains("microsoft") && both.contains("virtual") {
        "microsoft"
    } else if both.contains("qemu") || both.contains("kvm") {
        "kvm"
    } else if both.contains("xen") {
        "xen"
    } else if both.contains("amazon ec2") {
        "amazon"
    } else {
        return None;
    };
    Some(found.to_owned())
}

/// Reads [`FACTS_SCRIPT`]'s output. A host that printed none of it gives empty facts ([`HostSpecs::is_empty`]).
pub fn parse(output: &str) -> HostSpecs {
    let parts = sections(output);
    let part = |name: &str| parts.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let values = |name: &str| -> std::collections::HashMap<String, String> {
        part(name)
            .iter()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect()
    };
    let os = values("os");
    let system = values("system");
    let memory = values("memory");
    let get = |map: &std::collections::HashMap<String, String>, key: &str| map.get(key).and_then(|v| clean(v, 200));
    let number = |map: &std::collections::HashMap<String, String>, key: &str| {
        map.get(key).and_then(|v| v.trim().parse::<u64>().ok())
    };

    let mut specs = HostSpecs::default();
    let caption = get(&os, "caption");
    if caption.is_none() && get(&system, "name").is_none() && number(&memory, "total_kb").is_none() {
        return specs;
    }
    let name = caption
        .as_deref()
        .map(|c| c.trim_start_matches("Microsoft ").to_owned());
    let display = get(&os, "display");
    let version = get(&os, "version");
    let build = match (get(&os, "build"), get(&os, "ubr")) {
        (Some(build), Some(ubr)) => Some(format!("{build}.{ubr}")),
        (build, _) => build,
    };
    specs.os = OsInfo {
        name: name.clone(),
        version: version.clone(),
        version_id: display.clone(),
        id: Some("windows".into()),
        id_like: None,
        pretty_name: match (&name, &display) {
            (Some(name), Some(display)) => Some(format!("{name} ({display})")),
            (name, _) => name.clone(),
        },
    };
    specs.system = Some("Windows".into());
    specs.kernel = match (&version, os.get("ubr").and_then(|u| clean(u, 16))) {
        (Some(version), Some(ubr)) => Some(format!("{version}.{ubr}")),
        (version, _) => version.clone(),
    };
    specs.architecture = get(&os, "arch").map(|a| {
        let a = a.to_lowercase();
        if a.contains("arm") {
            "aarch64".to_owned()
        } else if a.contains("64") {
            "x86_64".to_owned()
        } else {
            "x86".to_owned()
        }
    });
    specs.hostname = get(&system, "dnsname").or_else(|| get(&system, "name"));
    specs.uptime_secs = number(&os, "uptime");

    let mut cpu = CpuInfo::default();
    let mut sockets = 0u32;
    let mut logical = 0u32;
    for line in part("cpu") {
        let Some(value) = line.strip_prefix("cpu=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(5, '|').collect();
        if fields.len() < 5 {
            continue;
        }
        // Review F4 #14: the host's numbers can't overflow (`panic = "abort"` would end the app).
        sockets = sockets.saturating_add(1);
        let cores = fields[0].trim().parse::<u32>().ok();
        let threads = fields[1].trim().parse::<u32>().ok();
        logical = logical.saturating_add(threads.unwrap_or(0));
        if sockets == 1 {
            cpu.cores_per_socket = cores;
            cpu.threads_per_core = cores.zip(threads).and_then(|(c, t)| (c > 0).then(|| t / c));
            cpu.max_mhz = fields[2].trim().parse::<f64>().ok();
            cpu.vendor = clean(fields[3], 64);
            cpu.model = clean(fields[4], 200);
        }
    }
    if sockets > 0 {
        cpu.sockets = Some(sockets);
        cpu.logical_cpus = (logical > 0).then_some(logical);
    }
    specs.cpu = cpu;

    specs.memory = MemoryInfo {
        total_bytes: number(&memory, "total_kb").map(|k| k.saturating_mul(1024)),
        available_bytes: number(&memory, "free_kb").map(|k| k.saturating_mul(1024)),
        swap_total_bytes: number(&memory, "pagetotal_kb").map(|k| k.saturating_mul(1024)),
        swap_free_bytes: number(&memory, "pagefree_kb").map(|k| k.saturating_mul(1024)),
    };
    for line in part("pagefile").iter().take(MAX_ITEMS) {
        let Some(value) = line.strip_prefix("page=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(3, '|').collect();
        if let [size, used, path] = fields.as_slice() {
            let mb = |v: &str| v.trim().parse::<u64>().ok().map(|m| m.saturating_mul(1024 * 1024));
            specs.swaps.push(SwapArea {
                path: clean(path, 260).unwrap_or_default(),
                kind: "file".into(),
                size_bytes: mb(size).unwrap_or(0),
                used_bytes: mb(used).unwrap_or(0),
            });
        }
    }
    for line in part("disks").iter().take(MAX_ITEMS) {
        let Some(value) = line.strip_prefix("disk=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(5, '|').collect();
        if let [index, size, interface, _media, model] = fields.as_slice() {
            specs.disks.push(BlockDevice {
                name: format!("disk{}", index.trim()),
                kind: "disk".into(),
                size_bytes: size.trim().parse().ok(),
                model: clean(model, 128),
                transport: clean(interface, 16).map(|t| t.to_lowercase()),
                ..BlockDevice::default()
            });
        }
    }
    for line in part("volumes").iter().take(MAX_ITEMS) {
        let Some(value) = line.strip_prefix("vol=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(5, '|').collect();
        if let [device, fs, size, free, label] = fields.as_slice() {
            let (Ok(size), Ok(free)) = (size.trim().parse::<u64>(), free.trim().parse::<u64>()) else {
                continue;
            };
            let used = size.saturating_sub(free);
            specs.filesystems.push(Filesystem {
                source: clean(label, 64).unwrap_or_else(|| device.trim().to_owned()),
                fstype: clean(fs, 16),
                size_bytes: size,
                used_bytes: used,
                available_bytes: free,
                used_pct: if size == 0 {
                    0.0
                } else {
                    used as f64 * 100.0 / size as f64
                },
                mount: clean(device, 16).unwrap_or_default(),
            });
        }
    }
    for line in part("adapters").iter().take(MAX_ITEMS) {
        let Some(value) = line.strip_prefix("nic=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(7, '|').collect();
        if let [mac, ips, masks, gateways, dns, dhcp, name] = fields.as_slice() {
            let masks = list(masks);
            let addresses = list(ips)
                .into_iter()
                .enumerate()
                .map(|(i, ip)| match masks.get(i).and_then(|m| prefix(m)) {
                    Some(bits) => format!("{ip}/{bits}"),
                    None => ip,
                })
                .collect();
            specs.adapters.push(NetAdapter {
                name: clean(name, 128).unwrap_or_default(),
                mac: clean(mac, 32).map(|m| m.replace('-', ":").to_lowercase()),
                addresses,
                gateways: list(gateways),
                dns_servers: list(dns),
                dhcp: match dhcp.trim() {
                    "True" => Some(true),
                    "False" => Some(false),
                    _ => None,
                },
            });
        }
    }
    for line in part("listening").iter().take(MAX_ITEMS) {
        let Some(value) = line.strip_prefix("tcp=") else {
            continue;
        };
        let fields: Vec<&str> = value.splitn(4, '|').collect();
        if let [port, pid, process, address] = fields.as_slice() {
            let Ok(port) = port.trim().parse::<u16>() else {
                continue;
            };
            specs.listening.push(ListeningPort {
                port,
                address: clean(address, 64).unwrap_or_default(),
                pid: pid.trim().parse().ok(),
                process: clean(process, 64),
            });
        }
    }
    let manufacturer = get(&system, "manufacturer");
    let model = get(&system, "model");
    specs.virtualization = virtualization(manufacturer.as_deref(), model.as_deref());
    let part_of_domain = match system.get("partofdomain").map(String::as_str) {
        Some("True") => Some(true),
        Some("False") => Some(false),
        _ => None,
    };
    let last_boot = get(&os, "boot").filter(|b| OffsetDateTime::parse(b, &Rfc3339).is_ok());
    specs.windows = Some(WindowsInfo {
        edition: get(&os, "edition"),
        display_version: display,
        build,
        domain: get(&system, "domain"),
        part_of_domain,
        workgroup: get(&system, "workgroup"),
        manufacturer,
        model,
        last_boot,
    });
    specs
}

/// Every cmdlet in `script` reads: its verb is one of the read-only ones, and no alias or call operator that runs
/// something else appears. As far as shell rules go for PowerShell (F8 brings its own rules).
#[cfg(test)]
pub(crate) fn assert_only_reads(script: &str) {
    const READ_VERBS: [&str; 6] = ["Get", "ForEach", "Sort", "Select", "Measure", "Where"];
    let words: Vec<&str> = script
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    for word in &words {
        if let Some((verb, noun)) = word.split_once('-') {
            let looks_like_cmdlet = verb.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && noun.chars().next().is_some_and(|c| c.is_ascii_uppercase());
            if looks_like_cmdlet {
                assert!(READ_VERBS.contains(&verb), "{word} is not a read");
            }
        }
        for banned in [
            "iex", "Invoke", "Set", "New", "Remove", "Start", "Stop", "Restart", "Add", "Clear",
        ] {
            assert!(
                !word.eq_ignore_ascii_case(banned),
                "{word} doesn't belong in a read-only script"
            );
        }
    }
    assert!(!script.contains(" & ") && !script.contains("& {"), "no call operator");
}

/// Test data: what a Windows Server 2022 guest prints for [`FACTS_SCRIPT`] (reserved names and addresses only).
#[cfg(any(test, feature = "fakes"))]
pub fn sample() -> String {
    [
        "@@os",
        "caption=Microsoft Windows Server 2022 Datacenter",
        "version=10.0.20348",
        "build=20348",
        "ubr=2340",
        "display=21H2",
        "edition=ServerDatacenter",
        "arch=64-bit",
        "boot=2026-10-30T08:00:00Z",
        "uptime=86400",
        "@@system",
        "name=WIN01",
        "dnsname=win01",
        "domain=corp.example.com",
        "partofdomain=True",
        "workgroup=",
        "manufacturer=VMware, Inc.",
        "model=VMware20,1",
        "@@memory",
        "total_kb=8388608",
        "free_kb=2097152",
        "pagetotal_kb=1310720",
        "pagefree_kb=1048576",
        "@@cpu",
        "cpu=2|4|2394|GenuineIntel|Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz",
        "cpu=2|4|2394|GenuineIntel|Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz",
        "@@pagefile",
        "page=1280|256|C:\\pagefile.sys",
        "@@disks",
        "disk=0|64422328320|SCSI|Fixed hard disk media|VMware Virtual disk SCSI Disk Device",
        "@@volumes",
        "vol=C:|NTFS|64424509440|21474836480|",
        "vol=D:|ReFS|107374182400|85899345920|Data",
        "@@adapters",
        "nic=00-50-56-AB-CD-EF|192.0.2.10,fe80::1|255.255.255.0,64|192.0.2.1|192.0.2.53,198.51.100.53|False|vmxnet3 Ethernet Adapter",
        "@@listening",
        "tcp=135|888|svchost|0.0.0.0",
        "tcp=3389|1024|svchost|0.0.0.0",
        "tcp=5985|4|System|0.0.0.0",
        "tcp=5986|4|System|0.0.0.0",
        "@@end",
    ]
    .join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_details::short_os;

    #[test]
    fn a_windows_host_fills_the_facts_a_linux_host_does() {
        let specs = parse(&sample());
        assert!(!specs.is_empty());
        assert_eq!(specs.os.name.as_deref(), Some("Windows Server 2022 Datacenter"));
        assert_eq!(
            specs.os.pretty_name.as_deref(),
            Some("Windows Server 2022 Datacenter (21H2)")
        );
        assert_eq!(short_os(&specs).as_deref(), Some("Windows Server 2022 Datacenter 21H2"));
        assert_eq!(specs.kernel.as_deref(), Some("10.0.20348.2340"));
        assert_eq!(specs.architecture.as_deref(), Some("x86_64"));
        assert_eq!(specs.cpu.sockets, Some(2));
        assert_eq!(specs.cpu.logical_cpus, Some(8));
        assert_eq!(specs.cpu.cores(), Some(4));
        assert_eq!(specs.memory.total_bytes, Some(8 * 1024 * 1024 * 1024));
        assert_eq!(specs.swaps[0].size_bytes, 1280 * 1024 * 1024);
        assert_eq!(specs.disks[0].transport.as_deref(), Some("scsi"));
        assert_eq!(specs.filesystems.len(), 2);
        assert_eq!(specs.filesystems[0].source, "C:");
        assert_eq!(specs.filesystems[1].source, "Data");
        assert_eq!(specs.virtualization.as_deref(), Some("vmware"));
        assert_eq!(specs.uptime_secs, Some(86_400));
        let nic = &specs.adapters[0];
        assert_eq!(nic.mac.as_deref(), Some("00:50:56:ab:cd:ef"));
        assert_eq!(nic.addresses, vec!["192.0.2.10/24", "fe80::1/64"]);
        assert_eq!(nic.dns_servers.len(), 2);
        assert_eq!(nic.dhcp, Some(false));
        assert_eq!(specs.listening.len(), 4);
        assert_eq!(specs.listening[1].process.as_deref(), Some("svchost"));
        let windows = specs.windows.unwrap();
        assert_eq!(windows.build.as_deref(), Some("20348.2340"));
        assert_eq!(windows.edition.as_deref(), Some("ServerDatacenter"));
        assert_eq!(windows.part_of_domain, Some(true));
        assert_eq!(windows.last_boot.as_deref(), Some("2026-10-30T08:00:00Z"));
    }

    #[test]
    fn junk_gives_empty_facts_and_hostile_text_is_cleaned() {
        assert!(parse("The term 'Get-CimInstance' is not recognized").is_empty());
        let hostile = "@@os\r\ncaption=Windows\u{202e}evil\u{7}\r\n@@listening\r\ntcp=99999|1|x|y\r\n";
        let specs = parse(hostile);
        assert_eq!(specs.os.name.as_deref(), Some("Windowsevil"));
        assert!(specs.listening.is_empty());
    }

    #[test]
    fn masks_become_prefixes() {
        assert_eq!(prefix("255.255.255.0"), Some(24));
        assert_eq!(prefix("255.255.0.255"), None);
        assert_eq!(prefix("64"), Some(64));
    }

    #[test]
    fn the_script_only_reads() {
        assert_only_reads(FACTS_SCRIPT);
        for line in FACTS_SCRIPT.lines() {
            let mut syntax = crate::adapters::winrm::console::Syntax::default();
            syntax.feed(line);
            assert!(syntax.complete(), "each line is a whole statement: {line}");
        }
    }
}
