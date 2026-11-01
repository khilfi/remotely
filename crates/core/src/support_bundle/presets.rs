//! FD-04: the support bundle's presets, one table for every host kind. Every preset command only reads, so it is
//! rated read-only by the default rules (a test checks each one) and a bundle of presets runs at once (Low; Medium
//! on Prod). BX-13: Windows presets are PowerShell reads over WinRM, rows of the Windows [`HostKind`], rated by the
//! PowerShell rules.

use serde::{Deserialize, Serialize};

use super::spec::BundleItem;

/// What kind of host a preset is for, and which collector reaches it ([`super::collect::BundleHost`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostKind {
    /// SSH: commands on exec channels, files over SFTP.
    Linux,
    /// BX-13: WinRM: PowerShell commands, files read with PowerShell as the sign-in user.
    Windows,
}

impl HostKind {
    /// BX-13: the language its commands run in, whose rules rate them.
    pub fn script_kind(self) -> crate::adapters::remote::ScriptKind {
        match self {
            HostKind::Linux => crate::adapters::remote::ScriptKind::Posix,
            HostKind::Windows => crate::adapters::remote::ScriptKind::PowerShell,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresetId {
    System,
    Logs,
    Containers,
    Network,
    /// BX-13.
    WindowsSystem,
    WindowsLogs,
    WindowsNetwork,
}

/// One item of a preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetItem {
    Command(&'static str),
    File(&'static str),
}

impl PresetItem {
    pub fn item(&self) -> BundleItem {
        match self {
            Self::Command(command) => BundleItem::command(command),
            Self::File(path) => BundleItem::file(path),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub id: PresetId,
    pub host_kind: HostKind,
    /// As the dialog shows it.
    pub label: &'static str,
    /// One line on what it is for.
    pub description: &'static str,
    pub items: &'static [PresetItem],
}

use PresetItem::{Command, File};

/// Every preset, in the order the dialog lists them.
pub const PRESETS: [Preset; 7] = [
    Preset {
        id: PresetId::System,
        host_kind: HostKind::Linux,
        label: "System",
        description: "OS release, kernel, uptime, disks, memory, addresses, routes, listening ports, failed services",
        items: &[
            File("/etc/os-release"),
            Command("uname -a"),
            Command("uptime"),
            Command("df -h"),
            Command("free -m"),
            Command("ip addr"),
            Command("ip route"),
            Command("ss -tulpn"),
            Command("systemctl --failed"),
        ],
    },
    Preset {
        id: PresetId::Logs,
        host_kind: HostKind::Linux,
        label: "Logs",
        description: "The journal's last 500 errors, the kernel log, and the end of syslog or messages",
        items: &[
            Command("journalctl -p err -n 500"),
            Command("dmesg"),
            // Debian and Ubuntu write syslog, Red Hat and its kin messages.
            Command("tail -n 1000 /var/log/syslog 2>/dev/null || tail -n 1000 /var/log/messages"),
        ],
    },
    Preset {
        id: PresetId::Containers,
        host_kind: HostKind::Linux,
        label: "Containers",
        description: "Docker's containers, running or not, and the engine's own report",
        items: &[Command("docker ps -a"), Command("docker info")],
    },
    Preset {
        id: PresetId::Network,
        host_kind: HostKind::Linux,
        label: "Network",
        description: "Interface counters, neighbours, socket totals, DNS settings, hosts file and firewall rules",
        items: &[
            Command("ip -s link"),
            Command("ip neigh show"),
            Command("ss -s"),
            Command("resolvectl status"),
            File("/etc/resolv.conf"),
            File("/etc/hosts"),
            Command("nft list ruleset"),
        ],
    },
    // BX-13: tables are made wide (`Out-String -Width`), so a column isn't cut to the window PowerShell imagines.
    Preset {
        id: PresetId::WindowsSystem,
        host_kind: HostKind::Windows,
        label: "Windows system",
        description: "Edition, build, hardware and domain, installed updates, and every service with its state",
        items: &[
            Command("Get-ComputerInfo"),
            Command("Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String -Width 4096"),
            Command("Get-Service | Sort-Object Status, Name | Format-Table -AutoSize Status, Name, DisplayName | Out-String -Width 4096"),
        ],
    },
    Preset {
        id: PresetId::WindowsLogs,
        host_kind: HostKind::Windows,
        label: "Windows logs",
        description: "The last 500 errors and critical events of the System and Application logs",
        items: &[Command(
            "Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2 } -MaxEvents 500 | Format-List TimeCreated, LogName, ProviderName, Id, LevelDisplayName, Message | Out-String -Width 4096",
        )],
    },
    Preset {
        id: PresetId::WindowsNetwork,
        host_kind: HostKind::Windows,
        label: "Windows network",
        description: "Every adapter's addresses, DNS and DHCP, and the ports listening",
        items: &[
            Command("ipconfig /all"),
            Command("Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table -AutoSize LocalAddress, LocalPort, OwningProcess | Out-String -Width 4096"),
        ],
    },
];

pub fn preset(id: PresetId) -> &'static Preset {
    // PRESETS has one row per id (a test checks it).
    PRESETS.iter().find(|p| p.id == id).unwrap_or(&PRESETS[0])
}

/// The presets' items for hosts of `kind` (in the table's order, each once), then the custom commands and files that
/// are not in them already. Blank lines are left out.
pub fn expand(kind: HostKind, ids: &[PresetId], commands: &[String], files: &[String]) -> Vec<BundleItem> {
    let mut items: Vec<BundleItem> = Vec::new();
    let mut push = |item: BundleItem| {
        if !items.contains(&item) {
            items.push(item);
        }
    };
    for preset in PRESETS.iter().filter(|p| p.host_kind == kind && ids.contains(&p.id)) {
        for item in preset.items {
            push(item.item());
        }
    }
    for command in commands.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
        push(BundleItem::command(command));
    }
    for path in files.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        push(BundleItem::file(path));
    }
    items
}

/// A preset as the dialog shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetView {
    pub id: PresetId,
    pub host_kind: HostKind,
    pub label: &'static str,
    pub description: &'static str,
    pub items: Vec<BundleItem>,
}

pub fn views() -> Vec<PresetView> {
    PRESETS
        .iter()
        .map(|p| PresetView {
            id: p.id,
            host_kind: p.host_kind,
            label: p.label,
            description: p.description,
            items: p.items.iter().map(PresetItem::item).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_has_one_row() {
        for id in [
            PresetId::System,
            PresetId::Logs,
            PresetId::Containers,
            PresetId::Network,
            PresetId::WindowsSystem,
            PresetId::WindowsLogs,
            PresetId::WindowsNetwork,
        ] {
            assert_eq!(PRESETS.iter().filter(|p| p.id == id).count(), 1, "{id:?}");
            assert_eq!(preset(id).id, id);
        }
    }

    #[test]
    fn the_plans_commands_are_in_the_presets() {
        let commands = |id| -> Vec<&str> {
            preset(id)
                .items
                .iter()
                .filter_map(|i| match i {
                    Command(c) => Some(*c),
                    File(_) => None,
                })
                .collect()
        };
        assert_eq!(
            commands(PresetId::System),
            [
                "uname -a",
                "uptime",
                "df -h",
                "free -m",
                "ip addr",
                "ip route",
                "ss -tulpn",
                "systemctl --failed"
            ]
        );
        assert!(preset(PresetId::System).items.contains(&File("/etc/os-release")));
        assert!(commands(PresetId::Logs).contains(&"journalctl -p err -n 500"));
        assert!(commands(PresetId::Logs).contains(&"dmesg"));
        assert_eq!(commands(PresetId::Containers), ["docker ps -a", "docker info"]);
    }

    #[test]
    fn expanding_keeps_each_item_once_and_presets_first() {
        let items = expand(
            HostKind::Linux,
            &[PresetId::Containers, PresetId::WindowsNetwork],
            &["  ".into(), "docker info".into(), "uptime".into()],
            &["/etc/hosts".into(), "".into()],
        );
        assert_eq!(
            items,
            [
                BundleItem::command("docker ps -a"),
                BundleItem::command("docker info"),
                BundleItem::command("uptime"),
                BundleItem::file("/etc/hosts"),
            ]
        );
        // BX-13: a Windows preset gives Windows hosts its items, never Linux ones.
        let windows = expand(
            HostKind::Windows,
            &[PresetId::Containers, PresetId::WindowsNetwork],
            &[],
            &[],
        );
        assert_eq!(windows[0], BundleItem::command("ipconfig /all"));
        assert_eq!(windows.len(), 2);
    }

    #[test]
    fn the_plans_windows_reads_are_in_the_presets() {
        let all: Vec<&str> = PRESETS
            .iter()
            .filter(|p| p.host_kind == HostKind::Windows)
            .flat_map(|p| p.items)
            .filter_map(|i| match i {
                Command(c) => Some(*c),
                File(_) => None,
            })
            .collect();
        for read in [
            "Get-ComputerInfo",
            "Get-WinEvent",
            "Get-Service",
            "Get-HotFix",
            "ipconfig /all",
            "Get-NetTCPConnection -State Listen",
        ] {
            assert!(all.iter().any(|c| c.starts_with(read)), "{read}");
        }
    }
}
