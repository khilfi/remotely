//! FD-04: the support bundle's presets, one table for every host kind. Every preset command only reads, so it is
//! rated read-only by the default rules (a test checks each one) and a bundle of presets runs at once (Low; Medium
//! on Prod). F8 adds Windows presets (PowerShell reads over WinRM) as rows of a Windows [`HostKind`].

use serde::{Deserialize, Serialize};

use super::spec::BundleItem;

/// What kind of host a preset is for, and which collector reaches it ([`super::collect::BundleHost`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostKind {
    /// SSH: commands on exec channels, files over SFTP.
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresetId {
    System,
    Logs,
    Containers,
    Network,
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
pub const PRESETS: [Preset; 4] = [
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
];

pub fn preset(id: PresetId) -> &'static Preset {
    // PRESETS has one row per id (a test checks it).
    PRESETS.iter().find(|p| p.id == id).unwrap_or(&PRESETS[0])
}

/// The presets' items (in the table's order, each once), then the custom commands and files that are not in them
/// already. Blank lines are left out.
pub fn expand(ids: &[PresetId], commands: &[String], files: &[String]) -> Vec<BundleItem> {
    let mut items: Vec<BundleItem> = Vec::new();
    let mut push = |item: BundleItem| {
        if !items.contains(&item) {
            items.push(item);
        }
    };
    for preset in PRESETS.iter().filter(|p| ids.contains(&p.id)) {
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
            &[PresetId::Containers],
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
    }
}
