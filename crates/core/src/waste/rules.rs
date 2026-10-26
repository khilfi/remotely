//! VM-14, VM-16: the waste finder's rules, pure so tests can check each one.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::adapters::vmware::SnapshotTree;
use crate::metrics::history::MinuteRow;

/// What counts as waste. Defaults: idle for 3 days, chains 5 snapshots deep or 20 GB.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WasteOptions {
    /// A running VM is idle when it stayed under the limits below this many days (1 to 30).
    pub idle_days: u32,
    /// A snapshot chain this deep is long (2 to 100).
    pub chain_depth: u32,
    /// Snapshot files this large (GB, 1 to 10,000) make a chain large.
    pub chain_gb: u64,
}

impl Default for WasteOptions {
    fn default() -> Self {
        Self {
            idle_days: 3,
            chain_depth: 5,
            chain_gb: 20,
        }
    }
}

impl WasteOptions {
    /// The options within their bounds.
    pub fn clamped(self) -> Self {
        Self {
            idle_days: self.idle_days.clamp(1, 30),
            chain_depth: self.chain_depth.clamp(2, 100),
            chain_gb: self.chain_gb.clamp(1, 10_000),
        }
    }
}

/// VM-14: the limits an idle VM stays under in its busiest hour.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdleLimits {
    /// The VM's share of this PC's CPU (host side), in percent.
    pub host_cpu_pct: f64,
    /// The guest's own CPU, in percent, when its linked session is watched.
    pub guest_cpu_pct: f64,
    /// The guest's network, received and sent together, in bytes a second.
    pub guest_net_bps: f64,
    /// The window's share that history must cover (the app was running then).
    pub min_coverage: f64,
    /// History must start within this share of the window, so a VM started an hour ago isn't idle "for days".
    pub start_within: f64,
}

pub const IDLE_LIMITS: IdleLimits = IdleLimits {
    host_cpu_pct: 2.0,
    guest_cpu_pct: 5.0,
    guest_net_bps: 20_000.0,
    min_coverage: 1.0 / 3.0,
    start_within: 0.25,
};

/// What the history says about a running VM over the window.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdleVerdict {
    pub idle: bool,
    /// Hours of the window the history covers.
    pub covered_hours: u32,
    /// The VM's average share of this PC's CPU over the window.
    pub cpu_avg: f64,
    /// Its busiest hour's average.
    pub cpu_peak_hour: f64,
    pub guest_cpu_peak_hour: Option<f64>,
    pub guest_net_peak_hour: Option<f64>,
    /// Why it isn't idle, or why the history can't tell.
    pub why_not: Option<String>,
}

/// Per hour: the rounds-weighted average of a value.
fn hourly(rows: &[MinuteRow], value: impl Fn(&MinuteRow) -> Option<f64>) -> BTreeMap<i64, f64> {
    let mut sums: BTreeMap<i64, (f64, f64)> = BTreeMap::new();
    for row in rows {
        if let Some(v) = value(row).filter(|v| v.is_finite()) {
            let w = f64::from(row.samples.max(1));
            let e = sums.entry(row.minute.div_euclid(60)).or_default();
            e.0 += v * w;
            e.1 += w;
        }
    }
    sums.into_iter()
        .filter(|(_, (_, w))| *w > 0.0)
        .map(|(h, (s, w))| (h, s / w))
        .collect()
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// VM-14: whether a running VM was idle over `[from_minute, to_minute)`: history covers enough of the window, starts
/// near its start, and in its busiest hour the VM stayed under `limits` (the guest's CPU and network too, when its
/// linked session's metrics are kept).
pub fn idle_verdict(
    host: &[MinuteRow],
    guest: Option<&[MinuteRow]>,
    from_minute: i64,
    to_minute: i64,
    limits: IdleLimits,
) -> IdleVerdict {
    let span = (to_minute - from_minute).max(1) as f64;
    let host: Vec<&MinuteRow> = host
        .iter()
        .filter(|r| r.minute >= from_minute && r.minute < to_minute && r.cpu_avg.is_some())
        .collect();
    let covered = host.len();
    let owned: Vec<MinuteRow> = host.iter().map(|r| (*r).clone()).collect();
    let hours = hourly(&owned, |r| r.cpu_avg);
    let peak = hours.values().copied().fold(0.0_f64, f64::max);
    let (sum, weight) = owned.iter().fold((0.0, 0.0), |(s, w), r| {
        let n = f64::from(r.samples.max(1));
        (s + r.cpu_avg.unwrap_or(0.0) * n, w + n)
    });
    let avg = if weight > 0.0 { sum / weight } else { 0.0 };
    let guest_hours = guest.map(|g| {
        let rows: Vec<MinuteRow> = g
            .iter()
            .filter(|r| r.minute >= from_minute && r.minute < to_minute)
            .cloned()
            .collect();
        let cpu = hourly(&rows, |r| r.cpu_avg)
            .values()
            .copied()
            .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
        let net = hourly(&rows, |r| match (r.rx_avg, r.tx_avg) {
            (None, None) => None,
            (rx, tx) => Some(rx.unwrap_or(0) as f64 + tx.unwrap_or(0) as f64),
        })
        .values()
        .copied()
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
        (cpu, net)
    });
    let (guest_cpu, guest_net) = guest_hours.unwrap_or((None, None));
    let mut verdict = IdleVerdict {
        idle: false,
        covered_hours: (covered / 60) as u32,
        cpu_avg: round2(avg),
        cpu_peak_hour: round2(peak),
        guest_cpu_peak_hour: guest_cpu.map(round2),
        guest_net_peak_hour: guest_net.map(f64::round),
        why_not: None,
    };
    let first = host.first().map(|r| r.minute);
    verdict.why_not = if (covered as f64) < span * limits.min_coverage {
        Some(format!(
            "the dashboard's history covers {} of the {} hours",
            verdict.covered_hours,
            (span / 60.0).round()
        ))
    } else if first.is_none_or(|m| (m - from_minute) as f64 > span * limits.start_within) {
        Some("its history starts too late in the window".into())
    } else if peak >= limits.host_cpu_pct {
        Some(format!("its busiest hour used {:.1}% of this PC's CPU", peak))
    } else if guest_cpu.is_some_and(|c| c >= limits.guest_cpu_pct) {
        Some(format!(
            "its guest's busiest hour used {:.1}% CPU",
            guest_cpu.unwrap_or(0.0)
        ))
    } else if guest_net.is_some_and(|n| n >= limits.guest_net_bps) {
        Some("its guest's network was busy".into())
    } else {
        None
    };
    verdict.idle = verdict.why_not.is_none();
    verdict
}

/// VM-16: how deep a snapshot tree goes: the most snapshots on one path from the first to a leaf.
pub fn chain_depth(tree: &SnapshotTree) -> usize {
    let parents: HashMap<u32, Option<u32>> = tree.snapshots.iter().map(|s| (s.uid, s.parent_uid)).collect();
    let mut deepest = 0;
    for snapshot in &tree.snapshots {
        let mut depth = 1;
        let mut at = snapshot.parent_uid;
        while let Some(uid) = at {
            depth += 1;
            if depth > tree.snapshots.len() {
                break; // A loop in a damaged .vmsd.
            }
            at = parents.get(&uid).copied().flatten();
        }
        deepest = deepest.max(depth);
    }
    deepest
}

/// VM-16: a Workstation file that belongs to a snapshot: its state (`web01-Snapshot3.vmsn`, `.vmem`, `.vmss`) or a
/// delta disk (`web01-000002.vmdk`, `web01-000002-s001.vmdk`).
pub fn is_snapshot_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.contains("-snapshot") && [".vmsn", ".vmem", ".vmss"].iter().any(|e| lower.ends_with(e)) {
        return true;
    }
    let Some(stem) = lower.strip_suffix(".vmdk") else {
        return false;
    };
    let delta = |s: &str| s.len() == 6 && s.chars().all(|c| c.is_ascii_digit());
    let mut parts = stem.rsplit('-');
    let last = parts.next().unwrap_or_default();
    if delta(last) {
        return true;
    }
    // `-000002-s001`: the extent of a split delta disk.
    last.len() == 4
        && last.starts_with('s')
        && last[1..].chars().all(|c| c.is_ascii_digit())
        && parts.next().is_some_and(delta)
}

/// VM-16: a Workstation suspended state file: the `.vmss` and `.vmem` that are not a snapshot's.
pub fn is_suspend_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".vmss") || lower.ends_with(".vmem")) && !lower.contains("-snapshot")
}

/// VM-16: a file only a VM has: its settings, disks, states and snapshots.
pub fn is_vm_file(name: &str) -> bool {
    const EXTENSIONS: [&str; 16] = [
        "vmx",
        "vmdk",
        "vmsd",
        "vmxf",
        "nvram",
        "vmss",
        "vmem",
        "vmsn",
        "vbox",
        "vbox-prev",
        "vdi",
        "vhd",
        "vhdx",
        "sav",
        "qcow2",
        "vmtm",
    ];
    let lower = name.to_ascii_lowercase();
    lower.rsplit_once('.').is_some_and(|(_, ext)| EXTENSIONS.contains(&ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vmware::SnapshotInfo;
    use crate::metrics::history::HistorySource;

    fn row(minute: i64, cpu: f64) -> MinuteRow {
        MinuteRow {
            source: HistorySource::Host,
            key: "k".into(),
            minute,
            samples: 12,
            cpu_avg: Some(cpu),
            cpu_min: Some(cpu),
            cpu_max: Some(cpu),
            mem_avg: None,
            mem_max: None,
            mem_total: None,
            swap_avg: None,
            swap_total: None,
            read_avg: None,
            write_avg: None,
            rx_avg: None,
            tx_avg: None,
            load_avg: None,
            load_max: None,
            disk_used_max: None,
        }
    }

    /// A day of minutes from `from`, every minute at `cpu`.
    fn day(from: i64, cpu: f64) -> Vec<MinuteRow> {
        (from..from + 24 * 60).map(|m| row(m, cpu)).collect()
    }

    const DAY: i64 = 24 * 60;

    #[test]
    fn a_vm_quiet_all_window_is_idle() {
        let rows = [day(0, 0.4), day(DAY, 0.3), day(2 * DAY, 0.5)].concat();
        let v = idle_verdict(&rows, None, 0, 3 * DAY, IDLE_LIMITS);
        assert!(v.idle, "{v:?}");
        assert_eq!(v.covered_hours, 72);
        assert_eq!(v.cpu_peak_hour, 0.5);
    }

    #[test]
    fn one_busy_hour_is_enough_to_not_be_idle() {
        let mut rows = [day(0, 0.4), day(DAY, 0.3), day(2 * DAY, 0.5)].concat();
        for r in rows.iter_mut().skip(30 * 60).take(60) {
            r.cpu_avg = Some(9.0);
        }
        let v = idle_verdict(&rows, None, 0, 3 * DAY, IDLE_LIMITS);
        assert!(!v.idle);
        assert!(v.why_not.unwrap().contains("busiest hour"));
        // A spike shorter than an hour averages out.
        let mut short = [day(0, 0.4), day(DAY, 0.3), day(2 * DAY, 0.5)].concat();
        short[100].cpu_avg = Some(40.0);
        assert!(idle_verdict(&short, None, 0, 3 * DAY, IDLE_LIMITS).idle);
    }

    #[test]
    fn too_little_or_too_late_history_cant_tell() {
        let thin: Vec<MinuteRow> = day(0, 0.1).into_iter().take(20 * 60).collect();
        let v = idle_verdict(&thin, None, 0, 3 * DAY, IDLE_LIMITS);
        assert!(!v.idle && v.why_not.unwrap().contains("covers 20 of the 72 hours"));
        // A third of the window is enough.
        assert!(idle_verdict(&day(0, 0.1), None, 0, 3 * DAY, IDLE_LIMITS).idle);
        let late = [day(DAY, 0.1), day(2 * DAY, 0.1)].concat();
        let v = idle_verdict(&late, None, 0, 3 * DAY, IDLE_LIMITS);
        assert!(!v.idle && v.why_not.unwrap().contains("starts too late"));
        let none = idle_verdict(&[], None, 0, 3 * DAY, IDLE_LIMITS);
        assert!(!none.idle);
    }

    #[test]
    fn a_busy_guest_is_not_idle_even_when_the_host_side_is_quiet() {
        let host = [day(0, 0.2), day(DAY, 0.2), day(2 * DAY, 0.2)].concat();
        let mut guest = host.clone();
        for r in &mut guest {
            r.source = HistorySource::Guest;
            r.cpu_avg = Some(1.0);
            r.rx_avg = Some(100);
            r.tx_avg = Some(100);
        }
        assert!(idle_verdict(&host, Some(&guest), 0, 3 * DAY, IDLE_LIMITS).idle);
        guest[500].rx_avg = Some(10_000_000);
        let v = idle_verdict(&host, Some(&guest), 0, 3 * DAY, IDLE_LIMITS);
        assert!(!v.idle && v.why_not.unwrap().contains("network"));
        for r in guest.iter_mut().take(120) {
            r.cpu_avg = Some(50.0);
        }
        assert!(!idle_verdict(&host, Some(&guest), 0, 3 * DAY, IDLE_LIMITS).idle);
    }

    fn snap(uid: u32, parent: Option<u32>) -> SnapshotInfo {
        SnapshotInfo {
            uid,
            parent_uid: parent,
            name: format!("s{uid}"),
            description: None,
            created_at: None,
            id: None,
            linked_clones: Vec::new(),
        }
    }

    #[test]
    fn the_depth_is_the_longest_path_not_the_count() {
        let tree = SnapshotTree {
            snapshots: vec![
                snap(1, None),
                snap(2, Some(1)),
                snap(3, Some(1)),
                snap(4, Some(3)),
                snap(5, Some(4)),
            ],
            current_uid: Some(5),
        };
        assert_eq!(chain_depth(&tree), 4);
        assert_eq!(chain_depth(&SnapshotTree::default()), 0);
        let looped = SnapshotTree {
            snapshots: vec![snap(1, Some(2)), snap(2, Some(1))],
            current_uid: None,
        };
        assert!(chain_depth(&looped) <= 3, "a damaged tree doesn't hang");
    }

    #[test]
    fn workstation_snapshot_and_suspend_files_are_told_apart() {
        for name in [
            "web01-Snapshot3.vmsn",
            "web01-Snapshot3.vmem",
            "web01-000002.vmdk",
            "web 01-000002-s001.vmdk",
        ] {
            assert!(is_snapshot_file(name), "{name}");
        }
        for name in [
            "web01.vmdk",
            "web01-s001.vmdk",
            "web01-flat.vmdk",
            "web01.vmx",
            "web01-1234.vmdk",
        ] {
            assert!(!is_snapshot_file(name), "{name}");
        }
        assert!(is_suspend_file("web01-6f1a.vmss"));
        assert!(is_suspend_file("web01-6f1a.vmem"));
        assert!(!is_suspend_file("web01-Snapshot1.vmem"));
        assert!(is_vm_file("old.VMDK") && is_vm_file("lab.vbox-prev") && !is_vm_file("notes.txt"));
    }

    #[test]
    fn options_are_kept_in_bounds() {
        let o = WasteOptions {
            idle_days: 0,
            chain_depth: 1000,
            chain_gb: 0,
        }
        .clamped();
        assert_eq!((o.idle_days, o.chain_depth, o.chain_gb), (1, 100, 1));
        let parsed: WasteOptions = serde_json::from_str(r#"{"idleDays":7}"#).unwrap();
        assert_eq!((parsed.idle_days, parsed.chain_depth), (7, 5));
    }
}
