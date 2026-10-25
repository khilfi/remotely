//! VM-27: warnings for snapshot chains deeper or larger than the limits set (Schedules page), from MO-13's disk sizes
//! (each delta disk's files down to its base) and the VM's snapshot tree. Each level a disk's chain gets slows its
//! reads, and a chain's files only grow until snapshots are deleted.

use serde::{Deserialize, Serialize};

use crate::adapters::vm_hardware::VmHardware;
use crate::adapters::vmware::SnapshotTree;
use crate::command_bus::human_size;
use crate::error::{CoreError, Result};

/// The setting: [`ChainLimits`].
pub const CHAIN_LIMITS_KEY: &str = "schedules.chainLimits";
/// The deepest chain the setting allows warning about (VMware supports 32 levels).
pub const MAX_DEPTH_LIMIT: u32 = 32;
/// The largest size the setting takes, in GB.
pub const MAX_SIZE_LIMIT_GB: u32 = 10_000;

const GB: u64 = 1_000_000_000;

/// When a chain warns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainLimits {
    /// Warn when a disk's chain is deeper than this many snapshots.
    pub max_depth: u32,
    /// Warn when the disks' chains take more than this many GB on this PC.
    pub max_size_gb: u32,
}

impl Default for ChainLimits {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_size_gb: 100,
        }
    }
}

impl ChainLimits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_DEPTH_LIMIT).contains(&self.max_depth) {
            return Err(CoreError::InvalidInput(format!(
                "Warn about chains deeper than 1 to {MAX_DEPTH_LIMIT} snapshots."
            )));
        }
        if !(1..=MAX_SIZE_LIMIT_GB).contains(&self.max_size_gb) {
            return Err(CoreError::InvalidInput(format!(
                "Warn about chains larger than 1 to {MAX_SIZE_LIMIT_GB} GB."
            )));
        }
        Ok(())
    }
}

/// One VM's snapshot chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainInfo {
    pub vm_key: String,
    pub name: String,
    /// Levels of the deepest disk's chain (snapshots in line down to the base); `None` when unknown.
    pub depth: Option<u32>,
    /// What the snapshot disks' files take, their bases included; `None` with no snapshot disk or when unknown.
    pub size_bytes: Option<u64>,
    /// Snapshots in the tree.
    pub snapshots: Option<usize>,
    pub warnings: Vec<String>,
    /// Why the chain could not be read.
    pub error: Option<String>,
}

/// The chain from the VM's disks (MO-13) or, when they can't be read, its snapshot tree.
pub fn assess(
    vm_key: &str,
    name: &str,
    hardware: Option<&VmHardware>,
    tree: Option<&SnapshotTree>,
    limits: ChainLimits,
) -> ChainInfo {
    let from_disks = hardware.and_then(|hw| {
        hw.disks
            .iter()
            .filter(|d| d.delta)
            .map(|d| u32::try_from(d.chain.len()).unwrap_or(u32::MAX))
            .max()
    });
    let from_tree = tree.map(|tree| {
        // Levels from the first snapshot down to "you are here".
        let mut depth = 0u32;
        let mut at = tree.current_uid;
        let mut seen = std::collections::HashSet::new();
        while let Some(uid) = at {
            if !seen.insert(uid) {
                break;
            }
            depth += 1;
            at = tree.snapshots.iter().find(|s| s.uid == uid).and_then(|s| s.parent_uid);
        }
        depth
    });
    let depth = match (hardware, from_disks) {
        (Some(_), Some(depth)) => Some(depth),
        // Disks read with no snapshot disk: no chain, whatever the tree says.
        (Some(_), None) => Some(0),
        (None, _) => from_tree,
    };
    let size_bytes = hardware.and_then(|hw| {
        let deltas: Vec<u64> = hw
            .disks
            .iter()
            .filter(|d| d.delta)
            .filter_map(|d| d.on_disk_bytes)
            .collect();
        (!deltas.is_empty()).then(|| deltas.iter().sum())
    });
    let mut warnings = Vec::new();
    if let Some(depth) = depth.filter(|d| *d > limits.max_depth) {
        warnings.push(format!(
            "{name}'s snapshot chain is {depth} deep, more than {}: each level slows its disk. Delete the snapshots it no longer needs.",
            limits.max_depth
        ));
    }
    if let Some(size) = size_bytes.filter(|s| *s > u64::from(limits.max_size_gb) * GB) {
        warnings.push(format!(
            "{name}'s snapshot chain takes {} on this PC, more than {} GB.",
            human_size(size),
            limits.max_size_gb
        ));
    }
    ChainInfo {
        vm_key: vm_key.to_owned(),
        name: name.to_owned(),
        depth,
        size_bytes,
        snapshots: tree.map(|t| t.snapshots.len()),
        warnings,
        error: None,
    }
}

/// VM-27, when a snapshot schedule is saved: keeping `keep` more snapshots in line would take a chain past the
/// depth limit.
pub fn projected_warning(info: &ChainInfo, keep: Option<u32>, limits: ChainLimits) -> Option<String> {
    let keep = keep?;
    let depth = info.depth.unwrap_or(0).saturating_add(keep);
    (depth > limits.max_depth).then(|| {
        format!(
            "Keeping {keep} snapshots would make {}'s chain about {depth} deep, more than the {} the Schedules page warns about.",
            info.name, limits.max_depth
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vm_hardware::VirtualDisk;
    use crate::adapters::vmware::SnapshotInfo;

    fn disk(delta: bool, chain: usize, bytes: u64) -> VirtualDisk {
        VirtualDisk {
            slot: "scsi0:0".into(),
            path: r"C:\VMs\web01\web01-000002.vmdk".into(),
            delta,
            chain: (0..chain).map(|n| format!("parent{n}.vmdk")).collect(),
            on_disk_bytes: Some(bytes),
            ..Default::default()
        }
    }

    fn hardware(disks: Vec<VirtualDisk>) -> VmHardware {
        VmHardware {
            disks,
            ..Default::default()
        }
    }

    #[test]
    fn a_deep_or_large_chain_warns() {
        let limits = ChainLimits::default();
        let deep = assess("k", "web01", Some(&hardware(vec![disk(true, 7, GB)])), None, limits);
        assert_eq!(deep.depth, Some(7));
        assert_eq!(deep.warnings.len(), 1);
        assert!(deep.warnings[0].contains("7 deep, more than 5"));
        let large = assess(
            "k",
            "web01",
            Some(&hardware(vec![
                disk(true, 2, 80 * GB),
                disk(true, 1, 30 * GB),
                disk(false, 0, 500 * GB),
            ])),
            None,
            limits,
        );
        assert_eq!(
            large.size_bytes,
            Some(110 * GB),
            "only the snapshot disks' chains count"
        );
        assert_eq!(
            large.warnings,
            ["web01's snapshot chain takes 110 GB on this PC, more than 100 GB."]
        );
        let fine = assess("k", "web01", Some(&hardware(vec![disk(true, 2, GB)])), None, limits);
        assert!(fine.warnings.is_empty());
        let none = assess(
            "k",
            "web01",
            Some(&hardware(vec![disk(false, 0, 500 * GB)])),
            None,
            limits,
        );
        assert_eq!((none.depth, none.size_bytes), (Some(0), None));
    }

    #[test]
    fn without_the_disks_the_tree_gives_the_depth() {
        let snap = |uid: u32, parent: Option<u32>| SnapshotInfo {
            uid,
            parent_uid: parent,
            name: format!("s{uid}"),
            description: None,
            created_at: None,
            id: None,
        };
        let tree = SnapshotTree {
            snapshots: (1..=7).map(|uid| snap(uid, (uid > 1).then(|| uid - 1))).collect(),
            current_uid: Some(7),
        };
        let info = assess("k", "web01", None, Some(&tree), ChainLimits::default());
        assert_eq!((info.depth, info.snapshots), (Some(7), Some(7)));
        assert_eq!(info.warnings.len(), 1);
    }

    #[test]
    fn keeping_many_snapshots_is_warned_about_when_saved() {
        let limits = ChainLimits::default();
        let info = assess("k", "web01", Some(&hardware(vec![disk(true, 1, GB)])), None, limits);
        assert!(projected_warning(&info, Some(3), limits).is_none());
        assert!(projected_warning(&info, Some(7), limits)
            .unwrap()
            .contains("about 8 deep"));
        assert!(projected_warning(&info, None, limits).is_none());
    }

    #[test]
    fn limits_are_checked() {
        assert!(ChainLimits {
            max_depth: 0,
            max_size_gb: 10
        }
        .validate()
        .is_err());
        assert!(ChainLimits {
            max_depth: 5,
            max_size_gb: 0
        }
        .validate()
        .is_err());
        assert!(ChainLimits::default().validate().is_ok());
    }
}
