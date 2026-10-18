//! Snapshot manager reads (VM-04) and safety snapshot names (VM-05).
//!
//! Reads skip the command bus: the tree and creation times come from each VM's .vmsd file through
//! the VMware adapter (vmrun only gives names). Taking, reverting and deleting snapshots are
//! [`crate::command_bus::Command::VmSnapshot`] commands, which go through the bus.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::adapters::vmware::{SnapshotInfo, SnapshotTree, VmwareAdapter};
use crate::domain::{Context, Environment, PowerState};
use crate::error::Result;
use crate::store::Store;

/// VM-04: snapshots older than this are flagged. Old snapshots slow the VM's disk and use space.
pub const OLD_AFTER_DAYS: i64 = 30;

/// VM-05: every safety snapshot's name starts with this, so it is easy to spot in Workstation too.
/// Names a user gives a snapshot may not start with it.
pub const SAFETY_PREFIX: &str = "Remotely safety";

/// True for a snapshot Remotely took before a high-risk action (VM-05).
pub fn is_safety_name(name: &str) -> bool {
    name.starts_with(SAFETY_PREFIX)
}

/// VM-05: one name for the whole job, so every VM's safety snapshot has the same name and a single
/// bulk revert undoes the job. For example `Remotely safety before shut down 2026-10-18 09:59 UTC
/// (job 1a2b3c4d)`. No `/`, which vmrun reads as a path to a child snapshot.
pub fn safety_snapshot_name(before: &str, at: OffsetDateTime, job_id: Uuid) -> String {
    let when = at
        .to_offset(time::UtcOffset::UTC)
        .format(format_description!("[year]-[month]-[day] [hour]:[minute]"))
        .unwrap_or_else(|_| at.unix_timestamp().to_string());
    let job = job_id.simple().to_string();
    format!("{SAFETY_PREFIX} before {before} {when} UTC (job {})", &job[..8])
}

/// One snapshot of one VM, ready to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotNode {
    pub uid: u32,
    pub parent_uid: Option<u32>,
    pub name: String,
    /// vmrun's path form, e.g. `base/child one`. It names the snapshot even when another snapshot
    /// of the VM has the same name.
    pub path: String,
    pub description: Option<String>,
    /// RFC 3339 UTC; `None` when the .vmsd has no time for it.
    pub created_at: Option<String>,
    pub age_days: Option<i64>,
    /// Levels below a first snapshot (0 for a first snapshot).
    pub depth: usize,
    /// Older than [`OLD_AFTER_DAYS`] days.
    pub old: bool,
    /// Taken by Remotely before a high-risk action (VM-05).
    pub safety: bool,
    /// The VM's current state was taken from this snapshot ("you are here").
    pub current: bool,
}

/// A VM and its snapshot tree.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSnapshots {
    pub vmx_path: String,
    pub display_name: String,
    pub power_state: PowerState,
    pub environment: Environment,
    pub protected: bool,
    /// Tree order: each snapshot comes right after its parent; brothers oldest first.
    pub snapshots: Vec<SnapshotNode>,
    pub old_count: usize,
    pub safety_count: usize,
    /// Why the snapshots could not be read; the list is empty then.
    pub error: Option<String>,
}

/// Puts a VM's snapshots in tree order and flags old, safety and current ones.
pub fn tree_nodes(tree: &SnapshotTree, now: OffsetDateTime) -> Vec<SnapshotNode> {
    let uids: HashSet<u32> = tree.snapshots.iter().map(|s| s.uid).collect();
    let mut children: HashMap<Option<u32>, Vec<usize>> = HashMap::new();
    for (index, snapshot) in tree.snapshots.iter().enumerate() {
        // A parent that is not in the file (a damaged .vmsd) makes it a first snapshot.
        let parent = snapshot.parent_uid.filter(|p| uids.contains(p) && *p != snapshot.uid);
        children.entry(parent).or_default().push(index);
    }
    for list in children.values_mut() {
        list.sort_by_key(|&i| (tree.snapshots[i].created_at, tree.snapshots[i].uid));
    }

    let node = |snapshot: &SnapshotInfo, depth: usize, path: String| {
        let age = snapshot.created_at.map(|at| now - at);
        SnapshotNode {
            uid: snapshot.uid,
            parent_uid: snapshot.parent_uid,
            name: snapshot.name.clone(),
            path,
            description: snapshot.description.clone(),
            created_at: snapshot.created_at.and_then(|at| at.format(&Rfc3339).ok()),
            age_days: age.map(|a| a.whole_days()),
            depth,
            old: age.is_some_and(|a| a > Duration::days(OLD_AFTER_DAYS)),
            safety: is_safety_name(&snapshot.name),
            current: tree.current_uid == Some(snapshot.uid),
        }
    };

    let mut nodes = Vec::with_capacity(tree.snapshots.len());
    let mut seen = HashSet::new();
    // (index, depth, parent path), last in first out.
    let mut stack: Vec<(usize, usize, String)> = children
        .get(&None)
        .map(|roots| roots.iter().rev().map(|&i| (i, 0, String::new())).collect())
        .unwrap_or_default();
    while let Some((index, depth, parent_path)) = stack.pop() {
        let snapshot = &tree.snapshots[index];
        if !seen.insert(snapshot.uid) {
            continue;
        }
        let path = if parent_path.is_empty() {
            snapshot.name.clone()
        } else {
            format!("{parent_path}/{}", snapshot.name)
        };
        if let Some(kids) = children.get(&Some(snapshot.uid)) {
            stack.extend(kids.iter().rev().map(|&i| (i, depth + 1, path.clone())));
        }
        nodes.push(node(snapshot, depth, path));
    }
    // A loop of parents (a damaged .vmsd) never reaches a first snapshot; list those at the end.
    for snapshot in &tree.snapshots {
        if seen.insert(snapshot.uid) {
            nodes.push(node(snapshot, 0, snapshot.name.clone()));
        }
    }
    nodes
}

/// Snapshot counts for the impact preview (AP-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotCounts {
    pub total: usize,
    pub old: usize,
}

pub fn counts(tree: &SnapshotTree, now: OffsetDateTime) -> SnapshotCounts {
    let old = tree
        .snapshots
        .iter()
        .filter(|s| s.created_at.is_some_and(|at| now - at > Duration::days(OLD_AFTER_DAYS)))
        .count();
    SnapshotCounts {
        total: tree.snapshots.len(),
        old,
    }
}

/// VM-04: reads every VM's snapshot tree. Reads only; no vmrun call.
pub struct SnapshotReader {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
}

impl SnapshotReader {
    pub fn new(store: Store, vmware: Arc<dyn VmwareAdapter>) -> Self {
        Self { store, vmware }
    }

    /// The snapshots of the VMs the last inventory refresh found, or of `only` those .vmx paths. A
    /// VM whose .vmsd cannot be read is listed with the error instead of failing the whole list.
    pub async fn list(&self, ctx: &Context, only: Option<&[String]>) -> Result<Vec<VmSnapshots>> {
        let wanted: Option<HashSet<String>> = only.map(|paths| paths.iter().map(|p| p.to_lowercase()).collect());
        let now = OffsetDateTime::now_utc();
        let mut out = Vec::new();
        for vm in self.store.list_vms(ctx).await? {
            if wanted
                .as_ref()
                .is_some_and(|w| !w.contains(&vm.vmx_path.to_lowercase()))
            {
                continue;
            }
            let (snapshots, error) = match self.vmware.snapshots(Path::new(&vm.vmx_path)).await {
                Ok(tree) => (tree_nodes(&tree, now), None),
                Err(err) => (Vec::new(), Some(format!("Could not read the snapshot list: {err}"))),
            };
            out.push(VmSnapshots {
                old_count: snapshots.iter().filter(|s| s.old).count(),
                safety_count: snapshots.iter().filter(|s| s.safety).count(),
                vmx_path: vm.vmx_path,
                display_name: vm.display_name,
                power_state: vm.power_state,
                environment: vm.environment,
                protected: vm.protected,
                snapshots,
                error,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-10-18 12:00 UTC);

    fn snap(uid: u32, parent: Option<u32>, name: &str, at: OffsetDateTime) -> SnapshotInfo {
        SnapshotInfo {
            uid,
            parent_uid: parent,
            name: name.into(),
            description: None,
            created_at: Some(at),
        }
    }

    fn names(nodes: &[SnapshotNode]) -> Vec<(usize, &str)> {
        nodes.iter().map(|n| (n.depth, n.name.as_str())).collect()
    }

    #[test]
    fn snapshots_come_in_tree_order_with_paths() {
        let tree = SnapshotTree {
            // File order is not tree order: a later branch sits before an earlier child.
            snapshots: vec![
                snap(1, None, "base", datetime!(2026-08-01 9:00 UTC)),
                snap(4, Some(1), "branch", datetime!(2026-10-01 9:00 UTC)),
                snap(2, Some(1), "child", datetime!(2026-09-01 9:00 UTC)),
                snap(3, Some(2), "grandchild", datetime!(2026-09-15 9:00 UTC)),
                snap(5, None, "second root", datetime!(2026-10-17 9:00 UTC)),
            ],
            current_uid: Some(3),
        };
        let nodes = tree_nodes(&tree, NOW);
        assert_eq!(
            names(&nodes),
            [
                (0, "base"),
                (1, "child"),
                (2, "grandchild"),
                (1, "branch"),
                (0, "second root")
            ]
        );
        assert_eq!(nodes[2].path, "base/child/grandchild");
        let current: Vec<_> = nodes.iter().filter(|n| n.current).map(|n| n.uid).collect();
        assert_eq!(current, [3]);
        assert_eq!(nodes[0].created_at.as_deref(), Some("2026-08-01T09:00:00Z"));
    }

    #[test]
    fn snapshots_older_than_30_days_are_flagged() {
        let tree = SnapshotTree {
            snapshots: vec![
                snap(1, None, "ancient", NOW - Duration::days(90)),
                snap(2, Some(1), "just over", NOW - Duration::days(30) - Duration::minutes(1)),
                snap(3, Some(2), "exactly 30 days", NOW - Duration::days(30)),
                snap(4, Some(3), "fresh", NOW - Duration::hours(2)),
            ],
            current_uid: Some(4),
        };
        let nodes = tree_nodes(&tree, NOW);
        let old: Vec<_> = nodes.iter().map(|n| (n.name.as_str(), n.old)).collect();
        assert_eq!(
            old,
            [
                ("ancient", true),
                ("just over", true),
                ("exactly 30 days", false),
                ("fresh", false)
            ]
        );
        assert_eq!(nodes[0].age_days, Some(90));
        assert_eq!(counts(&tree, NOW), SnapshotCounts { total: 4, old: 2 });
    }

    #[test]
    fn a_snapshot_without_a_time_is_never_old() {
        let mut no_time = snap(1, None, "unknown", NOW);
        no_time.created_at = None;
        let tree = SnapshotTree {
            snapshots: vec![no_time],
            current_uid: None,
        };
        let nodes = tree_nodes(&tree, NOW);
        assert!(!nodes[0].old);
        assert_eq!(nodes[0].age_days, None);
        assert_eq!(nodes[0].created_at, None);
    }

    #[test]
    fn safety_snapshots_are_named_recognisably_and_flagged() {
        let job = Uuid::parse_str("1a2b3c4d-0000-4000-8000-000000000000").unwrap();
        let name = safety_snapshot_name("shut down", datetime!(2026-10-18 09:59:30 +08:00), job);
        assert_eq!(
            name,
            "Remotely safety before shut down 2026-10-18 01:59 UTC (job 1a2b3c4d)"
        );
        assert!(!name.contains('/'), "vmrun reads / as a path");
        assert!(is_safety_name(&name));
        assert!(!is_safety_name("base"));

        let tree = SnapshotTree {
            snapshots: vec![snap(1, None, &name, NOW)],
            current_uid: Some(1),
        };
        assert!(tree_nodes(&tree, NOW)[0].safety);
    }

    #[test]
    fn a_damaged_vmsd_still_lists_every_snapshot_once() {
        let tree = SnapshotTree {
            snapshots: vec![
                snap(1, Some(2), "loop a", NOW),
                snap(2, Some(1), "loop b", NOW),
                snap(3, Some(99), "orphan", NOW),
                snap(4, Some(4), "own parent", NOW),
            ],
            current_uid: None,
        };
        let nodes = tree_nodes(&tree, NOW);
        let mut uids: Vec<_> = nodes.iter().map(|n| n.uid).collect();
        uids.sort();
        assert_eq!(uids, [1, 2, 3, 4]);
    }
}
