//! VM-04, VM-21, VM-24: linked clones, and the deletes Remotely refuses so that none breaks without a word.
//!
//! A linked clone (VM-21's deploy, VM-10's bulk clone, or one made in Workstation or VirtualBox) shares its golden VM's
//! disk as it was at a snapshot. What the hand checks found (Workstation 26, VirtualBox 7.2):
//!
//! * Workstation records each clone in the golden VM's .vmsd (`snapshotN.cloneM`, the first `snapshotN.numClones`).
//!   `vmrun deleteSnapshot` of that snapshot merges away the disk the clone is made from, and `vmrun deleteVM` of the
//!   golden VM deletes it, both without a word: the clone no longer powers on. Deleting the snapshot's parent, or a
//!   snapshot taken after it, is safe (Workstation keeps the disk the clone needs).
//! * VirtualBox keeps the clone's differencing disk under the snapshot's disk (in the golden VM's media registry).
//!   `snapshot delete` refuses while the golden VM's own disk is a child there too ("more than one child hard disk"),
//!   but once the golden VM has moved off the snapshot (restored an older one) it merges the clone's disk away and the
//!   clone no longer starts. `unregistervm --delete` unregisters the golden VM and deletes its current disk before it
//!   fails ("Cannot close medium ... because it has 1 child media"), leaving the clone's disk in a media registry
//!   VirtualBox no longer reads. Deleting the snapshot's parent is safe there too.
//!
//! So deleting such a snapshot, or the golden VM, is refused, with the clones named: by the command bus before it
//! asks when every VM of the command would be refused (else a warning in the approval), by the approval's preview
//! (AP-02), and by the job runner again just before it deletes (a clone made since the approval counts). VM-27's
//! schedule retention keeps such a snapshot. Reads only: Workstation's .vmsd and whether each clone's .vmx is still
//! there (a clone on a share counts, unopened: A3); VirtualBox's `list --long hdds` and `list vms`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;

use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::virtualbox::{find_snapshot, VboxListedVm, VboxMedium};
use crate::adapters::vmware::{SnapshotInfo, SnapshotTree};
use crate::command_bus::{Command, SnapshotOp};
use crate::domain::{Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::snapshots::tree_nodes;
use crate::vm_settings::VmLifecycleOp;

/// At most this many clones are named in a reason; the rest are counted.
const NAMED: usize = 10;

/// A VM made as a linked clone of another VM's snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedClone {
    pub name: String,
    /// Workstation: its .vmx; VirtualBox: its UUID (the VM's key in Remotely either way).
    pub key: String,
}

impl LinkedClone {
    /// `web-01 (C:\VMs\web-01\web-01.vmx)`; a VirtualBox clone by its name alone.
    fn label(&self) -> String {
        if Hypervisor::of_key(&self.key) == Hypervisor::Vmware {
            format!("{} ({})", self.name, self.key)
        } else {
            self.name.clone()
        }
    }
}

/// One snapshot of a VM and the linked clones made from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotClones {
    pub snapshot: String,
    /// As the snapshot list names it ([`crate::snapshots::SnapshotNode::uid`]).
    pub uid: u32,
    pub clones: Vec<LinkedClone>,
}

/// VirtualBox's media list and its registered VMs.
type MediaAndVms = (Vec<VboxMedium>, Vec<VboxListedVm>);

/// VirtualBox's media list and registered VMs, read once for every VirtualBox VM a check looks at.
#[derive(Default)]
pub struct VboxMedia {
    read: Option<std::result::Result<MediaAndVms, String>>,
}

impl VboxMedia {
    async fn get(&mut self, hypervisors: &Hypervisors) -> Result<(&[VboxMedium], &[VboxListedVm])> {
        if self.read.is_none() {
            let vbox = hypervisors.virtualbox();
            let read = match vbox.media().await {
                Ok(media) => match vbox.list_vms().await {
                    Ok(vms) => Ok((media, vms)),
                    Err(err) => Err(err.to_string()),
                },
                Err(err) => Err(err.to_string()),
            };
            self.read = Some(read);
        }
        match &self.read {
            Some(Ok((media, vms))) => Ok((media.as_slice(), vms.as_slice())),
            Some(Err(message)) => Err(CoreError::LinkedClones(message.clone())),
            None => Err(CoreError::LinkedClones("VirtualBox's media list was not read".into())),
        }
    }
}

/// VM-04, VM-21: VirtualBox's linked clones of a snapshot: the VMs other than `golden` that use a differencing disk made
/// from a disk the snapshot holds, or one made from that, and so on. A disk the golden VM itself uses (its current
/// state, or a snapshot taken later) is its own: the clones made from that hang off a later snapshot. A VM's name is any
/// text and may hold `(UUID: …)`, so a disk counts as the golden VM's only when no other registered VM uses it.
pub fn vbox_clones(golden: &str, snapshot: &str, media: &[VboxMedium], vms: &[VboxListedVm]) -> Vec<LinkedClone> {
    let machines: HashSet<&str> = vms.iter().map(|vm| vm.uuid.as_str()).collect();
    let mut children: HashMap<&str, Vec<&VboxMedium>> = HashMap::new();
    for medium in media {
        if let Some(parent) = &medium.parent {
            children.entry(parent.as_str()).or_default().push(medium);
        }
    }
    let others = |medium: &VboxMedium| -> Vec<String> {
        medium
            .used_by
            .iter()
            .filter(|u| u.as_str() != golden && machines.contains(u.as_str()))
            .cloned()
            .collect()
    };
    let mut users: Vec<String> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for image in media.iter().filter(|m| m.used_by.iter().any(|u| u == snapshot)) {
        let mut stack: Vec<&VboxMedium> = Vec::new();
        for child in children.get(image.uuid.as_str()).into_iter().flatten() {
            let golden_own = child.used_by.iter().any(|u| u == golden) && others(child).is_empty();
            if !golden_own {
                stack.push(child);
            }
        }
        while let Some(disk) = stack.pop() {
            if !seen.insert(disk.uuid.as_str()) {
                continue;
            }
            for user in others(disk) {
                if !users.contains(&user) {
                    users.push(user);
                }
            }
            stack.extend(children.get(disk.uuid.as_str()).into_iter().flatten());
        }
    }
    users
        .into_iter()
        .map(|uuid| LinkedClone {
            name: vms
                .iter()
                .find(|vm| vm.uuid == uuid)
                .map_or_else(|| uuid.clone(), |vm| vm.name.clone()),
            key: uuid,
        })
        .collect()
}

/// Finds the linked clones that depend on a VM's snapshots, and says why a delete would break them.
#[derive(Clone)]
pub struct LinkedClones {
    hypervisors: Hypervisors,
}

impl LinkedClones {
    pub fn new(hypervisors: Hypervisors) -> Self {
        Self { hypervisors }
    }

    /// The linked clones that depend on each of the VM's snapshots, for the snapshots with any, in tree order.
    pub async fn of_vm(&self, key: &str, media: &mut VboxMedia) -> Result<Vec<SnapshotClones>> {
        let tree = self.tree(key).await?;
        self.of_tree(key, &tree, media).await
    }

    /// [`Self::of_vm`] for a snapshot tree already read (VM-04's snapshot list).
    pub async fn of_tree(&self, key: &str, tree: &SnapshotTree, media: &mut VboxMedia) -> Result<Vec<SnapshotClones>> {
        self.of_snapshots(key, tree, &tree.snapshots.iter().collect::<Vec<_>>(), media)
            .await
    }

    /// The linked clones that depend on the snapshot a delete names (`name`: a name, vmrun's path form, or a
    /// VirtualBox UUID, as [`SnapshotOp::Delete`] takes it). Workstation reads a name two snapshots share as either.
    pub async fn of_snapshot(&self, key: &str, name: &str, media: &mut VboxMedia) -> Result<Vec<SnapshotClones>> {
        let tree = self.tree(key).await?;
        let named: Vec<&SnapshotInfo> = match Hypervisor::of_key(key) {
            Hypervisor::VirtualBox => find_snapshot(&tree, name).into_iter().collect(),
            Hypervisor::Vmware => {
                let nodes = tree_nodes(&tree, OffsetDateTime::now_utc());
                tree.snapshots
                    .iter()
                    .filter(|s| s.name == name || nodes.iter().any(|n| n.uid == s.uid && n.path == name))
                    .collect()
            }
        };
        self.of_snapshots(key, &tree, &named, media).await
    }

    async fn tree(&self, key: &str) -> Result<SnapshotTree> {
        match Hypervisor::of_key(key) {
            // The .vmsd: a read of a file, no vmrun.
            Hypervisor::Vmware => self.hypervisors.vmware().snapshots(Path::new(key)).await,
            // The ids are enough; the times (from the .vbox) are not needed here.
            Hypervisor::VirtualBox => Ok(self.hypervisors.virtualbox().vm_info(key).await?.snapshots),
        }
    }

    async fn of_snapshots(
        &self,
        key: &str,
        tree: &SnapshotTree,
        snapshots: &[&SnapshotInfo],
        media: &mut VboxMedia,
    ) -> Result<Vec<SnapshotClones>> {
        let mut out = Vec::new();
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => {
                let folder = Path::new(key).parent().unwrap_or(Path::new(""));
                for snapshot in snapshots {
                    let mut clones = Vec::new();
                    for written in &snapshot.linked_clones {
                        let path = crate::vm_settings::vmware::resolve(folder, written);
                        if let Some(clone) = self.vmware_clone(&path).await {
                            if !clones
                                .iter()
                                .any(|c: &LinkedClone| c.key.eq_ignore_ascii_case(&clone.key))
                            {
                                clones.push(clone);
                            }
                        }
                    }
                    if !clones.is_empty() {
                        out.push(SnapshotClones {
                            snapshot: snapshot.name.clone(),
                            uid: snapshot.uid,
                            clones,
                        });
                    }
                }
            }
            Hypervisor::VirtualBox => {
                if !snapshots.iter().any(|s| s.id.is_some()) {
                    return Ok(out);
                }
                let (all, vms) = media.get(&self.hypervisors).await?;
                for snapshot in snapshots {
                    let Some(id) = &snapshot.id else { continue };
                    let clones = vbox_clones(key, id, all, vms);
                    if !clones.is_empty() {
                        out.push(SnapshotClones {
                            snapshot: snapshot.name.clone(),
                            uid: snapshot.uid,
                            clones,
                        });
                    }
                }
            }
        }
        // Tree order is the order the user sees; the .vmsd's order is close to it already.
        let order: Vec<u32> = tree_nodes(tree, OffsetDateTime::now_utc())
            .iter()
            .map(|n| n.uid)
            .collect();
        out.sort_by_key(|s| order.iter().position(|uid| *uid == s.uid).unwrap_or(usize::MAX));
        Ok(out)
    }

    /// A clone Workstation recorded, while its .vmx is still there: one deleted by hand since can't break any more. A
    /// .vmx on a share or a device path is never opened (A3) and counts as there.
    async fn vmware_clone(&self, path: &Path) -> Option<LinkedClone> {
        let vmware = self.hypervisors.vmware();
        let refused = crate::untrusted::path_refusal(path).is_some();
        if !refused && !vmware.file_exists(path).await {
            return None;
        }
        let stem = || {
            path.file_stem()
                .map_or_else(|| path.display().to_string(), |s| s.to_string_lossy().into_owned())
        };
        let name = if refused {
            stem()
        } else {
            match vmware.read_vmx(path).await {
                Ok(info) => info.display_name.filter(|n| !n.trim().is_empty()).unwrap_or_else(stem),
                Err(_) => stem(),
            }
        };
        Some(LinkedClone {
            name,
            key: path.display().to_string(),
        })
    }

    /// For a snapshot or VM delete on the VM `key`: the linked clones that depend on what it deletes (empty when none
    /// does), or why that could not be checked. `None` for other commands.
    pub async fn check(
        &self,
        command: &Command,
        key: &str,
        media: &mut VboxMedia,
    ) -> Option<std::result::Result<Vec<SnapshotClones>, String>> {
        let found = match Deletes::of(command)? {
            Deletes::Snapshot(name) => self.of_snapshot(key, name, media).await,
            Deletes::Vm => self.of_vm(key, media).await,
        };
        Some(found.map_err(|err| err.to_string()))
    }

    /// Why `command` must not run on the VM `key`, without the VM's name (the job's row and the settings preview show
    /// it): a snapshot or VM delete that would break linked clones, or whose clones could not be checked.
    pub async fn refusal(&self, command: &Command, key: &str, media: &mut VboxMedia) -> Option<String> {
        let deletes = Deletes::of(command)?;
        match self.check(command, key, media).await? {
            Ok(found) if found.is_empty() => None,
            Ok(found) => Some(deletes.reason(None, &found)),
            Err(err) => Some(deletes.unchecked(None, &err)),
        }
    }

    /// VM-24: why the VM `key` must not be deleted (without its name), or `None` when no linked clone depends on it.
    pub async fn vm_delete_refusal(&self, key: &str, media: &mut VboxMedia) -> Option<String> {
        match self.of_vm(key, media).await {
            Ok(found) if found.is_empty() => None,
            Ok(found) => Some(Deletes::Vm.reason(None, &found)),
            Err(err) => Some(Deletes::Vm.unchecked(None, &err.to_string())),
        }
    }

    /// Every VM target `command` must not run on, reading VirtualBox's media list at most once. Empty for commands
    /// other than a snapshot or VM delete.
    pub async fn blocked(&self, command: &Command, targets: &[Target]) -> Vec<Blocked> {
        let Some(deletes) = Deletes::of(command) else {
            return Vec::new();
        };
        let mut media = VboxMedia::default();
        let mut out = Vec::new();
        for target in targets {
            let TargetRef::Vm { vmx_path } = &target.target else {
                continue;
            };
            let (snapshots, reason) = match self.check(command, vmx_path, &mut media).await {
                Some(Ok(found)) if found.is_empty() => continue,
                Some(Ok(found)) => {
                    let reason = deletes.reason(Some(&target.name), &found);
                    (found, reason)
                }
                Some(Err(err)) => (Vec::new(), deletes.unchecked(Some(&target.name), &err)),
                None => continue,
            };
            out.push(Blocked {
                target: vmx_path.clone(),
                snapshots,
                reason,
            });
        }
        out
    }
}

/// A VM target a delete must not touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// The target's key.
    pub target: String,
    /// What the delete would take that clones depend on: the snapshot it names, or each snapshot of a VM it deletes.
    /// Empty when the clones could not be checked.
    pub snapshots: Vec<SnapshotClones>,
    /// Why, with the VM's name.
    pub reason: String,
}

/// What a command deletes that linked clones can depend on.
enum Deletes<'a> {
    /// A snapshot, as [`SnapshotOp::Delete`] names it.
    Snapshot(&'a str),
    /// The whole VM (VM-24).
    Vm,
}

impl<'a> Deletes<'a> {
    fn of(command: &'a Command) -> Option<Self> {
        match command {
            Command::VmSnapshot {
                op: SnapshotOp::Delete { name },
                ..
            } => Some(Self::Snapshot(name)),
            Command::VmLifecycle {
                op: VmLifecycleOp::Delete,
                ..
            } => Some(Self::Vm),
            _ => None,
        }
    }

    fn reason(&self, vm: Option<&str>, found: &[SnapshotClones]) -> String {
        match self {
            Self::Snapshot(_) => snapshot_reason(vm, found),
            Self::Vm => vm_reason(vm, found),
        }
    }

    fn unchecked(&self, vm: Option<&str>, err: &str) -> String {
        let prefix = vm.map(|v| format!("'{v}': ")).unwrap_or_default();
        match self {
            Self::Snapshot(name) => format!(
                "{prefix}Remotely could not check whether linked clones depend on snapshot '{name}', so it is not deleted: {err}"
            ),
            Self::Vm => format!(
                "{prefix}Remotely could not check whether linked clones depend on the VM's snapshots, so it is not deleted: {err}"
            ),
        }
    }
}

/// A snapshot delete or a VM delete: the commands linked clones can stop.
pub fn deletes(command: &Command) -> bool {
    Deletes::of(command).is_some()
}

/// `web-01 (C:\…\web-01.vmx), web-02 (…)`, at most [`NAMED`] then a count.
pub fn clone_list(clones: &[LinkedClone]) -> String {
    let mut names: Vec<String> = clones.iter().take(NAMED).map(LinkedClone::label).collect();
    if clones.len() > NAMED {
        names.push(format!("and {} more", clones.len() - NAMED));
    }
    names.join(", ")
}

fn count(n: usize) -> String {
    if n == 1 {
        "1 linked clone depends".to_owned()
    } else {
        format!("{n} linked clones depend")
    }
}

/// `'golden': 2 linked clones depend on its`, or without the VM's name `2 linked clones depend on the VM's`.
fn lead(vm: Option<&str>, n: usize) -> String {
    match vm {
        Some(vm) => format!("'{vm}': {} on its", count(n)),
        None => format!("{} on the VM's", count(n)),
    }
}

/// Why a snapshot is not deleted (`vm`: the VM's name, when the reason is read apart from it).
pub fn snapshot_reason(vm: Option<&str>, found: &[SnapshotClones]) -> String {
    let clones: Vec<LinkedClone> = found.iter().flat_map(|s| s.clones.iter().cloned()).collect();
    let snapshot = found.first().map_or("", |s| s.snapshot.as_str());
    format!(
        "{} snapshot '{snapshot}': {}. Deleting the snapshot would break them, so it is not deleted: delete those clones first.",
        lead(vm, clones.len()),
        clone_list(&clones)
    )
}

/// Why a VM is not deleted.
pub fn vm_reason(vm: Option<&str>, found: &[SnapshotClones]) -> String {
    let total: usize = found.iter().map(|s| s.clones.len()).sum();
    let per_snapshot: Vec<String> = found
        .iter()
        .map(|s| format!("'{}' ({})", s.snapshot, clone_list(&s.clones)))
        .collect();
    format!(
        "{} snapshots: {}. Deleting the VM would delete the disks they are made from, so it is not deleted: delete those clones first.",
        lead(vm, total),
        per_snapshot.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = "520326dd-e514-4317-8c58-517f7c751b13";
    const BASE: &str = "7d2053f2-f6d0-4fbb-a779-e1887961ddcf";
    const LATER: &str = "7d2053f2-f6d0-4fbb-a779-e18879610002";
    const WEB01: &str = "b687ee40-7b2d-426e-91a5-cd86b996001a";
    const WEB02: &str = "a423e999-d1b2-4805-948d-0aa4857e27f2";
    const WEB03: &str = "a423e999-d1b2-4805-948d-0aa4857e0003";

    fn medium(uuid: &str, parent: Option<&str>, used_by: &[&str]) -> VboxMedium {
        VboxMedium {
            uuid: uuid.into(),
            parent: parent.map(str::to_owned),
            location: format!(r"C:\Users\alice\VirtualBox VMs\{uuid}.vdi"),
            used_by: used_by.iter().map(|u| (*u).to_owned()).collect(),
        }
    }

    fn vms() -> Vec<VboxListedVm> {
        [
            (GOLDEN, "golden"),
            (WEB01, "web-01"),
            (WEB02, "web-02"),
            (WEB03, "web-03"),
        ]
        .iter()
        .map(|(uuid, name)| VboxListedVm {
            uuid: (*uuid).into(),
            name: (*name).into(),
        })
        .collect()
    }

    /// The golden VM's base disk is held by "base"; its own current disk, web-01's (with web-01's own snapshot under
    /// it) and web-02's are made from it. A later snapshot of the golden VM holds its current disk, with web-03 made
    /// from that.
    fn media() -> Vec<VboxMedium> {
        vec![
            medium("d0", None, &[GOLDEN, BASE]),
            medium("d1", Some("d0"), &[GOLDEN, LATER]),
            medium("d2", Some("d1"), &[GOLDEN]),
            medium("c1", Some("d0"), &[WEB01, "ac2f81ed-9bfa-48db-891e-7908536dfa7f"]),
            medium("c1b", Some("c1"), &[WEB01]),
            medium("c2", Some("d0"), &[WEB02]),
            medium("c3", Some("d1"), &[WEB03]),
            // A disk a clone left behind that no VM uses breaks nothing.
            medium("orphan", Some("d0"), &[]),
        ]
    }

    fn names(clones: &[LinkedClone]) -> Vec<&str> {
        let mut names: Vec<&str> = clones.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn virtualbox_clones_are_the_other_vms_on_disks_made_from_the_snapshots_disk() {
        assert_eq!(
            names(&vbox_clones(GOLDEN, BASE, &media(), &vms())),
            ["web-01", "web-02"]
        );
        assert_eq!(
            names(&vbox_clones(GOLDEN, LATER, &media(), &vms())),
            ["web-03"],
            "a clone of a later snapshot is that snapshot's, not its parent's"
        );
        assert!(vbox_clones(WEB01, "ac2f81ed-9bfa-48db-891e-7908536dfa7f", &media(), &vms()).is_empty());
        assert!(vbox_clones(GOLDEN, "no-such-snapshot", &media(), &vms()).is_empty());
    }

    #[test]
    fn a_name_holding_the_golden_vms_uuid_hides_no_clone() {
        // VM-04, A-series: VBoxManage prints a VM's name before its UUID; a name can add a UUID to the list, never
        // take one away, so web-02's disk still counts as web-02's.
        let mut media = media();
        media[5].used_by.insert(0, GOLDEN.to_owned());
        assert_eq!(names(&vbox_clones(GOLDEN, BASE, &media, &vms())), ["web-01", "web-02"]);
        // A UUID no VM has (a snapshot of another VM) is no clone either.
        let unregistered: Vec<VboxListedVm> = vms().into_iter().filter(|vm| vm.uuid != WEB02).collect();
        assert_eq!(names(&vbox_clones(GOLDEN, BASE, &media, &unregistered)), ["web-01"]);
    }

    #[test]
    fn reasons_name_the_vm_the_snapshot_and_the_clones() {
        let clones = vec![
            LinkedClone {
                name: "web-01".into(),
                key: r"C:\Users\alice\Documents\Virtual Machines\web-01\web-01.vmx".into(),
            },
            LinkedClone {
                name: "web-02".into(),
                key: WEB02.into(),
            },
        ];
        let found = vec![SnapshotClones {
            snapshot: "base".into(),
            uid: 1,
            clones: clones.clone(),
        }];
        assert_eq!(
            snapshot_reason(Some("golden"), &found),
            r"'golden': 2 linked clones depend on its snapshot 'base': web-01 (C:\Users\alice\Documents\Virtual Machines\web-01\web-01.vmx), web-02. Deleting the snapshot would break them, so it is not deleted: delete those clones first."
        );
        assert!(snapshot_reason(None, &found).starts_with("2 linked clones depend on the VM's snapshot 'base': "));
        let two = vec![
            found[0].clone(),
            SnapshotClones {
                snapshot: "v2".into(),
                uid: 2,
                clones: vec![clones[1].clone()],
            },
        ];
        let reason = vm_reason(Some("golden"), &two);
        assert!(reason.starts_with("'golden': 3 linked clones depend on its snapshots: 'base' (web-01 ("));
        assert!(reason.contains("; 'v2' (web-02)."));
        assert!(reason.contains("Deleting the VM would delete the disks they are made from"));
        let one = vec![SnapshotClones {
            snapshot: "v2".into(),
            uid: 2,
            clones: vec![clones[1].clone()],
        }];
        assert!(vm_reason(None, &one).starts_with("1 linked clone depends on the VM's snapshots: 'v2' (web-02)."));

        let many: Vec<LinkedClone> = (0..12)
            .map(|n| LinkedClone {
                name: format!("lab{n:02}"),
                key: format!("5b1c0000-0000-4000-8000-0000000000{n:02}"),
            })
            .collect();
        assert!(clone_list(&many).ends_with("lab09, and 2 more"));
    }
}
