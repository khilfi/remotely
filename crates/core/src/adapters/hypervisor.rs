//! VM-18: which hypervisor runs a VM, and the one way the rest of the core reaches either of them.
//!
//! A VM's key (`vms.vmx_path`, [`crate::domain::TargetRef::Vm`]) is its .vmx path for VMware
//! Workstation and its UUID for Oracle VirtualBox. No .vmx path can be a UUID, so the key alone says
//! which adapter a call goes to; the inventory also saves the hypervisor with each VM, for the UI and
//! filters. Commands on the bus keep their meaning whatever the hypervisor, so the policy engine
//! rates them the same.
//!
//! [`Hypervisors`] holds both adapters. What both can do (snapshot trees and changes, the running
//! list) goes through it by key; what only one has (Workstation's library and .vmx files,
//! VirtualBox's `showvminfo`) is reached through [`Hypervisors::vmware`] and
//! [`Hypervisors::virtualbox`] by the modules that need it.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::virtualbox::VirtualBoxAdapter;
use super::vm_hardware::VmHardware;
use super::vmware::{path_key, SnapshotTree, VmwareAdapter};
use crate::command_bus::SnapshotOp;
use crate::error::{CoreError, Result};

/// The hypervisor that runs a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Hypervisor {
    /// VMware Workstation Pro, through vmrun and its files.
    #[default]
    Vmware,
    /// Oracle VirtualBox, through VBoxManage (VM-18).
    VirtualBox,
}

impl Hypervisor {
    pub const ALL: [Hypervisor; 2] = [Hypervisor::Vmware, Hypervisor::VirtualBox];

    pub fn as_str(self) -> &'static str {
        match self {
            Hypervisor::Vmware => "vmware",
            Hypervisor::VirtualBox => "virtualbox",
        }
    }

    /// Unknown values read as VMware, the only hypervisor before 0.4.0.
    pub fn parse(s: &str) -> Self {
        match s {
            "virtualbox" => Hypervisor::VirtualBox,
            _ => Hypervisor::Vmware,
        }
    }

    /// The hypervisor behind a VM key: a UUID is a VirtualBox VM, anything else a .vmx path.
    pub fn of_key(key: &str) -> Self {
        if virtualbox_key(key).is_some() {
            Hypervisor::VirtualBox
        } else {
            Hypervisor::Vmware
        }
    }

    /// What it is called in messages.
    pub fn label(self) -> &'static str {
        match self {
            Hypervisor::Vmware => "VMware Workstation",
            Hypervisor::VirtualBox => "VirtualBox",
        }
    }

    /// The tools in the guest that report its IP address and shut it down gracefully.
    pub fn tools_name(self) -> &'static str {
        match self {
            Hypervisor::Vmware => "VMware Tools",
            Hypervisor::VirtualBox => "Guest Additions",
        }
    }
}

/// A VirtualBox VM's key: its UUID in lower case without braces, as `VBoxManage` prints it.
/// `None` for anything that is not a UUID (a .vmx path, a name).
pub fn virtualbox_key(text: &str) -> Option<String> {
    let text = text.trim();
    let bare = text.strip_prefix('{').and_then(|t| t.strip_suffix('}')).unwrap_or(text);
    // Only the hyphenated form VirtualBox uses; `Uuid::parse_str` also takes 32 bare hex digits,
    // which a file name could be.
    if bare.len() != 36 {
        return None;
    }
    Uuid::parse_str(bare).ok().map(|id| id.hyphenated().to_string())
}

/// Both hypervisors' adapters. Cheap to clone; each module that reads or changes VMs holds one.
#[derive(Clone)]
pub struct Hypervisors {
    vmware: Arc<dyn VmwareAdapter>,
    virtualbox: Arc<dyn VirtualBoxAdapter>,
}

/// The VMs running now, asked of each hypervisor (VM-07, AP-02). Each side fails on its own.
pub struct RunningVms {
    /// .vmx paths from `vmrun list`.
    pub vmware: Result<Vec<String>>,
    /// UUIDs from `VBoxManage list runningvms`; empty when VirtualBox is not installed.
    pub virtualbox: Result<Vec<String>>,
}

impl RunningVms {
    /// Whether the VM with this key is running, when its hypervisor could be asked.
    pub fn contains(&self, key: &str) -> Option<bool> {
        let list = match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.vmware.as_ref().ok()?,
            Hypervisor::VirtualBox => self.virtualbox.as_ref().ok()?,
        };
        let key = path_key(Path::new(key));
        Some(list.iter().any(|k| path_key(Path::new(k)) == key))
    }
}

impl Hypervisors {
    pub fn new(vmware: Arc<dyn VmwareAdapter>, virtualbox: Arc<dyn VirtualBoxAdapter>) -> Self {
        Self { vmware, virtualbox }
    }

    pub fn vmware(&self) -> &Arc<dyn VmwareAdapter> {
        &self.vmware
    }

    pub fn virtualbox(&self) -> &Arc<dyn VirtualBoxAdapter> {
        &self.virtualbox
    }

    /// VM-04, VM-05: take, revert to or delete a snapshot. Only the job runner calls this.
    pub async fn snapshot(&self, key: &str, op: &SnapshotOp) -> Result<()> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.vmware.snapshot(Path::new(key), op).await,
            Hypervisor::VirtualBox => self.virtualbox.snapshot(key, op).await,
        }
    }

    /// VM-04: the VM's snapshot tree with creation times (VMware's .vmsd, VirtualBox's
    /// `showvminfo` and .vbox file).
    pub async fn snapshots(&self, key: &str) -> Result<SnapshotTree> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.vmware.snapshots(Path::new(key)).await,
            Hypervisor::VirtualBox => self.virtualbox.snapshots(key).await,
        }
    }

    /// MO-13: the VM's virtual hardware (VMware's .vmx, VirtualBox's `showvminfo`) and each disk's sizes.
    pub async fn hardware(&self, key: &str) -> Result<VmHardware> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.vmware.hardware(Path::new(key)).await,
            Hypervisor::VirtualBox => self.virtualbox.hardware(key).await,
        }
    }

    /// Both hypervisors' running VMs. VirtualBox not being installed is an empty list, not a failure.
    pub async fn running(&self) -> RunningVms {
        let vmware = self
            .vmware
            .list_running()
            .await
            .map(|paths| paths.iter().map(|p| p.to_string_lossy().into_owned()).collect());
        let virtualbox = match self.virtualbox.list_running().await {
            Err(CoreError::VboxManageNotFound) => Ok(Vec::new()),
            other => other,
        };
        RunningVms { vmware, virtualbox }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uuid_key_is_a_virtualbox_vm_and_a_path_is_a_vmware_one() {
        let id = "3F0C1A2B-1111-4222-8333-444455556666";
        assert_eq!(Hypervisor::of_key(id), Hypervisor::VirtualBox);
        assert_eq!(Hypervisor::of_key(&format!("{{{id}}}")), Hypervisor::VirtualBox);
        assert_eq!(Hypervisor::of_key(r"C:\VMs\web01\web01.vmx"), Hypervisor::Vmware);
        assert_eq!(
            Hypervisor::of_key(r"C:\VMs\3f0c1a2b-1111-4222-8333-444455556666.vmx"),
            Hypervisor::Vmware,
            "a .vmx named like a UUID is still a path"
        );
        assert_eq!(
            Hypervisor::of_key("3f0c1a2b111142228333444455556666"),
            Hypervisor::Vmware,
            "VirtualBox always writes the hyphens"
        );
        assert_eq!(
            virtualbox_key(&format!(" {{{id}}} ")).as_deref(),
            Some("3f0c1a2b-1111-4222-8333-444455556666")
        );
    }

    #[test]
    fn hypervisor_names_round_trip() {
        for h in Hypervisor::ALL {
            assert_eq!(Hypervisor::parse(h.as_str()), h);
            assert_eq!(serde_json::to_value(h).unwrap(), h.as_str());
        }
        assert_eq!(Hypervisor::parse("something new"), Hypervisor::Vmware);
        assert_eq!(Hypervisor::VirtualBox.tools_name(), "Guest Additions");
    }
}
