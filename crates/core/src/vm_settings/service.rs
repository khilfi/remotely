//! VM-23, VM-24: what the shell asks of VM settings besides commands the UI builds: the commands that carry
//! a path of this PC (an ISO, a shared folder, an existing VM), built here from a dialog or a drop so no path
//! comes from the UI; and reads: guest OS types, a VirtualBox screenshot, and Open console.
//!
//! Open console opens the hypervisor's own window (`vmware.exe <vmx>`, `VirtualBoxVM --startvm <uuid>
//! --separate`). It changes nothing about the VM, so it is not a command on the bus and has no tier; it is
//! audited (`vm_console_opened`), because from that window the user can change anything in the VM outside
//! Remotely's approvals, and refused while presenting with the read-only lock on, for the same reason. A
//! stopped VirtualBox VM has no window to open: it starts with one, which is the power command (Low).

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;

use super::ops::{VmConfigEdit, VmDeviceOp, VmLifecycleOp};
use crate::adapters::hypervisor::{virtualbox_key, Hypervisor, Hypervisors};
use crate::adapters::virtualbox::VboxOsType;
use crate::command_bus::{Command, CommandBus, PowerOp, SubmitOutcome};
use crate::domain::{Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::store::{NewAuditEntry, Store};
use crate::untrusted::{path_refusal, read_capped, MAX_VM_CONFIG_BYTES};
use crate::workspaces::Current;

/// VM-24: what Open console did.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ConsoleOutcome {
    /// The hypervisor's window opened.
    Opened,
    /// A VirtualBox VM that was off starts with its window: a power command on the bus.
    Starting { outcome: Box<SubmitOutcome> },
}

/// VM-23: a guest OS type a VM can be set up for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestOsType {
    pub id: String,
    pub description: String,
}

/// VM-23: Workstation's `guestOS` ids for the guests field engineers meet most (Workstation 17 to 26). A
/// VM's own id is always offered too, so nothing it has is lost.
pub const WORKSTATION_GUEST_OS: &[(&str, &str)] = &[
    ("ubuntu-64", "Ubuntu 64-bit"),
    ("debian12-64", "Debian 12.x 64-bit"),
    ("debian11-64", "Debian 11.x 64-bit"),
    ("rhel9-64", "Red Hat Enterprise Linux 9 64-bit"),
    ("rhel8-64", "Red Hat Enterprise Linux 8 64-bit"),
    ("rockylinux-64", "Rocky Linux 64-bit"),
    ("almalinux-64", "AlmaLinux 64-bit"),
    ("sles15-64", "SUSE Linux Enterprise 15 64-bit"),
    ("other6xlinux-64", "Other Linux 6.x kernel 64-bit"),
    ("other5xlinux-64", "Other Linux 5.x kernel 64-bit"),
    ("freebsd14-64", "FreeBSD 14 64-bit"),
    ("windows11-64", "Windows 11 x64"),
    ("windows9-64", "Windows 10 x64"),
    ("windows2022srvNext-64", "Windows Server 2025"),
    ("windows2019srvNext-64", "Windows Server 2022"),
    ("windows2019srv-64", "Windows Server 2019"),
    ("other-64", "Other 64-bit"),
];

/// The VM settings the shell reaches (`Core.vm_settings`).
#[derive(Clone)]
pub struct VmSettings {
    /// FD-02: the workspace shown.
    current: Current,
    store: Store,
    hypervisors: Hypervisors,
    bus: Arc<CommandBus>,
}

fn vm_ref(key: &str) -> TargetRef {
    TargetRef::Vm {
        vmx_path: key.to_owned(),
    }
}

/// VM-24: the UUID in a `.vbox` file: `<Machine uuid="{...}"`.
pub fn vbox_file_uuid(xml: &str) -> Option<String> {
    let at = xml.find("<Machine")?;
    let tag = &xml[at..];
    let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
    let start = tag.find(" uuid=\"")? + " uuid=\"".len();
    let end = tag[start..].find('"')? + start;
    virtualbox_key(&tag[start..end])
}

impl VmSettings {
    pub fn new(current: Current, store: Store, hypervisors: Hypervisors, bus: Arc<CommandBus>) -> Self {
        Self {
            current,
            store,
            hypervisors,
            bus,
        }
    }

    /// VM-23: an ISO from a file dialog or a drop, into the VM's CD/DVD drive (`slot`, or its first).
    pub async fn attach_iso(&self, key: &str, path: &Path, slot: Option<String>) -> Result<SubmitOutcome> {
        let command = Command::VmDevice {
            targets: vec![vm_ref(key)],
            op: VmDeviceOp::AttachIso {
                slot,
                path: path.display().to_string(),
            },
        };
        self.bus.submit(&self.current.get(), command).await
    }

    /// VM-23: a folder from a folder dialog, shared with the VM as `name`.
    pub async fn add_shared_folder(&self, key: &str, name: &str, path: &Path, writable: bool) -> Result<SubmitOutcome> {
        let command = Command::VmConfig {
            targets: vec![vm_ref(key)],
            edit: VmConfigEdit::AddSharedFolder {
                name: name.to_owned(),
                host_path: path.display().to_string(),
                writable,
            },
        };
        self.bus.submit(&self.current.get(), command).await
    }

    /// VM-24: an existing VM from a file dialog: a `.vmx` joins the VMs Remotely lists, a `.vbox` is
    /// registered with VirtualBox. The VM is the command's target: a `.vmx` by its path, a `.vbox` by the
    /// UUID in it.
    pub async fn add_existing(&self, path: &Path) -> Result<SubmitOutcome> {
        if let Some(refusal) = path_refusal(path) {
            return Err(CoreError::InvalidInput(format!(
                "{} {}, so Remotely doesn't add it: copy the VM to this PC first.",
                path.display(),
                refusal.describe()
            )));
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let key = match ext.as_str() {
            "vmx" => crate::adapters::vmware::with_backslashes(path).display().to_string(),
            "vbox" => {
                let bytes = read_capped(path, MAX_VM_CONFIG_BYTES).await?;
                vbox_file_uuid(&String::from_utf8_lossy(&bytes)).ok_or_else(|| {
                    CoreError::InvalidInput(format!("{} is not a VirtualBox VM's settings file.", path.display()))
                })?
            }
            _ => {
                return Err(CoreError::InvalidInput(format!(
                    "{} is not a Workstation .vmx or a VirtualBox .vbox file.",
                    path.display()
                )))
            }
        };
        let command = Command::VmLifecycle {
            targets: vec![vm_ref(&key)],
            op: VmLifecycleOp::Register {
                path: if ext == "vmx" {
                    key.clone()
                } else {
                    path.display().to_string()
                },
            },
        };
        self.bus.submit(&self.current.get(), command).await
    }

    /// VM-23: whether Workstation's window (`vmware.exe`) runs, for the edit dialogs' warning that it may write its
    /// own copy of a VM's settings over a change. A read.
    pub async fn workstation_window_open(&self) -> bool {
        self.hypervisors.vmware().workstation_window_open().await
    }

    /// VM-23: the guest OS types the VM's hypervisor offers.
    pub async fn guest_os_types(&self, key: &str) -> Result<Vec<GuestOsType>> {
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => Ok(WORKSTATION_GUEST_OS
                .iter()
                .map(|(id, description)| GuestOsType {
                    id: (*id).to_owned(),
                    description: (*description).to_owned(),
                })
                .collect()),
            Hypervisor::VirtualBox => Ok(self
                .hypervisors
                .virtualbox()
                .os_types()
                .await?
                .into_iter()
                .map(|VboxOsType { id, description, .. }| GuestOsType { id, description })
                .collect()),
        }
    }

    /// VM-23: a running VirtualBox VM's screen, as PNG. A read: nothing changes and nothing is kept.
    pub async fn screenshot(&self, key: &str) -> Result<Vec<u8>> {
        if Hypervisor::of_key(key) != Hypervisor::VirtualBox {
            return Err(CoreError::VmSettingRefused(
                "Screenshots come from VirtualBox; for a Workstation VM, open its console.".into(),
            ));
        }
        let vbox = self.hypervisors.virtualbox();
        if !vbox.vm_info(key).await?.power_state().is_on() {
            return Err(CoreError::VmSettingRefused(
                "The VM is not running, so it has no screen to show.".into(),
            ));
        }
        vbox.screenshot(key).await
    }

    /// VM-23: [`Self::screenshot`] as a `data:image/png;base64,` URL for the UI to show.
    pub async fn screenshot_data_url(&self, key: &str) -> Result<String> {
        use base64::Engine;
        let png = self.screenshot(key).await?;
        Ok(format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(png)
        ))
    }

    /// VM-23: an ISO dropped on a VM: the one `.iso` among the dropped files.
    pub async fn attach_dropped_iso(&self, key: &str, paths: Vec<std::path::PathBuf>) -> Result<SubmitOutcome> {
        let isos: Vec<std::path::PathBuf> = paths
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("iso")))
            .collect();
        match isos.as_slice() {
            [iso] => self.attach_iso(key, iso, None).await,
            [] => Err(CoreError::InvalidInput(
                "Drop an ISO image (.iso) on a VM to attach it to its CD/DVD drive.".into(),
            )),
            _ => Err(CoreError::InvalidInput("Drop one ISO image at a time.".into())),
        }
    }

    /// VM-24: the hypervisor's own window on the VM (see the module's notes on why it is audited, not rated).
    pub async fn open_console(&self, key: &str) -> Result<ConsoleOutcome> {
        if self.store.read_only().is_locked() {
            return Err(CoreError::ReadOnlyLock {
                what: "Open a VM's console".into(),
            });
        }
        let vm = self
            .store
            .find_vm(&self.current.get(), key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(key.to_owned()))?;
        match Hypervisor::of_key(key) {
            Hypervisor::Vmware => self.hypervisors.vmware().open_console(Path::new(key)).await?,
            Hypervisor::VirtualBox => {
                let vbox = self.hypervisors.virtualbox();
                if !vbox.vm_info(key).await?.power_state().is_on() {
                    let command = Command::VmPower {
                        targets: vec![vm_ref(key)],
                        op: PowerOp::Start { gui: true },
                    };
                    let outcome = self.bus.submit(&self.current.get(), command).await?;
                    return Ok(ConsoleOutcome::Starting {
                        outcome: Box::new(outcome),
                    });
                }
                vbox.open_console(key).await?;
            }
        }
        let target = Target {
            target: vm_ref(key),
            name: vm.display_name.clone(),
            environment: vm.environment,
            protected: vm.protected,
        };
        let action = format!("Opened the console of VM '{}'", vm.display_name);
        self.store
            .append_audit(
                &self.current.get(),
                NewAuditEntry {
                    event: "vm_console_opened",
                    action: &action,
                    tier: None,
                    job_id: None,
                    targets: &[target],
                    approval: None,
                    result: None,
                    detail: Some(match Hypervisor::of_key(key) {
                        Hypervisor::Vmware => "Workstation's window, without powering the VM on",
                        Hypervisor::VirtualBox => "VirtualBox's window on the running VM",
                    }),
                },
            )
            .await?;
        Ok(ConsoleOutcome::Opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vbox_file_names_its_vm_by_uuid() {
        let xml = r#"<?xml version="1.0"?>
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-windows">
  <Machine uuid="{D1853388-A060-4EED-8BBE-CC2FE0ECC7E6}" name="it-web" OSType="Ubuntu_64">
    <Snapshot uuid="{5b1c0000-0000-4000-8000-000000000001}"/>
  </Machine>
</VirtualBox>"#;
        assert_eq!(
            vbox_file_uuid(xml).as_deref(),
            Some("d1853388-a060-4eed-8bbe-cc2fe0ecc7e6")
        );
        assert_eq!(vbox_file_uuid("<VirtualBox/>"), None);
    }
}
