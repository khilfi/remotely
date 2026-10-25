//! VM-19 OS profiles: what a new VM's hardware depends on its guest for. Each profile sets the firmware (BIOS, EFI,
//! or EFI with Secure Boot), and for each hypervisor the disk controller, the network card, the guest OS type and
//! (Workstation) the hardware version. Images name their profile; a deploy (R2) takes these values, and a size
//! changes only CPU, RAM and disks.
//!
//! * Workstation's values are its own `.vmx` ones: `guestOS` (`ubuntu-64`), `virtualHW.version` (20, which
//!   Workstation 17.0 and later run), `scsiX.virtualDev` for SCSI (`pvscsi`), `ethernetN.virtualDev` (`vmxnet3` for
//!   Linux, `e1000e` for Windows, whose own drivers know it without VMware Tools).
//! * VirtualBox's are VBoxManage's: `--ostype` ids (`Ubuntu_64`), `storagectl --controller` (`IntelAhci`),
//!   `--nictype` (`virtio` for Linux, `82540EM` for Windows and other Linux), and `--tpm-type 2.0` for Windows 11.
//! * Windows 11 runs on VirtualBox only in 0.5.0 (its own vTPM and Secure Boot): Workstation's vTPM needs the VM
//!   encrypted with a password per VM, which stays out for now (`docs/plan-0.5.md`, Decisions).
//!
//! Profiles are part of the app, not stored: an image names one by its id.

use serde::{Deserialize, Serialize};

use super::sizes::DiskController;
use crate::adapters::hypervisor::Hypervisor;

/// How the VM boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Firmware {
    Bios,
    Efi,
    /// EFI with Secure Boot on.
    EfiSecureBoot,
}

impl Firmware {
    pub fn label(self) -> &'static str {
        match self {
            Firmware::Bios => "BIOS",
            Firmware::Efi => "EFI",
            Firmware::EfiSecureBoot => "EFI with Secure Boot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GuestFamily {
    Linux,
    Windows,
}

/// A profile's values on VMware Workstation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkstationSpec {
    /// The `.vmx`'s `guestOS`.
    pub guest_os: &'static str,
    /// `virtualHW.version`.
    pub hardware_version: u32,
    pub controller: DiskController,
    /// `scsiX.virtualDev` when the controller is SCSI.
    pub scsi_adapter: Option<&'static str>,
    /// `ethernetN.virtualDev`.
    pub nic: &'static str,
}

/// A profile's values on VirtualBox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualBoxSpec {
    /// `createvm --ostype`.
    pub os_type: &'static str,
    pub controller: DiskController,
    /// `storagectl --controller`.
    pub controller_model: &'static str,
    /// `modifyvm --nictype1`.
    pub nic: &'static str,
    /// `modifyvm --tpm-type`, when the guest needs a TPM.
    pub tpm: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OsProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub family: GuestFamily,
    pub firmware: Firmware,
    /// `None`: not on Workstation; [`OsProfile::workstation_note`] says why.
    pub workstation: Option<WorkstationSpec>,
    pub virtualbox: VirtualBoxSpec,
    pub workstation_note: Option<&'static str>,
}

/// Why Windows 11 isn't on Workstation (yet).
pub const WINDOWS_11_ON_WORKSTATION: &str = "Windows 11 deploys on VirtualBox only in this version: it needs a TPM, and Workstation's virtual TPM needs each VM encrypted with its own password.";

/// The hardware version new Workstation VMs get: what Workstation 17.0 and later run.
pub const WORKSTATION_HARDWARE_VERSION: u32 = 20;

const fn linux_on_virtualbox(os_type: &'static str) -> VirtualBoxSpec {
    VirtualBoxSpec {
        os_type,
        controller: DiskController::Sata,
        controller_model: "IntelAhci",
        nic: "virtio",
        tpm: None,
    }
}

const fn linux_on_workstation(guest_os: &'static str) -> WorkstationSpec {
    WorkstationSpec {
        guest_os,
        hardware_version: WORKSTATION_HARDWARE_VERSION,
        controller: DiskController::Scsi,
        scsi_adapter: Some("pvscsi"),
        nic: "vmxnet3",
    }
}

const fn windows_on_workstation(guest_os: &'static str) -> WorkstationSpec {
    WorkstationSpec {
        guest_os,
        hardware_version: WORKSTATION_HARDWARE_VERSION,
        controller: DiskController::Nvme,
        scsi_adapter: None,
        nic: "e1000e",
    }
}

const fn windows_on_virtualbox(os_type: &'static str, tpm: Option<&'static str>) -> VirtualBoxSpec {
    VirtualBoxSpec {
        os_type,
        controller: DiskController::Sata,
        controller_model: "IntelAhci",
        nic: "82540EM",
        tpm,
    }
}

/// Every profile, in the order the image editor offers them.
pub fn profiles() -> [OsProfile; 7] {
    [
        OsProfile {
            id: "ubuntu",
            name: "Ubuntu",
            family: GuestFamily::Linux,
            firmware: Firmware::Efi,
            workstation: Some(linux_on_workstation("ubuntu-64")),
            virtualbox: linux_on_virtualbox("Ubuntu_64"),
            workstation_note: None,
        },
        OsProfile {
            id: "debian",
            name: "Debian",
            family: GuestFamily::Linux,
            firmware: Firmware::Efi,
            workstation: Some(linux_on_workstation("debian12-64")),
            virtualbox: linux_on_virtualbox("Debian_64"),
            workstation_note: None,
        },
        OsProfile {
            id: "rhel",
            name: "RHEL family (RHEL, Rocky, Alma)",
            family: GuestFamily::Linux,
            firmware: Firmware::Efi,
            workstation: Some(linux_on_workstation("rhel9-64")),
            virtualbox: linux_on_virtualbox("RedHat_64"),
            workstation_note: None,
        },
        OsProfile {
            id: "windows-server",
            name: "Windows Server",
            family: GuestFamily::Windows,
            firmware: Firmware::EfiSecureBoot,
            workstation: Some(windows_on_workstation("windows2019srvNext-64")),
            virtualbox: windows_on_virtualbox("Windows2022_64", None),
            workstation_note: None,
        },
        OsProfile {
            id: "windows-10",
            name: "Windows 10",
            family: GuestFamily::Windows,
            firmware: Firmware::Efi,
            workstation: Some(windows_on_workstation("windows9-64")),
            virtualbox: windows_on_virtualbox("Windows10_64", None),
            workstation_note: None,
        },
        OsProfile {
            id: "windows-11",
            name: "Windows 11",
            family: GuestFamily::Windows,
            firmware: Firmware::EfiSecureBoot,
            workstation: None,
            virtualbox: windows_on_virtualbox("Windows11_64", Some("2.0")),
            workstation_note: Some(WINDOWS_11_ON_WORKSTATION),
        },
        OsProfile {
            id: "other-linux",
            name: "Other Linux",
            family: GuestFamily::Linux,
            firmware: Firmware::Bios,
            workstation: Some(WorkstationSpec {
                guest_os: "other5xlinux-64",
                hardware_version: WORKSTATION_HARDWARE_VERSION,
                controller: DiskController::Sata,
                scsi_adapter: None,
                nic: "e1000e",
            }),
            virtualbox: VirtualBoxSpec {
                os_type: "Linux_64",
                controller: DiskController::Sata,
                controller_model: "IntelAhci",
                nic: "82540EM",
                tpm: None,
            },
            workstation_note: None,
        },
    ]
}

pub fn profile(id: &str) -> Option<OsProfile> {
    profiles().into_iter().find(|p| p.id == id)
}

impl OsProfile {
    /// Whether a VM with this profile deploys on `hypervisor`.
    pub fn runs_on(&self, hypervisor: Hypervisor) -> bool {
        match hypervisor {
            Hypervisor::Vmware => self.workstation.is_some(),
            Hypervisor::VirtualBox => true,
        }
    }

    /// Why it doesn't run on `hypervisor`, or `None` when it does.
    pub fn refusal(&self, hypervisor: Hypervisor) -> Option<&'static str> {
        if self.runs_on(hypervisor) {
            None
        } else {
            Some(
                self.workstation_note
                    .unwrap_or("This OS profile doesn't deploy on Workstation."),
            )
        }
    }

    /// The disk controller on `hypervisor`.
    pub fn controller(&self, hypervisor: Hypervisor) -> DiskController {
        match (hypervisor, self.workstation) {
            (Hypervisor::Vmware, Some(ws)) => ws.controller,
            _ => self.virtualbox.controller,
        }
    }
}

/// The profile a VM's own guest OS type suggests, for a golden VM image: Workstation's `guestOS` id (`ubuntu-64`) or
/// VirtualBox's OS type description ("Ubuntu (64-bit)"). `None` when nothing fits.
pub fn suggest(guest_os: &str) -> Option<&'static str> {
    let os = guest_os.to_ascii_lowercase();
    let has = |word: &str| os.contains(word);
    let id = if has("ubuntu") {
        "ubuntu"
    } else if has("debian") {
        "debian"
    } else if has("rhel")
        || has("red hat")
        || has("redhat")
        || has("rocky")
        || has("alma")
        || has("centos")
        || has("oracle")
    {
        "rhel"
    } else if has("srv") || has("server") || has("windows20") || has("windows 20") {
        "windows-server"
    } else if has("windows11") || has("windows 11") {
        "windows-11"
    } else if has("windows9") || has("windows10") || has("windows 10") {
        "windows-10"
    } else if has("linux") {
        "other-linux"
    } else {
        return None;
    };
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profiles_the_plan_names() {
        let ids: Vec<&str> = profiles().iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            [
                "ubuntu",
                "debian",
                "rhel",
                "windows-server",
                "windows-10",
                "windows-11",
                "other-linux"
            ]
        );
        for p in profiles() {
            // Network cards are the plan's: vmxnet3 or e1000e on Workstation, virtio or 82540EM on VirtualBox.
            if let Some(ws) = p.workstation {
                assert!(["vmxnet3", "e1000e"].contains(&ws.nic), "{}", p.id);
                assert_eq!(ws.hardware_version, 20, "{}", p.id);
                assert!(ws.guest_os.ends_with("-64"), "{}", p.id);
                assert_eq!(
                    ws.scsi_adapter.is_some(),
                    ws.controller == DiskController::Scsi,
                    "{}",
                    p.id
                );
            }
            assert!(["virtio", "82540EM"].contains(&p.virtualbox.nic), "{}", p.id);
            assert!(p.virtualbox.os_type.ends_with("_64"), "{}", p.id);
            assert!(p.runs_on(Hypervisor::VirtualBox));
            assert_eq!(profile(p.id), Some(p));
        }
        let ubuntu = profile("ubuntu").unwrap();
        assert_eq!(ubuntu.workstation.unwrap().guest_os, "ubuntu-64");
        assert_eq!(ubuntu.virtualbox.os_type, "Ubuntu_64");
        assert_eq!(ubuntu.controller(Hypervisor::Vmware), DiskController::Scsi);
        assert_eq!(ubuntu.controller(Hypervisor::VirtualBox), DiskController::Sata);
        let server = profile("windows-server").unwrap();
        assert_eq!(server.workstation.unwrap().nic, "e1000e");
        assert_eq!(server.virtualbox.nic, "82540EM");
        assert_eq!(profile("nope"), None);
    }

    #[test]
    fn windows_11_is_on_virtualbox_only_with_a_tpm_and_secure_boot() {
        let w11 = profile("windows-11").unwrap();
        assert_eq!(w11.firmware, Firmware::EfiSecureBoot);
        assert_eq!(w11.virtualbox.tpm, Some("2.0"));
        assert_eq!(w11.virtualbox.os_type, "Windows11_64");
        assert!(!w11.runs_on(Hypervisor::Vmware));
        assert_eq!(w11.refusal(Hypervisor::Vmware), Some(WINDOWS_11_ON_WORKSTATION));
        assert_eq!(w11.refusal(Hypervisor::VirtualBox), None);
        assert!(profiles()
            .iter()
            .filter(|p| p.id != "windows-11")
            .all(|p| p.runs_on(Hypervisor::Vmware)));
    }

    #[test]
    fn a_vms_guest_os_suggests_a_profile() {
        for (os, id) in [
            ("ubuntu-64", Some("ubuntu")),
            ("Ubuntu (64-bit)", Some("ubuntu")),
            ("debian12-64", Some("debian")),
            ("rhel9-64", Some("rhel")),
            ("Red Hat (64-bit)", Some("rhel")),
            ("windows2019srvNext-64", Some("windows-server")),
            ("Windows 2022 (64-bit)", Some("windows-server")),
            ("windows9-64", Some("windows-10")),
            ("Windows 10 (64-bit)", Some("windows-10")),
            ("windows11-64", Some("windows-11")),
            ("Windows 11 (64-bit)", Some("windows-11")),
            ("other5xlinux-64", Some("other-linux")),
            ("Other Linux (64-bit)", Some("other-linux")),
            ("freebsd-64", None),
        ] {
            assert_eq!(suggest(os), id, "{os}");
        }
    }
}
