//! VM-11, VM-12, VM-15, VM-16, VM-23, VM-24: the rows docs/plan-0.5.md's "Approval tiers" adds to the PRD's
//! tier table, one test per rule. A Prod-labelled VM moves each up one tier; protected VMs are skipped.

use super::*;
use crate::command_bus::Command;
use crate::domain::{Environment, Target, TargetRef};
use crate::vm_settings::{Firmware, NicNetwork, VmConfigEdit, VmDeviceOp, VmDiskOp, VmLifecycleOp};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn vm(n: usize, environment: Environment) -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: format!(r"C:\VMs\vm{n}\vm{n}.vmx"),
        },
        name: format!("vm{n}"),
        environment,
        protected: false,
    }
}

fn lab(count: usize) -> Vec<Target> {
    (0..count).map(|n| vm(n, Environment::Lab)).collect()
}

fn refs(targets: &[Target]) -> Vec<TargetRef> {
    targets.iter().map(|t| t.target.clone()).collect()
}

fn config(edit: VmConfigEdit, targets: &[Target]) -> Command {
    Command::VmConfig {
        targets: refs(targets),
        edit,
    }
}

fn device(op: VmDeviceOp, targets: &[Target]) -> Command {
    Command::VmDevice {
        targets: refs(targets),
        op,
    }
}

fn disk(op: VmDiskOp, targets: &[Target]) -> Command {
    Command::VmDisk {
        targets: refs(targets),
        op,
    }
}

fn lifecycle(op: VmLifecycleOp, targets: &[Target]) -> Command {
    Command::VmLifecycle {
        targets: refs(targets),
        op,
    }
}

fn resize() -> VmConfigEdit {
    VmConfigEdit::Resources {
        vcpus: Some(4),
        cores_per_socket: None,
        memory_mb: Some(8192),
        nested_virtualization: None,
    }
}

fn tier(command: &Command, targets: &[Target]) -> Tier {
    engine().evaluate(command, targets).tier
}

/// One command of every VM settings kind, for the policy tests that cover every action.
pub(super) fn every_vm_settings_command() -> Vec<(Command, Vec<Target>)> {
    let one = lab(1);
    let iso = VmDeviceOp::AttachIso {
        slot: None,
        path: r"C:\ISOs\ubuntu.iso".into(),
    };
    vec![
        (config(resize(), &one), one.clone()),
        (config(VmConfigEdit::UpgradeHardware, &one), one.clone()),
        (device(iso, &one), one.clone()),
        (
            device(
                VmDeviceOp::ConnectNic {
                    slot: "ethernet0".into(),
                },
                &one,
            ),
            one.clone(),
        ),
        (
            device(
                VmDeviceOp::DisconnectNic {
                    slot: "ethernet0".into(),
                },
                &one,
            ),
            one.clone(),
        ),
        (device(VmDeviceOp::InstallTools, &one), one.clone()),
        (
            disk(
                VmDiskOp::Add {
                    size_mb: 20 * 1024,
                    thin: true,
                    bus: None,
                },
                &one,
            ),
            one.clone(),
        ),
        (disk(VmDiskOp::Compact { slot: "scsi0:0".into() }, &one), one.clone()),
        (
            disk(
                VmDiskOp::Expand {
                    slot: "scsi0:0".into(),
                    size_mb: 60 * 1024,
                },
                &one,
            ),
            one.clone(),
        ),
        (disk(VmDiskOp::Remove { slot: "scsi0:1".into() }, &one), one.clone()),
        (lifecycle(VmLifecycleOp::Delete, &one), one.clone()),
        (
            lifecycle(
                VmLifecycleOp::Register {
                    path: r"C:\VMs\vm0\vm0.vmx".into(),
                },
                &one,
            ),
            one.clone(),
        ),
    ]
}

#[test]
fn editing_settings_of_a_vm_that_is_off_is_medium_and_a_bulk_resize_is_one_confirm() {
    for n in [1, 2, 20] {
        let vms = lab(n);
        let decision = engine().evaluate(&config(resize(), &vms), &vms);
        assert_eq!(decision.action, ActionKind::VmConfigure);
        assert_eq!(decision.tier, Tier::Medium, "{n} VMs");
        assert_eq!(decision.steps, [ApprovalStep::Confirm]);
    }
    for edit in [
        VmConfigEdit::Firmware {
            firmware: Firmware::Efi,
            secure_boot: true,
            tpm: None,
        },
        VmConfigEdit::Rename { name: "web02".into() },
        VmConfigEdit::GuestOs {
            os_type: "ubuntu-64".into(),
        },
        VmConfigEdit::AddNic {
            network: NicNetwork::Nat,
            model: None,
        },
        VmConfigEdit::RemoveNic {
            slot: "ethernet1".into(),
        },
        VmConfigEdit::RemoveSharedFolder { name: "data".into() },
    ] {
        assert_eq!(tier(&config(edit.clone(), &lab(1)), &lab(1)), Tier::Medium, "{edit:?}");
    }
}

#[test]
fn a_hardware_upgrade_is_high_and_offers_a_safety_snapshot() {
    let one = lab(1);
    let command = config(VmConfigEdit::UpgradeHardware, &one);
    let decision = engine().evaluate(&command, &one);
    assert_eq!(
        (decision.action, decision.tier),
        (ActionKind::VmUpgradeHardware, Tier::High)
    );
    assert!(decision
        .steps
        .contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    assert!(decision.reasons.iter().any(|r| r.contains("can't be undone")));
}

#[test]
fn isos_and_connecting_a_cable_are_low() {
    let two = lab(2);
    let iso = device(
        VmDeviceOp::AttachIso {
            slot: None,
            path: r"C:\ISOs\x.iso".into(),
        },
        &two,
    );
    assert_eq!(tier(&iso, &two), Tier::Low);
    assert_eq!(
        tier(&device(VmDeviceOp::EjectIso { slot: None }, &two), &two),
        Tier::Low
    );
    let connect = device(
        VmDeviceOp::ConnectNic {
            slot: "ethernet0".into(),
        },
        &two,
    );
    assert_eq!(engine().evaluate(&connect, &two).steps, Vec::<ApprovalStep>::new());
}

#[test]
fn disconnecting_a_cable_is_medium_and_critical_in_bulk() {
    let cut = |targets: &[Target]| {
        device(
            VmDeviceOp::DisconnectNic {
                slot: "ethernet0".into(),
            },
            targets,
        )
    };
    assert_eq!(tier(&cut(&lab(1)), &lab(1)), Tier::Medium);
    // The PRD: a bulk network disconnect is Critical.
    let decision = engine().evaluate(&cut(&lab(2)), &lab(2));
    assert_eq!(decision.tier, Tier::Critical);
    assert!(decision.steps.contains(&ApprovalStep::VaultReauth));
    assert!(
        !decision
            .steps
            .iter()
            .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
        "a snapshot keeps nothing a cable changes"
    );
}

#[test]
fn installing_tools_adding_and_compacting_disks_are_medium() {
    let one = lab(1);
    assert_eq!(tier(&device(VmDeviceOp::InstallTools, &one), &one), Tier::Medium);
    let add = disk(
        VmDiskOp::Add {
            size_mb: 1024,
            thin: true,
            bus: None,
        },
        &one,
    );
    assert_eq!(tier(&add, &one), Tier::Medium);
    assert_eq!(
        tier(&disk(VmDiskOp::Compact { slot: "scsi0:0".into() }, &one), &one),
        Tier::Medium
    );
    let defrag = disk(VmDiskOp::Defragment { slot: "scsi0:0".into() }, &one);
    assert_eq!(engine().classify(&defrag), ActionKind::VmDiskCompact);
}

#[test]
fn expanding_a_disk_is_high_without_a_safety_snapshot() {
    let one = lab(1);
    let expand = disk(
        VmDiskOp::Expand {
            slot: "scsi0:0".into(),
            size_mb: 60 * 1024,
        },
        &one,
    );
    let decision = engine().evaluate(&expand, &one);
    assert_eq!(decision.tier, Tier::High);
    // A disk can't be expanded under snapshots, so taking one first would refuse the expand itself.
    assert!(!decision
        .steps
        .iter()
        .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    assert!(decision.reasons.iter().any(|r| r.contains("can't be shrunk back")));
}

#[test]
fn removing_a_disk_and_deleting_vms_are_critical() {
    let one = lab(1);
    let remove = disk(VmDiskOp::Remove { slot: "scsi0:1".into() }, &one);
    let decision = engine().evaluate(&remove, &one);
    assert_eq!(decision.tier, Tier::Critical);
    assert!(decision.steps.contains(&ApprovalStep::VaultReauth));
    assert!(decision.reasons.iter().any(|r| r.contains("files are deleted")));
    let three = lab(3);
    let delete = lifecycle(VmLifecycleOp::Delete, &three);
    let decision = engine().evaluate(&delete, &three);
    assert_eq!((decision.action, decision.tier), (ActionKind::VmDelete, Tier::Critical));
    assert!(decision.steps.contains(&ApprovalStep::TypeTargetCount { expected: 3 }));
    assert!(!decision
        .steps
        .iter()
        .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
}

#[test]
fn adding_an_existing_vm_is_low() {
    let one = lab(1);
    let add = lifecycle(
        VmLifecycleOp::Register {
            path: r"C:\VMs\vm0\vm0.vmx".into(),
        },
        &one,
    );
    assert_eq!(tier(&add, &one), Tier::Low);
}

#[test]
fn prod_raises_each_one_tier() {
    let prod = vec![vm(0, Environment::Prod)];
    let cases = [
        (config(resize(), &prod), Tier::High),
        (config(VmConfigEdit::UpgradeHardware, &prod), Tier::Critical),
        (device(VmDeviceOp::EjectIso { slot: None }, &prod), Tier::Medium),
        (
            device(
                VmDeviceOp::DisconnectNic {
                    slot: "ethernet0".into(),
                },
                &prod,
            ),
            Tier::High,
        ),
        (device(VmDeviceOp::InstallTools, &prod), Tier::High),
        (disk(VmDiskOp::Compact { slot: "scsi0:0".into() }, &prod), Tier::High),
        (lifecycle(VmLifecycleOp::Delete, &prod), Tier::Critical),
    ];
    for (command, want) in cases {
        assert_eq!(tier(&command, &prod), want, "{command:?}");
    }
    // A Prod settings change is High, and its safety snapshot undoes it.
    let decision = engine().evaluate(&config(resize(), &prod), &prod);
    assert!(decision
        .steps
        .contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    // A rename has nothing for a snapshot to undo.
    let rename = config(VmConfigEdit::Rename { name: "web02".into() }, &prod);
    assert!(!safety_snapshot_applies(&rename));
}

#[test]
fn protected_vms_are_skipped() {
    let mut vms = lab(2);
    vms[1].protected = true;
    let decision = engine().evaluate(&lifecycle(VmLifecycleOp::Delete, &vms), &vms);
    assert_eq!(decision.targets.len(), 1);
    assert_eq!(decision.skipped.len(), 1);
    assert_eq!(
        decision.steps.iter().find_map(|s| match s {
            ApprovalStep::TypeTargetCount { expected } => Some(*expected),
            _ => None,
        }),
        Some(1)
    );
}

#[test]
fn every_vm_settings_kind_is_refused_under_the_read_only_lock() {
    let engine = engine();
    for (command, _) in every_vm_settings_command() {
        let err = engine.check_read_only(true, &command).expect_err("locked");
        assert_eq!(err.code(), "read_only_lock");
        assert!(engine.check_read_only(false, &command).is_ok());
    }
}

#[test]
fn the_ui_cant_name_a_file_or_folder_of_this_pc() {
    let one = lab(1);
    let iso = device(
        VmDeviceOp::AttachIso {
            slot: None,
            path: r"C:\Users\alice\.ssh\id_ed25519.iso".into(),
        },
        &one,
    );
    assert!(iso.check_from_ui().is_err());
    let share = config(
        VmConfigEdit::AddSharedFolder {
            name: "home".into(),
            host_path: r"C:\Users\alice".into(),
            writable: false,
        },
        &one,
    );
    assert!(share.check_from_ui().is_err());
    let add = lifecycle(
        VmLifecycleOp::Register {
            path: r"C:\VMs\vm0\vm0.vmx".into(),
        },
        &one,
    );
    assert!(add.check_from_ui().is_err());
    assert!(add.with_targets(refs(&lab(2))).is_none(), "an added VM is its file");
    assert!(config(resize(), &one).check_from_ui().is_ok());
    assert!(lifecycle(VmLifecycleOp::Delete, &one).check_from_ui().is_ok());
}
