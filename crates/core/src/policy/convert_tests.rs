//! CV-03, VM-17, CV-02 tier rules (docs/plan-0.5.md, "Approval tiers"): export, convert or inspect (reads the
//! source, writes new files only) is Low. A Prod-labelled VM's export moves up one, to Medium. Inspect and Verify
//! are reads, never commands. An import is a deploy (VmDeploy's rules, tested in deploy_tests.rs).

use super::*;
use crate::adapters::hypervisor::Hypervisor;
use crate::command_bus::Command;
use crate::convert::args::OvfVersion;
use crate::convert::formats::{DiskFormat, OutputKind};
use crate::convert::{ConvertSpec, ExportSpec, ExportTarget};
use crate::domain::{Environment, Target, TargetRef};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

pub(super) fn convert() -> (Command, Vec<Target>) {
    let spec = ConvertSpec {
        source: r"C:\Images\rocky.qcow2".into(),
        source_format: DiskFormat::Qcow2,
        output: r"C:\Images\rocky.vmdk".into(),
        kind: OutputKind::VmdkSparse,
        whole_megabytes: false,
    };
    let targets = vec![Target {
        target: spec.targets()[0].clone(),
        name: "rocky.vmdk".into(),
        environment: Environment::None,
        protected: false,
    }];
    (
        Command::ImageConvert {
            targets: spec.targets(),
            spec: Box::new(spec),
        },
        targets,
    )
}

pub(super) fn export(environment: Environment, protected: bool) -> (Command, Vec<Target>) {
    let spec = ExportSpec {
        vm_key: r"C:\VMs\web01\web01.vmx".into(),
        vm_name: "web01".into(),
        hypervisor: Hypervisor::Vmware,
        target: ExportTarget::Appliance {
            ova: true,
            version: OvfVersion::V1,
        },
        folder: r"C:\Exports".into(),
        name: "web01-ova".into(),
        disk_kind: None,
    };
    let targets = vec![Target {
        target: TargetRef::Vm {
            vmx_path: spec.vm_key.clone(),
        },
        name: "web01".into(),
        environment,
        protected,
    }];
    (
        Command::VmExport {
            targets: spec.targets(),
            spec: Box::new(spec),
        },
        targets,
    )
}

#[test]
fn a_conversion_is_low_and_runs_without_asking() {
    let (command, targets) = convert();
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::ImageConvert);
    assert_eq!(d.tier, Tier::Low);
    assert!(d.steps.is_empty());
    assert!(!safety_snapshot_applies(&command));
}

#[test]
fn an_export_is_low_and_a_prod_vms_is_medium() {
    let (command, targets) = export(Environment::Lab, false);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::VmExport);
    assert_eq!(d.tier, Tier::Low);
    assert!(d.steps.is_empty());
    // Its data leaves the VM: a Prod label moves it up one, to one confirm.
    let (command, targets) = export(Environment::Prod, false);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, [ApprovalStep::Confirm]);
    assert!(d.reasons.iter().any(|r| r == "a target is labelled Prod: low -> medium"), "{:?}", d.reasons);
    // The source is only read, so no safety snapshot.
    assert!(!safety_snapshot_applies(&command));
}

#[test]
fn a_protected_vm_is_not_exported() {
    let (command, targets) = export(Environment::Lab, true);
    let d = engine().evaluate(&command, &targets);
    assert!(d.targets.is_empty());
    assert_eq!(d.skipped.len(), 1);
}

#[test]
fn conversions_and_exports_are_refused_from_the_ui_and_while_presenting() {
    for (command, _) in [convert(), export(Environment::Lab, false)] {
        let err = command.check_from_ui().unwrap_err().to_string();
        assert!(err.contains("asks for the folder") || err.contains("where the new image goes"), "{err}");
        command.validate().unwrap();
        assert!(engine().check_read_only(true, &command).is_err());
        // A retry runs it again, on the same one target.
        let again = command.with_targets(command.targets().to_vec()).unwrap();
        assert_eq!(again, command);
        assert!(command.with_targets(Vec::new()).is_none());
    }
    // A command whose target isn't its spec's.
    let (command, _) = convert();
    let Command::ImageConvert { spec, .. } = command else {
        unreachable!()
    };
    let wrong = Command::ImageConvert {
        targets: vec![TargetRef::DiskImage {
            path: r"C:\Images\other.vmdk".into(),
        }],
        spec,
    };
    assert!(wrong.validate().is_err());
}
