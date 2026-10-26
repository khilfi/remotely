//! VM-08 tier rules (docs/plan-0.5.md, "Approval tiers"): a stack's deploy is a deploy of all its VMs (Medium for 1
//! to 4, High for 5 or more or Prod); starting, shutting down or suspending an instance is the power action's own
//! tier on its VMs; tearing one down is Critical. Protected VMs are skipped, and the read-only lock refuses them all.

use super::*;
use crate::adapters::hypervisor::Hypervisor;
use crate::command_bus::Command;
use crate::deploy::spec::tests::{cloud, plan};
use crate::deploy::{DeployOrigin, DeploySpec};
use crate::domain::{Environment, Target, TargetRef};
use crate::stacks::{
    KeptVm, NamedVm, PowerStep, Readiness, StackDeploySpec, StackPowerSpec, StackStepRun, StackTag, StackTeardownSpec,
};
use uuid::Uuid;

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

const INSTANCE: Uuid = Uuid::from_u128(42);

/// A step of `count` VMs named `<prefix>-<n>`.
fn step(prefix: &str, count: u32, index: u32, environment: Environment) -> StackStepRun {
    let mut spec = DeploySpec::from_plan(
        &plan(cloud(), "ubuntu", Hypervisor::Vmware, count),
        DeployOrigin::Custom { name: prefix.into() },
        r"C:\VMs\lab".into(),
        None,
    );
    for vm in &mut spec.vms {
        vm.name = format!("{prefix}-{}", vm.number);
        vm.hostname = vm.name.clone();
    }
    spec.environment = environment;
    spec.stack = Some(StackTag {
        instance_id: INSTANCE,
        step: index,
    });
    StackStepRun {
        label: prefix.into(),
        template_id: Uuid::from_u128(u128::from(index) + 1),
        spec,
        readiness: Readiness::Tools,
        ready_timeout_secs: 600,
        delay_secs: 0,
    }
}

fn resolved(targets: &[TargetRef], environment: Environment) -> Vec<Target> {
    targets
        .iter()
        .map(|target| Target {
            name: match target {
                TargetRef::NewVm { name, .. } => name.clone(),
                other => other.key(),
            },
            target: target.clone(),
            environment,
            protected: false,
        })
        .collect()
}

/// A stack deploy of `db` VMs then `web` VMs.
fn stack_deploy(db: u32, web: u32, environment: Environment) -> (Command, Vec<Target>) {
    let spec = StackDeploySpec {
        stack_id: Uuid::from_u128(7),
        stack_name: "web lab".into(),
        instance_id: INSTANCE,
        instance_name: "web lab 1".into(),
        steps: vec![step("db", db, 0, environment), step("web", web, 1, environment)],
    };
    spec.validate().expect("a valid stack deploy");
    let targets = spec.targets();
    let resolved = resolved(&targets, environment);
    (
        Command::Stack {
            targets,
            op: StackOp::Deploy { spec: Box::new(spec) },
        },
        resolved,
    )
}

fn vm(name: &str) -> TargetRef {
    TargetRef::Vm {
        vmx_path: format!(r"C:\VMs\lab\{name}\{name}.vmx"),
    }
}

fn instance_power(op: PowerOp, names: &[&str], environment: Environment) -> (Command, Vec<Target>) {
    let spec = StackPowerSpec {
        instance_id: INSTANCE,
        instance_name: "web lab 1".into(),
        op,
        steps: vec![PowerStep {
            label: "web".into(),
            vms: names.iter().map(|n| vm(n).key()).collect(),
            ready: names
                .iter()
                .map(|n| NamedVm {
                    key: vm(n).key(),
                    name: (*n).into(),
                })
                .collect(),
            readiness: Readiness::None,
            ready_timeout_secs: 600,
            delay_secs: 0,
        }],
    };
    let targets = spec.targets();
    let resolved = resolved(&targets, environment);
    (
        Command::Stack {
            targets,
            op: StackOp::Power { spec: Box::new(spec) },
        },
        resolved,
    )
}

fn teardown(names: &[&str], environment: Environment, kept: usize) -> (Command, Vec<Target>) {
    let targets: Vec<TargetRef> = names.iter().map(|n| vm(n)).collect();
    let resolved = resolved(&targets, environment);
    (
        Command::Stack {
            targets,
            op: StackOp::Teardown {
                spec: Box::new(StackTeardownSpec {
                    instance_id: INSTANCE,
                    instance_name: "web lab 1".into(),
                    stack_name: "web lab".into(),
                    kept: (0..kept)
                        .map(|i| KeptVm {
                            key: format!("k{i}"),
                            name: format!("hand-{i}"),
                            why: "added to the instance by hand".into(),
                        })
                        .collect(),
                }),
            },
        },
        resolved,
    )
}

#[test]
fn a_stack_deploy_is_a_deploy_of_all_its_vms() {
    // 1 + 3 = 4 VMs: one confirm.
    let (command, targets) = stack_deploy(1, 3, Environment::Lab);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::VmDeploy);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, [ApprovalStep::Confirm]);
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("stack 'web lab': 4 new VMs in 2 step(s)")),
        "{:?}",
        d.reasons
    );
    // 1 + 4 = 5: the deploy's bulk tier, which counts the whole stack.
    let (command, targets) = stack_deploy(1, 4, Environment::Lab);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::High);
    assert!(d.steps.contains(&ApprovalStep::TypeTargetCount { expected: 5 }));
    assert!(
        !d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
        "nothing to snapshot: the VMs don't exist yet"
    );
    assert!(!safety_snapshot_applies(&command));
}

#[test]
fn a_prod_stack_deploy_moves_up_one() {
    let (command, targets) = stack_deploy(1, 1, Environment::Prod);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::High);
    assert!(d.reasons.iter().any(|r| r.contains("labelled Prod")), "{:?}", d.reasons);
}

#[test]
fn starting_or_stopping_an_instance_is_the_power_actions_own_tier() {
    let start = PowerOp::Start { gui: false };
    let stop = PowerOp::Stop { mode: StopMode::Soft };
    // Start: Low, as VM-02's start is.
    let (command, targets) = instance_power(start, &["web-1", "web-2"], Environment::Lab);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::VmStart);
    assert_eq!(d.tier, Tier::Low);
    assert!(d.steps.is_empty());
    assert!(
        d.reasons.iter().any(|r| r.contains("started in boot order")),
        "{:?}",
        d.reasons
    );
    // Shut down: one VM Medium, two the bulk tier with the safety snapshot offered (VM-05).
    let (command, targets) = instance_power(stop, &["web-1"], Environment::Lab);
    let d = engine().evaluate(&command, &targets);
    assert_eq!((d.action, d.tier), (ActionKind::VmStopSoft, Tier::Medium));
    let (command, targets) = instance_power(stop, &["web-1", "web-2"], Environment::Lab);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::High);
    assert!(d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    assert!(safety_snapshot_applies(&command));
    assert!(
        d.reasons.iter().any(|r| r.contains("last step first")),
        "{:?}",
        d.reasons
    );
    // Suspend, as VM-02's.
    let (command, targets) = instance_power(PowerOp::Suspend, &["web-1"], Environment::Lab);
    assert_eq!(engine().classify(&command), ActionKind::VmSuspend);
    assert_eq!(
        engine().evaluate(&command, &targets).tier,
        engine()
            .evaluate(
                &Command::VmPower {
                    targets: vec![vm("web-1")],
                    op: PowerOp::Suspend
                },
                &targets
            )
            .tier
    );
}

#[test]
fn tearing_down_an_instance_is_critical_even_for_one_vm() {
    for names in [vec!["web-1"], vec!["db-1", "web-1", "web-2"]] {
        let (command, targets) = teardown(&names, Environment::Lab, 1);
        let d = engine().evaluate(&command, &targets);
        assert_eq!(d.action, ActionKind::StackTeardown);
        assert_eq!(d.tier, Tier::Critical, "{names:?}");
        assert_eq!(d.steps.last(), Some(&ApprovalStep::VaultReauth));
        assert!(
            !d.steps.iter().any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })),
            "the VMs go with their snapshots"
        );
        assert!(
            d.reasons.iter().any(|r| r.contains("deleted with their files")),
            "{:?}",
            d.reasons
        );
        assert!(
            d.reasons.iter().any(|r| r.contains("1 VM(s) of the instance are kept")),
            "{:?}",
            d.reasons
        );
    }
    assert_eq!(
        PolicyRules::default().tiers[&ActionKind::StackTeardown],
        TierRule::same(Tier::Critical)
    );
}

#[test]
fn a_teardown_skips_protected_vms() {
    let (command, mut targets) = teardown(&["db-1", "web-1"], Environment::Lab, 0);
    targets[0].protected = true;
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.targets.len(), 1);
    assert_eq!(d.skipped.len(), 1);
    assert_eq!(d.skipped[0].name, targets[0].name);
    assert_eq!(d.tier, Tier::Critical);
}

#[test]
fn the_read_only_lock_refuses_every_stack_command() {
    for (command, _) in [
        stack_deploy(1, 1, Environment::Lab),
        instance_power(PowerOp::Start { gui: false }, &["web-1"], Environment::Lab),
        teardown(&["web-1"], Environment::Lab, 0),
    ] {
        let err = engine().check_read_only(true, &command).unwrap_err();
        assert_eq!(err.code(), "read_only_lock");
        engine().check_read_only(false, &command).unwrap();
    }
}

#[test]
fn stack_commands_are_built_by_the_core_only() {
    let (command, _) = stack_deploy(1, 1, Environment::Lab);
    assert!(command.check_from_ui().is_err());
    command.validate().unwrap();
    // A target that isn't the spec's is refused.
    let Command::Stack { op, mut targets } = command else {
        unreachable!()
    };
    targets.pop();
    assert!(Command::Stack { targets, op }.validate().is_err());
    // A stop of a hard kind isn't an instance's.
    let (command, _) = instance_power(PowerOp::Stop { mode: StopMode::Hard }, &["web-1"], Environment::Lab);
    assert!(command.validate().is_err());
}

/// FD-03: one stack command of each kind, for the read-only lock's test of every action.
pub(super) fn every_stack_command() -> Vec<(Command, Vec<Target>)> {
    vec![
        stack_deploy(1, 1, Environment::Lab),
        instance_power(PowerOp::Start { gui: false }, &["web-1"], Environment::Lab),
        teardown(&["web-1"], Environment::Lab, 0),
    ]
}
