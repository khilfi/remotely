//! VM-11: docs/plan-0.5.md's "Change NAT port forwards or a host network (affects every VM on it): High", one test
//! per rule. A network counts as Prod when a VM on it is ([`crate::host_networks::HostNetworks::target`]), so the
//! Prod rule moves it to Critical.

use super::*;
use crate::adapters::host_networks::ForwardProtocol;
use crate::adapters::hypervisor::Hypervisor;
use crate::command_bus::Command;
use crate::domain::{Environment, Target, TargetRef};
use crate::host_networks::{HostNetworkOp, NatForward};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn network(hypervisor: Hypervisor, name: &str, environment: Environment) -> Target {
    Target {
        target: TargetRef::Network {
            hypervisor,
            name: name.into(),
        },
        name: name.into(),
        environment,
        protected: false,
    }
}

fn vbox_vm(environment: Environment, protected: bool) -> Target {
    Target {
        target: TargetRef::Vm {
            vmx_path: "00000000-0000-4000-8000-0000000000aa".into(),
        },
        name: "lab01".into(),
        environment,
        protected,
    }
}

fn web() -> NatForward {
    NatForward {
        name: Some("web".into()),
        protocol: ForwardProtocol::Tcp,
        host_ip: None,
        host_port: 8080,
        guest_ip: Some("203.0.113.10".into()),
        guest_port: 80,
        slot: None,
    }
}

fn forward(op: HostNetworkOp, target: &Target) -> Command {
    Command::HostNetwork {
        targets: vec![target.target.clone()],
        op,
    }
}

fn add(target: &Target) -> Command {
    forward(HostNetworkOp::AddForward { forward: web() }, target)
}

fn remove(target: &Target) -> Command {
    forward(HostNetworkOp::RemoveForward { forward: web() }, target)
}

/// One command of each port forward kind, for the policy tests that cover every action.
pub(super) fn every_host_network_command() -> Vec<(Command, Vec<Target>)> {
    let vmnet = network(Hypervisor::Vmware, "vmnet8", Environment::None);
    vec![(add(&vmnet), vec![vmnet.clone()]), (remove(&vmnet), vec![vmnet])]
}

#[test]
fn adding_a_nat_port_forward_is_high_without_a_safety_snapshot() {
    for target in [
        network(Hypervisor::Vmware, "vmnet8", Environment::None),
        network(Hypervisor::VirtualBox, "lab-net", Environment::Lab),
        vbox_vm(Environment::Lab, false),
    ] {
        let decision = engine().evaluate(&add(&target), std::slice::from_ref(&target));
        assert_eq!(
            (decision.action, decision.tier),
            (ActionKind::NatForwardAdd, Tier::High),
            "{target:?}"
        );
        assert!(decision.steps.contains(&ApprovalStep::Reason));
        assert!(decision.steps.contains(&ApprovalStep::TypeTargetCount { expected: 1 }));
        // A snapshot of a guest doesn't undo a network's setting.
        assert!(!decision
            .steps
            .iter()
            .any(|s| matches!(s, ApprovalStep::SafetySnapshot { .. })));
    }
}

#[test]
fn removing_a_nat_port_forward_is_high() {
    let target = network(Hypervisor::VirtualBox, "lab-net", Environment::None);
    let decision = engine().evaluate(&remove(&target), std::slice::from_ref(&target));
    assert_eq!(
        (decision.action, decision.tier),
        (ActionKind::NatForwardRemove, Tier::High)
    );
}

#[test]
fn a_network_with_a_prod_vm_on_it_moves_up_to_critical() {
    let target = network(Hypervisor::Vmware, "vmnet8", Environment::Prod);
    let decision = engine().evaluate(&add(&target), std::slice::from_ref(&target));
    assert_eq!(decision.tier, Tier::Critical);
    assert!(decision.steps.contains(&ApprovalStep::VaultReauth));
}

#[test]
fn a_protected_vms_nat_rules_are_left_alone() {
    let target = vbox_vm(Environment::Lab, true);
    let decision = engine().evaluate(&add(&target), std::slice::from_ref(&target));
    assert!(decision.targets.is_empty());
    assert_eq!(decision.skipped.len(), 1);
}

#[test]
fn the_tiers_can_be_edited_and_lowering_them_asks_for_the_vault_password() {
    let before = PolicyRules::default();
    let mut after = before.clone();
    after.tiers.insert(
        ActionKind::NatForwardAdd,
        TierRule {
            single: Tier::Medium,
            bulk: Tier::Medium,
        },
    );
    let engine = PolicyEngine::new(after.clone()).expect("valid");
    let target = network(Hypervisor::Vmware, "vmnet8", Environment::None);
    assert_eq!(engine.evaluate(&add(&target), &[target.clone()]).tier, Tier::Medium);
    assert!(before
        .loosened(&after)
        .iter()
        .any(|l| l.contains("Add a NAT port forward")));
}

#[test]
fn the_read_only_lock_refuses_port_forwards() {
    let target = network(Hypervisor::Vmware, "vmnet8", Environment::None);
    let err = engine().check_read_only(true, &remove(&target)).unwrap_err();
    assert!(err.to_string().contains("Remove a NAT port forward"), "{err}");
    assert!(engine().check_read_only(false, &remove(&target)).is_ok());
}

#[test]
fn saved_rules_from_before_get_the_new_tiers() {
    let mut old = PolicyRules::default();
    old.tiers.remove(&ActionKind::NatForwardAdd);
    old.tiers.remove(&ActionKind::NatForwardRemove);
    assert!(old.validate().is_err());
    old.fill_missing_tiers();
    assert_eq!(old.tiers[&ActionKind::NatForwardAdd].single, Tier::High);
    assert_eq!(old.tiers[&ActionKind::NatForwardRemove].bulk, Tier::High);
}
