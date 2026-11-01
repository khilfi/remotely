//! FD-09 tier rules (docs/plan-0.7.md, "Approval tiers"): Wake-on-LAN is Low, and a Prod-labelled target moves it up
//! one, to Medium. The toolbox's reads (ping, trace route, DNS, ports, certificates) are never commands.

use super::*;
use crate::command_bus::Command;
use crate::domain::{Environment, Target, TargetRef};
use crate::toolbox::{WakeDestination, WakeSpec};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn spec() -> WakeSpec {
    WakeSpec {
        mac: "00:0c:29:ab:cd:ef".into(),
        destination: WakeDestination::Address {
            address: "192.0.2.255".parse().expect("an address"),
        },
        port: 9,
    }
}

fn wake(target: TargetRef, environment: Environment, protected: bool) -> (Command, Vec<Target>) {
    let targets = vec![Target {
        target: target.clone(),
        name: "nas01".into(),
        environment,
        protected,
    }];
    (
        Command::WakeOnLan {
            targets: vec![target],
            wake: spec(),
        },
        targets,
    )
}

/// One wake-up, for the read-only lock's list of every command.
pub(super) fn wake_on_lan() -> (Command, Vec<Target>) {
    wake(TargetRef::App, Environment::None, false)
}

fn session() -> TargetRef {
    TargetRef::Session {
        session_id: uuid::Uuid::new_v4(),
    }
}

#[test]
fn a_wake_up_is_low_and_runs_without_asking() {
    for target in [
        session(),
        TargetRef::App,
        TargetRef::Vm {
            vmx_path: r"C:\VMs\nas01\nas01.vmx".into(),
        },
    ] {
        let (command, targets) = wake(target, Environment::Lab, false);
        let d = engine().evaluate(&command, &targets);
        assert_eq!(d.action, ActionKind::WakeOnLan);
        assert_eq!(d.tier, Tier::Low);
        assert!(d.steps.is_empty());
        assert!(!safety_snapshot_applies(&command));
    }
}

#[test]
fn a_prod_targets_wake_up_is_medium() {
    let (command, targets) = wake(session(), Environment::Prod, false);
    let d = engine().evaluate(&command, &targets);
    assert_eq!(d.tier, Tier::Medium);
    assert_eq!(d.steps, [ApprovalStep::Confirm]);
    assert!(
        d.reasons
            .iter()
            .any(|r| r == "a target is labelled Prod: low -> medium"),
        "{:?}",
        d.reasons
    );
}

#[test]
fn a_protected_target_is_not_woken() {
    let (command, targets) = wake(session(), Environment::Lab, true);
    let d = engine().evaluate(&command, &targets);
    assert!(d.targets.is_empty());
    assert_eq!(d.skipped.len(), 1);
}

#[test]
fn a_wake_up_is_refused_while_presenting_and_never_retried_elsewhere() {
    let (command, _) = wake(session(), Environment::Lab, false);
    command.validate().expect("valid");
    command.check_from_ui().expect("the UI may send it");
    assert!(engine().check_read_only(true, &command).is_err());
    assert!(command.with_targets(vec![TargetRef::App]).is_none());
    assert_eq!(command.summary(1), "Wake up 00:0c:29:ab:cd:ef (to 192.0.2.255, port 9)");
}

#[test]
fn a_wake_up_has_one_target_and_a_real_mac() {
    let two = Command::WakeOnLan {
        targets: vec![session(), session()],
        wake: spec(),
    };
    assert!(two.validate().is_err());
    let terminal = Command::WakeOnLan {
        targets: vec![TargetRef::Terminal {
            terminal_id: uuid::Uuid::new_v4(),
            session_id: None,
        }],
        wake: spec(),
    };
    assert!(terminal.validate().is_err());
    let broadcast = Command::WakeOnLan {
        targets: vec![TargetRef::App],
        wake: WakeSpec {
            mac: "ff:ff:ff:ff:ff:ff".into(),
            ..spec()
        },
    };
    assert!(broadcast.validate().is_err());
}

#[test]
fn its_rule_is_listed_and_can_be_raised() {
    assert!(ActionKind::ALL.contains(&ActionKind::WakeOnLan));
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::WakeOnLan, TierRule::same(Tier::Medium));
    let engine = PolicyEngine::new(rules).expect("valid");
    let (command, targets) = wake(TargetRef::App, Environment::None, false);
    assert_eq!(engine.evaluate(&command, &targets).tier, Tier::Medium);
}
