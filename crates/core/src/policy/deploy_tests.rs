//! VM-21, VM-10 tier rules (docs/plan-0.5.md, "Approval tiers"): deploy 1 to 4 VMs is Medium; 5 or more VMs, or
//! VMs labelled Prod, High. A Prod label moves the tier up one, as for every action.

use super::*;
use crate::adapters::hypervisor::Hypervisor;
use crate::command_bus::Command;
use crate::deploy::spec::tests::{cloud, plan};
use crate::deploy::{DeployOrigin, DeploySpec};
use crate::domain::{Environment, Target, TargetRef};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

/// A deploy of `count` VMs labelled `environment`, and its targets as the bus resolves them.
pub(super) fn deploy(count: u32, environment: Environment) -> (Command, Vec<Target>) {
    let mut spec = DeploySpec::from_plan(
        &plan(cloud(), "ubuntu", Hypervisor::Vmware, count),
        DeployOrigin::Custom { name: "lab".into() },
        r"C:\VMs\lab".into(),
        None,
    );
    spec.environment = environment;
    let targets: Vec<Target> = spec
        .targets()
        .into_iter()
        .map(|target| {
            let TargetRef::NewVm { name, .. } = &target else {
                unreachable!()
            };
            Target {
                name: name.clone(),
                target: target.clone(),
                environment,
                protected: false,
            }
        })
        .collect();
    (
        Command::Deploy {
            targets: spec.targets(),
            spec: Box::new(spec),
        },
        targets,
    )
}

fn decide(count: u32, environment: Environment) -> Decision {
    let (command, targets) = deploy(count, environment);
    engine().evaluate(&command, &targets)
}

#[test]
fn deploying_one_to_four_vms_is_medium_with_one_confirm() {
    for n in [1, 4] {
        let d = decide(n, Environment::Lab);
        assert_eq!(d.action, ActionKind::VmDeploy);
        assert_eq!(d.tier, Tier::Medium, "{n}");
        assert_eq!(d.steps, [ApprovalStep::Confirm], "{n}");
        assert_eq!(d.targets.len(), n as usize);
    }
}

#[test]
fn deploying_five_or_more_vms_is_high_without_a_safety_snapshot() {
    for n in [5, 50] {
        let d = decide(n, Environment::Lab);
        assert_eq!(d.tier, Tier::High, "{n}");
        assert_eq!(
            d.steps,
            [
                ApprovalStep::ImpactPreview,
                ApprovalStep::TypeTargetCount { expected: n as usize },
                ApprovalStep::Reason,
                ApprovalStep::Countdown { seconds: 10 },
            ],
            "nothing to snapshot: the VMs don't exist yet"
        );
        assert!(
            d.reasons.iter().any(|r| r == "5 or more new VMs: the bulk tier for deploys applies"),
            "{:?}",
            d.reasons
        );
    }
    let (command, _) = deploy(5, Environment::Lab);
    assert!(!safety_snapshot_applies(&command));
}

#[test]
fn a_prod_label_raises_a_deploy_one_tier() {
    let d = decide(1, Environment::Prod);
    assert_eq!(d.tier, Tier::High);
    assert!(d.reasons.iter().any(|r| r == "a target is labelled Prod: medium -> high"));
    // Five Prod VMs: High, and Prod moves it up to Critical with the vault password.
    let d = decide(5, Environment::Prod);
    assert_eq!(d.tier, Tier::Critical);
    assert_eq!(d.steps.last(), Some(&ApprovalStep::VaultReauth));
    let staging = decide(2, Environment::Staging);
    assert_eq!(staging.tier, Tier::Medium);
}

#[test]
fn the_bulk_threshold_for_deploys_is_its_own_rule() {
    assert_eq!(PolicyRules::default().threshold(ActionKind::VmDeploy), 5);
    let e = PolicyEngine::new(PolicyRules {
        deploy_bulk_threshold: 3,
        ..Default::default()
    })
    .unwrap();
    let (two, two_targets) = deploy(2, Environment::Lab);
    let (three, three_targets) = deploy(3, Environment::Lab);
    assert_eq!(e.evaluate(&two, &two_targets).tier, Tier::Medium);
    assert_eq!(e.evaluate(&three, &three_targets).tier, Tier::High);
    // The VM actions' threshold (2) leaves deploys alone.
    let e = PolicyEngine::new(PolicyRules {
        bulk_threshold: 10,
        ..Default::default()
    })
    .unwrap();
    let (five, five_targets) = deploy(5, Environment::Lab);
    assert_eq!(e.evaluate(&five, &five_targets).tier, Tier::High);
}

#[test]
fn the_deploy_threshold_has_bounds_and_saved_rules_without_it_load() {
    for threshold in [0, 1, MAX_BULK_THRESHOLD + 1] {
        let err = PolicyRules {
            deploy_bulk_threshold: threshold,
            ..Default::default()
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("'Bulk threshold for deploys': must be 2 to 1000 VMs"), "{threshold}: {err}");
    }
    // 0.4.x saved neither the threshold nor a tier for deploys.
    let mut json = serde_json::to_value(PolicyRules::default()).unwrap();
    json.as_object_mut().unwrap().remove("deployBulkThreshold");
    json["tiers"].as_object_mut().unwrap().remove("vmDeploy");
    let mut saved: PolicyRules = serde_json::from_value(json).unwrap();
    saved.fill_missing_tiers();
    assert_eq!(saved.deploy_bulk_threshold, DEFAULT_DEPLOY_BULK_THRESHOLD);
    assert_eq!(
        saved.tiers[&ActionKind::VmDeploy],
        TierRule {
            single: Tier::Medium,
            bulk: Tier::High
        }
    );
    assert!(PolicyEngine::new(saved).is_ok());
}

#[test]
fn a_higher_deploy_threshold_loosens_the_rules_and_is_named() {
    let base = PolicyRules::default();
    let higher = PolicyRules {
        deploy_bulk_threshold: 10,
        ..base.clone()
    };
    assert_eq!(base.loosened(&higher), ["a higher bulk threshold for deploys"]);
    assert_eq!(base.changes(&higher), ["Bulk threshold for deploys: 5 -> 10 VMs"]);
    let lower = PolicyRules {
        deploy_bulk_threshold: 2,
        ..base.clone()
    };
    assert!(base.loosened(&lower).is_empty(), "a lower one only tightens");
    let mut low_tier = base.clone();
    low_tier.tiers.insert(ActionKind::VmDeploy, TierRule::same(Tier::Low));
    assert_eq!(base.loosened(&low_tier), ["Deploy VMs (create, clone or import) asks less"]);
}

#[test]
fn the_read_only_lock_refuses_a_deploy() {
    let (command, _) = deploy(1, Environment::Lab);
    let err = engine().check_read_only(true, &command).unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    assert!(err.to_string().contains("Deploy VMs (create, clone or import)"), "{err}");
}
