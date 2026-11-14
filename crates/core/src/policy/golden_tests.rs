//! VM-30 (docs/plan-0.8.md, "Approval tiers"): building a golden image is Medium; keeping only its newest versions
//! deletes older versions' VMs, so it is rated like deleting VMs (Critical).

use super::*;
use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::templates::Network;
use crate::domain::{Environment, Target};
use crate::golden::{BuildOs, BuildRecipe, BuildSpec, SignIn};
use crate::vault::SecretId;

/// A build of version 1 of a new image, keeping `keep` versions (its VM is the deploy tests' one VM).
pub(super) fn build(keep: Option<u32>) -> (Command, Vec<Target>) {
    let (command, targets) = super::deploy_tests::deploy(1, Environment::None);
    let Command::Deploy { spec, .. } = command else {
        unreachable!()
    };
    let spec = BuildSpec {
        image_id: uuid::Uuid::from_u128(30),
        image_new: true,
        image_name: "Ubuntu golden".into(),
        os_profile: "ubuntu".into(),
        version: 1,
        os: BuildOs::Ubuntu,
        recipe: BuildRecipe {
            iso_image_id: uuid::Uuid::from_u128(1),
            install_config_id: uuid::Uuid::from_u128(2),
            size_id: "gp.medium".into(),
            hypervisor: Hypervisor::Vmware,
            network: Network::Nat,
            host_adapter: None,
            vm_folder: None,
            values: Default::default(),
            address_pool_id: None,
            install_minutes: 60,
            keep,
        },
        config_name: "lab".into(),
        config_fingerprint: "0".repeat(64),
        iso_path: r"C:\ISOs\noble.iso".into(),
        iso_seen: None,
        seal_minutes: 30,
        sign_in: SignIn::Ssh {
            user: "alice".into(),
            key_id: SecretId(uuid::Uuid::from_u128(3)),
            sudo_password_id: None,
        },
        deploy: *spec,
        prune: Vec::new(),
        retained: Vec::new(),
    };
    (
        Command::ImageBuild {
            targets: spec.targets(),
            spec: Box::new(spec),
        },
        targets,
    )
}

#[test]
fn a_build_is_medium_and_a_build_that_deletes_old_versions_is_critical() {
    let engine = PolicyEngine::new(PolicyRules::default()).expect("default rules are valid");
    let (command, targets) = build(None);
    let d = engine.evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::ImageBuild);
    assert_eq!(d.tier, Tier::Medium);
    assert!(
        d.reasons
            .iter()
            .any(|r| r.contains("version 1 of image 'Ubuntu golden'")),
        "{:?}",
        d.reasons
    );
    let (pruning, targets) = build(Some(2));
    let d = engine.evaluate(&pruning, &targets);
    assert_eq!(d.action, ActionKind::ImageBuildPrune);
    assert_eq!(d.tier, Tier::Critical);
    assert!(
        d.reasons.iter().any(|r| r.contains("keeps its newest 2")),
        "{:?}",
        d.reasons
    );
    // No safety snapshot: the build's VM doesn't exist yet.
    assert!(!safety_snapshot_applies(&command));
    assert_eq!(
        ActionKind::ImageBuildPrune.label(),
        "Build a golden image and delete its old versions"
    );
}

#[test]
fn the_build_tiers_are_rules_like_any() {
    let mut rules = PolicyRules::default();
    rules.tiers.insert(ActionKind::ImageBuild, TierRule::same(Tier::High));
    let engine = PolicyEngine::new(rules).expect("valid rules");
    let (command, targets) = build(None);
    assert_eq!(engine.evaluate(&command, &targets).tier, Tier::High);
    assert!(ActionKind::ALL.contains(&ActionKind::ImageBuild));
    assert!(ActionKind::ALL.contains(&ActionKind::ImageBuildPrune));
}

#[test]
fn the_old_versions_a_build_deletes_are_its_targets_and_rated_with_their_labels() {
    // B3 of PR 100's review: each old version's VM is a target the approval names, and a protected one is skipped.
    let engine = PolicyEngine::new(PolicyRules::default()).expect("default rules are valid");
    let (command, mut targets) = build(Some(1));
    let Command::ImageBuild { spec, .. } = command else {
        unreachable!()
    };
    let mut spec = *spec;
    spec.prune = vec![
        crate::golden::PruneVm {
            number: 1,
            vm_key: "C:/VMs/golden-v1/golden-v1.vmx".into(),
            vm_name: "golden-v1".into(),
        },
        crate::golden::PruneVm {
            number: 2,
            vm_key: "C:/VMs/golden-v2/golden-v2.vmx".into(),
            vm_name: "golden-v2".into(),
        },
    ];
    let command = Command::ImageBuild {
        targets: spec.targets(),
        spec: Box::new(spec),
    };
    let refs = command.targets();
    assert_eq!(refs.len(), 3);
    targets.push(Target {
        name: "golden-v1".into(),
        target: refs[1].clone(),
        environment: Environment::Prod,
        protected: false,
    });
    targets.push(Target {
        name: "golden-v2".into(),
        target: refs[2].clone(),
        environment: Environment::None,
        protected: true,
    });
    let d = engine.evaluate(&command, &targets);
    assert_eq!(d.action, ActionKind::ImageBuildPrune);
    assert_eq!(d.tier, Tier::Critical);
    let names: Vec<&str> = d.targets.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"golden-v1"), "{names:?}");
    assert!(!names.contains(&"golden-v2"), "a protected VM is skipped: {names:?}");
}
