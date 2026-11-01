//! FD-04 tier rules (docs/plan-0.7.md, "Approval tiers"): a support bundle's commands are rated as a Compare hosts
//! run's (read-only presets are Low; Medium on Prod), its files are reads, and nothing about it is VM-shaped.

use super::*;
use crate::command_bus::{Command, Rollout};
use crate::domain::{Environment, Target, TargetRef};
use crate::support_bundle::presets::{self, PresetId, PRESETS};
use crate::support_bundle::{BundleItem, BundleSpec};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyRules::default()).expect("default rules are valid")
}

fn host(n: usize, environment: Environment) -> Target {
    Target {
        target: TargetRef::Session {
            session_id: uuid::Uuid::from_u128(n as u128 + 1),
        },
        name: format!("web{n:02}"),
        environment,
        protected: false,
    }
}

fn bundle(items: Vec<BundleItem>, hosts: &[Target]) -> Command {
    Command::SupportBundle {
        targets: hosts.iter().map(|t| t.target.clone()).collect(),
        spec: Box::new(BundleSpec {
            presets: Vec::new(),
            items,
            windows_items: Vec::new(),
            sudo: false,
            sudo_password_id: None,
            trust_new_host_keys: false,
            timeout_secs: None,
            rollout: Rollout::default(),
            output: r"C:\Users\alice\Documents\bundle.zip".into(),
            workspace: "Lab".into(),
        }),
    }
}

fn every_preset() -> Vec<BundleItem> {
    let ids: Vec<PresetId> = PRESETS.iter().map(|p| p.id).collect();
    presets::expand(presets::HostKind::Linux, &ids, &[], &[])
}

#[test]
fn every_preset_command_is_read_only_under_the_default_rules() {
    let engine = engine();
    for preset in PRESETS {
        for item in preset.items {
            if let BundleItem::Command { command } = item.item() {
                assert_eq!(
                    engine.classify_script_as(&command, preset.host_kind.script_kind()),
                    ActionKind::ExecReadOnly,
                    "{}: {command}",
                    preset.label
                );
            }
        }
    }
}

#[test]
fn a_bundle_of_presets_is_low_and_runs_at_once() {
    let hosts: Vec<Target> = (0..10).map(|n| host(n, Environment::Lab)).collect();
    let command = bundle(every_preset(), &hosts);
    let decision = engine().evaluate(&command, &hosts);
    assert_eq!(decision.action, ActionKind::ExecReadOnly);
    assert_eq!(decision.tier, Tier::Low, "{:?}", decision.reasons);
    assert!(decision.steps.is_empty());
    assert!(
        decision.reasons.iter().any(|r| r.starts_with("support bundle: its")),
        "{:?}",
        decision.reasons
    );
}

#[test]
fn a_prod_host_moves_a_bundle_up_to_medium() {
    let hosts = vec![host(0, Environment::Lab), host(1, Environment::Prod)];
    let decision = engine().evaluate(&bundle(every_preset(), &hosts), &hosts);
    assert_eq!(decision.tier, Tier::Medium);
    assert_eq!(decision.steps, vec![ApprovalStep::Confirm]);
    assert!(decision.reasons.iter().any(|r| r.contains("labelled Prod")));
}

#[test]
fn files_alone_are_reads() {
    let hosts = vec![host(0, Environment::Lab)];
    let command = bundle(
        vec![BundleItem::file("/etc/hosts"), BundleItem::file("/var/log/app.log")],
        &hosts,
    );
    let decision = engine().evaluate(&command, &hosts);
    assert_eq!(decision.action, ActionKind::ExecReadOnly);
    assert_eq!(decision.tier, Tier::Low);
    assert!(
        decision
            .reasons
            .iter()
            .any(|r| r.contains("2 files are read over SFTP as the login user, never with sudo")),
        "{:?}",
        decision.reasons
    );
}

#[test]
fn a_command_that_changes_something_rates_the_bundle_as_compare_would() {
    let mut items = every_preset();
    items.push(BundleItem::command("systemctl restart nginx"));
    let one = vec![host(0, Environment::Lab)];
    let decision = engine().evaluate(&bundle(items.clone(), &one), &one);
    assert_eq!(decision.action, ActionKind::ExecOther);
    assert_eq!(decision.tier, Tier::Medium);

    // BX-06: from the bulk threshold for commands on hosts, the full approval.
    let many: Vec<Target> = (0..DEFAULT_EXEC_BULK_THRESHOLD)
        .map(|n| host(n, Environment::Lab))
        .collect();
    let decision = engine().evaluate(&bundle(items, &many), &many);
    assert_eq!(decision.tier, Tier::High);
    assert!(decision.steps.contains(&ApprovalStep::Reason));
}

#[test]
fn a_dangerous_command_makes_the_bundle_dangerous() {
    let hosts = vec![host(0, Environment::Lab)];
    let command = bundle(
        vec![
            BundleItem::command("uptime"),
            BundleItem::command("rm -rf /var/log/old"),
        ],
        &hosts,
    );
    let decision = engine().evaluate(&command, &hosts);
    assert_eq!(decision.action, ActionKind::ExecDangerous);
    assert_eq!(decision.tier, Tier::High);
    assert!(decision.reasons.iter().any(|r| r.starts_with("flagged dangerous")));
}

#[test]
fn a_container_prune_in_a_bundle_is_rated_like_the_containers_page() {
    let hosts = vec![host(0, Environment::Lab)];
    let command = bundle(vec![BundleItem::command("docker volume prune -f")], &hosts);
    let decision = engine().evaluate(&command, &hosts);
    assert_eq!(decision.tier, Tier::Critical, "{:?}", decision.reasons);
}

#[test]
fn sudo_does_not_change_the_tier_as_in_compare() {
    let hosts = vec![host(0, Environment::Lab)];
    let mut command = bundle(every_preset(), &hosts);
    if let Command::SupportBundle { spec, .. } = &mut command {
        spec.sudo = true;
    }
    assert_eq!(engine().evaluate(&command, &hosts).tier, Tier::Low);
}

#[test]
fn protected_hosts_are_skipped() {
    let mut locked = host(1, Environment::Lab);
    locked.protected = true;
    let hosts = vec![host(0, Environment::Lab), locked];
    let decision = engine().evaluate(&bundle(every_preset(), &hosts), &hosts);
    assert_eq!(decision.targets.len(), 1);
    assert_eq!(decision.skipped.len(), 1);
}

#[test]
fn the_read_only_lock_refuses_a_bundle_and_no_safety_snapshot_applies() {
    let hosts = vec![host(0, Environment::Lab)];
    let command = bundle(every_preset(), &hosts);
    assert!(matches!(
        engine().check_read_only(true, &command),
        Err(crate::error::CoreError::ReadOnlyLock { .. })
    ));
    assert!(engine().check_read_only(false, &command).is_ok());
    assert!(!safety_snapshot_applies(&command));
}
