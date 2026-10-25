//! VM-14, VM-27 standing approvals (docs/plan-0.5.md, "Approval tiers": "A scheduled action: the action's own tier,
//! approved when it is scheduled"). A schedule is approved when it is saved, with the same steps as running it then
//! (AP-06 included), and each run is a run of that approval. These are the policy engine's rules for it:
//!
//! * A schedule submits more than one command (a snapshot schedule takes a snapshot, then its retention deletes the
//!   oldest ones), so it is rated as the highest of its commands on its targets: retention's delete (High) makes
//!   the save ask what a delete asks ([`PolicyEngine::evaluate_standing`]).
//! * The countdown is the run's, not the save's: each run's job waits it out and can be cancelled then, so the
//!   save asks every other step and leaves the countdown out.
//! * The approval is bound to the rules that rated it: the tiers of its actions, their bulk threshold, the Prod
//!   rule, the countdown and the safety snapshot default ([`PolicyRules::fingerprint`]). Another rule (a
//!   dangerous-command pattern, a read-only command, another action's tier) leaves it as it was; any of those
//!   changing makes the schedule ask again.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{ActionKind, ApprovalStep, Decision, PolicyEngine, PolicyRules};
use crate::command_bus::Command;
use crate::domain::Target;

/// The order steps are asked in, for steps merged from several decisions.
fn step_rank(step: &ApprovalStep) -> u8 {
    match step {
        ApprovalStep::Confirm => 0,
        ApprovalStep::ImpactPreview => 1,
        ApprovalStep::SafetySnapshot { .. } => 2,
        ApprovalStep::TypeTargetCount { .. } => 3,
        ApprovalStep::Reason => 4,
        ApprovalStep::Countdown { .. } => 5,
        ApprovalStep::VaultReauth => 6,
    }
}

impl PolicyRules {
    /// VM-14, VM-27: a fingerprint of the rules that rate `kinds`: each one's tier for one target and in bulk and
    /// the bulk threshold it uses, the Prod rule, the countdown and the safety snapshot default. A standing approval
    /// keeps it, and asks again once it differs. Other rules don't change it.
    pub fn fingerprint(&self, kinds: &[ActionKind]) -> String {
        let mut tiers = BTreeMap::new();
        for kind in kinds {
            let rule = self.tiers.get(kind).copied();
            tiers.insert(
                *kind,
                serde_json::json!({
                    "single": rule.map(|r| r.single.as_str()),
                    "bulk": rule.map(|r| r.bulk.as_str()),
                    "threshold": self.threshold(*kind),
                }),
            );
        }
        let rated = serde_json::json!({
            "v": 1,
            "tiers": tiers,
            "prodBump": self.prod_bump,
            "countdownSeconds": self.countdown_seconds,
            "safetySnapshotDefault": self.safety_snapshot_default,
        });
        hex::encode(Sha256::digest(rated.to_string().as_bytes()))
    }
}

impl PolicyEngine {
    /// VM-14, VM-27: the actions a schedule's commands are, in order, each once.
    pub fn standing_kinds(&self, commands: &[Command]) -> Vec<ActionKind> {
        let mut kinds: Vec<ActionKind> = Vec::new();
        for command in commands {
            let kind = self.classify(command);
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        kinds
    }

    /// VM-14, VM-27: the approval a schedule asks for when it is saved. Each of its commands is rated on the targets
    /// as it would be if it ran now; the schedule gets the highest tier and that tier's steps (merged when two
    /// commands share it), every reason and warning, and no countdown: each run's job has its own. `targets` are
    /// the schedule's targets after lookup; every command acts on all of them.
    pub fn evaluate_standing(&self, commands: &[Command], targets: &[Target]) -> Option<Decision> {
        let decisions: Vec<Decision> = commands.iter().map(|c| self.evaluate(c, targets)).collect();
        let top = decisions.iter().map(|d| d.tier).max()?;
        let mut merged: Option<Decision> = None;
        for decision in decisions {
            let Some(into) = merged.as_mut() else {
                merged = Some(decision);
                continue;
            };
            if decision.tier > into.tier {
                into.action = decision.action;
                into.tier = decision.tier;
                into.steps = decision.steps.clone();
            } else if decision.tier == into.tier {
                for step in &decision.steps {
                    if !into.steps.contains(step) {
                        into.steps.push(step.clone());
                    }
                }
            }
            for reason in decision.reasons {
                if !into.reasons.contains(&reason) {
                    into.reasons.push(reason);
                }
            }
            into.warnings.extend(decision.warnings);
        }
        let mut merged = merged?;
        debug_assert_eq!(merged.tier, top);
        merged.steps.retain(|s| !matches!(s, ApprovalStep::Countdown { .. }));
        merged.steps.sort_by_key(step_rank);
        Some(merged)
    }

    /// VM-14, VM-27: the fingerprint of the rules that rate these commands ([`PolicyRules::fingerprint`]).
    pub fn standing_fingerprint(&self, commands: &[Command]) -> String {
        self.rules.fingerprint(&self.standing_kinds(commands))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Tier, TierRule};
    use super::*;
    use crate::command_bus::{PowerOp, SnapshotOp, StopMode};
    use crate::domain::{Environment, TargetRef};

    fn engine(rules: PolicyRules) -> PolicyEngine {
        PolicyEngine::new(rules).expect("valid rules")
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

    fn targets(count: usize, environment: Environment) -> Vec<Target> {
        (0..count).map(|n| vm(n, environment)).collect()
    }

    fn refs(targets: &[Target]) -> Vec<TargetRef> {
        targets.iter().map(|t| t.target.clone()).collect()
    }

    fn take(targets: &[Target]) -> Command {
        Command::VmSnapshot {
            targets: refs(targets),
            op: SnapshotOp::Take {
                name: "Remotely schedule 'nightly'".into(),
            },
        }
    }

    fn delete(targets: &[Target]) -> Command {
        Command::VmSnapshot {
            targets: refs(targets),
            op: SnapshotOp::Delete {
                name: "Remotely schedule 'nightly'".into(),
            },
        }
    }

    fn power(op: PowerOp, targets: &[Target]) -> Command {
        Command::VmPower {
            targets: refs(targets),
            op,
        }
    }

    #[test]
    fn a_snapshot_schedule_without_retention_is_low_and_asks_nothing() {
        let lab = targets(3, Environment::Lab);
        let decision = engine(PolicyRules::default())
            .evaluate_standing(&[take(&lab)], &lab)
            .unwrap();
        assert_eq!(decision.tier, Tier::Low);
        assert!(decision.steps.is_empty());
    }

    #[test]
    fn retention_deletes_snapshots_so_the_save_asks_what_a_delete_asks() {
        let lab = targets(2, Environment::Lab);
        let decision = engine(PolicyRules::default())
            .evaluate_standing(&[take(&lab), delete(&lab)], &lab)
            .unwrap();
        assert_eq!(decision.tier, Tier::High);
        assert_eq!(decision.action, ActionKind::SnapshotDelete);
        assert_eq!(
            decision.steps,
            [
                ApprovalStep::ImpactPreview,
                ApprovalStep::TypeTargetCount { expected: 2 },
                ApprovalStep::Reason,
            ],
            "no safety snapshot for a delete, and no countdown at the save"
        );
        assert!(decision.reasons.iter().any(|r| r.contains("Take a snapshot")));
        assert!(decision.reasons.iter().any(|r| r.contains("Delete a snapshot")));
    }

    #[test]
    fn the_countdown_is_the_runs_not_the_saves() {
        let lab = targets(2, Environment::Lab);
        let engine = engine(PolicyRules::default());
        let suspend = power(PowerOp::Suspend, &lab);
        let now = engine.evaluate(&suspend, &lab);
        assert!(now.steps.contains(&ApprovalStep::Countdown { seconds: 10 }));
        let saved = engine.evaluate_standing(&[suspend], &lab).unwrap();
        assert_eq!(saved.tier, Tier::High);
        assert!(!saved.steps.iter().any(|s| matches!(s, ApprovalStep::Countdown { .. })));
        // A suspend can lose what the guest does: the safety snapshot is asked at the save, for every run.
        assert!(saved.steps.contains(&ApprovalStep::SafetySnapshot { default_on: true }));
    }

    #[test]
    fn a_prod_target_raises_a_schedule_like_any_action_and_critical_asks_for_the_vault_password() {
        let mut prod = targets(2, Environment::Lab);
        prod[1].environment = Environment::Prod;
        let decision = engine(PolicyRules::default())
            .evaluate_standing(&[take(&prod), delete(&prod)], &prod)
            .unwrap();
        assert_eq!(decision.tier, Tier::Critical);
        assert_eq!(decision.steps.last(), Some(&ApprovalStep::VaultReauth));
    }

    #[test]
    fn a_scheduled_start_on_one_lab_vm_is_low_and_a_shutdown_is_one_confirm() {
        let one = targets(1, Environment::Lab);
        let engine = engine(PolicyRules::default());
        let start = engine
            .evaluate_standing(&[power(PowerOp::Start { gui: false }, &one)], &one)
            .unwrap();
        assert_eq!(start.tier, Tier::Low);
        let stop = engine
            .evaluate_standing(&[power(PowerOp::Stop { mode: StopMode::Soft }, &one)], &one)
            .unwrap();
        assert_eq!(stop.tier, Tier::Medium);
        assert_eq!(stop.steps, [ApprovalStep::Confirm]);
    }

    #[test]
    fn protected_targets_are_skipped_by_a_schedule_too() {
        let mut lab = targets(2, Environment::Lab);
        lab[0].protected = true;
        let decision = engine(PolicyRules::default())
            .evaluate_standing(&[take(&lab)], &lab)
            .unwrap();
        assert_eq!(decision.targets.len(), 1);
        assert_eq!(decision.skipped.len(), 1);
    }

    #[test]
    fn no_commands_rate_nothing() {
        assert!(engine(PolicyRules::default()).evaluate_standing(&[], &[]).is_none());
    }

    #[test]
    fn the_fingerprint_follows_the_rules_that_rate_the_schedule_only() {
        let lab = targets(1, Environment::Lab);
        let commands = [take(&lab), delete(&lab)];
        let base = PolicyRules::default();
        let print = |rules: &PolicyRules| engine(rules.clone()).standing_fingerprint(&commands);
        let before = print(&base);
        assert_eq!(before, print(&base), "the same rules give the same fingerprint");

        // What rates it.
        let mut tier = base.clone();
        tier.tiers
            .insert(ActionKind::SnapshotDelete, TierRule::same(Tier::Critical));
        let mut prod = base.clone();
        prod.prod_bump = false;
        let mut countdown = base.clone();
        countdown.countdown_seconds = 30;
        let mut threshold = base.clone();
        threshold.bulk_threshold = 3;
        let mut safety = base.clone();
        safety.safety_snapshot_default = false;
        for changed in [tier, prod, countdown, threshold, safety] {
            assert_ne!(print(&changed), before, "{:?}", base.changes(&changed));
        }

        // What doesn't.
        let mut other_tier = base.clone();
        other_tier
            .tiers
            .insert(ActionKind::VmDelete, TierRule::same(Tier::High));
        let mut dangerous = base.clone();
        dangerous.dangerous_commands.pop();
        let mut read_only = base.clone();
        read_only.read_only_commands.push("remotely-test-reader".into());
        let mut exec_threshold = base.clone();
        exec_threshold.exec_bulk_threshold = 9;
        for unrelated in [other_tier, dangerous, read_only, exec_threshold] {
            assert_eq!(print(&unrelated), before, "{:?}", base.changes(&unrelated));
        }
    }

    #[test]
    fn a_schedules_kinds_are_its_commands_actions_once_each() {
        let lab = targets(1, Environment::Lab);
        let engine = engine(PolicyRules::default());
        assert_eq!(
            engine.standing_kinds(&[take(&lab), delete(&lab), delete(&lab)]),
            [ActionKind::SnapshotTake, ActionKind::SnapshotDelete]
        );
    }
}
