//! Policy engine (AP-01): classes every state-changing command into a risk tier, and the tier decides
//! the approval steps.
//!
//! | Tier     | Steps before it runs                                                                  |
//! |----------|---------------------------------------------------------------------------------------|
//! | Low      | none; logged only                                                                     |
//! | Medium   | one confirm showing the impact summary                                               |
//! | High     | impact preview, safety snapshot (VMs, on by default), type the target count, reason, |
//! |          | 10-second countdown with cancel                                                       |
//! | Critical | all High steps, then the vault password again                                         |
//!
//! A target labelled Prod moves the action up one tier. Protected targets (AP-04) are skipped.
//! The rules are data ([`PolicyRules`]) so they can be edited and saved.

mod commands;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::command_bus::{Command, PowerOp, SnapshotOp, StopMode};
use crate::domain::{Environment, Target, TargetRef};
use crate::error::{CoreError, Result};

pub use commands::{default_dangerous_patterns, default_read_only_commands, DangerousPattern};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Tier {
    Low,
    Medium,
    High,
    Critical,
}

impl Tier {
    /// One tier up, capped at Critical (the Prod rule).
    pub fn bump(self) -> Tier {
        match self {
            Tier::Low => Tier::Medium,
            Tier::Medium => Tier::High,
            Tier::High | Tier::Critical => Tier::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Low => "low",
            Tier::Medium => "medium",
            Tier::High => "high",
            Tier::Critical => "critical",
        }
    }
}

/// What the action is, independent of how many targets it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionKind {
    VmStart,
    VmUnpause,
    VmPause,
    VmSuspend,
    VmResetSoft,
    VmResetHard,
    VmStopSoft,
    VmStopHard,
    SnapshotTake,
    SnapshotRevert,
    SnapshotDelete,
    /// Mark VMs "do not touch" (AP-04).
    VmProtect,
    /// Unlock protected VMs (AP-04), so other actions reach them again.
    VmUnprotect,
    /// Every part of the command starts with a word on the read-only list.
    ExecReadOnly,
    /// Not read-only, not dangerous.
    ExecOther,
    /// Matches a dangerous-command rule (BX-06).
    ExecDangerous,
    /// Install an app update (FD-14).
    AppUpdate,
}

/// Tier for one target and for a bulk action (`bulk_threshold` targets or more).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierRule {
    pub single: Tier,
    pub bulk: Tier,
}

impl TierRule {
    const fn same(tier: Tier) -> Self {
        Self {
            single: tier,
            bulk: tier,
        }
    }
}

/// An approval step the user must pass before the job runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ApprovalStep {
    /// Medium: one confirm showing the impact summary.
    Confirm,
    /// High: targets with their current state (AP-02).
    ImpactPreview,
    /// High, VM targets only: snapshot each VM first (VM-05).
    SafetySnapshot { default_on: bool },
    /// High: type the number of targets (AP-03).
    TypeTargetCount { expected: usize },
    /// High: a reason or ticket number (AP-03).
    Reason,
    /// High: the job waits this long after approval and can be cancelled meanwhile (AP-03).
    Countdown { seconds: u32 },
    /// Critical: the vault password again (AP-06).
    VaultReauth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRules {
    pub tiers: BTreeMap<ActionKind, TierRule>,
    /// Target count from which `TierRule::bulk` applies (the PRD says "2 or more VMs").
    pub bulk_threshold: usize,
    /// A target labelled Prod moves the action up one tier.
    pub prod_bump: bool,
    /// BX-06: editable list of dangerous-command patterns.
    pub dangerous_commands: Vec<DangerousPattern>,
    /// Commands (first words) treated as read-only.
    pub read_only_commands: Vec<String>,
    pub countdown_seconds: u32,
    pub safety_snapshot_default: bool,
}

impl PolicyRules {
    /// Rules saved before an action existed have no tier for it; give those the default tier, so an
    /// update that adds an action does not stop the app from loading the user's rules.
    pub fn fill_missing_tiers(&mut self) {
        for (kind, rule) in PolicyRules::default().tiers {
            self.tiers.entry(kind).or_insert(rule);
        }
    }
}

impl Default for PolicyRules {
    fn default() -> Self {
        use ActionKind::*;
        use Tier::*;
        let tiers = BTreeMap::from([
            (VmStart, TierRule::same(Low)),
            (VmUnpause, TierRule::same(Low)),
            (VmPause, TierRule::same(Medium)),
            (
                VmSuspend,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                VmResetSoft,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (
                VmStopSoft,
                TierRule {
                    single: Medium,
                    bulk: High,
                },
            ),
            (VmResetHard, TierRule::same(Critical)),
            (VmStopHard, TierRule::same(Critical)),
            (SnapshotTake, TierRule::same(Low)),
            (SnapshotRevert, TierRule::same(High)),
            (SnapshotDelete, TierRule::same(High)),
            (VmProtect, TierRule::same(Low)),
            (VmUnprotect, TierRule::same(Medium)),
            (ExecReadOnly, TierRule::same(Low)),
            (ExecOther, TierRule::same(Medium)),
            (ExecDangerous, TierRule::same(High)),
            (AppUpdate, TierRule::same(Medium)),
        ]);
        Self {
            tiers,
            bulk_threshold: 2,
            prod_bump: true,
            dangerous_commands: default_dangerous_patterns(),
            read_only_commands: default_read_only_commands(),
            countdown_seconds: 10,
            safety_snapshot_default: true,
        }
    }
}

/// The engine's answer for one command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub action: ActionKind,
    pub tier: Tier,
    pub steps: Vec<ApprovalStep>,
    /// Targets the action will run on.
    pub targets: Vec<Target>,
    /// Protected targets that will be left alone (AP-04).
    pub skipped: Vec<Target>,
    /// Why the tier is what it is, for the impact preview and the audit log.
    pub reasons: Vec<String>,
}

pub struct PolicyEngine {
    rules: PolicyRules,
    dangerous: Vec<(String, Regex)>,
}

impl PolicyEngine {
    /// Fails when a dangerous-command pattern is not a valid regex or an action has no tier.
    pub fn new(rules: PolicyRules) -> Result<Self> {
        let dangerous = rules
            .dangerous_commands
            .iter()
            .map(|p| {
                Regex::new(&p.pattern)
                    .map(|re| (p.name.clone(), re))
                    .map_err(|e| CoreError::InvalidRule {
                        name: p.name.clone(),
                        message: e.to_string(),
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        for kind in ALL_ACTIONS {
            if !rules.tiers.contains_key(&kind) {
                return Err(CoreError::InvalidRule {
                    name: format!("{kind:?}"),
                    message: "no tier set for this action".into(),
                });
            }
        }
        if rules.bulk_threshold < 2 {
            return Err(CoreError::InvalidRule {
                name: "bulkThreshold".into(),
                message: "must be 2 or more".into(),
            });
        }
        Ok(Self { rules, dangerous })
    }

    pub fn rules(&self) -> &PolicyRules {
        &self.rules
    }

    /// Names of the dangerous-command rules the script matches (BX-06).
    pub fn dangerous_matches(&self, script: &str) -> Vec<String> {
        self.dangerous
            .iter()
            .filter(|(_, re)| re.is_match(script))
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn classify(&self, command: &Command) -> ActionKind {
        match command {
            Command::VmPower { op, .. } => match op {
                PowerOp::Start { .. } => ActionKind::VmStart,
                PowerOp::Unpause => ActionKind::VmUnpause,
                PowerOp::Pause => ActionKind::VmPause,
                PowerOp::Suspend => ActionKind::VmSuspend,
                PowerOp::Reset { mode: StopMode::Soft } => ActionKind::VmResetSoft,
                PowerOp::Reset { mode: StopMode::Hard } => ActionKind::VmResetHard,
                PowerOp::Stop { mode: StopMode::Soft } => ActionKind::VmStopSoft,
                PowerOp::Stop { mode: StopMode::Hard } => ActionKind::VmStopHard,
            },
            Command::VmSnapshot { op, .. } => match op {
                SnapshotOp::Take { .. } => ActionKind::SnapshotTake,
                SnapshotOp::Revert { .. } => ActionKind::SnapshotRevert,
                SnapshotOp::Delete { .. } => ActionKind::SnapshotDelete,
            },
            Command::VmProtect { protected: true, .. } => ActionKind::VmProtect,
            Command::VmProtect { protected: false, .. } => ActionKind::VmUnprotect,
            Command::RemoteExec { script, .. } => {
                if !self.dangerous_matches(script).is_empty() {
                    ActionKind::ExecDangerous
                } else if commands::is_read_only(script, &self.rules.read_only_commands) {
                    ActionKind::ExecReadOnly
                } else {
                    ActionKind::ExecOther
                }
            }
            Command::AppUpdate { .. } => ActionKind::AppUpdate,
        }
    }

    /// `targets` are the command's targets after lookup, in the same order.
    pub fn evaluate(&self, command: &Command, targets: &[Target]) -> Decision {
        let action = self.classify(command);
        // AP-04: actions skip protected targets, except the one that changes protection.
        let skips_protected = !matches!(action, ActionKind::VmProtect | ActionKind::VmUnprotect);
        let (skipped, active): (Vec<Target>, Vec<Target>) =
            targets.iter().cloned().partition(|t| skips_protected && t.protected);
        let mut reasons = Vec::new();

        let rule = self.rules.tiers[&action];
        let bulk = active.len() >= self.rules.bulk_threshold;
        let mut tier = if bulk { rule.bulk } else { rule.single };
        reasons.push(format!("{action:?} on {} target(s) is {}", active.len(), tier.as_str()));

        if let Command::RemoteExec { script, .. } = command {
            let hits = self.dangerous_matches(script);
            if !hits.is_empty() {
                reasons.push(format!("flagged dangerous: {}", hits.join(", ")));
            }
        }

        if self.rules.prod_bump && active.iter().any(|t| t.environment == Environment::Prod) {
            let bumped = tier.bump();
            if bumped != tier {
                reasons.push(format!(
                    "a target is labelled Prod: {} -> {}",
                    tier.as_str(),
                    bumped.as_str()
                ));
            }
            tier = bumped;
        }

        if !skipped.is_empty() {
            reasons.push(format!("{} protected target(s) skipped", skipped.len()));
        }

        let steps = self.steps_for(tier, command, active.len());
        Decision {
            action,
            tier,
            steps,
            targets: active,
            skipped,
            reasons,
        }
    }

    fn steps_for(&self, tier: Tier, command: &Command, target_count: usize) -> Vec<ApprovalStep> {
        match tier {
            Tier::Low => vec![],
            Tier::Medium => vec![ApprovalStep::Confirm],
            Tier::High | Tier::Critical => {
                let mut steps = vec![ApprovalStep::ImpactPreview];
                if wants_safety_snapshot(command) {
                    steps.push(ApprovalStep::SafetySnapshot {
                        default_on: self.rules.safety_snapshot_default,
                    });
                }
                steps.push(ApprovalStep::TypeTargetCount { expected: target_count });
                steps.push(ApprovalStep::Reason);
                steps.push(ApprovalStep::Countdown {
                    seconds: self.rules.countdown_seconds,
                });
                if tier == Tier::Critical {
                    steps.push(ApprovalStep::VaultReauth);
                }
                steps
            }
        }
    }
}

/// VM-05 applies to VM targets, except taking a snapshot (which is itself the safety net) and
/// changing protection (which does not touch the VM).
fn wants_safety_snapshot(command: &Command) -> bool {
    let on_vms = command.targets().iter().any(|t| matches!(t, TargetRef::Vm { .. }));
    let leaves_vm_alone = matches!(
        command,
        Command::VmSnapshot {
            op: SnapshotOp::Take { .. },
            ..
        } | Command::VmProtect { .. }
    );
    on_vms && !leaves_vm_alone
}

const ALL_ACTIONS: [ActionKind; 17] = [
    ActionKind::VmStart,
    ActionKind::VmUnpause,
    ActionKind::VmPause,
    ActionKind::VmSuspend,
    ActionKind::VmResetSoft,
    ActionKind::VmResetHard,
    ActionKind::VmStopSoft,
    ActionKind::VmStopHard,
    ActionKind::SnapshotTake,
    ActionKind::SnapshotRevert,
    ActionKind::SnapshotDelete,
    ActionKind::VmProtect,
    ActionKind::VmUnprotect,
    ActionKind::ExecReadOnly,
    ActionKind::ExecOther,
    ActionKind::ExecDangerous,
    ActionKind::AppUpdate,
];
