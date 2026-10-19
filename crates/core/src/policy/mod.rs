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
    /// Add a public key to hosts' `~/.ssh/authorized_keys` (SS-09): it grants a login.
    SshKeyPush,
    /// Upload files into a folder on a terminal's host (SS-08), adding new files only.
    FileUpload,
    /// Upload files that replace files on the host (SS-08). Never below Medium: replacing asks.
    FileReplace,
}

impl ActionKind {
    /// Every action, in the order Settings lists them (AP-01).
    pub const ALL: [ActionKind; 20] = [
        ActionKind::VmStart,
        ActionKind::VmUnpause,
        ActionKind::VmPause,
        ActionKind::VmSuspend,
        ActionKind::VmResetSoft,
        ActionKind::VmStopSoft,
        ActionKind::VmResetHard,
        ActionKind::VmStopHard,
        ActionKind::SnapshotTake,
        ActionKind::SnapshotRevert,
        ActionKind::SnapshotDelete,
        ActionKind::VmProtect,
        ActionKind::VmUnprotect,
        ActionKind::ExecReadOnly,
        ActionKind::ExecOther,
        ActionKind::ExecDangerous,
        ActionKind::SshKeyPush,
        ActionKind::FileUpload,
        ActionKind::FileReplace,
        ActionKind::AppUpdate,
    ];

    /// What the user sees in Settings, approval reasons and the audit log.
    pub fn label(self) -> &'static str {
        match self {
            ActionKind::VmStart => "Start VMs",
            ActionKind::VmUnpause => "Unpause VMs",
            ActionKind::VmPause => "Pause VMs",
            ActionKind::VmSuspend => "Suspend VMs",
            ActionKind::VmResetSoft => "Restart VMs",
            ActionKind::VmStopSoft => "Shut down VMs",
            ActionKind::VmResetHard => "Reset VMs (hard)",
            ActionKind::VmStopHard => "Power off VMs (hard)",
            ActionKind::SnapshotTake => "Take a snapshot",
            ActionKind::SnapshotRevert => "Revert to a snapshot",
            ActionKind::SnapshotDelete => "Delete a snapshot",
            ActionKind::VmProtect => "Protect VMs",
            ActionKind::VmUnprotect => "Unprotect VMs",
            ActionKind::ExecReadOnly => "Run a read-only command",
            ActionKind::ExecOther => "Run any other command",
            ActionKind::ExecDangerous => "Run a dangerous command",
            ActionKind::AppUpdate => "Install an app update",
            ActionKind::SshKeyPush => "Add an SSH key to hosts",
            ActionKind::FileUpload => "Upload files",
            ActionKind::FileReplace => "Upload files that replace files on the host",
        }
    }
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

/// SS-08: replacing a file on a host always asks at least for a confirm.
pub const MIN_REPLACE_TIER: Tier = Tier::Medium;

/// AP-01: the editable numbers stay within these bounds.
pub const MAX_BULK_THRESHOLD: usize = 1000;
pub const MAX_COUNTDOWN_SECONDS: u32 = 300;

/// Characters that join or redirect shell commands. A read-only entry holding one would let a
/// writing command ride along on a read-only one.
const SHELL_SPECIAL: &[char] = &[';', '&', '|', '>', '<', '`', '$', '(', ')', '\n', '\r'];

impl PolicyRules {
    /// Trims names and patterns and collapses the spaces in read-only entries, so the same rule
    /// typed twice compares equal. Changes nothing else.
    pub fn normalized(mut self) -> Self {
        for p in &mut self.dangerous_commands {
            p.name = p.name.trim().to_owned();
            p.pattern = p.pattern.trim().to_owned();
        }
        for entry in &mut self.read_only_commands {
            *entry = entry.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        self
    }

    /// AP-01: every problem that makes the rules unusable, or unsafe to save. Reported one at a time,
    /// so the message names the rule to fix.
    pub fn validate(&self) -> Result<()> {
        let invalid = |name: &str, message: String| {
            Err(CoreError::InvalidRule {
                name: name.to_owned(),
                message,
            })
        };
        for kind in ActionKind::ALL {
            let Some(rule) = self.tiers.get(&kind) else {
                return invalid(kind.label(), "no tier set for this action".into());
            };
            if kind == ActionKind::FileReplace && rule.single < MIN_REPLACE_TIER {
                return invalid(
                    kind.label(),
                    format!(
                        "replacing a file always asks first, so this can't be lower than {}",
                        MIN_REPLACE_TIER.as_str()
                    ),
                );
            }
            if rule.bulk < rule.single {
                return invalid(
                    kind.label(),
                    format!(
                        "the tier for {} or more targets ({}) can't be lower than for one target ({})",
                        self.bulk_threshold,
                        rule.bulk.as_str(),
                        rule.single.as_str()
                    ),
                );
            }
        }
        if !(2..=MAX_BULK_THRESHOLD).contains(&self.bulk_threshold) {
            return invalid("Bulk threshold", format!("must be 2 to {MAX_BULK_THRESHOLD} targets"));
        }
        if self.countdown_seconds > MAX_COUNTDOWN_SECONDS {
            return invalid("Countdown", format!("must be 0 to {MAX_COUNTDOWN_SECONDS} seconds"));
        }
        let mut names = std::collections::HashSet::new();
        for p in &self.dangerous_commands {
            let label = if p.name.trim().is_empty() {
                "Dangerous command"
            } else {
                p.name.as_str()
            };
            if p.name.trim().is_empty() {
                return invalid(label, "give the pattern a name".into());
            }
            if !names.insert(p.name.trim().to_lowercase()) {
                return invalid(label, "another dangerous-command rule has this name".into());
            }
            if p.pattern.trim().is_empty() {
                return invalid(label, "the pattern is empty".into());
            }
            match Regex::new(&p.pattern) {
                Err(err) => return invalid(label, format!("not a valid regular expression: {err}")),
                // A pattern that matches the empty string matches every command.
                Ok(re) if re.is_match("") => {
                    return invalid(label, "the pattern matches every command".into());
                }
                Ok(_) => {}
            }
        }
        let mut entries = std::collections::HashSet::new();
        for entry in &self.read_only_commands {
            let shown = entry.trim();
            if shown.is_empty() {
                return invalid("Read-only commands", "an entry is empty".into());
            }
            if shown.contains(SHELL_SPECIAL) {
                return invalid(
                    "Read-only commands",
                    format!("'{shown}' holds a shell operator (; & | > < ` $ or brackets)"),
                );
            }
            if !entries.insert(shown.split_whitespace().collect::<Vec<_>>().join(" ")) {
                return invalid("Read-only commands", format!("'{shown}' is listed twice"));
            }
        }
        Ok(())
    }

    /// What changed from `self` to `new`, one line per change, for the audit log (AP-01).
    pub fn changes(&self, new: &PolicyRules) -> Vec<String> {
        let mut out = Vec::new();
        for kind in ActionKind::ALL {
            let (before, after) = (self.tiers.get(&kind), new.tiers.get(&kind));
            if before == after {
                continue;
            }
            let show = |r: Option<&TierRule>| {
                r.map_or_else(
                    || "none".to_owned(),
                    |r| format!("{} for one, {} in bulk", r.single.as_str(), r.bulk.as_str()),
                )
            };
            out.push(format!("{}: {} -> {}", kind.label(), show(before), show(after)));
        }
        if self.bulk_threshold != new.bulk_threshold {
            out.push(format!(
                "Bulk threshold: {} -> {} targets",
                self.bulk_threshold, new.bulk_threshold
            ));
        }
        if self.prod_bump != new.prod_bump {
            out.push(format!(
                "Prod raises the tier: {} -> {}",
                on_off(self.prod_bump),
                on_off(new.prod_bump)
            ));
        }
        if self.countdown_seconds != new.countdown_seconds {
            out.push(format!(
                "Countdown: {} -> {} s",
                self.countdown_seconds, new.countdown_seconds
            ));
        }
        if self.safety_snapshot_default != new.safety_snapshot_default {
            out.push(format!(
                "Safety snapshot by default: {} -> {}",
                on_off(self.safety_snapshot_default),
                on_off(new.safety_snapshot_default)
            ));
        }
        for p in &new.dangerous_commands {
            match self.dangerous_commands.iter().find(|old| old.name == p.name) {
                None => out.push(format!("Dangerous command added: {} = {}", p.name, p.pattern)),
                Some(old) if old.pattern != p.pattern => out.push(format!(
                    "Dangerous command changed: {} = {} -> {}",
                    p.name, old.pattern, p.pattern
                )),
                Some(_) => {}
            }
        }
        for p in &self.dangerous_commands {
            if !new.dangerous_commands.iter().any(|n| n.name == p.name) {
                out.push(format!("Dangerous command removed: {}", p.name));
            }
        }
        for entry in &new.read_only_commands {
            if !self.read_only_commands.contains(entry) {
                out.push(format!("Read-only command added: {entry}"));
            }
        }
        for entry in &self.read_only_commands {
            if !new.read_only_commands.contains(entry) {
                out.push(format!("Read-only command removed: {entry}"));
            }
        }
        out
    }

    /// Rules saved before an action existed have no tier for it; give those the default tier, so an
    /// update that adds an action does not stop the app from loading the user's rules.
    pub fn fill_missing_tiers(&mut self) {
        for (kind, rule) in PolicyRules::default().tiers {
            self.tiers.entry(kind).or_insert(rule);
        }
    }
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
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
            // A key in authorized_keys lets its holder log in: a change like any other command.
            (SshKeyPush, TierRule::same(Medium)),
            // SS-08: a new file in a folder the user can write to anyway; replacing one asks first.
            (FileUpload, TierRule::same(Low)),
            (FileReplace, TierRule::same(Medium)),
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

/// BX-06: a dangerous-command rule a script matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DangerousMatch {
    /// The rule's name, as in Settings.
    pub rule: String,
    /// The script line it first matched, trimmed (at most 200 characters).
    pub text: String,
    /// That line's number, from 1.
    pub line: usize,
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
    /// Problems found before the action, e.g. not enough host RAM (VM-07). The user must see them.
    pub warnings: Vec<String>,
}

impl Decision {
    /// VM-07: warnings must reach the user before the action runs, so an action that would run
    /// without a dialog gets one confirm. The tier, and the steps of a tier that has a dialog anyway,
    /// stay as they are.
    pub fn add_warnings(&mut self, warnings: Vec<String>) {
        if warnings.is_empty() {
            return;
        }
        if self.steps.is_empty() {
            self.steps.push(ApprovalStep::Confirm);
        }
        self.warnings.extend(warnings);
    }
}

pub struct PolicyEngine {
    rules: PolicyRules,
    dangerous: Vec<(String, Regex)>,
}

impl PolicyEngine {
    /// Fails with the first problem [`PolicyRules::validate`] finds.
    pub fn new(rules: PolicyRules) -> Result<Self> {
        rules.validate()?;
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

    /// BX-06: each rule the script matches, with the line of its first match, so the editor and the
    /// approval dialog can show why the command needs approval.
    pub fn dangerous_details(&self, script: &str) -> Vec<DangerousMatch> {
        self.dangerous
            .iter()
            .filter_map(|(name, re)| {
                let found = re.find(script)?;
                // A match may start on the separator before the command (`\n`, `;`), so the line
                // is the one where its text begins.
                let start = found.start() + (found.as_str().len() - found.as_str().trim_start().len());
                let line_start = script[..start].rfind('\n').map_or(0, |i| i + 1);
                let line_end = script[start..].find('\n').map_or(script.len(), |i| start + i);
                let text: String = script[line_start..line_end].trim().chars().take(200).collect();
                Some(DangerousMatch {
                    rule: name.clone(),
                    text,
                    line: script[..line_start].matches('\n').count() + 1,
                })
            })
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
            Command::RemoteExec { script, .. } => self.classify_script(script),
            Command::AppUpdate { .. } => ActionKind::AppUpdate,
            Command::PushSshKey { .. } => ActionKind::SshKeyPush,
            // SS-10: a MultiExec line is rated like a bulk run's command. When Remotely could not follow
            // what was typed, the shells may run something else, so it is never read-only.
            Command::TerminalLine { line, unreliable, .. } => match self.classify_script(line) {
                ActionKind::ExecReadOnly if *unreliable => ActionKind::ExecOther,
                kind => kind,
            },
            // SS-08: replacing a file loses what was there; adding one does not.
            Command::FileUpload { files, .. } if files.iter().any(|f| f.replace) => ActionKind::FileReplace,
            Command::FileUpload { .. } => ActionKind::FileUpload,
        }
    }

    /// A shell command on its own: dangerous (BX-06), read-only, or other. Bulk runs use it, and the
    /// command panel (BX-08) shows it for each saved and built-in command.
    pub fn classify_script(&self, script: &str) -> ActionKind {
        if !self.dangerous_matches(script).is_empty() {
            ActionKind::ExecDangerous
        } else if commands::is_read_only(script, &self.rules.read_only_commands) {
            ActionKind::ExecReadOnly
        } else {
            ActionKind::ExecOther
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
        let count = match active.len() {
            1 => "1 target".to_owned(),
            n => format!("{n} targets"),
        };
        reasons.push(format!("{} on {count}: {}", action.label(), tier.as_str()));

        if let Command::RemoteExec { script, .. } | Command::TerminalLine { line: script, .. } = command {
            let hits = self.dangerous_matches(script);
            if !hits.is_empty() {
                reasons.push(format!("flagged dangerous: {}", hits.join(", ")));
            }
        }

        // SS-10: a line Remotely could not follow gets at least a confirm, whatever the rules say for
        // "other" commands: the approval shows what is known of it.
        if let Command::TerminalLine { unreliable: true, .. } = command {
            reasons.push(
                "the line was edited with keys Remotely can't follow (Tab, arrow keys, history) or had text on it \
                 already, so the terminals may run something else"
                    .into(),
            );
            if tier < Tier::Medium {
                reasons.push(format!("{} -> {}", tier.as_str(), Tier::Medium.as_str()));
                tier = Tier::Medium;
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
            warnings: Vec::new(),
        }
    }

    fn steps_for(&self, tier: Tier, command: &Command, target_count: usize) -> Vec<ApprovalStep> {
        match tier {
            Tier::Low => vec![],
            Tier::Medium => vec![ApprovalStep::Confirm],
            Tier::High | Tier::Critical => {
                let mut steps = vec![ApprovalStep::ImpactPreview];
                if safety_snapshot_applies(command) {
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

/// VM-05: a safety snapshot is offered (when the tier is High or Critical) for the VM actions that
/// can lose what the guest is doing: stop, reset, suspend and revert. The rest have nothing to undo
/// (start, pause, unpause), are snapshots themselves (take), would undo their own purpose (deleting
/// snapshots to free space would add one per VM; the deleted snapshot is not in it anyway) or do not
/// touch the VM (protect). The job runner asks this too, so the dialog and the job always agree.
pub fn safety_snapshot_applies(command: &Command) -> bool {
    let on_vms = command.targets().iter().any(|t| matches!(t, TargetRef::Vm { .. }));
    let can_lose_state = match command {
        Command::VmPower { op, .. } => matches!(op, PowerOp::Stop { .. } | PowerOp::Reset { .. } | PowerOp::Suspend),
        Command::VmSnapshot { op, .. } => matches!(op, SnapshotOp::Revert { .. }),
        Command::VmProtect { .. }
        | Command::RemoteExec { .. }
        | Command::AppUpdate { .. }
        | Command::PushSshKey { .. }
        | Command::TerminalLine { .. }
        | Command::FileUpload { .. } => false,
    };
    on_vms && can_lose_state
}
