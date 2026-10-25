//! VM-14, VM-27: what a schedule does, on which targets and when, and the commands each run submits to the bus.
//!
//! The content (action, targets, timing) is what its approval is given for: [`ScheduleSpec::content_hash`] is the
//! SHA-256 of it, kept with the standing approval, so an edit of any of it asks again. The schedule's name is not
//! part of it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::timing::Timing;
use crate::command_bus::{Command, PowerOp, SnapshotOp, StopMode, MAX_SNAPSHOT_NAME};
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};

/// VM-27: the most snapshots a schedule keeps.
pub const MAX_KEEP: u32 = 100;
/// The longest schedule name.
pub const MAX_NAME: usize = 80;
/// The most targets (VMs and tags) one schedule lists.
pub const MAX_TARGETS: usize = 100;
/// VM-27: every snapshot a schedule takes is named starting with this, so it is easy to spot in Workstation and
/// VirtualBox too. Retention goes by the id recorded when it was taken, not by the name.
pub const SNAPSHOT_PREFIX: &str = "Remotely schedule";

/// What a schedule does at each run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScheduleAction {
    /// VM-27: take a snapshot of each VM. With `keep`, then delete the schedule's own snapshots beyond the newest
    /// `keep` of each VM (only snapshots it took, recorded by id).
    Snapshot {
        #[serde(default)]
        keep: Option<u32>,
    },
    /// VM-14: power on the VMs that are off or suspended.
    Start,
    /// VM-14: shut the running VMs down through the guest (VMware Tools; VirtualBox's ACPI power button).
    Stop,
    /// VM-14: suspend the running VMs. With idle timing, the ones idle long enough (auto-suspend).
    Suspend,
    /// VM-14: power on the VMs that are suspended; the ones that are off stay off.
    Resume,
}

impl ScheduleAction {
    pub fn label(&self) -> String {
        match self {
            ScheduleAction::Snapshot { keep: None } => "Take a snapshot".into(),
            ScheduleAction::Snapshot { keep: Some(1) } => "Take a snapshot, keep the last 1".into(),
            ScheduleAction::Snapshot { keep: Some(n) } => format!("Take a snapshot, keep the last {n}"),
            ScheduleAction::Start => "Start".into(),
            ScheduleAction::Stop => "Shut down".into(),
            ScheduleAction::Suspend => "Suspend".into(),
            ScheduleAction::Resume => "Resume".into(),
        }
    }

    /// The power operation of a power action.
    pub fn power_op(&self) -> Option<PowerOp> {
        match self {
            ScheduleAction::Start | ScheduleAction::Resume => Some(PowerOp::Start { gui: false }),
            ScheduleAction::Stop => Some(PowerOp::Stop { mode: StopMode::Soft }),
            ScheduleAction::Suspend => Some(PowerOp::Suspend),
            ScheduleAction::Snapshot { .. } => None,
        }
    }
}

/// What a schedule acts on. Each run looks the VMs up again: a tag's VMs are the ones with it then (a new one asks
/// again before it is touched).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ScheduleTarget {
    /// One VM, by its key (.vmx path or VirtualBox UUID).
    Vm { vm_key: String },
    /// Every VM with this tag.
    Tag { tag: String },
    /// VM-08: every VM of every instance of this stack, looked up like a tag's ([`super::Schedules::resolve`]); a
    /// VM that joins an instance later asks again before it is touched.
    Stack { stack_id: Uuid },
}

impl ScheduleTarget {
    fn sort_key(&self) -> (u8, String) {
        match self {
            ScheduleTarget::Vm { vm_key } => (0, vm_key.to_lowercase()),
            ScheduleTarget::Tag { tag } => (1, tag.to_lowercase()),
            ScheduleTarget::Stack { stack_id } => (2, stack_id.to_string()),
        }
    }
}

/// A schedule's content: what its approval is given for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleSpec {
    pub action: ScheduleAction,
    pub targets: Vec<ScheduleTarget>,
    pub timing: Timing,
}

impl ScheduleSpec {
    /// Checks it, and puts the targets in one order (each once), so the same content always hashes the same.
    pub fn normalized(self) -> Result<Self> {
        let invalid = |message: String| Err(CoreError::InvalidInput(message));
        let timing = self.timing.normalized()?;
        if timing.is_idle() && self.action != ScheduleAction::Suspend {
            return invalid("Only Suspend can run when VMs are idle (auto-suspend).".into());
        }
        if let ScheduleAction::Snapshot { keep: Some(keep) } = self.action {
            if !(1..=MAX_KEEP).contains(&keep) {
                return invalid(format!("Keep 1 to {MAX_KEEP} snapshots, or turn retention off."));
            }
        }
        let mut targets = Vec::with_capacity(self.targets.len());
        for target in self.targets {
            let target = match target {
                ScheduleTarget::Vm { vm_key } => {
                    let vm_key = vm_key.trim().to_owned();
                    if vm_key.is_empty() {
                        return invalid("A VM target has no VM.".into());
                    }
                    ScheduleTarget::Vm { vm_key }
                }
                ScheduleTarget::Tag { tag } => {
                    let tag = crate::store::clean_name("tag", &tag, crate::store::MAX_TAG_LEN)?;
                    ScheduleTarget::Tag { tag }
                }
                ScheduleTarget::Stack { stack_id } => ScheduleTarget::Stack { stack_id },
            };
            if !targets
                .iter()
                .any(|t: &ScheduleTarget| t.sort_key() == target.sort_key())
            {
                targets.push(target);
            }
        }
        if targets.is_empty() {
            return invalid("Choose at least one VM, tag or stack.".into());
        }
        if targets.len() > MAX_TARGETS {
            return invalid(format!(
                "A schedule can list at most {MAX_TARGETS} VMs, tags and stacks."
            ));
        }
        targets.sort_by_key(ScheduleTarget::sort_key);
        Ok(Self {
            action: self.action,
            targets,
            timing,
        })
    }

    /// SHA-256 of the content, in hex.
    pub fn content_hash(&self) -> String {
        let text = serde_json::to_string(self).unwrap_or_default();
        hex::encode(Sha256::digest(text.as_bytes()))
    }

    /// The commands a run submits, on `targets`: what the approval is asked for when the schedule is saved. A
    /// snapshot's name is the run's; `snapshot_name` stands in for it here.
    pub fn commands(&self, targets: Vec<TargetRef>, snapshot_name: &str) -> Vec<Command> {
        match &self.action {
            ScheduleAction::Snapshot { keep } => {
                let take = Command::VmSnapshot {
                    targets: targets.clone(),
                    op: SnapshotOp::Take {
                        name: snapshot_name.to_owned(),
                    },
                };
                match keep {
                    None => vec![take],
                    Some(_) => vec![
                        take,
                        Command::VmSnapshot {
                            targets,
                            op: SnapshotOp::Delete {
                                name: snapshot_name.to_owned(),
                            },
                        },
                    ],
                }
            }
            other => other
                .power_op()
                .map(|op| vec![Command::VmPower { targets, op }])
                .unwrap_or_default(),
        }
    }

    /// For the approval dialog and the audit log: "Schedule 'nightly': take a snapshot of 3 VMs daily at 02:00,
    /// keeping the last 7".
    pub fn summary(&self, name: &str, vms: usize) -> String {
        let vms = match vms {
            1 => "1 VM".to_owned(),
            n => format!("{n} VMs"),
        };
        let when = self.timing.describe();
        let when = match self.timing {
            Timing::Idle { .. } => when.replacen("When", "when", 1),
            _ => lower_first(&when),
        };
        let what = match &self.action {
            ScheduleAction::Snapshot { keep: None } => format!("take a snapshot of {vms} {when}"),
            ScheduleAction::Snapshot { keep: Some(n) } => {
                format!("take a snapshot of {vms} {when}, keeping the last {n}")
            }
            ScheduleAction::Start => format!("start {vms} {when}"),
            ScheduleAction::Stop => format!("shut down {vms} {when}"),
            ScheduleAction::Suspend => format!("suspend {vms} {when}"),
            ScheduleAction::Resume => format!("resume {vms} {when} (the suspended ones)"),
        };
        format!("Schedule '{name}': {what}")
    }
}

fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// A schedule name as typed: trimmed, 1 to [`MAX_NAME`] characters, no line breaks.
pub fn clean_schedule_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Give the schedule a name.".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "A schedule name can't hold line breaks or tabs.".into(),
        ));
    }
    if name.chars().count() > MAX_NAME {
        return Err(CoreError::InvalidInput(format!(
            "A schedule name can be at most {MAX_NAME} characters."
        )));
    }
    Ok(name.to_owned())
}

/// VM-27: the name of the snapshots one run takes, e.g. `Remotely schedule 'nightly' 2026-10-25 02:00 (run
/// 1a2b3c4d)`: recognisable, the local time it was due, and the run's id so two runs never share a name. No `/`
/// (vmrun reads it as a path) and at most [`MAX_SNAPSHOT_NAME`] characters.
pub fn snapshot_name(schedule: &str, due_local: OffsetDateTime, run_id: Uuid) -> String {
    let shown: String = schedule
        .chars()
        .map(|c| if c == '/' || c.is_control() { '-' } else { c })
        .take(40)
        .collect();
    let shown = shown.trim();
    let when = format!(
        "{}-{:02}-{:02} {:02}:{:02}",
        due_local.year(),
        u8::from(due_local.month()),
        due_local.day(),
        due_local.hour(),
        due_local.minute()
    );
    let run = run_id.simple().to_string();
    let name = format!("{SNAPSHOT_PREFIX} '{shown}' {when} (run {})", &run[..8]);
    name.chars().take(MAX_SNAPSHOT_NAME).collect()
}

/// The name a save's approval shows for the snapshots its runs take.
pub fn example_snapshot_name(schedule: &str) -> String {
    let shown: String = schedule
        .chars()
        .map(|c| if c == '/' || c.is_control() { '-' } else { c })
        .take(40)
        .collect();
    format!("{SNAPSHOT_PREFIX} '{}' <date and time>", shown.trim())
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::super::timing::{Day, WallTime};
    use super::*;

    fn daily() -> Timing {
        Timing::Daily {
            at: WallTime::new(2, 0).unwrap(),
        }
    }

    fn spec(action: ScheduleAction, targets: Vec<ScheduleTarget>) -> ScheduleSpec {
        ScheduleSpec {
            action,
            targets,
            timing: daily(),
        }
    }

    fn vm(key: &str) -> ScheduleTarget {
        ScheduleTarget::Vm { vm_key: key.into() }
    }

    fn tag(name: &str) -> ScheduleTarget {
        ScheduleTarget::Tag { tag: name.into() }
    }

    #[test]
    fn the_same_content_hashes_the_same_in_any_order_and_any_change_hashes_differently() {
        let a = spec(
            ScheduleAction::Suspend,
            vec![vm(r"C:\VMs\b\b.vmx"), tag("lab"), vm(r"C:\VMs\a\a.vmx")],
        )
        .normalized()
        .unwrap();
        let b = spec(
            ScheduleAction::Suspend,
            vec![tag("lab"), vm(r"C:\VMs\a\a.vmx"), vm(r"C:\VMs\b\b.vmx")],
        )
        .normalized()
        .unwrap();
        assert_eq!(a.content_hash(), b.content_hash());
        let other_action = ScheduleSpec {
            action: ScheduleAction::Stop,
            ..a.clone()
        };
        let other_time = ScheduleSpec {
            timing: Timing::Weekly {
                days: vec![Day::Mon],
                at: WallTime::new(2, 0).unwrap(),
            },
            ..a.clone()
        };
        let fewer = ScheduleSpec {
            targets: vec![tag("lab")],
            ..a.clone()
        };
        for changed in [other_action, other_time, fewer] {
            assert_ne!(changed.content_hash(), a.content_hash());
        }
    }

    #[test]
    fn targets_are_kept_once() {
        let s = spec(ScheduleAction::Start, vec![tag("Lab"), tag("lab"), vm("x"), vm("X")])
            .normalized()
            .unwrap();
        assert_eq!(s.targets.len(), 2);
    }

    #[test]
    fn bad_content_is_refused() {
        assert!(spec(ScheduleAction::Start, vec![]).normalized().is_err());
        assert!(spec(ScheduleAction::Start, vec![vm("  ")]).normalized().is_err());
        assert!(spec(ScheduleAction::Snapshot { keep: Some(0) }, vec![vm("x")])
            .normalized()
            .is_err());
        assert!(spec(
            ScheduleAction::Snapshot {
                keep: Some(MAX_KEEP + 1)
            },
            vec![vm("x")]
        )
        .normalized()
        .is_err());
        let idle = Timing::Idle {
            minutes: 30,
            cpu_below_pct: 5,
        };
        let idle_start = ScheduleSpec {
            timing: idle.clone(),
            ..spec(ScheduleAction::Start, vec![vm("x")])
        };
        assert!(idle_start.normalized().is_err(), "only Suspend can run on idle");
        let idle_suspend = ScheduleSpec {
            timing: idle,
            ..spec(ScheduleAction::Suspend, vec![vm("x")])
        };
        assert!(idle_suspend.normalized().is_ok());
        assert!(clean_schedule_name(" ").is_err());
        assert!(clean_schedule_name("a\nb").is_err());
        assert!(clean_schedule_name(&"x".repeat(MAX_NAME + 1)).is_err());
        assert_eq!(clean_schedule_name("  nightly ").unwrap(), "nightly");
    }

    #[test]
    fn a_snapshot_schedule_with_retention_runs_a_take_and_a_delete() {
        let targets = vec![TargetRef::Vm {
            vmx_path: r"C:\VMs\a\a.vmx".into(),
        }];
        let commands = spec(ScheduleAction::Snapshot { keep: Some(3) }, vec![vm("x")]).commands(targets.clone(), "n");
        assert!(matches!(
            commands.as_slice(),
            [
                Command::VmSnapshot {
                    op: SnapshotOp::Take { .. },
                    ..
                },
                Command::VmSnapshot {
                    op: SnapshotOp::Delete { .. },
                    ..
                }
            ]
        ));
        let resume = spec(ScheduleAction::Resume, vec![vm("x")]).commands(targets, "n");
        assert!(matches!(
            resume.as_slice(),
            [Command::VmPower {
                op: PowerOp::Start { gui: false },
                ..
            }]
        ));
    }

    #[test]
    fn snapshot_names_are_recognisable_unique_per_run_and_never_hold_a_slash() {
        let run = Uuid::parse_str("1a2b3c4d-0000-4000-8000-000000000000").unwrap();
        let name = snapshot_name("lab/web nightly", datetime!(2026-10-25 02:00 +2), run);
        assert_eq!(
            name,
            "Remotely schedule 'lab-web nightly' 2026-10-25 02:00 (run 1a2b3c4d)"
        );
        assert!(!name.contains('/'));
        let long = snapshot_name(&"x".repeat(80), datetime!(2026-10-25 02:00 UTC), run);
        assert!(long.chars().count() <= MAX_SNAPSHOT_NAME);
        assert!(long.starts_with(SNAPSHOT_PREFIX));
    }

    #[test]
    fn summaries_say_what_when_and_how_many() {
        let s = spec(ScheduleAction::Snapshot { keep: Some(7) }, vec![tag("lab")]);
        assert_eq!(
            s.summary("nightly", 3),
            "Schedule 'nightly': take a snapshot of 3 VMs daily at 02:00, keeping the last 7"
        );
        let idle = ScheduleSpec {
            timing: Timing::Idle {
                minutes: 30,
                cpu_below_pct: 5,
            },
            ..spec(ScheduleAction::Suspend, vec![tag("lab")])
        };
        assert_eq!(
            idle.summary("idle lab", 1),
            "Schedule 'idle lab': suspend 1 VM when idle for 30 minutes (CPU under 5%)"
        );
    }
}
