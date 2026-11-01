//! FD-08: what was done in the handover's dates, grouped as the Activity page groups it (`src/lib/activity.ts`
//! `groupActivity`): each job is one item with its audit entries folded under it (approval asked, approved, started,
//! finished), the approval that let it run included (the core writes an approval's entries before the job exists, so
//! the approval of the same action granted just before the job is its own). Entries of no job that changed
//! something (a session edited, a host key trusted, a VM's environment) are listed apart; what only concerns this PC
//! (the vault unlocking, a setting, the trash, a workspace switch, an export) is left out of a customer's pack.
//!
//! Every text goes through [`super::table::clean`] when it is written (secrets redacted); a job's output only with
//! "Include outputs", each capped.

use std::collections::HashMap;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::command_bus::ApprovalRecord;
use crate::store::{AuditEntry, JobSummary};

/// How long an approval lives (the core's `APPROVAL_TTL`), and the slack for the job's countdown after it.
const APPROVAL_LIFE_MS: i64 = 15 * 60 * 1000;
const COUNTDOWN_SLACK_MS: i64 = 10 * 60 * 1000;

/// Approval events that end an approval without a job.
const APPROVAL_ENDS: [&str; 3] = ["approval_cancelled", "approval_expired", "approval_refused"];

/// Events of no job that concern only this PC or the app's own data, left out of the pack.
const LOCAL_ONLY: [&str; 18] = [
    "vault_",
    "workspace_",
    "setting_",
    "alert_",
    "dashboard_",
    "history_pruned",
    "journal_purged",
    "trash_",
    "audit_exported",
    "data_exported",
    "data_imported",
    "database_set_aside",
    "favourite_",
    "multiexec_group_",
    "terminal_",
    "folder_hook_",
    "note_changed",
    "job_exported",
];

/// One job, or one entry of its own.
#[derive(Debug, Clone)]
pub struct Group {
    pub key: String,
    pub job: Option<JobSummary>,
    /// The approval the job ran under, as journaled.
    pub approval: Option<ApprovalRecord>,
    pub title: String,
    /// When it began, in Unix ms: its approval's ask, the job's creation or its first entry.
    pub at_ms: i64,
    pub tier: Option<String>,
    /// Oldest first.
    pub entries: Vec<AuditEntry>,
    pub targets: Vec<String>,
    /// The last result written.
    pub result: Option<String>,
}

impl Group {
    pub fn is_job(&self) -> bool {
        self.job.is_some()
    }
}

pub fn ms(ts: &str) -> i64 {
    OffsetDateTime::parse(ts, &Rfc3339)
        .map(|t| i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(0))
        .unwrap_or(0)
}

/// The names an entry's targets carry.
pub fn target_names(targets_json: &str) -> Vec<String> {
    let parsed: Vec<Value> = serde_json::from_str(targets_json).unwrap_or_default();
    parsed
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .collect()
}

fn add_targets(group: &mut Group, names: Vec<String>) {
    for name in names {
        if !group.targets.contains(&name) {
            group.targets.push(name);
        }
    }
}

/// Jobs and entries as one list, oldest first (a pack reads in order), each job with its entries folded under it.
pub fn group(jobs: Vec<(JobSummary, Option<String>)>, audit: &[AuditEntry]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut by_job: HashMap<String, usize> = HashMap::new();
    for (job, approval) in jobs {
        by_job.insert(job.id.clone(), groups.len());
        groups.push(Group {
            key: job.id.clone(),
            approval: approval.and_then(|a| serde_json::from_str(&a).ok()),
            title: job.summary.clone(),
            at_ms: ms(&job.created_at),
            tier: Some(job.tier.clone()),
            job: Some(job),
            entries: Vec::new(),
            targets: Vec::new(),
            result: None,
        });
    }
    let mut merged = vec![false; groups.len()];
    // Approvals asked and not ended yet, by action text: the group, and when it was granted.
    let mut approvals: HashMap<String, (usize, Option<i64>)> = HashMap::new();
    let mut entries: Vec<&AuditEntry> = audit.iter().collect();
    entries.sort_by_key(|e| e.seq);
    for entry in entries {
        let names = target_names(&entry.targets_json);
        let at = ms(&entry.ts);
        if let Some(job_id) = &entry.job_id {
            let index = match by_job.get(job_id) {
                Some(i) => *i,
                None => {
                    // A job older than the range whose entries are in it.
                    by_job.insert(job_id.clone(), groups.len());
                    groups.push(Group {
                        key: job_id.clone(),
                        job: None,
                        approval: None,
                        title: entry.action.clone(),
                        at_ms: at,
                        tier: entry.tier.clone(),
                        entries: Vec::new(),
                        targets: Vec::new(),
                        result: None,
                    });
                    merged.push(false);
                    groups.len() - 1
                }
            };
            if groups[index].entries.is_empty() {
                // The approval of this action, granted shortly before, is the job's.
                if let Some(&(open, Some(granted))) = approvals.get(&entry.action) {
                    if at >= granted - 1000 && at - granted <= COUNTDOWN_SLACK_MS && open != index {
                        approvals.remove(&entry.action);
                        merged[open] = true;
                        let folded = std::mem::take(&mut groups[open].entries);
                        let targets = std::mem::take(&mut groups[open].targets);
                        let tier = groups[open].tier.clone();
                        let group = &mut groups[index];
                        let mut all = folded;
                        all.append(&mut group.entries);
                        group.entries = all;
                        if group.tier.is_none() {
                            group.tier = tier;
                        }
                        add_targets(group, targets);
                    }
                }
            }
            let group = &mut groups[index];
            group.entries.push(entry.clone());
            if entry.result.is_some() {
                group.result.clone_from(&entry.result);
            }
            if group.tier.is_none() {
                group.tier.clone_from(&entry.tier);
            }
            add_targets(group, names);
            continue;
        }
        if entry.event.starts_with("approval_") && entry.event != "approval_used" {
            let fresh = match approvals.get(&entry.action) {
                None => true,
                Some(&(open, _)) => entry.event == "approval_requested" || at - groups[open].at_ms > APPROVAL_LIFE_MS,
            };
            if fresh {
                approvals.insert(entry.action.clone(), (groups.len(), None));
                groups.push(Group {
                    key: format!("seq-{}", entry.seq),
                    job: None,
                    approval: None,
                    title: entry.action.clone(),
                    at_ms: at,
                    tier: entry.tier.clone(),
                    entries: Vec::new(),
                    targets: Vec::new(),
                    result: None,
                });
                merged.push(false);
            }
            if let Some((open, granted)) = approvals.get_mut(&entry.action) {
                let group = &mut groups[*open];
                group.entries.push(entry.clone());
                if group.tier.is_none() {
                    group.tier.clone_from(&entry.tier);
                }
                add_targets(group, names);
                if entry.event == "approval_granted" {
                    *granted = Some(at);
                }
            }
            if APPROVAL_ENDS.contains(&entry.event.as_str()) {
                approvals.remove(&entry.action);
            }
            continue;
        }
        groups.push(Group {
            key: format!("seq-{}", entry.seq),
            job: None,
            approval: None,
            title: entry.action.clone(),
            at_ms: at,
            tier: entry.tier.clone(),
            entries: vec![entry.clone()],
            targets: names,
            result: entry.result.clone(),
        });
        merged.push(false);
    }
    let mut kept: Vec<Group> = groups
        .into_iter()
        .zip(merged)
        .filter(|(_, m)| !m)
        .map(|(g, _)| g)
        .collect();
    for g in &mut kept {
        if let Some(first) = g.entries.first() {
            g.at_ms = g.at_ms.min(ms(&first.ts));
        }
    }
    kept.sort_by(|a, b| a.at_ms.cmp(&b.at_ms).then_with(|| a.key.cmp(&b.key)));
    kept
}

/// An entry of no job that belongs in a customer's pack: it changed something there, not only on this PC.
pub fn worth_listing(group: &Group) -> bool {
    if group.job.is_some() || group.entries.len() != 1 {
        return false;
    }
    let event = group.entries[0].event.as_str();
    !event.starts_with("approval_") && !LOCAL_ONLY.iter().any(|p| event.starts_with(p))
}

/// An event in words, as the Activity page says it (`EVENT_LABELS`); a code it doesn't know as its words.
pub fn event_label(event: &str) -> String {
    let known = match event {
        "approval_requested" => "Approval asked",
        "approval_granted" => "Approved",
        "approval_rejected" => "Approval refused: wrong vault password",
        "approval_cancelled" => "Approval cancelled",
        "approval_expired" => "Approval expired",
        "approval_refused" => "Refused: no standing approval",
        "approval_used" => "Ran on its standing approval",
        "job_started" => "Started",
        "job_finished" => "Finished",
        "job_cancelled" => "Cancelled",
        "canary_go_on" => "Went on after the first host",
        "host_key_trusted" => "Host key trusted",
        "host_key_retrusted" => "Host key replaced",
        "host_key_changed" => "Host key changed: blocked",
        "host_key_removed" => "Host key forgotten",
        "rdp_opened" => "Remote desktop opened",
        "vnc_opened" => "VNC viewer opened",
        "tunnel_opened" => "Tunnel opened",
        "tunnel_closed" => "Tunnel closed",
        "file_downloaded" => "File downloaded",
        "file_uploaded" => "File uploaded",
        "session_changed" => "Sessions changed",
        "sessions_imported" => "Sessions imported",
        "vm_assigned" => "VM added to the workspace",
        "vm_released" => "VM taken out of the workspace",
        "vm_label_changed" => "VM environment or protection changed",
        "vm_console_opened" => "Console opened",
        "catalog_changed" => "Templates changed",
        "stack_changed" => "Stack changed",
        "schedule_saved" => "Schedule saved",
        "schedule_paused" => "Schedule paused",
        "schedule_resumed" => "Schedule resumed",
        "schedule_deleted" => "Schedule deleted",
        "schedule_run" => "Schedule ran",
        "schedule_missed" => "Run missed",
        "schedule_skipped" => "Run skipped",
        "check_changed" => "Health check changed",
        _ => "",
    };
    if !known.is_empty() {
        return known.to_owned();
    }
    let words = event.replace('_', " ");
    let mut chars = words.trim().chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Event".into(),
    }
}

/// A result in words.
pub fn result_label(result: &str) -> String {
    match result {
        "succeeded" => "Succeeded".into(),
        "failed" => "Failed".into(),
        "partially_failed" | "partiallyFailed" => "Partly failed".into(),
        "cancelled" => "Cancelled".into(),
        "missed" => "Missed".into(),
        "skipped" => "Skipped".into(),
        "paused" => "Paused".into(),
        "interrupted" => "Interrupted".into(),
        other => {
            let words = other.replace('_', " ");
            let mut chars = words.chars();
            match chars.next() {
                Some(first) => first
                    .to_uppercase()
                    .chain(chars.map(|c| c.to_ascii_lowercase()))
                    .collect(),
                None => String::new(),
            }
        }
    }
}

/// A tier in words.
pub fn tier_label(tier: &str) -> &'static str {
    match tier {
        "low" => "Low",
        "medium" => "Medium",
        "high" => "High",
        "critical" => "Critical",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: i64, ts: &str, event: &str, action: &str, job: Option<&str>) -> AuditEntry {
        AuditEntry {
            seq,
            id: format!("e{seq}"),
            workspace_id: "w".into(),
            user_id: "u".into(),
            ts: ts.into(),
            event: event.into(),
            action: action.into(),
            tier: Some("high".into()),
            job_id: job.map(str::to_owned),
            targets_json: r#"[{"name":"web01"}]"#.into(),
            approval_json: None,
            result: (event == "job_finished").then(|| "succeeded".into()),
            detail: None,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    fn job(id: &str, created: &str) -> JobSummary {
        JobSummary {
            id: id.into(),
            summary: "Stop 1 VM".into(),
            action: "vmStop".into(),
            tier: "high".into(),
            status: "succeeded".into(),
            created_at: created.into(),
            started_at: None,
            finished_at: None,
            targets_total: 1,
            targets_succeeded: 1,
            targets_failed: 0,
            targets_unknown: 0,
            countdown_until: None,
            retry_of: None,
            bodies_removed: false,
            command_redacted: false,
            change_id: Some("CHG-1".into()),
        }
    }

    #[test]
    fn a_job_takes_its_approval_and_entries_of_their_own_stay_apart() {
        let audit = vec![
            entry(1, "2026-11-01T10:00:00Z", "approval_requested", "Stop 1 VM", None),
            entry(2, "2026-11-01T10:01:00Z", "approval_granted", "Stop 1 VM", None),
            entry(3, "2026-11-01T10:01:05Z", "job_started", "Stop 1 VM", Some("j1")),
            entry(4, "2026-11-01T10:01:30Z", "job_finished", "Stop 1 VM", Some("j1")),
            entry(
                5,
                "2026-11-01T11:00:00Z",
                "host_key_trusted",
                "Trusted a host key",
                None,
            ),
            entry(6, "2026-11-01T12:00:00Z", "vault_unlocked", "Unlocked the vault", None),
            entry(7, "2026-11-01T12:30:00Z", "approval_requested", "Delete 3 VMs", None),
            entry(8, "2026-11-01T12:31:00Z", "approval_cancelled", "Delete 3 VMs", None),
        ];
        let groups = group(vec![(job("j1", "2026-11-01T10:01:02Z"), None)], &audit);
        assert_eq!(groups.len(), 4, "{groups:#?}");
        let j = &groups[0];
        assert!(j.is_job());
        let events: Vec<&str> = j.entries.iter().map(|e| e.event.as_str()).collect();
        assert_eq!(
            events,
            ["approval_requested", "approval_granted", "job_started", "job_finished"]
        );
        assert_eq!(
            j.at_ms,
            ms("2026-11-01T10:00:00Z"),
            "it began when its approval was asked"
        );
        assert_eq!(j.result.as_deref(), Some("succeeded"));
        assert_eq!(j.targets, ["web01"]);
        assert!(worth_listing(&groups[1]), "a host key trusted");
        assert!(!worth_listing(&groups[2]), "the vault: this PC's");
        assert!(!worth_listing(&groups[3]), "an approval that never ran");
    }

    #[test]
    fn words_for_codes() {
        assert_eq!(event_label("job_started"), "Started");
        assert_eq!(event_label("something_new"), "Something new");
        assert_eq!(event_label(""), "Event");
        assert_eq!(result_label("partially_failed"), "Partly failed");
        assert_eq!(result_label("WEIRD_one"), "Weird one");
        assert_eq!(tier_label("critical"), "Critical");
        assert_eq!(ms("not a time"), 0);
        assert_eq!(target_names("not json"), Vec::<String>::new());
    }
}
