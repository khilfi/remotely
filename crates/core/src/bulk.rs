//! Bulk execution (BX-01, BX-03, BX-05): which hosts a run reaches, its results grouped by output, the
//! diff between two groups, and exports. Running a command is `Command::RemoteExec` through the
//! command bus; everything here reads, except an export, which writes the file the user chose and is
//! audited. The Terminal page's Compare output (BX-03, post-MVP P6) runs one command this way on the
//! hosts of the picked tabs and of sessions picked in its tree.
//!
//! * BX-01: hosts are saved sessions. A VM is reached through a session linked to it
//!   (`sessions.vm_id`); a VM with none can't run commands yet (guest operations, VM-09, are v2).
//!   A4, H11: only through a link the user chose or confirmed. An automatic link (QL-01) rests on the
//!   address the guest reports about itself, which a hostile VM can make up (a production server's
//!   IP), so a VM whose only links are automatic is listed in [`ResolvedTargets::vms_unconfirmed`]
//!   instead of being reached, until the user confirms the link.
//!   Tags pick sessions and VMs; saved filters pick VMs; an open terminal picks its saved session (a
//!   quick connection that was not saved has none to run on).
//! * BX-03: finished hosts group by exit code and output (stdout and stderr, hashed whole as they
//!   arrived, so a cut output still groups right), optionally ignoring trailing whitespace. Hosts that
//!   failed before their command ran group by cause.
//! * BX-05: CSV, JSON or HTML. The run's vault secrets were scrubbed from the output before it was
//!   stored (BX-07), and every text an export writes goes through [`redact_secrets`] as well.
//! * QL-12: a MultiExec line recorded in each terminal (`terminal::record`) groups and diffs with the
//!   same code ([`group_with_output`], [`diff_lines`]) and exports the same way, with each group's
//!   diff from group A ([`BulkRuns::export_recorded`]).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use similar::{ChangeTag, TextDiff};
use uuid::Uuid;

use crate::adapters::vmware::path_key;
use crate::command_bus::Command;
use crate::domain::{Context, Environment};
use crate::error::{CoreError, Result};
use crate::export::{push_row, redact_secrets};
use crate::jobs::TargetStatus;
use crate::policy::Tier;
use crate::sessions::SessionRecord;
use crate::store::{JobSummary, JobTargetRecord, NewAuditEntry, Store, VmRecord};
use crate::terminal::Terminals;

// ---- BX-01: targets ----------------------------------------------------------------------------

/// What the user picked: tabs and sessions in the Terminal page's tree (Compare), or sessions, VMs,
/// tags and filters (the SS-09 key push). Every list may be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetPicks {
    pub session_ids: Vec<Uuid>,
    /// Open terminals (picked tabs), each reached through its saved session.
    pub terminal_ids: Vec<Uuid>,
    /// VMs by .vmx path; each is reached through its linked session.
    pub vm_paths: Vec<String>,
    /// Sessions and VMs with any of these tags.
    pub tags: Vec<String>,
    /// Saved VM filters (VM-02), by id.
    pub filter_ids: Vec<String>,
}

/// A host a run will reach: a saved session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkHost {
    pub session_id: Uuid,
    pub name: String,
    /// `user@host:port`.
    pub address: String,
    /// As the policy engine sees it: Prod when the session or its VM is labelled Prod.
    pub environment: Environment,
    /// AP-04: skipped by the run (the session or its VM is protected).
    pub protected: bool,
    /// The VM the session reaches, if one is linked.
    pub vm_name: Option<String>,
    /// How it was picked, e.g. "session", "VM 'web01'", "tag 'web'", "filter 'Lab'".
    pub via: Vec<String>,
}

/// BX-01: a picked VM that no session reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmWithoutSession {
    pub vmx_path: String,
    pub name: String,
    pub via: Vec<String>,
}

/// A4, H11: a picked VM whose linked session was linked automatically, by the address the guest
/// reports. A run reaches it once the user confirms that link (`VmLinks::confirm`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedLink {
    pub vmx_path: String,
    pub name: String,
    pub session_id: Uuid,
    pub session_name: String,
    /// `user@host:port` of the session.
    pub address: String,
    pub via: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedTargets {
    /// By name. Submit these as the run's session targets.
    pub hosts: Vec<BulkHost>,
    /// Picked VMs a run can't reach yet: commands go over SSH, through a session linked to the VM.
    /// Running them through VMware Tools without SSH (VM-09) comes in v2.
    pub vms_without_session: Vec<VmWithoutSession>,
    /// A4, H11: picked VMs reached only through an automatic link, which the user has to confirm
    /// first. They are not in `hosts`.
    pub vms_unconfirmed: Vec<UnconfirmedLink>,
    /// Worth knowing, e.g. a VM with two linked sessions (the first by name is used).
    pub notes: Vec<String>,
}

/// Collects picked sessions and VMs, keeping the order they were first picked and every reason.
#[derive(Default)]
struct Picked {
    sessions: Vec<Uuid>,
    via: HashMap<Uuid, Vec<String>>,
    vms: Vec<String>,
    vm_via: HashMap<String, Vec<String>>,
    /// A4, H11: VMs reached only through an automatic link, with that session.
    unconfirmed: Vec<(String, Uuid)>,
    notes: Vec<String>,
}

impl Picked {
    fn session(&mut self, id: Uuid, via: String) {
        let reasons = self.via.entry(id).or_default();
        if reasons.is_empty() {
            self.sessions.push(id);
        }
        if !reasons.contains(&via) {
            reasons.push(via);
        }
    }

    fn vm(
        &mut self,
        vm: &VmRecord,
        linked: &HashMap<String, Vec<Uuid>>,
        sessions: &HashMap<Uuid, &SessionRecord>,
        via: String,
    ) {
        let all = linked.get(&vm.id).map(Vec::as_slice).unwrap_or_default();
        // A4, H11: only links the user chose or confirmed reach a VM.
        let confirmed: Vec<Uuid> = all
            .iter()
            .copied()
            .filter(|id| {
                sessions
                    .get(id)
                    .is_some_and(|s| s.vm_link != Some(crate::vm_links::VmLink::Auto))
            })
            .collect();
        let name = |id: &Uuid| sessions.get(id).map_or("the first", |s| s.name.as_str());
        match (confirmed.as_slice(), all.first()) {
            ([first, rest @ ..], _) => {
                if !rest.is_empty() {
                    let note = format!(
                        "VM '{}' has {} linked sessions; the run uses '{}'",
                        vm.display_name,
                        rest.len() + 1,
                        name(first)
                    );
                    if !self.notes.contains(&note) {
                        self.notes.push(note);
                    }
                }
                if confirmed.len() < all.len() {
                    let note = format!(
                        "VM '{}' also has a session linked automatically, which the run doesn't use",
                        vm.display_name
                    );
                    if !self.notes.contains(&note) {
                        self.notes.push(note);
                    }
                }
                self.session(*first, via);
            }
            ([], Some(auto)) => {
                let reasons = self.vm_via.entry(vm.id.clone()).or_default();
                if reasons.is_empty() {
                    self.unconfirmed.push((vm.id.clone(), *auto));
                }
                if !reasons.contains(&via) {
                    reasons.push(via);
                }
            }
            ([], None) => {
                let reasons = self.vm_via.entry(vm.id.clone()).or_default();
                if reasons.is_empty() {
                    self.vms.push(vm.id.clone());
                }
                if !reasons.contains(&via) {
                    reasons.push(via);
                }
            }
        }
    }
}

fn address(s: &SessionRecord) -> String {
    let user = s.username.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
    format!("{user}{}", crate::known_hosts::address(&s.host, s.port))
}

// ---- BX-03: results ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GroupOptions {
    /// Spaces, tabs and `\r` at line ends, and blank lines at the end, don't make outputs differ.
    pub ignore_trailing_whitespace: bool,
}

/// What a remote command run was asked to do, for the results view (no secret: a vault id at most).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunInfo {
    pub script: String,
    pub sudo: bool,
    pub trust_new_host_keys: bool,
    pub timeout_secs: Option<u64>,
}

/// One host of a run, without its output (that is in its group, or [`BulkRuns::host_output`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub target_key: String,
    pub name: String,
    pub status: String,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub stdout_bytes: Option<i64>,
    pub stderr_bytes: Option<i64>,
    pub truncated: bool,
    /// Index into the groups; `None` while it waits or runs, and when it was cancelled.
    pub group: Option<usize>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// The address this PC reached (a host reached directly).
    pub peer_ip: Option<String>,
    /// The host key the host presented and the run accepted.
    pub host_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupKind {
    /// The command ran: same exit code and output.
    Output,
    /// It failed before or around the command (connection, login, sudo, time limit): same cause.
    Error,
}

/// Hosts with the same result (BX-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputGroup {
    /// "A", "B", … by size, largest first.
    pub label: String,
    pub kind: GroupKind,
    /// Every host in it succeeded.
    pub ok: bool,
    pub exit_code: Option<i64>,
    /// An error group's cause: the first host's message, and its code.
    pub error: Option<String>,
    pub error_code: Option<String>,
    /// The hosts' messages are not all the same (they often name their own address).
    pub messages_differ: bool,
    /// Target keys, in the run's order.
    pub hosts: Vec<String>,
    /// The host whose output stands for the group.
    pub sample: String,
    /// The sample's output, unless the reply was already large (then load it with
    /// [`BulkRuns::host_output`]).
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub total: usize,
    pub pending: usize,
    pub running: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: usize,
    /// H9: timed out, or cancelled while the command ran: it may have run.
    pub unknown: usize,
    /// H9: never started (the run stopped after its failures, or after its canary).
    pub skipped: usize,
}

/// A run's results, grouped (BX-03).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResults {
    pub job: JobSummary,
    /// `None` for a job that was not a remote command.
    pub run: Option<RunInfo>,
    pub counts: Counts,
    pub hosts: Vec<HostResult>,
    pub groups: Vec<OutputGroup>,
    /// "48 hosts same, 2 differ".
    pub headline: String,
    pub ignore_trailing_whitespace: bool,
    /// H9: the canary host finished and the rest wait for the go-ahead (set by the caller, which
    /// asks the job runner).
    pub canary: Option<crate::jobs::CanaryWait>,
}

/// One host's whole stored output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOutput {
    pub target_key: String,
    pub name: String,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub exit_code: Option<i64>,
    pub error: Option<String>,
}

/// Sample outputs sent with the results, at most; the rest load on demand.
const SAMPLE_BUDGET: usize = 4 * 1024 * 1024;

/// "A".."Z", "AA".., like spreadsheet columns.
pub fn group_label(index: usize) -> String {
    let mut n = index + 1;
    let mut label = Vec::new();
    while n > 0 {
        let rem = (n - 1) % 26;
        label.push(char::from(b'A' + rem as u8));
        n = (n - 1) / 26;
    }
    label.iter().rev().collect()
}

/// The group a finished target belongs to, or `None` while it waits or runs, or when it was cancelled
/// or never started. H9: hosts whose outcome is unknown group by why (a time limit, a cancel).
fn group_key(t: &JobTargetRecord, opts: GroupOptions) -> Option<String> {
    if t.status == TargetStatus::Unknown.as_str() {
        return Some(format!("err:{}", t.error_code.as_deref().unwrap_or("unknown")));
    }
    if t.status != TargetStatus::Succeeded.as_str() && t.status != TargetStatus::Failed.as_str() {
        return None;
    }
    let hash = if opts.ignore_trailing_whitespace {
        &t.output_hash_loose
    } else {
        &t.output_hash
    };
    let exit = t.exit_code.map_or_else(|| "-".to_owned(), |c| c.to_string());
    Some(match hash {
        Some(hash) => format!("out:{exit}:{hash}"),
        None if t.status == TargetStatus::Failed.as_str() => {
            format!("err:{}", t.error_code.as_deref().unwrap_or("failed"))
        }
        // A target with no output that worked (a VM action).
        None => "done".to_owned(),
    })
}

/// BX-03: groups finished targets; returns the groups (without output yet) and each target's group.
fn group_targets(targets: &[JobTargetRecord], opts: GroupOptions) -> (Vec<OutputGroup>, Vec<Option<usize>>) {
    let mut order: Vec<String> = Vec::new();
    let mut members: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, t) in targets.iter().enumerate() {
        if let Some(key) = group_key(t, opts) {
            let list = members.entry(key.clone()).or_default();
            if list.is_empty() {
                order.push(key);
            }
            list.push(i);
        }
    }
    let mut groups: Vec<(String, Vec<usize>)> = order
        .into_iter()
        .map(|key| {
            let list = members.remove(&key).unwrap_or_default();
            (key, list)
        })
        .collect();
    // Largest first; then what worked, then by exit code; ties keep the run's order.
    groups.sort_by_key(|(key, list)| {
        let first = &targets[list[0]];
        (
            std::cmp::Reverse(list.len()),
            key.starts_with("err:"),
            first.status != TargetStatus::Succeeded.as_str(),
            first.exit_code,
        )
    });
    let mut of_target = vec![None; targets.len()];
    let groups = groups
        .into_iter()
        .enumerate()
        .map(|(index, (key, list))| {
            for &i in &list {
                of_target[i] = Some(index);
            }
            let first = &targets[list[0]];
            let error_group = key.starts_with("err:");
            let messages: HashSet<Option<&str>> = list.iter().map(|&i| targets[i].error.as_deref()).collect();
            OutputGroup {
                label: group_label(index),
                kind: if error_group {
                    GroupKind::Error
                } else {
                    GroupKind::Output
                },
                ok: list
                    .iter()
                    .all(|&i| targets[i].status == TargetStatus::Succeeded.as_str()),
                exit_code: first.exit_code,
                error: if error_group { first.error.clone() } else { None },
                error_code: if error_group { first.error_code.clone() } else { None },
                messages_differ: error_group && messages.len() > 1,
                hosts: list.iter().map(|&i| targets[i].target_key.clone()).collect(),
                sample: first.target_key.clone(),
                stdout: None,
                stderr: None,
                truncated: first.output_truncated,
            }
        })
        .collect();
    (groups, of_target)
}

/// Each target's row in the results, with its group.
fn host_rows(targets: impl IntoIterator<Item = JobTargetRecord>, of_target: Vec<Option<usize>>) -> Vec<HostResult> {
    targets
        .into_iter()
        .zip(of_target)
        .map(|(t, group)| HostResult {
            target_key: t.target_key,
            name: t.target_name,
            status: t.status,
            exit_code: t.exit_code,
            duration_ms: t.duration_ms,
            error: t.error,
            error_code: t.error_code,
            stdout_bytes: t.stdout_bytes,
            stderr_bytes: t.stderr_bytes,
            truncated: t.output_truncated,
            group,
            started_at: t.started_at,
            finished_at: t.finished_at,
            peer_ip: t.peer_ip,
            host_key: t.host_key,
        })
        .collect()
}

/// BX-03 for targets that carry their whole output already (QL-12: a MultiExec line recorded in each
/// terminal): the groups with their sample's output, the counts, each target's row and the headline.
#[derive(Debug, Clone)]
pub(crate) struct Grouped {
    pub groups: Vec<OutputGroup>,
    pub counts: Counts,
    pub hosts: Vec<HostResult>,
    pub headline: String,
}

pub(crate) fn group_with_output(targets: &[JobTargetRecord], opts: GroupOptions) -> Grouped {
    let (mut groups, of_target) = group_targets(targets, opts);
    let by_key: HashMap<&str, &JobTargetRecord> = targets.iter().map(|t| (t.target_key.as_str(), t)).collect();
    for group in &mut groups {
        if let Some(sample) = by_key.get(group.sample.as_str()) {
            group.stdout = Some(sample.output.clone().unwrap_or_default());
            group.stderr = Some(sample.stderr.clone().unwrap_or_default());
        }
    }
    let counts = count(targets);
    Grouped {
        headline: headline(&groups, &counts),
        hosts: host_rows(targets.iter().cloned(), of_target),
        groups,
        counts,
    }
}

fn count(targets: &[JobTargetRecord]) -> Counts {
    let mut counts = Counts {
        total: targets.len(),
        ..Counts::default()
    };
    for t in targets {
        match t.status.as_str() {
            "pending" => counts.pending += 1,
            "running" => counts.running += 1,
            "succeeded" => counts.succeeded += 1,
            "failed" => counts.failed += 1,
            "unknown" => counts.unknown += 1,
            "skipped" => counts.skipped += 1,
            _ => counts.cancelled += 1,
        }
    }
    counts
}

fn hosts(n: usize) -> String {
    if n == 1 {
        "1 host".into()
    } else {
        format!("{n} hosts")
    }
}

/// BX-03: the one line that sums up a run, e.g. "48 hosts same, 2 differ".
pub fn headline(groups: &[OutputGroup], counts: &Counts) -> String {
    let done: usize = groups.iter().map(|g| g.hosts.len()).sum();
    let largest = groups.first().map_or(0, |g| g.hosts.len());
    let mut text = match groups.len() {
        0 if counts.pending + counts.running > 0 => "Waiting for the first host".to_owned(),
        0 => "No host ran the command".to_owned(),
        1 if done == 1 => "1 host finished".to_owned(),
        1 => format!("All {done} hosts the same"),
        _ if largest == 1 => format!("{done} hosts, all different"),
        _ => format!("{} same, {} differ", hosts(largest), done - largest),
    };
    let open = counts.pending + counts.running;
    if open > 0 {
        text.push_str(&format!("; {} still to finish", hosts(open)));
    }
    if counts.unknown > 0 {
        text.push_str(&format!("; {} with the outcome unknown", hosts(counts.unknown)));
    }
    if counts.cancelled > 0 {
        text.push_str(&format!("; {} cancelled", counts.cancelled));
    }
    if counts.skipped > 0 {
        text.push_str(&format!("; {} not started", hosts(counts.skipped)));
    }
    text
}

fn run_info(command: &Command) -> Option<RunInfo> {
    match command {
        Command::RemoteExec {
            script,
            sudo,
            trust_new_host_keys,
            timeout_secs,
            ..
        } => Some(RunInfo {
            script: script.clone(),
            sudo: *sudo,
            trust_new_host_keys: *trust_new_host_keys,
            timeout_secs: *timeout_secs,
        }),
        // SS-09: a key push is a remote command too; its results show like a run's.
        Command::PushSshKey {
            public_key,
            trust_new_host_keys,
            timeout_secs,
            options,
            ..
        } => crate::ssh_keys::parse_public_key(public_key).ok().map(|key| RunInfo {
            script: crate::ssh_keys::authorized_keys_script(&key, options),
            sudo: false,
            trust_new_host_keys: *trust_new_host_keys,
            timeout_secs: *timeout_secs,
        }),
        Command::RemoveSshKey {
            public_key,
            trust_new_host_keys,
            timeout_secs,
            ..
        } => crate::ssh_keys::parse_public_key(public_key).ok().map(|key| RunInfo {
            script: crate::ssh_keys::remove_key_script(&key),
            sudo: false,
            trust_new_host_keys: *trust_new_host_keys,
            timeout_secs: *timeout_secs,
        }),
        _ => None,
    }
}

// ---- BX-03: diff -------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffKind {
    Same,
    /// Only in the left output.
    Removed,
    /// Only in the right output.
    Added,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

/// Two hosts' outputs, line by line (BX-03: the UI passes two groups' samples).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputDiff {
    pub left: String,
    pub right: String,
    pub left_exit_code: Option<i64>,
    pub right_exit_code: Option<i64>,
    pub stdout: Vec<DiffLine>,
    pub stderr: Vec<DiffLine>,
}

/// Lines with trailing whitespace and trailing blank lines dropped.
fn trim_trailing(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let keep = lines.iter().rposition(|l| !l.is_empty()).map_or(0, |i| i + 1);
    let mut out = lines[..keep].join("\n");
    if keep > 0 {
        out.push('\n');
    }
    out
}

/// A line diff of two texts.
pub fn diff_lines(left: &str, right: &str, opts: GroupOptions) -> Vec<DiffLine> {
    let (left, right) = if opts.ignore_trailing_whitespace {
        (trim_trailing(left), trim_trailing(right))
    } else {
        (left.to_owned(), right.to_owned())
    };
    let diff = TextDiff::configure()
        .timeout(Duration::from_secs(2))
        .diff_lines(left.as_str(), right.as_str());
    diff.iter_all_changes()
        .map(|change| DiffLine {
            kind: match change.tag() {
                ChangeTag::Equal => DiffKind::Same,
                ChangeTag::Delete => DiffKind::Removed,
                ChangeTag::Insert => DiffKind::Added,
            },
            text: change.value().trim_end_matches(['\n', '\r']).to_owned(),
        })
        .collect()
}

// ---- BX-05: export -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Html,
}

impl ExportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
            ExportFormat::Html => "html",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ExportFormat::Csv => "CSV",
            ExportFormat::Json => "JSON",
            ExportFormat::Html => "HTML",
        }
    }
}

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkExport {
    pub path: String,
    pub format: ExportFormat,
    pub hosts: usize,
    /// Texts where something that looked like a secret was replaced by `[redacted]`.
    pub redacted: usize,
}

/// The file name the save dialog offers, e.g. `remotely-run-2026-10-18-1a2b3c4d.html`.
pub fn export_file_name(job_id: Uuid, format: ExportFormat) -> String {
    let today = time::OffsetDateTime::now_utc().date();
    let short: String = job_id.simple().to_string().chars().take(8).collect();
    format!("remotely-run-{today}-{short}.{}", format.extension())
}

/// Redacts texts and counts the ones it changed.
#[derive(Default)]
struct Redactor {
    changed: usize,
}

impl Redactor {
    fn clean(&mut self, text: &str) -> String {
        let (clean, changed) = redact_secrets(text);
        self.changed += usize::from(changed);
        clean
    }

    fn opt(&mut self, text: Option<&str>) -> String {
        text.map(|t| self.clean(t)).unwrap_or_default()
    }
}

/// Everything an export holds, already redacted.
struct ExportData {
    job: JobSummary,
    run: Option<RunInfo>,
    headline: String,
    grouped_by: &'static str,
    groups: Vec<ExportGroup>,
    rows: Vec<ExportRow>,
}

struct ExportGroup {
    label: String,
    kind: GroupKind,
    ok: bool,
    exit_code: Option<i64>,
    error: String,
    hosts: Vec<String>,
    stdout: String,
    stderr: String,
}

struct ExportRow {
    name: String,
    group: String,
    status: String,
    exit_code: Option<i64>,
    duration_ms: Option<i64>,
    stdout: String,
    stderr: String,
    truncated: bool,
    error: String,
}

fn opt_num(n: Option<i64>) -> String {
    n.map(|n| n.to_string()).unwrap_or_default()
}

fn to_csv(data: &ExportData) -> String {
    let mut out = String::from("\u{FEFF}");
    let header = [
        "host",
        "group",
        "status",
        "exit_code",
        "duration_ms",
        "stdout",
        "stderr",
        "output_truncated",
        "error",
        // AP-08: the run's change ID, on every row.
        "change_id",
    ];
    push_row(&mut out, header.iter().map(|h| (*h).to_owned()));
    let change_id = data.job.change_id.clone().unwrap_or_default();
    for r in &data.rows {
        push_row(
            &mut out,
            [
                r.name.clone(),
                r.group.clone(),
                r.status.clone(),
                opt_num(r.exit_code),
                opt_num(r.duration_ms),
                r.stdout.clone(),
                r.stderr.clone(),
                r.truncated.to_string(),
                r.error.clone(),
                change_id.clone(),
            ]
            .into_iter(),
        );
    }
    out
}

fn to_json(data: &ExportData) -> Result<String> {
    let job = &data.job;
    let value = json!({
        "job": {
            "id": job.id,
            "summary": job.summary,
            "status": job.status,
            "tier": job.tier,
            "createdAt": job.created_at,
            "startedAt": job.started_at,
            "finishedAt": job.finished_at,
            "retryOf": job.retry_of,
            "changeId": job.change_id,
        },
        "command": data.run.as_ref().map(|r| json!({
            "script": r.script,
            "sudo": r.sudo,
            "trustNewHostKeys": r.trust_new_host_keys,
            "timeoutSecs": r.timeout_secs,
        })),
        "groupedBy": data.grouped_by,
        "headline": data.headline,
        "groups": data.groups.iter().map(|g| json!({
            "label": g.label,
            "kind": g.kind,
            "ok": g.ok,
            "exitCode": g.exit_code,
            "error": if g.error.is_empty() { None } else { Some(&g.error) },
            "hosts": g.hosts,
            "stdout": g.stdout,
            "stderr": g.stderr,
        })).collect::<Vec<_>>(),
        "hosts": data.rows.iter().map(|r| json!({
            "name": r.name,
            "group": if r.group.is_empty() { None } else { Some(&r.group) },
            "status": r.status,
            "exitCode": r.exit_code,
            "durationMs": r.duration_ms,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "outputTruncated": r.truncated,
            "error": if r.error.is_empty() { None } else { Some(&r.error) },
        })).collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The exports' page style: light and dark, no outside resource.
const HTML_STYLE: &str = "<style>\n\
    :root{color-scheme:light dark;--fg:#1b1b1f;--muted:#5f6068;--bg:#fff;--line:#d9d9de;--ok:#1a7f37;--bad:#c62828;--code:#f4f4f6}\n\
    @media (prefers-color-scheme:dark){:root{--fg:#e8e8ec;--muted:#a0a1a8;--bg:#161618;--line:#34343a;--ok:#4ac26b;--bad:#ff6b6b;--code:#202024}}\n\
    body{font:14px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;color:var(--fg);background:var(--bg);margin:0 auto;padding:24px 16px;max-width:1100px}\n\
    h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}.muted{color:var(--muted)}\n\
    table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}\n\
    pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;margin:6px 0}\n\
    .group{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}\n\
    .label{display:inline-block;min-width:22px;text-align:center;font-weight:600;border:1px solid var(--line);border-radius:4px;margin-right:6px}\n\
    .diff div{white-space:pre-wrap;word-break:break-word;padding:0 4px}.diff .removed{color:var(--bad)}.diff .added{color:var(--ok)}\n\
    </style>\n";

/// A self-contained page: no script, no outside resource, every text escaped.
fn to_html(data: &ExportData) -> String {
    let e = html_escape;
    let job = &data.job;
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!("<title>Remotely run: {}</title>\n", e(&job.summary)));
    out.push_str(HTML_STYLE);
    out.push_str("</head>\n<body>\n");
    out.push_str(&format!("<h1>{}</h1>\n", e(&job.summary)));
    out.push_str(&format!(
        "<p class=\"muted\">Exported from Remotely. Job {} &middot; {} &middot; tier {} &middot; started {} &middot; finished {}</p>\n",
        e(&job.id),
        e(&job.status.replace('_', " ")),
        e(&job.tier),
        e(job.started_at.as_deref().unwrap_or("not yet")),
        e(job.finished_at.as_deref().unwrap_or("not yet"))
    ));
    if let Some(change_id) = &job.change_id {
        out.push_str(&format!("<p class=\"muted\">Change ID {}</p>\n", e(change_id)));
    }
    out.push_str(&format!(
        "<p><strong>{}</strong> <span class=\"muted\">(grouped by {})</span></p>\n",
        e(&data.headline),
        e(data.grouped_by)
    ));
    if let Some(run) = &data.run {
        let mut how = Vec::new();
        if run.sudo {
            how.push("with sudo".to_owned());
        }
        if run.trust_new_host_keys {
            how.push("trusting new host keys".to_owned());
        }
        if let Some(secs) = run.timeout_secs {
            how.push(format!("time limit {secs} s per host"));
        }
        out.push_str("<h2>Command</h2>\n");
        if !how.is_empty() {
            out.push_str(&format!("<p class=\"muted\">{}</p>\n", e(&how.join(", "))));
        }
        out.push_str(&format!("<pre>{}</pre>\n", e(&run.script)));
    }
    out.push_str("<h2>Groups</h2>\n");
    for g in &data.groups {
        let state = if g.ok {
            "<span class=\"ok\">succeeded</span>".to_owned()
        } else {
            "<span class=\"bad\">failed</span>".to_owned()
        };
        let exit = g
            .exit_code
            .map(|c| format!(" &middot; exit code {c}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "<div class=\"group\"><p><span class=\"label\">{}</span><strong>{}</strong> &middot; {}{}</p>\n<p class=\"muted\">{}</p>\n",
            e(&g.label),
            hosts(g.hosts.len()),
            state,
            exit,
            e(&g.hosts.join(", "))
        ));
        if g.kind == GroupKind::Error && !g.error.is_empty() {
            out.push_str(&format!("<p class=\"bad\">{}</p>\n", e(&g.error)));
        }
        if !g.stdout.is_empty() {
            out.push_str(&format!("<pre>{}</pre>\n", e(&g.stdout)));
        }
        if !g.stderr.is_empty() {
            out.push_str(&format!("<p class=\"muted\">stderr</p><pre>{}</pre>\n", e(&g.stderr)));
        }
        out.push_str("</div>\n");
    }
    out.push_str("<h2>Hosts</h2>\n<table>\n<thead><tr><th>Host</th><th>Group</th><th>Status</th><th>Exit code</th><th>Duration</th><th>Error</th></tr></thead>\n<tbody>\n");
    for r in &data.rows {
        let duration = r
            .duration_ms
            .map(|ms| format!("{:.1} s", ms as f64 / 1000.0))
            .unwrap_or_default();
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            e(&r.name),
            e(&r.group),
            e(&r.status),
            opt_num(r.exit_code),
            duration,
            e(&r.error)
        ));
    }
    out.push_str("</tbody>\n</table>\n</body>\n</html>\n");
    out
}

// ---- QL-12: recorded MultiExec lines -----------------------------------------------------------

/// A MultiExec line as it was recorded in each terminal (`terminal::record`), for an export. Each
/// target is a terminal: its output from Enter until its prompt came back, already scrubbed of the
/// terminal's secrets.
#[derive(Debug, Clone)]
pub struct RecordedRun {
    pub line: String,
    pub tier: Tier,
    /// When the line was held (RFC 3339).
    pub recorded_at: String,
    pub job_id: Option<Uuid>,
    pub targets: Vec<JobTargetRecord>,
    /// AP-08: the change ID its line's approval was given with (the export reads it from the journal).
    pub change_id: Option<String>,
}

/// What a recordings export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedExport {
    pub path: String,
    pub format: ExportFormat,
    pub lines: usize,
    /// Terminal outputs written (one per terminal per line).
    pub outputs: usize,
    /// Texts where something that looked like a secret was replaced by `[redacted]`.
    pub redacted: usize,
}

/// The file name the save dialog offers: `remotely-multiexec-2026-10-21.html` for every line,
/// `remotely-multiexec-2026-10-21-1a2b3c4d.html` for one.
pub fn recorded_export_file_name(line_id: Option<Uuid>, format: ExportFormat) -> String {
    let today = time::OffsetDateTime::now_utc().date();
    match line_id {
        Some(id) => {
            let short: String = id.simple().to_string().chars().take(8).collect();
            format!("remotely-multiexec-{today}-{short}.{}", format.extension())
        }
        None => format!("remotely-multiexec-{today}.{}", format.extension()),
    }
}

/// One recorded line, ready to write: grouped, diffed against group A, redacted.
struct RecordedSection {
    line: String,
    tier: Tier,
    /// AP-08.
    change_id: String,
    recorded_at: String,
    job_id: Option<Uuid>,
    headline: String,
    groups: Vec<ExportGroup>,
    /// Each group after A: its diff from A's output.
    diffs: Vec<Option<Vec<DiffLine>>>,
    rows: Vec<ExportRow>,
}

fn recorded_sections(runs: &[RecordedRun], opts: GroupOptions, r: &mut Redactor) -> Vec<RecordedSection> {
    runs.iter()
        .map(|run| {
            let grouped = group_with_output(&run.targets, opts);
            let names: HashMap<&str, &str> = run
                .targets
                .iter()
                .map(|t| (t.target_key.as_str(), t.target_name.as_str()))
                .collect();
            let outputs: Vec<String> = grouped.groups.iter().map(|g| r.opt(g.stdout.as_deref())).collect();
            let diffs = (0..outputs.len())
                .map(|i| (i > 0).then(|| diff_lines(&outputs[0], &outputs[i], opts)))
                .collect();
            let groups = grouped
                .groups
                .iter()
                .zip(outputs)
                .map(|(g, stdout)| ExportGroup {
                    label: g.label.clone(),
                    kind: g.kind,
                    ok: g.ok,
                    exit_code: g.exit_code,
                    error: r.opt(g.error.as_deref()),
                    hosts: g
                        .hosts
                        .iter()
                        .map(|k| names.get(k.as_str()).copied().unwrap_or(k).to_owned())
                        .collect(),
                    stdout,
                    stderr: String::new(),
                })
                .collect();
            let rows = run
                .targets
                .iter()
                .zip(&grouped.hosts)
                .map(|(t, h)| ExportRow {
                    name: t.target_name.clone(),
                    group: h.group.map(group_label).unwrap_or_default(),
                    status: t.status.clone(),
                    exit_code: None,
                    duration_ms: t.duration_ms,
                    stdout: r.opt(t.output.as_deref()),
                    stderr: String::new(),
                    truncated: t.output_truncated,
                    error: r.opt(t.error.as_deref()),
                })
                .collect();
            RecordedSection {
                line: r.clean(&run.line),
                tier: run.tier,
                change_id: r.opt(run.change_id.as_deref()),
                recorded_at: run.recorded_at.clone(),
                job_id: run.job_id,
                headline: grouped.headline,
                groups,
                diffs,
                rows,
            }
        })
        .collect()
}

/// A diff as plain text: `- ` removed, `+ ` added, two spaces for the same.
fn diff_text(lines: &[DiffLine]) -> String {
    lines
        .iter()
        .map(|l| {
            let mark = match l.kind {
                DiffKind::Same => "  ",
                DiffKind::Removed => "- ",
                DiffKind::Added => "+ ",
            };
            format!("{mark}{}\n", l.text)
        })
        .collect()
}

fn recorded_csv(sections: &[RecordedSection]) -> String {
    let mut out = String::from("\u{FEFF}");
    let header = [
        "line",
        "recorded_at",
        "tier",
        "change_id",
        "terminal",
        "group",
        "status",
        "duration_ms",
        "output",
        "output_truncated",
        "error",
        "diff_from_group_a",
    ];
    push_row(&mut out, header.iter().map(|h| (*h).to_owned()));
    for s in sections {
        let diff_of = |group: &str| {
            s.groups
                .iter()
                .position(|g| g.label == group)
                .and_then(|i| s.diffs.get(i).cloned().flatten())
                .map(|d| diff_text(&d))
                .unwrap_or_default()
        };
        for r in &s.rows {
            push_row(
                &mut out,
                [
                    s.line.clone(),
                    s.recorded_at.clone(),
                    s.tier.as_str().to_owned(),
                    s.change_id.clone(),
                    r.name.clone(),
                    r.group.clone(),
                    r.status.clone(),
                    opt_num(r.duration_ms),
                    r.stdout.clone(),
                    r.truncated.to_string(),
                    r.error.clone(),
                    diff_of(&r.group),
                ]
                .into_iter(),
            );
        }
    }
    out
}

fn recorded_json(sections: &[RecordedSection], grouped_by: &str) -> Result<String> {
    let value = json!({
        "exportedFrom": "Remotely MultiExec recording",
        "groupedBy": grouped_by,
        "lines": sections.iter().map(|s| json!({
            "line": s.line,
            "recordedAt": s.recorded_at,
            "tier": s.tier,
            "changeId": if s.change_id.is_empty() { None } else { Some(&s.change_id) },
            "jobId": s.job_id,
            "headline": s.headline,
            "groups": s.groups.iter().zip(&s.diffs).map(|(g, diff)| json!({
                "label": g.label,
                "kind": g.kind,
                "ok": g.ok,
                "error": if g.error.is_empty() { None } else { Some(&g.error) },
                "terminals": g.hosts,
                "output": g.stdout,
                "diffFromA": diff,
            })).collect::<Vec<_>>(),
            "terminals": s.rows.iter().map(|r| json!({
                "name": r.name,
                "group": if r.group.is_empty() { None } else { Some(&r.group) },
                "status": r.status,
                "durationMs": r.duration_ms,
                "output": r.stdout,
                "outputTruncated": r.truncated,
                "error": if r.error.is_empty() { None } else { Some(&r.error) },
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

fn recorded_html(sections: &[RecordedSection], grouped_by: &str) -> String {
    let e = html_escape;
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>Remotely MultiExec recording</title>\n");
    out.push_str(HTML_STYLE);
    out.push_str("</head>\n<body>\n<h1>MultiExec recording</h1>\n");
    out.push_str(&format!(
        "<p class=\"muted\">Exported from Remotely: {} recorded in the terminals, grouped by {}. Each output runs from Enter until the terminal's prompt came back.</p>\n",
        if sections.len() == 1 { "1 line".to_owned() } else { format!("{} lines", sections.len()) },
        e(grouped_by)
    ));
    for s in sections {
        out.push_str(&format!(
            "<h2><code>{}</code></h2>\n<p class=\"muted\">Recorded {} &middot; tier {}{}</p>\n<p><strong>{}</strong></p>\n",
            e(&s.line),
            e(&s.recorded_at),
            e(s.tier.as_str()),
            if s.change_id.is_empty() {
                String::new()
            } else {
                format!(" &middot; change ID {}", e(&s.change_id))
            },
            e(&s.headline)
        ));
        for (g, diff) in s.groups.iter().zip(&s.diffs) {
            let state = if g.ok {
                "<span class=\"ok\">prompt back</span>"
            } else {
                "<span class=\"bad\">not finished</span>"
            };
            out.push_str(&format!(
                "<div class=\"group\"><p><span class=\"label\">{}</span><strong>{}</strong> &middot; {}</p>\n<p class=\"muted\">{}</p>\n",
                e(&g.label),
                plural_terminals(g.hosts.len()),
                state,
                e(&g.hosts.join(", "))
            ));
            if !g.error.is_empty() {
                out.push_str(&format!("<p class=\"bad\">{}</p>\n", e(&g.error)));
            }
            out.push_str(&format!("<pre>{}</pre>\n", e(&g.stdout)));
            if let Some(diff) = diff {
                out.push_str(&format!(
                    "<p class=\"muted\">Diff from group A</p><pre class=\"diff\">{}</pre>\n",
                    diff.iter()
                        .map(|l| {
                            let (class, mark) = match l.kind {
                                DiffKind::Same => ("same", " "),
                                DiffKind::Removed => ("removed", "-"),
                                DiffKind::Added => ("added", "+"),
                            };
                            format!("<div class=\"{class}\">{mark} {}</div>", e(&l.text))
                        })
                        .collect::<String>()
                ));
            }
            out.push_str("</div>\n");
        }
        out.push_str("<table>\n<thead><tr><th>Terminal</th><th>Group</th><th>Status</th><th>Duration</th><th>Note</th></tr></thead>\n<tbody>\n");
        for r in &s.rows {
            let duration = r
                .duration_ms
                .map(|ms| format!("{:.1} s", ms as f64 / 1000.0))
                .unwrap_or_default();
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                e(&r.name),
                e(&r.group),
                e(&r.status),
                duration,
                e(&r.error)
            ));
        }
        out.push_str("</tbody>\n</table>\n");
    }
    out.push_str("</body>\n</html>\n");
    out
}

fn plural_terminals(n: usize) -> String {
    if n == 1 {
        "1 terminal".into()
    } else {
        format!("{n} terminals")
    }
}

/// QL-12: recorded lines as a file's text. Returns it with how many texts were redacted and how many
/// terminal outputs it holds.
pub fn render_recorded(
    runs: &[RecordedRun],
    format: ExportFormat,
    opts: GroupOptions,
) -> Result<(String, usize, usize)> {
    let mut r = Redactor::default();
    let sections = recorded_sections(runs, opts, &mut r);
    let grouped_by = if opts.ignore_trailing_whitespace {
        "output, ignoring trailing whitespace"
    } else {
        "output"
    };
    let text = match format {
        ExportFormat::Csv => recorded_csv(&sections),
        ExportFormat::Json => recorded_json(&sections, grouped_by)?,
        ExportFormat::Html => recorded_html(&sections, grouped_by),
    };
    let outputs = runs.iter().map(|run| run.targets.len()).sum();
    Ok((text, r.changed, outputs))
}

// ---- The service -------------------------------------------------------------------------------

pub struct BulkRuns {
    store: Store,
    terminals: Option<Terminals>,
}

impl BulkRuns {
    pub fn new(store: Store) -> Self {
        Self { store, terminals: None }
    }

    /// Open terminals pick their sessions (Compare in the Terminal page).
    pub fn with_terminals(mut self, terminals: Terminals) -> Self {
        self.terminals = Some(terminals);
        self
    }

    /// BX-01: the hosts a run on these picks reaches, and the picked VMs it can't reach.
    pub async fn resolve(&self, ctx: &Context, picks: &TargetPicks) -> Result<ResolvedTargets> {
        let sessions = self.store.list_sessions(ctx).await?;
        let by_id: HashMap<Uuid, &SessionRecord> = sessions.iter().map(|s| (s.id, s)).collect();
        let vms = self.store.list_vms(ctx).await?;
        let vm_by_id: HashMap<&str, &VmRecord> = vms.iter().map(|v| (v.id.as_str(), v)).collect();
        let linked = self.store.sessions_by_vm(ctx).await?;
        let mut picked = Picked::default();

        for id in &picks.terminal_ids {
            let info = self.terminals.as_ref().and_then(|t| t.pane_info(*id));
            match info {
                // SS-12: a tunnel tab's connection is its jump host's, and a Telnet or serial tab is no shell:
                // none of them is a host Compare hosts runs on.
                Some(info) if !info.kind.joins_multiexec() => {
                    let note = format!(
                        "{} is a {} tab, so it was left out: Compare hosts runs over SSH only.",
                        info.name,
                        info.kind.label()
                    );
                    if !picked.notes.contains(&note) {
                        picked.notes.push(note);
                    }
                }
                Some(info) => match info.session_id {
                    Some(session) if by_id.contains_key(&session) => picked.session(session, "open tab".into()),
                    Some(_) => picked
                        .notes
                        .push(format!("The session of '{}' no longer exists.", info.name)),
                    None => {
                        let note = format!(
                            "{} is a quick connection, not a saved session, so Compare can't run on it. Save it as a session first.",
                            info.name
                        );
                        if !picked.notes.contains(&note) {
                            picked.notes.push(note);
                        }
                    }
                },
                None => picked.notes.push("A picked tab has closed.".into()),
            }
        }
        for id in &picks.session_ids {
            if by_id.contains_key(id) {
                picked.session(*id, "session".into());
            } else {
                picked.notes.push("A picked session no longer exists.".into());
            }
        }
        for path in &picks.vm_paths {
            let key = path_key(Path::new(path));
            match vms.iter().find(|v| path_key(Path::new(&v.vmx_path)) == key) {
                Some(vm) => picked.vm(vm, &linked, &by_id, format!("VM '{}'", vm.display_name)),
                None => picked.notes.push(format!("{path} is not in the VM list.")),
            }
        }
        for tag in &picks.tags {
            let tag = tag.trim();
            let via = format!("tag '{tag}'");
            for s in sessions
                .iter()
                .filter(|s| s.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
            {
                picked.session(s.id, via.clone());
            }
            for vm in vms
                .iter()
                .filter(|v| v.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
            {
                picked.vm(vm, &linked, &by_id, via.clone());
            }
        }
        if !picks.filter_ids.is_empty() {
            let filters = self.store.list_saved_filters(ctx).await?;
            for id in &picks.filter_ids {
                let Some(saved) = filters.iter().find(|f| &f.id == id) else {
                    picked.notes.push("A picked saved filter no longer exists.".into());
                    continue;
                };
                for vm in vms.iter().filter(|v| saved.filter.matches(v)) {
                    picked.vm(vm, &linked, &by_id, format!("filter '{}'", saved.name));
                }
            }
        }

        // SS-12: every run on these targets (Compare hosts, a key push, a support bundle) is over SSH: a Telnet,
        // serial, RDP or VNC session is left out, saying so without naming one of them.
        for s in picked.sessions.iter().filter_map(|id| by_id.get(id)) {
            if !s.kind.is_ssh() {
                picked.notes.push(format!(
                    "'{}' is a {} session, so it was left out: this works over SSH only.",
                    s.name,
                    s.kind.label()
                ));
            }
        }
        let mut hosts: Vec<BulkHost> = picked
            .sessions
            .iter()
            .filter_map(|id| by_id.get(id))
            .filter(|s| s.kind.is_ssh())
            .map(|s| {
                let vm = s.vm_id.as_deref().and_then(|v| vm_by_id.get(v));
                let environment = match vm {
                    Some(vm) if vm.environment == Environment::Prod => Environment::Prod,
                    _ => s.environment,
                };
                BulkHost {
                    session_id: s.id,
                    name: s.name.clone(),
                    address: address(s),
                    environment,
                    protected: s.protected || vm.is_some_and(|vm| vm.protected),
                    vm_name: vm.map(|vm| vm.display_name.clone()),
                    via: picked.via.get(&s.id).cloned().unwrap_or_default(),
                }
            })
            .collect();
        hosts.sort_by_key(|h| h.name.to_lowercase());
        let vms_without_session = picked
            .vms
            .iter()
            .filter_map(|id| vm_by_id.get(id.as_str()))
            .map(|vm| VmWithoutSession {
                vmx_path: vm.vmx_path.clone(),
                name: vm.display_name.clone(),
                via: picked.vm_via.get(&vm.id).cloned().unwrap_or_default(),
            })
            .collect();
        let vms_unconfirmed = picked
            .unconfirmed
            .iter()
            .filter_map(|(vm_id, session)| Some((vm_by_id.get(vm_id.as_str())?, by_id.get(session)?)))
            .map(|(vm, session)| UnconfirmedLink {
                vmx_path: vm.vmx_path.clone(),
                name: vm.display_name.clone(),
                session_id: session.id,
                session_name: session.name.clone(),
                address: address(session),
                via: picked.vm_via.get(&vm.id).cloned().unwrap_or_default(),
            })
            .collect();
        Ok(ResolvedTargets {
            hosts,
            vms_without_session,
            vms_unconfirmed,
            notes: picked.notes,
        })
    }

    /// BX-02: the newest bulk runs, newest first.
    pub async fn recent(&self, ctx: &Context, limit: u32) -> Result<Vec<JobSummary>> {
        self.store.recent_exec_jobs(ctx, limit).await
    }

    async fn job(&self, ctx: &Context, job_id: Uuid) -> Result<(JobSummary, Command)> {
        self.store
            .job_detail(ctx, job_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("job {job_id}")))
    }

    /// BX-03: a run's results so far, grouped. Cheap enough to call after every host that finishes.
    pub async fn results(&self, ctx: &Context, job_id: Uuid, opts: GroupOptions) -> Result<BulkResults> {
        let (job, command) = self.job(ctx, job_id).await?;
        let targets = self.store.job_targets_brief(ctx, job_id).await?;
        let (mut groups, of_target) = group_targets(&targets, opts);
        let mut budget = SAMPLE_BUDGET;
        for group in &mut groups {
            let Some(sample) = self.store.job_target(ctx, job_id, &group.sample).await? else {
                continue;
            };
            let size = sample.output.as_ref().map_or(0, String::len) + sample.stderr.as_ref().map_or(0, String::len);
            if size > budget {
                continue;
            }
            budget -= size;
            group.stdout = Some(sample.output.unwrap_or_default());
            group.stderr = Some(sample.stderr.unwrap_or_default());
        }
        let counts = count(&targets);
        let hosts = host_rows(targets, of_target);
        Ok(BulkResults {
            headline: headline(&groups, &counts),
            run: run_info(&command),
            job,
            counts,
            hosts,
            groups,
            ignore_trailing_whitespace: opts.ignore_trailing_whitespace,
            canary: None,
        })
    }

    /// One host's stored output.
    pub async fn host_output(&self, ctx: &Context, job_id: Uuid, target_key: &str) -> Result<HostOutput> {
        let t = self
            .store
            .job_target(ctx, job_id, target_key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("host {target_key} of job {job_id}")))?;
        Ok(HostOutput {
            target_key: t.target_key,
            name: t.target_name,
            stdout: t.output.unwrap_or_default(),
            stderr: t.stderr.unwrap_or_default(),
            truncated: t.output_truncated,
            exit_code: t.exit_code,
            error: t.error,
        })
    }

    /// BX-03: the line diff between two hosts' outputs (two groups' samples).
    pub async fn diff(
        &self,
        ctx: &Context,
        job_id: Uuid,
        left: &str,
        right: &str,
        opts: GroupOptions,
    ) -> Result<OutputDiff> {
        let a = self.host_output(ctx, job_id, left).await?;
        let b = self.host_output(ctx, job_id, right).await?;
        Ok(OutputDiff {
            stdout: diff_lines(&a.stdout, &b.stdout, opts),
            stderr: diff_lines(&a.stderr, &b.stderr, opts),
            left: a.name,
            right: b.name,
            left_exit_code: a.exit_code,
            right_exit_code: b.exit_code,
        })
    }

    /// BX-05: the run's results as a file's text. Returns it with how many texts were redacted.
    pub async fn render(
        &self,
        ctx: &Context,
        job_id: Uuid,
        format: ExportFormat,
        opts: GroupOptions,
    ) -> Result<(String, usize, usize)> {
        let (job, command) = self.job(ctx, job_id).await?;
        let targets = self.store.job_targets(ctx, job_id).await?;
        let (groups, of_target) = group_targets(&targets, opts);
        let counts = count(&targets);
        let mut r = Redactor::default();
        let names: HashMap<&str, &str> = targets
            .iter()
            .map(|t| (t.target_key.as_str(), t.target_name.as_str()))
            .collect();
        let by_key: HashMap<&str, &JobTargetRecord> = targets.iter().map(|t| (t.target_key.as_str(), t)).collect();
        let export_groups = groups
            .iter()
            .map(|g| {
                let sample = by_key.get(g.sample.as_str());
                ExportGroup {
                    label: g.label.clone(),
                    kind: g.kind,
                    ok: g.ok,
                    exit_code: g.exit_code,
                    error: r.opt(g.error.as_deref()),
                    hosts: g
                        .hosts
                        .iter()
                        .map(|k| names.get(k.as_str()).copied().unwrap_or(k).to_owned())
                        .collect(),
                    stdout: r.opt(sample.and_then(|s| s.output.as_deref())),
                    stderr: r.opt(sample.and_then(|s| s.stderr.as_deref())),
                }
            })
            .collect();
        let rows = targets
            .iter()
            .zip(&of_target)
            .map(|(t, group)| ExportRow {
                name: t.target_name.clone(),
                group: group.map(group_label).unwrap_or_default(),
                status: t.status.clone(),
                exit_code: t.exit_code,
                duration_ms: t.duration_ms,
                stdout: r.opt(t.output.as_deref()),
                stderr: r.opt(t.stderr.as_deref()),
                truncated: t.output_truncated,
                error: r.opt(t.error.as_deref()),
            })
            .collect();
        let mut run = run_info(&command);
        if let Some(run) = &mut run {
            run.script = r.clean(&run.script);
        }
        let data = ExportData {
            headline: headline(&groups, &counts),
            grouped_by: if opts.ignore_trailing_whitespace {
                "exit code and output, ignoring trailing whitespace"
            } else {
                "exit code and output"
            },
            job,
            run,
            groups: export_groups,
            rows,
        };
        let text = match format {
            ExportFormat::Csv => to_csv(&data),
            ExportFormat::Json => to_json(&data)?,
            ExportFormat::Html => to_html(&data),
        };
        Ok((text, r.changed, targets.len()))
    }

    /// BX-05: writes the export to `path` (chosen by the user in a save dialog) and logs that it did. Never into a
    /// Git working tree ([`crate::save_guard`]).
    pub async fn export(
        &self,
        ctx: &Context,
        job_id: Uuid,
        format: ExportFormat,
        opts: GroupOptions,
        path: &Path,
    ) -> Result<BulkExport> {
        crate::save_guard::refuse_repository(path, crate::save_guard::Saved::Results)?;
        let (text, redacted, hosts_count) = self.render(ctx, job_id, format, opts).await?;
        tokio::fs::write(path, text).await?;
        let file = path
            .file_name()
            .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "job_exported",
                    action: &format!("Exported a bulk run's results to {}", format.label()),
                    tier: None,
                    job_id: Some(job_id),
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&format!("{} to {file}", hosts(hosts_count))),
                },
            )
            .await?;
        Ok(BulkExport {
            path: path.display().to_string(),
            format,
            hosts: hosts_count,
            redacted,
        })
    }

    /// QL-12, BX-05: writes recorded MultiExec lines to `path` (chosen in a save dialog) and logs that
    /// it did: how many lines and terminals, the format and the file. Never the output. Never into a Git
    /// working tree ([`crate::save_guard`]).
    pub async fn export_recorded(
        &self,
        ctx: &Context,
        runs: &[RecordedRun],
        format: ExportFormat,
        opts: GroupOptions,
        path: &Path,
    ) -> Result<RecordedExport> {
        if runs.is_empty() {
            return Err(CoreError::InvalidInput("There is no recorded line to export.".into()));
        }
        crate::save_guard::refuse_repository(path, crate::save_guard::Saved::Results)?;
        // AP-08: each line's change ID, from its job's approval.
        let mut runs = runs.to_vec();
        for run in &mut runs {
            if run.change_id.is_none() {
                if let Some(job) = run.job_id {
                    run.change_id = self
                        .store
                        .job_detail(ctx, job)
                        .await?
                        .and_then(|(summary, _)| summary.change_id);
                }
            }
        }
        let runs = runs.as_slice();
        let (text, redacted, outputs) = render_recorded(runs, format, opts)?;
        tokio::fs::write(path, text).await?;
        let file = path
            .file_name()
            .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
        let lines = if runs.len() == 1 {
            "1 line".to_owned()
        } else {
            format!("{} lines", runs.len())
        };
        let terminals: HashSet<&str> = runs
            .iter()
            .flat_map(|run| run.targets.iter().map(|t| t.target_key.as_str()))
            .collect();
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "multiexec_exported",
                    action: &format!("Exported recorded MultiExec lines to {}", format.label()),
                    tier: None,
                    job_id: match runs {
                        [run] => run.job_id,
                        _ => None,
                    },
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&format!("{lines} from {} to {file}", plural_terminals(terminals.len()))),
                },
            )
            .await?;
        Ok(RecordedExport {
            path: path.display().to_string(),
            format,
            lines: runs.len(),
            outputs,
            redacted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(key: &str, status: &str, exit: Option<i64>, hash: Option<&str>, loose: Option<&str>) -> JobTargetRecord {
        JobTargetRecord {
            target_kind: "session".into(),
            target_key: key.into(),
            target_name: format!("host-{key}"),
            status: status.into(),
            exit_code: exit,
            output: None,
            error: None,
            started_at: None,
            finished_at: None,
            duration_ms: Some(10),
            safety_snapshot: None,
            stderr: None,
            stdout_bytes: None,
            stderr_bytes: None,
            output_truncated: false,
            output_hash: hash.map(String::from),
            output_hash_loose: loose.map(String::from),
            error_code: None,
            peer_ip: None,
            host_key: None,
        }
    }

    fn failed(key: &str, code: &str, message: &str) -> JobTargetRecord {
        let mut t = target(key, "failed", None, None, None);
        t.error_code = Some(code.into());
        t.error = Some(message.into());
        t
    }

    #[test]
    fn identical_outputs_collapse_into_one_group_largest_first() {
        let mut targets: Vec<JobTargetRecord> = (0..48)
            .map(|i| target(&format!("s{i}"), "succeeded", Some(0), Some("same"), Some("same")))
            .collect();
        targets.insert(3, target("odd1", "succeeded", Some(0), Some("other"), Some("other")));
        targets.push(target("odd2", "failed", Some(2), Some("same"), Some("same")));
        let (groups, of) = group_targets(&targets, GroupOptions::default());
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].hosts.len(), 48);
        assert_eq!(groups[0].label, "A");
        assert!(groups[0].ok);
        // Same output, other exit code: a group of its own.
        assert!(groups
            .iter()
            .any(|g| g.exit_code == Some(2) && !g.ok && g.hosts == ["odd2"]));
        assert_eq!(of[3], Some(groups.iter().position(|g| g.hosts == ["odd1"]).unwrap()));
        let counts = count(&targets);
        assert_eq!(headline(&groups, &counts), "48 hosts same, 2 differ");
    }

    #[test]
    fn ignoring_trailing_whitespace_uses_the_loose_hash() {
        let targets = vec![
            target("a", "succeeded", Some(0), Some("x1"), Some("x")),
            target("b", "succeeded", Some(0), Some("x2"), Some("x")),
        ];
        assert_eq!(group_targets(&targets, GroupOptions::default()).0.len(), 2);
        let loose = GroupOptions {
            ignore_trailing_whitespace: true,
        };
        let (groups, _) = group_targets(&targets, loose);
        assert_eq!(groups.len(), 1);
        assert_eq!(headline(&groups, &count(&targets)), "All 2 hosts the same");
    }

    #[test]
    fn failures_before_the_command_group_by_cause() {
        let targets = vec![
            failed("a", "ssh", "can't connect to 192.0.2.10:22: refused"),
            failed("b", "ssh", "can't connect to 192.0.2.11:22: refused"),
            failed("c", "sudo_password_refused", "sudo refused the password from the vault"),
            target("d", "succeeded", Some(0), Some("h"), Some("h")),
        ];
        let (groups, _) = group_targets(&targets, GroupOptions::default());
        assert_eq!(groups.len(), 3);
        let ssh = groups.iter().find(|g| g.error_code.as_deref() == Some("ssh")).unwrap();
        assert_eq!(ssh.kind, GroupKind::Error);
        assert_eq!(ssh.hosts, ["a", "b"]);
        assert!(ssh.messages_differ);
        assert_eq!(groups[0].hosts, ["a", "b"], "the largest group comes first");
        let sudo = groups
            .iter()
            .find(|g| g.error_code.as_deref() == Some("sudo_password_refused"))
            .unwrap();
        assert!(!sudo.messages_differ);
    }

    #[test]
    fn hosts_still_running_or_cancelled_are_not_grouped_but_counted() {
        let targets = vec![
            target("a", "succeeded", Some(0), Some("h"), Some("h")),
            target("b", "running", None, None, None),
            target("c", "pending", None, None, None),
            target("d", "cancelled", None, None, None),
        ];
        let (groups, of) = group_targets(&targets, GroupOptions::default());
        assert_eq!(groups.len(), 1);
        assert_eq!(of, [Some(0), None, None, None]);
        let counts = count(&targets);
        assert_eq!((counts.running, counts.pending, counts.cancelled), (1, 1, 1));
        assert_eq!(
            headline(&groups, &counts),
            "1 host finished; 2 hosts still to finish; 1 cancelled"
        );
        assert_eq!(
            headline(&[], &counts),
            "Waiting for the first host; 2 hosts still to finish; 1 cancelled"
        );
    }

    #[test]
    fn every_host_different_reads_that_way() {
        let targets: Vec<JobTargetRecord> = (0..3)
            .map(|i| {
                let h = format!("h{i}");
                target(&format!("s{i}"), "succeeded", Some(0), Some(&h), Some(&h))
            })
            .collect();
        let (groups, _) = group_targets(&targets, GroupOptions::default());
        assert_eq!(headline(&groups, &count(&targets)), "3 hosts, all different");
    }

    #[test]
    fn group_labels_run_like_spreadsheet_columns() {
        assert_eq!(group_label(0), "A");
        assert_eq!(group_label(25), "Z");
        assert_eq!(group_label(26), "AA");
        assert_eq!(group_label(27), "AB");
    }

    #[test]
    fn diffs_show_added_and_removed_lines() {
        let diff = diff_lines("a\nb\nc\n", "a\nB\nc\nd\n", GroupOptions::default());
        let shown: Vec<(DiffKind, &str)> = diff.iter().map(|l| (l.kind, l.text.as_str())).collect();
        assert_eq!(
            shown,
            [
                (DiffKind::Same, "a"),
                (DiffKind::Removed, "b"),
                (DiffKind::Added, "B"),
                (DiffKind::Same, "c"),
                (DiffKind::Added, "d"),
            ]
        );
        let loose = GroupOptions {
            ignore_trailing_whitespace: true,
        };
        assert!(diff_lines("a  \nb\n\n", "a\nb\n", loose)
            .iter()
            .all(|l| l.kind == DiffKind::Same));
    }

    #[test]
    fn html_export_escapes_everything() {
        assert_eq!(html_escape("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn recorded_exports_are_named_for_one_line_or_all_and_diffs_read_as_text() {
        let id = Uuid::parse_str("1a2b3c4d-0000-4000-8000-000000000000").unwrap();
        let one = recorded_export_file_name(Some(id), ExportFormat::Csv);
        assert!(
            one.starts_with("remotely-multiexec-") && one.ends_with("-1a2b3c4d.csv"),
            "{one}"
        );
        let all = recorded_export_file_name(None, ExportFormat::Json);
        assert!(
            all.starts_with("remotely-multiexec-") && all.ends_with(".json"),
            "{all}"
        );
        assert_eq!(all.len(), "remotely-multiexec-2026-10-21.json".len());
        let diff = diff_lines("a\nb\n", "a\nc\n", GroupOptions::default());
        assert_eq!(diff_text(&diff), "  a\n- b\n+ c\n");
    }

    #[test]
    fn export_names_carry_the_date_and_the_job() {
        let id = Uuid::parse_str("1a2b3c4d-0000-4000-8000-000000000000").unwrap();
        let name = export_file_name(id, ExportFormat::Html);
        assert!(name.starts_with("remotely-run-"), "{name}");
        assert!(name.ends_with("-1a2b3c4d.html"), "{name}");
    }
}
