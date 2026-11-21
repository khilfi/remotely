//! QL-31 (0.9.0 H7, `docs/plan-0.9.md`): "Keep this line" stores a line typed in all tabs (a QL-12 recording, which
//! lives in memory only and goes when typing stops) as a run in the job journal.
//!
//! * **What is kept.** A job of its own, of type [`KEPT_LINE`], whose id is the recorded line's id, so keeping it twice
//!   keeps it once. Its command is the line's [`Command::TerminalLine`] as the line's own job journaled it (the line and
//!   its run key, redacted by [`Command::for_journal`]), each target naming its terminal and saved session. Its
//!   targets are the terminals, in the order the line went to them, each with what the recorder kept: its output from
//!   Enter until the prompt came back (scrubbed of the terminal's secrets as it was recorded, then of what looks like a
//!   secret by `redact_secrets`, since a pasted block's later lines are echoed at the prompts; the hashes stay as
//!   recorded), its times, and its exit state where known: succeeded when the prompt came back, failed when Enter never
//!   reached it, unknown otherwise (quiet, the next line first, the time limit, the connection lost mid-command: the
//!   command may still run), with why. A typed line has no exit code: the shell tells Remotely none. Its tier and action
//!   are the ones the line was rated with; the keep itself has no tier and no approval. A line Enter reached no tab of,
//!   one waiting for its approval or countdown and one a tab still runs can't be kept.
//! * **Why the journal.** A kept line is a run: it lists, groups, diffs and exports as one (Compare hosts' results list
//!   through `Store::recent_bulk_jobs`, Activity's grouped view), and every rule of the journal holds for it without a
//!   table of its own: per workspace (rule 8), terminal targets and their statuses, `command_type` and its index, and
//!   BX-02's retention (`Store::purge_job_bodies` empties its outputs, line and keys as a typed line's, counted from
//!   when it was typed).
//! * **No retry.** Pressing Enter again later could run the line after something else, as for a typed line: the bus's
//!   `retry_failed` refuses a kept line, and its view says why.
//! * **Audit.** `multiexec_line_kept`, under the kept job: the line as its summary shows it (redacted, its first line;
//!   the audit log is never purged), the terminals, and where it is kept. Never the output. It commits in one
//!   transaction with the job and its targets (`Store::insert_kept_line`, under the audit chain's lock), so a kept line
//!   is never left unaudited; everything it names is read before.
//! * **The read-only lock** (FD-03) refuses it here, before anything is read ([`Change::KeptLines`]).

use serde::Serialize;
use uuid::Uuid;

use crate::command_bus::Command;
use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::jobs::{JobStatus, TargetStatus};
use crate::presentation::Change;
use crate::retention::{Retention, RETENTION_KEY};
use crate::store::{JobTargetRecord, NewAuditEntry, NewKeptLine, Store};
use crate::terminal::record::LineToKeep;
use crate::Core;

/// Why a kept line is never retried, as `CommandBus::retry_failed` refuses it. The window says it word for word
/// (`src/lib/results-list.ts` KEPT_NO_RETRY; its test reads this line).
pub const NO_RETRY: &str = "A kept line can't be retried: pressing Enter again later could run it after something else. Type it again, or run it from Compare hosts as a command.";

/// What "Keep this line" did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptLine {
    /// The kept run's job: the recorded line's id.
    pub job_id: Uuid,
    /// It was kept before; nothing was written or audited again.
    pub already_kept: bool,
}

impl Core {
    /// QL-31: keeps a recorded line of the shown workspace's typing in all tabs as a run in its job journal, once every
    /// tab has finished it (see the module comment). Refused by the read-only lock; audited, never with the output.
    pub async fn keep_line(&self, line_id: Uuid) -> Result<KeptLine> {
        self.store.read_only().check(Change::KeptLines)?;
        let ctx = self.ctx();
        let line = self.multiexec.line_to_keep(line_id)?;
        let kept = keep(&self.store, &ctx, &line).await?;
        self.multiexec.mark_kept(line_id);
        Ok(kept)
    }
}

/// `n` terminals, or tabs.
fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// The line as a summary shows it: its first line redacted, and how many more there were. Empty for a line recalled
/// from the shell's history (Remotely saw only Enter).
fn first_line(line: &str) -> String {
    let mut lines = line.lines().filter(|l| !l.trim().is_empty());
    let (first, _) = redact_secrets(lines.next().unwrap_or_default().trim());
    if first.is_empty() {
        return String::new();
    }
    let more = match lines.count() {
        0 => String::new(),
        1 => " (and 1 more line)".to_owned(),
        n => format!(" (and {n} more lines)"),
    };
    format!("`{first}`{more}")
}

/// The kept run's summary, as Activity and the results list show it: "Typed `uptime` in 3 tabs".
fn summary(line: &str, tabs: usize) -> String {
    match first_line(line) {
        shown if shown.is_empty() => format!("Pressed Enter in {}", count(tabs, "tab")),
        shown => format!("Typed {shown} in {}", count(tabs, "tab")),
    }
}

/// As the job runner ends a run: every terminal's prompt came back, succeeded; none did, failed; else partly (an
/// unknown terminal, whose prompt never came back, counts as not succeeded, as a run's unknown host does).
fn status_of(targets: &[JobTargetRecord]) -> JobStatus {
    let count = |status: TargetStatus| targets.iter().filter(|t| t.status == status.as_str()).count();
    let (succeeded, failed, unknown) = (
        count(TargetStatus::Succeeded),
        count(TargetStatus::Failed),
        count(TargetStatus::Unknown),
    );
    if succeeded > 0 && failed == 0 && unknown == 0 {
        JobStatus::Succeeded
    } else if succeeded == 0 {
        JobStatus::Failed
    } else {
        JobStatus::PartiallyFailed
    }
}

async fn keep(store: &Store, ctx: &Context, line: &LineToKeep) -> Result<KeptLine> {
    // The line's own job, in this workspace's journal: the line as it was journaled and rated.
    let Some((line_job, command)) = store.job_detail(ctx, line.job_id).await? else {
        return Err(match store.job_workspace(line.job_id).await? {
            // FD-02: nothing of another workspace is said.
            Some(_) => CoreError::NotInWorkspace("That line's job".into()),
            // QL-15: a journal write that failed while the line ran.
            None => CoreError::InvalidInput(
                "That line's own job is not in the journal (writing it failed when the line ran), so it can't be kept."
                    .into(),
            ),
        });
    };
    if line_job.bodies_removed {
        return Err(CoreError::InvalidInput(
            "That line is older than how long job outputs are kept (Settings, General), so it can't be kept.".into(),
        ));
    }
    let Command::TerminalLine {
        line: text,
        keys,
        unreliable,
        ..
    } = command
    else {
        return Err(CoreError::InvalidInput("That job is not a typed line.".into()));
    };
    let terminals = line.terminals.len();

    // Everything read first, so the job, its targets and its audit entry are then written together.
    let mut refs = Vec::with_capacity(terminals);
    let mut targets = Vec::with_capacity(terminals);
    for t in &line.terminals {
        let terminal_id = Uuid::parse_str(&t.record.target_key)
            .map_err(|_| CoreError::UnknownTarget(format!("terminal {}", t.record.target_key)))?;
        let target = TargetRef::Terminal {
            terminal_id,
            session_id: t.session_id,
        };
        let (environment, protected) = match t.session_id {
            Some(session) => store
                .find_session_target(ctx, session)
                .await?
                .map_or((Environment::None, false), |(_, environment, protected)| {
                    (environment, protected)
                }),
            None => (Environment::None, false),
        };
        refs.push(target.clone());
        targets.push(Target {
            target,
            name: t.record.target_name.clone(),
            environment,
            protected,
        });
    }
    let retention = store
        .get_setting::<Retention>(ctx, RETENTION_KEY)
        .await?
        .unwrap_or_default();
    let kept_for = match retention.days() {
        Some(_) => format!("for {}", retention.label()),
        None => "for good".to_owned(),
    };
    let journaled = summary(&text, terminals);
    let shown = match first_line(&text) {
        shown if shown.is_empty() => "Enter".to_owned(),
        shown => shown,
    };
    // The audit: the line as its summary shows it, the terminals and where it is kept; never the output.
    let detail = format!(
        "{shown} from {}; kept in the job journal like a run, whose outputs are kept {kept_for}",
        count(terminals, "terminal")
    );
    let kept_command = Command::TerminalLine {
        targets: refs,
        line: text,
        unreliable,
        keys,
    };
    let records: Vec<JobTargetRecord> = line.terminals.iter().map(|t| t.record.clone()).collect();
    let started_at = records.iter().filter_map(|t| t.started_at.as_deref()).min();
    let finished_at = records.iter().filter_map(|t| t.finished_at.as_deref()).max();
    let inserted = store
        .insert_kept_line(
            ctx,
            NewKeptLine {
                id: line.id,
                summary: &journaled,
                action: &line_job.action,
                tier: &line_job.tier,
                command: &kept_command,
                status: status_of(&records),
                created_at: &line.recorded_at,
                started_at,
                finished_at,
                change_id: line_job.change_id.as_deref(),
                command_redacted: line_job.command_redacted,
                targets: &records,
            },
            NewAuditEntry {
                event: "multiexec_line_kept",
                action: "Kept a typed line as a run",
                tier: None,
                job_id: Some(line.id),
                targets: &targets,
                approval: None,
                result: None,
                detail: Some(&detail),
            },
        )
        .await?;
    Ok(KeptLine {
        job_id: line.id,
        already_kept: !inserted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(status: &str) -> JobTargetRecord {
        JobTargetRecord {
            target_kind: "terminal".into(),
            target_key: Uuid::new_v4().to_string(),
            target_name: "web01".into(),
            status: status.into(),
            exit_code: None,
            output: None,
            error: None,
            started_at: None,
            finished_at: None,
            duration_ms: None,
            safety_snapshot: None,
            stderr: None,
            stdout_bytes: None,
            stderr_bytes: None,
            output_truncated: false,
            output_hash: None,
            output_hash_loose: None,
            error_code: None,
            peer_ip: None,
            host_key: None,
        }
    }

    #[test]
    fn a_kept_lines_summary_names_its_first_line_redacted_and_its_tabs() {
        assert_eq!(summary("uptime", 3), "Typed `uptime` in 3 tabs");
        assert_eq!(
            summary("\nmysql --password=hunter2 -e 'select 1'\nexit\n", 1),
            "Typed `mysql --password=[redacted] -e 'select 1'` (and 1 more line) in 1 tab"
        );
        assert_eq!(summary("a\nb\nc", 2), "Typed `a` (and 2 more lines) in 2 tabs");
        assert_eq!(summary("", 2), "Pressed Enter in 2 tabs");
    }

    #[test]
    fn a_kept_line_succeeds_only_when_every_prompt_came_back_as_a_run_counts_its_hosts() {
        let ok = target("succeeded");
        let not_sent = target("failed");
        let quiet = target("unknown");
        assert_eq!(status_of(&[ok.clone(), ok.clone()]), JobStatus::Succeeded);
        assert_eq!(status_of(&[ok.clone(), not_sent.clone()]), JobStatus::PartiallyFailed);
        assert_eq!(status_of(&[ok, quiet.clone()]), JobStatus::PartiallyFailed);
        assert_eq!(status_of(&[quiet.clone(), quiet]), JobStatus::Failed);
        assert_eq!(status_of(&[not_sent]), JobStatus::Failed);
        assert_eq!(status_of(&[]), JobStatus::Failed);
    }
}
