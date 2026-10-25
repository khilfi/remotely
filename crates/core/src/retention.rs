//! BX-02, BX-05, SS-10: how long the job journal keeps job outputs and command text (Settings, General).
//!
//! Every job keeps its targets' stdout and stderr (up to 64 KiB each) and its command: a Compare run's whole
//! script, a MultiExec line. That is customer data, on the laptop, and an active user adds tens of megabytes a
//! month. So a purge runs at start and daily after that: jobs older than the setting (30 days, **90 days** by
//! default, 1 year, or forever) lose their outputs and their script or line text
//! ([`Store::purge_job_bodies`]); their rows, summaries, tiers, targets, results and hashes stay, so Activity
//! still lists them. Rows journaled before migration 0017 have their scripts and lines redacted once
//! ([`Store::redact_old_commands`]). The audit log is never touched: it is append-only and hash-chained, and
//! its text is redacted when it is written.
//!
//! The database deletes securely (`secure_delete`), the write-ahead log is emptied after a purge, and a purge
//! that left a lot of free space compacts the file (`VACUUM`) while no job runs. A purge that removed something
//! is audited (`journal_purged`), and so is every "Purge now". Presentation mode's read-only lock refuses
//! changing the setting and "Purge now", but never stops the scheduled purge.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::command_bus::human_size;
use crate::domain::{now_rfc3339, Context};
use crate::error::Result;
use crate::jobs::JobRunner;
use crate::locks;
use crate::presentation::Change;
use crate::store::{NewAuditEntry, PurgedBodies, Store};

/// The setting: a [`Retention`].
pub const RETENTION_KEY: &str = "jobs.retention";

/// How often the scheduled purge runs.
pub const PURGE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the schedule looks at the clock: the PC may sleep, so the wall clock decides, not a timer.
const TICK: Duration = Duration::from_secs(60 * 60);

/// Free space below this never warrants compacting.
const COMPACT_MIN_FREE: u64 = 8 * 1024 * 1024;

/// Free space above this always does.
const COMPACT_ALWAYS_FREE: u64 = 64 * 1024 * 1024;

/// How long job outputs and command text are kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Retention {
    #[serde(rename = "days30")]
    Days30,
    #[default]
    #[serde(rename = "days90")]
    Days90,
    #[serde(rename = "year")]
    Year,
    #[serde(rename = "forever")]
    Forever,
}

impl Retention {
    /// Days kept; `None`: forever.
    pub fn days(self) -> Option<i64> {
        match self {
            Retention::Days30 => Some(30),
            Retention::Days90 => Some(90),
            Retention::Year => Some(365),
            Retention::Forever => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Retention::Days30 => "30 days",
            Retention::Days90 => "90 days",
            Retention::Year => "1 year",
            Retention::Forever => "forever",
        }
    }
}

/// What one purge did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeReport {
    pub at: String,
    pub retention: Retention,
    /// Jobs created before this (RFC 3339) lost their outputs and command text; `None` when kept forever.
    pub before: Option<String>,
    pub removed: PurgedBodies,
    /// Older rows' scripts and lines that had something redacted (journaled before migration 0017).
    pub redacted: u64,
    /// The database file was compacted afterwards.
    pub compacted: bool,
    /// "Purge now", not the schedule.
    pub by_hand: bool,
}

/// The setting and the last purge since the app started, for Settings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionInfo {
    pub retention: Retention,
    pub last_purge: Option<PurgeReport>,
}

/// The purge and its setting (`Core.retention`). The shell starts the schedule with [`JournalRetention::run`].
pub struct JournalRetention {
    store: Store,
    ctx: Context,
    jobs: Arc<JobRunner>,
    /// One purge at a time.
    purging: tokio::sync::Mutex<()>,
    last: Mutex<Option<PurgeReport>>,
}

impl JournalRetention {
    pub fn new(store: Store, ctx: Context, jobs: Arc<JobRunner>) -> Self {
        Self {
            store,
            ctx,
            jobs,
            purging: tokio::sync::Mutex::new(()),
            last: Mutex::new(None),
        }
    }

    /// The saved setting, or the default (90 days).
    pub async fn retention(&self) -> Result<Retention> {
        Ok(self
            .store
            .get_setting::<Retention>(&self.ctx, RETENTION_KEY)
            .await?
            .unwrap_or_default())
    }

    pub async fn info(&self) -> Result<RetentionInfo> {
        Ok(RetentionInfo {
            retention: self.retention().await?,
            last_purge: locks::lock(&self.last).clone(),
        })
    }

    /// Saves the setting. It applies at the next purge (daily, or "Purge now"). Audited; refused while presenting.
    pub async fn set_retention(&self, retention: Retention) -> Result<RetentionInfo> {
        self.store.read_only().check(Change::Settings)?;
        let old = self.retention().await?;
        if old != retention {
            self.store.put_setting(&self.ctx, RETENTION_KEY, &retention).await?;
            let detail = format!(
                "{} -> {}; applies at the next purge (daily, or Purge now)",
                old.label(),
                retention.label()
            );
            self.audit(
                "setting_changed",
                "Set how long job outputs and command text are kept",
                &detail,
            )
            .await?;
        }
        self.info().await
    }

    /// "Purge now" in Settings: purges at once with the setting, and is audited even when nothing was old enough.
    /// Refused while presenting.
    pub async fn purge_now(&self) -> Result<PurgeReport> {
        self.store.read_only().check(Change::Settings)?;
        self.purge(true).await
    }

    /// The scheduled purge: at start and daily. Not stopped by the read-only lock; audited when it removed
    /// something.
    pub async fn purge_scheduled(&self) -> Result<PurgeReport> {
        self.purge(false).await
    }

    /// Purges now, then whenever [`PURGE_EVERY`] has passed by the wall clock, until `stop`.
    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        let mut last_run: Option<OffsetDateTime> = None;
        loop {
            let now = OffsetDateTime::now_utc();
            let due = last_run.is_none_or(|at| now - at >= PURGE_EVERY);
            if due {
                last_run = Some(now);
                if let Err(err) = self.purge_scheduled().await {
                    tracing::error!(error = %err, "the job journal's retention purge failed");
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    async fn purge(&self, by_hand: bool) -> Result<PurgeReport> {
        let _one = self.purging.lock().await;
        let redacted = self.store.redact_old_commands().await?;
        let retention = self.retention().await?;
        let before = retention.days().map(cutoff);
        let removed = match &before {
            Some(before) => self.store.purge_job_bodies(&self.ctx, before).await?,
            None => PurgedBodies::default(),
        };
        let changed = removed.removed_any() || redacted > 0;
        let mut compacted = false;
        if changed {
            // Text just removed is not left in the -wal file either.
            if let Err(err) = self.store.checkpoint().await {
                tracing::warn!(error = %err, "could not empty the database's write-ahead log after a purge");
            }
            let (size, free) = self.store.space().await?;
            if worth_compacting(size, free) {
                match self.jobs.when_idle(self.store.vacuum()).await {
                    Some(Ok(())) => compacted = true,
                    Some(Err(err)) => tracing::warn!(error = %err, "could not compact the database after a purge"),
                    None => tracing::info!("a job is running: the database is compacted after a later purge"),
                }
            }
        }
        let report = PurgeReport {
            at: now_rfc3339(),
            retention,
            before,
            removed,
            redacted,
            compacted,
            by_hand,
        };
        if by_hand || changed {
            let action = if by_hand {
                "Purged old job outputs and command text"
            } else {
                "Removed old job outputs and command text"
            };
            self.audit("journal_purged", action, &describe(&report)).await?;
        }
        if changed {
            tracing::info!(
                jobs = report.removed.jobs,
                outputs = report.removed.outputs,
                commands = report.removed.commands,
                bytes = report.removed.bytes,
                redacted,
                compacted,
                "purged old job outputs and command text"
            );
        }
        *locks::lock(&self.last) = Some(report.clone());
        Ok(report)
    }

    async fn audit(&self, event: &str, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                &self.ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

/// `days` before now, to the second (RFC 3339 UTC, as the journal's times are).
fn cutoff(days: i64) -> String {
    let at = OffsetDateTime::now_utc() - time::Duration::days(days);
    let at = at.replace_nanosecond(0).unwrap_or(at);
    at.format(&Rfc3339).unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// After a purge: compact when it left a lot of free space, as a share of the file or outright.
pub fn worth_compacting(size: u64, free: u64) -> bool {
    free >= COMPACT_ALWAYS_FREE || (free >= COMPACT_MIN_FREE && free.saturating_mul(5) >= size)
}

/// What a purge did, in words, for the audit log and Settings.
pub fn describe(report: &PurgeReport) -> String {
    let mut parts = Vec::new();
    match &report.before {
        None => parts.push("job outputs and command text are kept forever, so nothing was removed".to_owned()),
        Some(before) => {
            let date = before.get(..10).unwrap_or(before);
            let r = &report.removed;
            if r.removed_any() {
                parts.push(format!(
                    "older than {} (before {date}): removed {} and {} ({}) from {}, whose rows, results and hashes \
                     are kept",
                    report.retention.label(),
                    plural(r.outputs, "output", "outputs"),
                    plural(r.commands, "script or line", "scripts or lines"),
                    human_size(r.bytes),
                    plural(r.jobs, "job", "jobs"),
                ));
            } else {
                parts.push(format!(
                    "nothing older than {} (before {date}) was left to remove",
                    report.retention.label()
                ));
            }
        }
    }
    if report.redacted > 0 {
        parts.push(format!(
            "{} had something that looked like a secret, now [redacted]",
            plural(report.redacted, "older command", "older commands")
        ));
    }
    if report.compacted {
        parts.push("the database file was compacted".to_owned());
    }
    parts.join("; ")
}

fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_90_days_and_each_choice_has_its_days() {
        assert_eq!(Retention::default(), Retention::Days90);
        assert_eq!(Retention::Days30.days(), Some(30));
        assert_eq!(Retention::Days90.days(), Some(90));
        assert_eq!(Retention::Year.days(), Some(365));
        assert_eq!(Retention::Forever.days(), None);
        for (r, json) in [
            (Retention::Days30, "\"days30\""),
            (Retention::Days90, "\"days90\""),
            (Retention::Year, "\"year\""),
            (Retention::Forever, "\"forever\""),
        ] {
            assert_eq!(serde_json::to_string(&r).unwrap(), json);
            assert_eq!(serde_json::from_str::<Retention>(json).unwrap(), r);
        }
    }

    #[test]
    fn the_cutoff_is_that_many_days_ago_to_the_second() {
        let at = OffsetDateTime::parse(&cutoff(90), &Rfc3339).unwrap();
        let days = (OffsetDateTime::now_utc() - at).whole_days();
        assert_eq!(days, 90);
        assert_eq!(at.nanosecond(), 0);
    }

    #[test]
    fn only_a_lot_of_free_space_is_worth_compacting() {
        const MB: u64 = 1024 * 1024;
        assert!(!worth_compacting(10 * MB, 0));
        assert!(!worth_compacting(10 * MB, 2 * MB), "too little to bother");
        assert!(!worth_compacting(100 * MB, 10 * MB), "a tenth of the file");
        assert!(worth_compacting(40 * MB, 10 * MB), "a quarter of the file");
        assert!(worth_compacting(2000 * MB, 64 * MB), "a lot, however big the file");
    }

    #[test]
    fn a_report_says_what_went_and_what_stayed() {
        let report = PurgeReport {
            at: "2026-10-25T08:00:00Z".into(),
            retention: Retention::Days90,
            before: Some("2026-07-27T08:00:00Z".into()),
            removed: PurgedBodies {
                jobs: 12,
                outputs: 340,
                commands: 25,
                bytes: 2_100_000,
            },
            redacted: 1,
            compacted: true,
            by_hand: true,
        };
        assert_eq!(
            describe(&report),
            "older than 90 days (before 2026-07-27): removed 340 outputs and 25 scripts or lines (2.1 MB) from 12 \
             jobs, whose rows, results and hashes are kept; 1 older command had something that looked like a \
             secret, now [redacted]; the database file was compacted"
        );
        let nothing = PurgeReport {
            removed: PurgedBodies::default(),
            redacted: 0,
            compacted: false,
            ..report.clone()
        };
        assert_eq!(
            describe(&nothing),
            "nothing older than 90 days (before 2026-07-27) was left to remove"
        );
        let forever = PurgeReport {
            retention: Retention::Forever,
            before: None,
            ..nothing
        };
        assert_eq!(
            describe(&forever),
            "job outputs and command text are kept forever, so nothing was removed"
        );
    }
}
