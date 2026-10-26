//! MO-06: the dashboard's history on disk.
//!
//! The collector's rounds (every 5 s on the host side, every 5 to 60 s for a watched guest) stay in memory for
//! 30 minutes ([`super::MetricsHub`]). For longer charts, each series' rounds are added up per minute
//! ([`Rollup`]): the average of the minute, with the lowest and highest CPU, the highest memory and load, and
//! the fullest disk. Once a minute is over, its rows are written in one transaction ([`MetricsHistory`], a
//! [`super::RoundObserver`]), so the database sees one write a minute whatever the number of VMs. Series are
//! a VM's host side, a watched host's guest metrics and this PC's CPU, RAM and paging files.
//!
//! Charts read a range (1 hour to 7 days) back in buckets ([`bucket`]: 1 minute up to 6 hours, 5 minutes for
//! a day, 30 minutes for a week), then carry on with the live rounds in memory.
//!
//! The history is kept for as long as Settings says (7 days by default, [`HistoryRetention`]), then pruned at
//! start and daily, with the alert list's resolved alerts ([`crate::alerts`]). Like the job journal's purge
//! ([`crate::retention`]), the database deletes securely, the write-ahead log is emptied after a prune, and a
//! prune that left a lot of free space compacts the file while no job runs. The history stays on this PC: FD-07
//! exports never carry it. Every row carries the workspace and the user.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use super::{MetricPoint, MetricSource, RecordedRound, RoundObserver};
use crate::command_bus::human_size;
use crate::domain::{now_rfc3339, Context, WorkspaceId, THIS_PC_KEY};
use crate::error::Result;
use crate::jobs::JobRunner;
use crate::locks;
use crate::presentation::Change;
use crate::retention::worth_compacting;
use crate::store::{HistoryPruned, HistorySize, NewAuditEntry, Store};

/// The setting: a [`HistoryRetention`].
pub const HISTORY_RETENTION_KEY: &str = "metrics.historyRetention";

pub const MINUTE_MS: i64 = 60_000;

/// How often the scheduled prune runs.
pub const PRUNE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the schedule looks at the clock: the PC may sleep, so the wall clock decides, not a timer.
const TICK: Duration = Duration::from_secs(60 * 60);

/// Which kind of series: a VM's host side, a watched host's guest, or this PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HistorySource {
    Host,
    Guest,
    ThisPc,
}

impl HistorySource {
    pub fn as_str(self) -> &'static str {
        match self {
            HistorySource::Host => "host",
            HistorySource::Guest => "guest",
            HistorySource::ThisPc => "thisPc",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "host" => Some(HistorySource::Host),
            "guest" => Some(HistorySource::Guest),
            "thisPc" => Some(HistorySource::ThisPc),
            _ => None,
        }
    }
}

impl From<MetricSource> for HistorySource {
    fn from(source: MetricSource) -> Self {
        match source {
            MetricSource::Host => HistorySource::Host,
            MetricSource::Guest => HistorySource::Guest,
        }
    }
}

/// How long the history is kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryRetention {
    #[serde(rename = "day1")]
    Day1,
    #[serde(rename = "days3")]
    Days3,
    #[default]
    #[serde(rename = "days7")]
    Days7,
    #[serde(rename = "days14")]
    Days14,
    #[serde(rename = "days30")]
    Days30,
}

impl HistoryRetention {
    pub const ALL: [HistoryRetention; 5] = [
        HistoryRetention::Day1,
        HistoryRetention::Days3,
        HistoryRetention::Days7,
        HistoryRetention::Days14,
        HistoryRetention::Days30,
    ];

    pub fn days(self) -> i64 {
        match self {
            HistoryRetention::Day1 => 1,
            HistoryRetention::Days3 => 3,
            HistoryRetention::Days7 => 7,
            HistoryRetention::Days14 => 14,
            HistoryRetention::Days30 => 30,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            HistoryRetention::Day1 => "1 day",
            HistoryRetention::Days3 => "3 days",
            HistoryRetention::Days7 => "7 days",
            HistoryRetention::Days14 => "14 days",
            HistoryRetention::Days30 => "30 days",
        }
    }
}

/// A chart's range. The live view (the last 30 minutes, every round) is the collector's own
/// ([`super::MetricsHub::series`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HistoryRange {
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "6h")]
    SixHours,
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
}

impl HistoryRange {
    pub fn span_minutes(self) -> i64 {
        match self {
            HistoryRange::Hour => 60,
            HistoryRange::SixHours => 6 * 60,
            HistoryRange::Day => 24 * 60,
            HistoryRange::Week => 7 * 24 * 60,
        }
    }

    /// Minutes per point: at most a few hundred points whatever the range.
    pub fn bucket_minutes(self) -> i64 {
        match self {
            HistoryRange::Hour | HistoryRange::SixHours => 1,
            HistoryRange::Day => 5,
            HistoryRange::Week => 30,
        }
    }
}

/// One measure added up over a minute or a bucket. Values that are not finite are left out.
#[derive(Debug, Clone, Copy, Default)]
struct Stat {
    n: u32,
    sum: f64,
    min: f64,
    max: f64,
}

impl Stat {
    fn add(&mut self, value: Option<f64>) {
        let Some(v) = value.filter(|v| v.is_finite()) else {
            return;
        };
        if self.n == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        self.n += 1;
        self.sum += v;
    }

    fn avg(&self) -> Option<f64> {
        (self.n > 0).then(|| self.sum / f64::from(self.n))
    }

    fn min(&self) -> Option<f64> {
        (self.n > 0).then_some(self.min)
    }

    fn max(&self) -> Option<f64> {
        (self.n > 0).then_some(self.max)
    }
}

/// A minute of one series while it is still open.
#[derive(Debug, Clone, Default)]
struct Acc {
    samples: u32,
    cpu: Stat,
    mem: Stat,
    mem_total: Option<u64>,
    swap: Stat,
    swap_total: Option<u64>,
    read: Stat,
    write: Stat,
    rx: Stat,
    tx: Stat,
    load: Stat,
    disk_used: Stat,
}

fn bytes(value: Option<u64>) -> Option<f64> {
    #[allow(clippy::cast_precision_loss)]
    value.map(|v| v as f64)
}

/// A non-negative whole number, for bytes and bytes per second.
fn whole(value: Option<f64>) -> Option<u64> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    value.filter(|v| v.is_finite()).map(|v| v.max(0.0).round() as u64)
}

/// Two decimals are plenty for a percentage or a load average, and repeat less on disk.
fn hundredths(value: Option<f64>) -> Option<f64> {
    value.map(|v| (v * 100.0).round() / 100.0)
}

impl Acc {
    fn add(&mut self, p: &MetricPoint) {
        self.samples += 1;
        self.cpu.add(p.cpu_pct);
        self.mem.add(bytes(p.mem_bytes));
        self.mem_total = p.mem_total_bytes.or(self.mem_total);
        self.swap.add(bytes(p.swap_used_bytes));
        self.swap_total = p.swap_total_bytes.or(self.swap_total);
        self.read.add(p.disk_read_bps);
        self.write.add(p.disk_write_bps);
        self.rx.add(p.net_rx_bps);
        self.tx.add(p.net_tx_bps);
        self.load.add(p.load1);
        self.disk_used.add(p.disk_used_pct);
    }

    fn row(&self, source: HistorySource, key: String, minute: i64) -> MinuteRow {
        MinuteRow {
            source,
            key,
            minute,
            samples: self.samples,
            cpu_avg: hundredths(self.cpu.avg()),
            cpu_min: hundredths(self.cpu.min()),
            cpu_max: hundredths(self.cpu.max()),
            mem_avg: whole(self.mem.avg()),
            mem_max: whole(self.mem.max()),
            mem_total: self.mem_total,
            swap_avg: whole(self.swap.avg()),
            swap_total: self.swap_total,
            read_avg: whole(self.read.avg()),
            write_avg: whole(self.write.avg()),
            rx_avg: whole(self.rx.avg()),
            tx_avg: whole(self.tx.avg()),
            load_avg: hundredths(self.load.avg()),
            load_max: hundredths(self.load.max()),
            disk_used_max: hundredths(self.disk_used.max()),
        }
    }
}

/// One series' minute, as stored (`metric_minutes`). `minute` is Unix time in minutes.
#[derive(Debug, Clone, PartialEq)]
pub struct MinuteRow {
    pub source: HistorySource,
    pub key: String,
    pub minute: i64,
    /// Rounds in the minute.
    pub samples: u32,
    pub cpu_avg: Option<f64>,
    pub cpu_min: Option<f64>,
    pub cpu_max: Option<f64>,
    pub mem_avg: Option<u64>,
    pub mem_max: Option<u64>,
    /// The latest reading of what there is (a VM's configured RAM, a guest's or this PC's total).
    pub mem_total: Option<u64>,
    pub swap_avg: Option<u64>,
    pub swap_total: Option<u64>,
    pub read_avg: Option<u64>,
    pub write_avg: Option<u64>,
    pub rx_avg: Option<u64>,
    pub tx_avg: Option<u64>,
    pub load_avg: Option<f64>,
    pub load_max: Option<f64>,
    /// The fullest disk's highest reading.
    pub disk_used_max: Option<f64>,
}

/// MO-06: each series' rounds, added up per minute until the minute is over.
#[derive(Debug, Default)]
pub struct Rollup {
    open: BTreeMap<(i64, HistorySource, String), Acc>,
}

impl Rollup {
    /// Adds one round's reading of a series, in the minute of `point.t` (Unix ms).
    pub fn add(&mut self, source: HistorySource, key: &str, point: &MetricPoint) {
        let minute = point.t.div_euclid(MINUTE_MS);
        self.open
            .entry((minute, source, key.to_owned()))
            .or_default()
            .add(point);
    }

    /// Takes the rows of every minute before `minute`, oldest first.
    pub fn take_before(&mut self, minute: i64) -> Vec<MinuteRow> {
        let later = self.open.split_off(&(minute, HistorySource::Host, String::new()));
        let done = std::mem::replace(&mut self.open, later);
        done.into_iter()
            .map(|((minute, source, key), acc)| acc.row(source, key, minute))
            .collect()
    }

    /// Takes every row, the open minute's too (the app is closing).
    pub fn take_all(&mut self) -> Vec<MinuteRow> {
        self.take_before(i64::MAX)
    }

    /// The oldest minute still open.
    pub fn first_minute(&self) -> Option<i64> {
        self.open.keys().next().map(|(minute, _, _)| *minute)
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

/// One point of a history chart: a bucket of minutes. Averages are weighted by each minute's rounds; the
/// lowest and highest are over the whole bucket. The fields the live points have ([`MetricPoint`]) mean the
/// same, so a chart draws both.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPoint {
    /// The bucket's start, Unix time in milliseconds.
    pub t: i64,
    /// Rounds in the bucket.
    pub samples: u32,
    pub cpu_pct: Option<f64>,
    pub cpu_min: Option<f64>,
    pub cpu_max: Option<f64>,
    pub mem_bytes: Option<u64>,
    pub mem_max_bytes: Option<u64>,
    pub mem_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub load1: Option<f64>,
    pub load_max: Option<f64>,
    pub disk_used_pct: Option<f64>,
}

/// An average weighted by the rounds behind each value.
#[derive(Default)]
struct Weighted {
    weight: f64,
    sum: f64,
}

impl Weighted {
    fn add(&mut self, value: Option<f64>, samples: u32) {
        if let Some(v) = value.filter(|v| v.is_finite()) {
            let w = f64::from(samples.max(1));
            self.weight += w;
            self.sum += v * w;
        }
    }

    fn avg(&self) -> Option<f64> {
        (self.weight > 0.0).then(|| self.sum / self.weight)
    }
}

#[derive(Default)]
struct BucketAcc {
    samples: u32,
    cpu: Weighted,
    cpu_min: Stat,
    cpu_max: Stat,
    mem: Weighted,
    mem_max: Stat,
    mem_total: Option<u64>,
    swap: Weighted,
    swap_total: Option<u64>,
    read: Weighted,
    write: Weighted,
    rx: Weighted,
    tx: Weighted,
    load: Weighted,
    load_max: Stat,
    disk_used: Stat,
}

/// Minutes (oldest first) in buckets of `bucket_minutes`, oldest first. A bucket with no minute has no point,
/// so a chart breaks its line there.
pub fn bucket(rows: &[MinuteRow], bucket_minutes: i64) -> Vec<HistoryPoint> {
    let size = bucket_minutes.max(1);
    let mut buckets: BTreeMap<i64, BucketAcc> = BTreeMap::new();
    for row in rows {
        let start = row.minute.div_euclid(size) * size;
        let b = buckets.entry(start).or_default();
        let n = row.samples;
        b.samples = b.samples.saturating_add(n);
        b.cpu.add(row.cpu_avg, n);
        b.cpu_min.add(row.cpu_min);
        b.cpu_max.add(row.cpu_max);
        b.mem.add(bytes(row.mem_avg), n);
        b.mem_max.add(bytes(row.mem_max));
        b.mem_total = row.mem_total.or(b.mem_total);
        b.swap.add(bytes(row.swap_avg), n);
        b.swap_total = row.swap_total.or(b.swap_total);
        b.read.add(bytes(row.read_avg), n);
        b.write.add(bytes(row.write_avg), n);
        b.rx.add(bytes(row.rx_avg), n);
        b.tx.add(bytes(row.tx_avg), n);
        b.load.add(row.load_avg, n);
        b.load_max.add(row.load_max);
        b.disk_used.add(row.disk_used_max);
    }
    buckets
        .into_iter()
        .map(|(start, b)| HistoryPoint {
            t: start.saturating_mul(MINUTE_MS),
            samples: b.samples,
            cpu_pct: hundredths(b.cpu.avg()),
            cpu_min: b.cpu_min.min(),
            cpu_max: b.cpu_max.max(),
            mem_bytes: whole(b.mem.avg()),
            mem_max_bytes: whole(b.mem_max.max()),
            mem_total_bytes: b.mem_total,
            swap_used_bytes: whole(b.swap.avg()),
            swap_total_bytes: b.swap_total,
            disk_read_bps: b.read.avg().map(f64::round),
            disk_write_bps: b.write.avg().map(f64::round),
            net_rx_bps: b.rx.avg().map(f64::round),
            net_tx_bps: b.tx.avg().map(f64::round),
            load1: hundredths(b.load.avg()),
            load_max: b.load_max.max(),
            disk_used_pct: b.disk_used.max(),
        })
        .collect()
}

/// A chart's history: the range's stored minutes in buckets, and where the stored minutes end, so the live
/// rounds take over from there.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistorySeries {
    pub range: HistoryRange,
    pub bucket_secs: u64,
    /// The range: from (Unix ms, inclusive) to now.
    pub from: i64,
    pub to: i64,
    /// The end of the last stored minute (Unix ms), when there is one: rounds from then on are in memory only.
    pub stored_until: Option<i64>,
    pub points: Vec<HistoryPoint>,
}

/// What one prune did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPruneReport {
    pub at: String,
    pub retention: HistoryRetention,
    /// Minutes and resolved alerts from before this (RFC 3339) were removed.
    pub before: String,
    pub removed: HistoryPruned,
    pub compacted: bool,
}

/// The setting, what is kept, and the last prune since the app started, for Settings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryInfo {
    pub retention: HistoryRetention,
    pub size: HistorySize,
    pub last_prune: Option<HistoryPruneReport>,
}

/// Now, in Unix milliseconds.
pub fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

/// MO-06: the history's writes, reads, setting and prune (`Core.history`). The collector hands it each round
/// ([`RoundObserver`]); the shell starts the prune's schedule with [`MetricsHistory::run`].
pub struct MetricsHistory {
    store: Store,
    /// FD-02: the workspace shown ([`MetricsHistory::switch_to`]): its settings and size.
    ctx: RwLock<Context>,
    /// FD-02: each workspace's open minutes, written under that workspace. The shown workspace gets its VMs, its
    /// watched hosts and this PC; another workspace its running VMs' host side, so VM-14's idle check works there.
    rollups: Mutex<HashMap<WorkspaceId, Rollup>>,
    /// One write at a time, in minute order.
    writing: tokio::sync::Mutex<()>,
    /// The job runner, for compacting the file while no job runs.
    jobs: OnceLock<Arc<JobRunner>>,
    /// One prune at a time.
    pruning: tokio::sync::Mutex<()>,
    last_prune: Mutex<Option<HistoryPruneReport>>,
}

impl MetricsHistory {
    pub fn new(store: Store, ctx: Context) -> Self {
        Self {
            store,
            ctx: RwLock::new(ctx),
            rollups: Mutex::new(HashMap::new()),
            writing: tokio::sync::Mutex::new(()),
            jobs: OnceLock::new(),
            pruning: tokio::sync::Mutex::new(()),
            last_prune: Mutex::new(None),
        }
    }

    fn ctx(&self) -> Context {
        *locks::read(&self.ctx)
    }

    /// FD-02: another workspace is shown. Each round says whose readings it has, so nothing open moves: the old
    /// workspace's minutes are written to it as they end.
    pub async fn switch_to(&self, ctx: Context) -> Result<()> {
        *locks::write(&self.ctx) = ctx;
        Ok(())
    }

    /// The job runner, once it exists: a prune compacts the file only while no job runs.
    pub fn set_jobs(&self, jobs: Arc<JobRunner>) {
        let _ = self.jobs.set(jobs);
    }

    /// Adds a round's readings to the open minutes: each VM's host side, each guest polled in it, this PC. FD-02:
    /// the shown workspace's in it; another workspace's running VMs in theirs.
    pub fn add_round(&self, round: &RecordedRound<'_>) {
        let mut rollups = locks::lock(&self.rollups);
        for (workspace, sample) in round.host_elsewhere {
            rollups.entry(*workspace).or_default().add(
                HistorySource::Host,
                &sample.target.key(),
                &super::MetricsHub::point(round.t_ms, sample),
            );
        }
        let rollup = rollups.entry(round.workspace).or_default();
        for sample in round.host.unwrap_or_default() {
            rollup.add(
                HistorySource::Host,
                &sample.target.key(),
                &super::MetricsHub::point(round.t_ms, sample),
            );
        }
        for sample in round.guest.unwrap_or_default() {
            rollup.add(
                HistorySource::Guest,
                &sample.target.key(),
                &super::MetricsHub::point(round.t_ms, sample),
            );
        }
        if let Some(point) = round.this_pc_point() {
            rollup.add(HistorySource::ThisPc, THIS_PC_KEY, &point);
        }
    }

    /// Writes every minute that is over at `now_ms`, in one transaction. Returns the rows written.
    pub async fn flush_due(&self, now_ms: i64) -> Result<usize> {
        let minute = now_ms.div_euclid(MINUTE_MS);
        // Nothing to write until a minute is over: no lock, no database.
        let due = locks::lock(&self.rollups)
            .values()
            .any(|r| r.first_minute().is_some_and(|m| m < minute));
        if !due {
            return Ok(0);
        }
        let _one = self.writing.lock().await;
        let rows = Self::take(&mut locks::lock(&self.rollups), |r| r.take_before(minute));
        self.write(rows).await
    }

    /// Writes everything, the open minute too: the app is closing.
    pub async fn flush_all(&self) -> Result<usize> {
        let _one = self.writing.lock().await;
        let rows = Self::take(&mut locks::lock(&self.rollups), Rollup::take_all);
        self.write(rows).await
    }

    /// Each workspace's rows `take` gives, dropping the rollups left empty.
    fn take(
        rollups: &mut HashMap<WorkspaceId, Rollup>,
        take: impl Fn(&mut Rollup) -> Vec<MinuteRow>,
    ) -> Vec<(WorkspaceId, Vec<MinuteRow>)> {
        let rows = rollups
            .iter_mut()
            .map(|(workspace, rollup)| (*workspace, take(rollup)))
            .filter(|(_, rows)| !rows.is_empty())
            .collect();
        rollups.retain(|_, rollup| !rollup.is_empty());
        rows
    }

    /// One transaction per workspace with rows (one in the usual case).
    async fn write(&self, rows: Vec<(WorkspaceId, Vec<MinuteRow>)>) -> Result<usize> {
        let user_id = self.ctx().user_id;
        let mut count = 0;
        for (workspace_id, rows) in rows {
            let ctx = Context { workspace_id, user_id };
            self.store.write_history(&ctx, &rows).await?;
            count += rows.len();
        }
        Ok(count)
    }

    /// A chart's range of one series, in buckets, up to `now_ms`.
    pub async fn series(
        &self,
        ctx: &Context,
        source: HistorySource,
        key: &str,
        range: HistoryRange,
        now_ms: i64,
    ) -> Result<HistorySeries> {
        let to_minute = now_ms.div_euclid(MINUTE_MS) + 1;
        // Whole buckets, so the first point covers as much as the others.
        let size = range.bucket_minutes();
        let from_minute = (to_minute - range.span_minutes()).div_euclid(size) * size;
        let rows = self
            .store
            .read_history(ctx, source, key, from_minute, to_minute)
            .await?;
        let stored_until = rows.last().map(|r| (r.minute + 1).saturating_mul(MINUTE_MS));
        Ok(HistorySeries {
            range,
            bucket_secs: u64::try_from(size * 60).unwrap_or(60),
            from: from_minute.saturating_mul(MINUTE_MS),
            to: now_ms,
            stored_until,
            points: bucket(&rows, size),
        })
    }

    /// The saved setting, or the default (7 days).
    pub async fn retention(&self) -> Result<HistoryRetention> {
        Ok(self
            .store
            .get_setting::<HistoryRetention>(&self.ctx(), HISTORY_RETENTION_KEY)
            .await?
            .unwrap_or_default())
    }

    pub async fn info(&self) -> Result<HistoryInfo> {
        Ok(HistoryInfo {
            retention: self.retention().await?,
            size: self.store.history_size(&self.ctx()).await?,
            last_prune: locks::lock(&self.last_prune).clone(),
        })
    }

    /// Saves the setting and prunes at once with it (a shorter time removes what is now too old). Audited;
    /// refused while presenting with the read-only lock.
    pub async fn set_retention(&self, retention: HistoryRetention) -> Result<HistoryInfo> {
        self.store.read_only().check(Change::Settings)?;
        let old = self.retention().await?;
        if old != retention {
            self.store
                .put_setting(&self.ctx(), HISTORY_RETENTION_KEY, &retention)
                .await?;
            let detail = format!(
                "{} -> {}; kept on this PC only, pruned daily",
                old.label(),
                retention.label()
            );
            self.audit(
                &self.ctx(),
                "setting_changed",
                "Set how long the dashboard keeps its history",
                &detail,
            )
            .await?;
            if retention.days() < old.days() {
                self.prune().await?;
            }
        }
        self.info().await
    }

    /// The scheduled prune: at start and daily. Not stopped by the read-only lock. Audited when it removed
    /// something.
    pub async fn prune(&self) -> Result<HistoryPruneReport> {
        let _one = self.pruning.lock().await;
        let retention = self.retention().await?;
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(retention.days());
        let cutoff = cutoff.replace_nanosecond(0).unwrap_or(cutoff);
        let before_minute = cutoff.unix_timestamp().div_euclid(60);
        let before = cutoff
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| cutoff.unix_timestamp().to_string());
        // FD-02: the retention is this PC's, so every workspace's history is pruned, each audited in its own log.
        let mut removed = HistoryPruned::default();
        let mut pruned = Vec::new();
        let ctx = self.ctx();
        for workspace in self.store.list_workspaces(ctx.user_id).await? {
            let ctx = Context {
                workspace_id: workspace.id,
                user_id: ctx.user_id,
            };
            let got = self.store.prune_history(&ctx, before_minute, &before).await?;
            if got.removed_any() {
                removed.minutes += got.minutes;
                removed.series += got.series;
                removed.alerts += got.alerts;
                pruned.push((ctx, got));
            }
        }
        let mut compacted = false;
        if removed.removed_any() {
            if let Err(err) = self.store.checkpoint().await {
                tracing::warn!(error = %err, "could not empty the database's write-ahead log after a history prune");
            }
            let (size, free) = self.store.space().await?;
            if worth_compacting(size, free) {
                if let Some(jobs) = self.jobs.get() {
                    match jobs.when_idle(self.store.vacuum()).await {
                        Some(Ok(())) => compacted = true,
                        Some(Err(err)) => tracing::warn!(error = %err, "could not compact the database after a prune"),
                        None => tracing::info!("a job is running: the database is compacted after a later prune"),
                    }
                }
            }
        }
        let report = HistoryPruneReport {
            at: now_rfc3339(),
            retention,
            before,
            removed,
            compacted,
        };
        for (ctx, got) in &pruned {
            let theirs = HistoryPruneReport {
                removed: *got,
                ..report.clone()
            };
            self.audit(
                ctx,
                "history_pruned",
                "Removed old dashboard history",
                &describe(&theirs),
            )
            .await?;
        }
        if removed.removed_any() {
            tracing::info!(
                minutes = removed.minutes,
                series = removed.series,
                alerts = removed.alerts,
                compacted,
                "pruned old dashboard history"
            );
        }
        *locks::lock(&self.last_prune) = Some(report.clone());
        Ok(report)
    }

    /// Prunes now, then whenever [`PRUNE_EVERY`] has passed by the wall clock, until `stop`.
    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        let mut last_run: Option<OffsetDateTime> = None;
        loop {
            let now = OffsetDateTime::now_utc();
            if last_run.is_none_or(|at| now - at >= PRUNE_EVERY) {
                last_run = Some(now);
                if let Err(err) = self.prune().await {
                    tracing::error!(error = %err, "the dashboard history's prune failed");
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    async fn audit(&self, ctx: &Context, event: &str, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
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

#[async_trait]
impl RoundObserver for MetricsHistory {
    async fn after_round(&self, round: &RecordedRound<'_>) {
        self.add_round(round);
        if let Err(err) = self.flush_due(round.t_ms).await {
            // The minutes are lost, not retried: the next minute is written as usual.
            tracing::warn!(error = %err, "could not write the dashboard's history");
        }
    }
}

/// What a prune did, in words, for the audit log and Settings.
pub fn describe(report: &HistoryPruneReport) -> String {
    let date = report.before.get(..10).unwrap_or(&report.before);
    let r = &report.removed;
    let mut parts = vec![format!(
        "older than {} (before {date}): removed {} and {}",
        report.retention.label(),
        plural(r.minutes, "one-minute reading", "one-minute readings"),
        plural(r.alerts, "resolved alert", "resolved alerts"),
    )];
    if r.series > 0 {
        parts.push(format!(
            "{} that no longer report went with them",
            plural(r.series, "series", "series")
        ));
    }
    if report.compacted {
        parts.push("the database file was compacted".to_owned());
    }
    parts.join("; ")
}

/// What the history takes, in words: "1.2 MB for 3 series".
pub fn describe_size(size: &HistorySize) -> String {
    match size.bytes {
        Some(bytes) => format!("{} for {}", human_size(bytes), plural(size.series, "series", "series")),
        None => plural(size.minutes, "minute", "minutes"),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests;
