//! VM-14 auto-suspend: whether a running VM has been idle long enough, from the dashboard's history on disk (MO-06's
//! 1-minute averages of the VM's own CPU, host side) and, for the minutes not written yet, the collector's live
//! rounds in memory. Reads only.
//!
//! Idle means: every minute of the window has a reading (one may still wait to be written), and each minute's
//! average CPU is under the limit. A gap (Remotely closed, the PC asleep, the VM off or suspended) means "not known
//! to be idle": the window starts again once the VM has run that long with Remotely watching.

use std::collections::BTreeMap;

use crate::domain::Context;
use crate::error::Result;
use crate::metrics::history::{HistorySource, MINUTE_MS};
use crate::metrics::{MetricSource, MetricsHub};
use crate::store::Store;

/// What the readings say about one VM.
#[derive(Debug, Clone, PartialEq)]
pub enum IdleVerdict {
    /// Under the limit in every minute of the window; `avg_pct` is the window's average.
    Idle { avg_pct: f64 },
    /// A minute at or over the limit.
    Busy { minute_pct: f64 },
    /// Not enough readings for the window.
    NotEnough { minutes: usize },
}

/// The verdict for the VM with this key over the `minutes` before `now_ms` (Unix ms).
pub async fn idle_verdict(
    store: &Store,
    ctx: &Context,
    hub: &MetricsHub,
    key: &str,
    minutes: u32,
    below_pct: u8,
    now_ms: i64,
) -> Result<IdleVerdict> {
    let now_minute = now_ms.div_euclid(MINUTE_MS);
    let from = now_minute - i64::from(minutes);
    let rows = store
        .read_history(ctx, HistorySource::Host, key, from, now_minute)
        .await?;
    let mut by_minute: BTreeMap<i64, f64> = rows
        .iter()
        .filter_map(|r| r.cpu_avg.map(|cpu| (r.minute, cpu)))
        .collect();
    // The live rounds of the minutes not written yet.
    let mut live: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    for point in hub.series(MetricSource::Host, key) {
        let minute = point.t.div_euclid(MINUTE_MS);
        if minute < from || minute > now_minute || by_minute.contains_key(&minute) {
            continue;
        }
        if let Some(cpu) = point.cpu_pct {
            live.entry(minute).or_default().push(cpu);
        }
    }
    for (minute, readings) in live {
        let avg = readings.iter().sum::<f64>() / readings.len() as f64;
        by_minute.insert(minute, avg);
    }
    Ok(verdict(&by_minute, from, now_minute, minutes, below_pct))
}

/// The verdict from each minute's average: `[from, now_minute)` must be covered, but for one minute that may still
/// wait to be written; the current minute counts too when it has readings.
pub fn verdict(by_minute: &BTreeMap<i64, f64>, from: i64, now_minute: i64, minutes: u32, below_pct: u8) -> IdleVerdict {
    let limit = f64::from(below_pct);
    if let Some((_, busy)) = by_minute.range(from..=now_minute).find(|(_, cpu)| **cpu >= limit) {
        return IdleVerdict::Busy { minute_pct: *busy };
    }
    let covered = by_minute.range(from..now_minute).count();
    let needed = (minutes as usize).saturating_sub(1);
    if covered < needed || covered == 0 {
        return IdleVerdict::NotEnough { minutes: covered };
    }
    let readings: Vec<f64> = by_minute.range(from..=now_minute).map(|(_, cpu)| *cpu).collect();
    IdleVerdict::Idle {
        avg_pct: readings.iter().sum::<f64>() / readings.len() as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minutes(range: std::ops::Range<i64>, cpu: f64) -> BTreeMap<i64, f64> {
        range.map(|m| (m, cpu)).collect()
    }

    #[test]
    fn a_whole_window_under_the_limit_is_idle() {
        let readings = minutes(100..130, 2.0);
        assert_eq!(verdict(&readings, 100, 130, 30, 5), IdleVerdict::Idle { avg_pct: 2.0 });
    }

    #[test]
    fn the_last_minute_may_still_wait_to_be_written() {
        let readings = minutes(100..129, 2.0);
        assert!(matches!(verdict(&readings, 100, 130, 30, 5), IdleVerdict::Idle { .. }));
    }

    #[test]
    fn a_gap_is_not_idle() {
        let mut readings = minutes(100..130, 2.0);
        readings.remove(&110);
        readings.remove(&111);
        assert_eq!(
            verdict(&readings, 100, 130, 30, 5),
            IdleVerdict::NotEnough { minutes: 28 }
        );
        assert_eq!(
            verdict(&BTreeMap::new(), 100, 130, 30, 5),
            IdleVerdict::NotEnough { minutes: 0 }
        );
    }

    #[test]
    fn one_busy_minute_is_not_idle() {
        let mut readings = minutes(100..130, 2.0);
        readings.insert(115, 40.0);
        assert_eq!(
            verdict(&readings, 100, 130, 30, 5),
            IdleVerdict::Busy { minute_pct: 40.0 }
        );
        // Exactly the limit counts as busy.
        readings.insert(115, 5.0);
        assert!(matches!(verdict(&readings, 100, 130, 30, 5), IdleVerdict::Busy { .. }));
    }
}
