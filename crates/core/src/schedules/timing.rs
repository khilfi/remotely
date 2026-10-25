//! VM-14, VM-27: when a schedule runs. Hourly at a minute, daily at a time, or weekly on chosen days at a time, all
//! in local time; or, for auto-suspend, whenever a VM has been idle long enough (no clock time at all).
//!
//! Daylight saving never doubles or skips a run silently:
//!
//! * A daily or weekly time runs once a day. When the clocks go back and the time comes twice, it runs at the
//!   first, and says so. When the clocks go forward and the time doesn't exist that day, it runs at the first
//!   minute after the jump (02:30 runs at 03:00), and says so.
//! * Hourly runs once each real hour, at the minute asked for on the local clock: an hour the clocks repeat runs
//!   twice (it is two hours), an hour they skip doesn't exist, and the runs stay an hour apart.

use serde::{Deserialize, Serialize};
use time::{Date, Duration, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};

use super::clock::Clock;
use crate::error::{CoreError, Result};

/// A time of day on the local clock, `HH:MM` in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WallTime {
    pub hour: u8,
    pub minute: u8,
}

impl WallTime {
    pub fn new(hour: u8, minute: u8) -> Result<Self> {
        if hour > 23 || minute > 59 {
            return Err(CoreError::InvalidInput(format!(
                "{hour:02}:{minute:02} is not a time of day (00:00 to 23:59)."
            )));
        }
        Ok(Self { hour, minute })
    }

    fn time(self) -> Time {
        Time::from_hms(self.hour, self.minute, 0).unwrap_or(Time::MIDNIGHT)
    }
}

impl std::fmt::Display for WallTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}:{:02}", self.hour, self.minute)
    }
}

impl TryFrom<String> for WallTime {
    type Error = String;

    fn try_from(text: String) -> std::result::Result<Self, String> {
        let bad = || format!("'{text}' is not a time like 08:00");
        let (h, m) = text.trim().split_once(':').ok_or_else(bad)?;
        if h.is_empty() || h.len() > 2 || m.len() != 2 {
            return Err(bad());
        }
        let hour: u8 = h.parse().map_err(|_| bad())?;
        let minute: u8 = m.parse().map_err(|_| bad())?;
        WallTime::new(hour, minute).map_err(|e| e.to_string())
    }
}

impl From<WallTime> for String {
    fn from(at: WallTime) -> Self {
        at.to_string()
    }
}

/// A day of the week, `mon` to `sun` in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Day {
    pub const ALL: [Day; 7] = [Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri, Day::Sat, Day::Sun];

    pub fn weekday(self) -> Weekday {
        match self {
            Day::Mon => Weekday::Monday,
            Day::Tue => Weekday::Tuesday,
            Day::Wed => Weekday::Wednesday,
            Day::Thu => Weekday::Thursday,
            Day::Fri => Weekday::Friday,
            Day::Sat => Weekday::Saturday,
            Day::Sun => Weekday::Sunday,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Day::Mon => "Mon",
            Day::Tue => "Tue",
            Day::Wed => "Wed",
            Day::Thu => "Thu",
            Day::Fri => "Fri",
            Day::Sat => "Sat",
            Day::Sun => "Sun",
        }
    }
}

/// VM-14: the shortest and longest idle time auto-suspend waits for, in minutes.
pub const MIN_IDLE_MINUTES: u32 = 10;
pub const MAX_IDLE_MINUTES: u32 = 24 * 60;
/// VM-14: the CPU share under which a VM counts as idle, at most.
pub const MAX_IDLE_CPU_PCT: u8 = 50;

/// When a schedule runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Timing {
    /// Every hour, at this minute of the local clock.
    Hourly { minute: u8 },
    /// Every day at this local time.
    Daily { at: WallTime },
    /// On these days, at this local time.
    Weekly { days: Vec<Day>, at: WallTime },
    /// VM-14 auto-suspend: a running VM whose CPU stayed under `cpu_below_pct` percent for `minutes` minutes
    /// (from the dashboard's history and its live rounds).
    Idle { minutes: u32, cpu_below_pct: u8 },
}

/// One planned run: when (UTC), and what daylight saving did to it that day, in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub at: OffsetDateTime,
    pub note: Option<String>,
}

impl Timing {
    /// Checks the numbers. Weekly days are put in order, each once.
    pub fn normalized(self) -> Result<Self> {
        let invalid = |message: &str| Err(CoreError::InvalidInput(message.into()));
        match self {
            Timing::Hourly { minute } if minute > 59 => invalid("Choose a minute from 0 to 59."),
            Timing::Weekly { mut days, at } => {
                days.sort();
                days.dedup();
                if days.is_empty() {
                    return invalid("Choose at least one day of the week.");
                }
                Ok(Timing::Weekly { days, at })
            }
            Timing::Idle { minutes, cpu_below_pct } => {
                if !(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&minutes) {
                    return Err(CoreError::InvalidInput(format!(
                        "A VM can count as idle after {MIN_IDLE_MINUTES} minutes to {} hours.",
                        MAX_IDLE_MINUTES / 60
                    )));
                }
                if !(1..=MAX_IDLE_CPU_PCT).contains(&cpu_below_pct) {
                    return Err(CoreError::InvalidInput(format!(
                        "Idle means CPU under 1% to {MAX_IDLE_CPU_PCT}%."
                    )));
                }
                Ok(Timing::Idle { minutes, cpu_below_pct })
            }
            other => Ok(other),
        }
    }

    pub fn is_idle(&self) -> bool {
        matches!(self, Timing::Idle { .. })
    }

    /// "Every hour at :15", "Daily at 02:00", "Mon, Wed, Fri at 08:00", "Weekdays at 08:00", "When idle for 30
    /// minutes (CPU under 5%)".
    pub fn describe(&self) -> String {
        match self {
            Timing::Hourly { minute } => format!("Every hour at :{minute:02}"),
            Timing::Daily { at } => format!("Daily at {at}"),
            Timing::Weekly { days, at } => {
                let weekdays = [Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri];
                let which = if days.len() == 7 {
                    "Every day".to_owned()
                } else if days.as_slice() == weekdays {
                    "Weekdays".to_owned()
                } else if days.as_slice() == [Day::Sat, Day::Sun] {
                    "Weekends".to_owned()
                } else {
                    days.iter().map(|d| d.label()).collect::<Vec<_>>().join(", ")
                };
                format!("{which} at {at}")
            }
            Timing::Idle { minutes, cpu_below_pct } => {
                let span = if minutes % 60 == 0 {
                    match minutes / 60 {
                        1 => "1 hour".to_owned(),
                        h => format!("{h} hours"),
                    }
                } else {
                    format!("{minutes} minutes")
                };
                format!("When idle for {span} (CPU under {cpu_below_pct}%)")
            }
        }
    }

    /// The first run after `after` (UTC), in the clock's local time. `None` for auto-suspend, which has no times.
    pub fn next_after(&self, after: OffsetDateTime, clock: &dyn Clock) -> Option<Occurrence> {
        match self {
            Timing::Hourly { minute } => next_hourly(*minute, after, clock),
            Timing::Daily { at } => next_daily(*at, None, after, clock),
            Timing::Weekly { days, at } => next_daily(*at, Some(days), after, clock),
            Timing::Idle { .. } => None,
        }
    }

    /// The runs due after `after` and up to `until` (both UTC): how many, and the first and last (a missed stretch
    /// is reported once). Counts at most `cap`.
    pub fn due_between(
        &self,
        after: OffsetDateTime,
        until: OffsetDateTime,
        clock: &dyn Clock,
        cap: usize,
    ) -> (usize, Option<OffsetDateTime>, Option<OffsetDateTime>) {
        let mut count = 0;
        let (mut first, mut last) = (None, None);
        let mut cursor = after;
        while count < cap {
            let Some(next) = self.next_after(cursor, clock) else {
                break;
            };
            if next.at > until {
                break;
            }
            count += 1;
            first.get_or_insert(next.at);
            last = Some(next.at);
            cursor = next.at;
        }
        (count, first, last)
    }
}

/// The local time at `at`.
fn local(at: OffsetDateTime, clock: &dyn Clock) -> OffsetDateTime {
    at.to_offset(clock.offset_at(at))
}

fn whole_minute(at: OffsetDateTime) -> OffsetDateTime {
    at.replace_second(0).and_then(|t| t.replace_nanosecond(0)).unwrap_or(at)
}

/// Hourly: the first instant after `after` whose local minute is `minute`, one per real hour.
fn next_hourly(minute: u8, after: OffsetDateTime, clock: &dyn Clock) -> Option<Occurrence> {
    let utc = after.to_offset(UtcOffset::UTC);
    let hour = utc.replace_minute(0).ok().map(whole_minute)?;
    for i in 0..=50 {
        let start = hour + Duration::hours(i);
        // The minute of the UTC hour that shows `minute` on the local clock, with the offset at the hour's start, or
        // at the candidate itself when the offset changes within the hour.
        let mut candidate = None;
        let mut offset = clock.offset_at(start);
        for _ in 0..2 {
            let shift = offset.whole_minutes() as i64;
            let at = start + Duration::minutes((i64::from(minute) - shift).rem_euclid(60));
            if local(at, clock).minute() == minute {
                candidate = Some(at);
                break;
            }
            offset = clock.offset_at(at);
        }
        if let Some(at) = candidate.filter(|at| *at > after) {
            return Some(Occurrence { at, note: None });
        }
    }
    None
}

/// Daily (`days` None) or weekly: the first day's run after `after`.
fn next_daily(at: WallTime, days: Option<&[Day]>, after: OffsetDateTime, clock: &dyn Clock) -> Option<Occurrence> {
    let today = local(after, clock).date();
    for shift in -1..=9 {
        let Some(date) = today.checked_add(Duration::days(shift)) else {
            continue;
        };
        if let Some(days) = days {
            if !days.iter().any(|d| d.weekday() == date.weekday()) {
                continue;
            }
        }
        let occurrence = occurrence_on(date, at, clock);
        if occurrence.at > after {
            return Some(occurrence);
        }
    }
    None
}

/// The one run of `at` on the local `date`: the time itself, the first of two when the clocks go back, or the first
/// minute after the jump when the clocks go forward over it.
fn occurrence_on(date: Date, at: WallTime, clock: &dyn Clock) -> Occurrence {
    let wanted = PrimitiveDateTime::new(date, at.time());
    let probe = wanted.assume_utc();
    let offsets = [
        clock.offset_at(probe - Duration::days(1)),
        clock.offset_at(probe + Duration::days(1)),
    ];
    let mut found: Vec<OffsetDateTime> = offsets
        .iter()
        .map(|&offset| wanted.assume_offset(offset).to_offset(UtcOffset::UTC))
        .filter(|&t| local(t, clock).time() == wanted.time() && local(t, clock).date() == date)
        .collect();
    found.sort();
    found.dedup();
    let when = format!("{at} on {}", short_date(date));
    match found.as_slice() {
        [one] => Occurrence { at: *one, note: None },
        [first, ..] => Occurrence {
            at: *first,
            note: Some(format!(
                "{when} comes twice as the clocks go back: it runs once, at the first"
            )),
        },
        [] => {
            // The clocks jump over it: the first minute whose local time is past it.
            let candidates = offsets.map(|offset| wanted.assume_offset(offset).to_offset(UtcOffset::UTC));
            let (mut lo, mut hi) = (
                candidates.iter().min().copied().unwrap_or(probe),
                candidates.iter().max().copied().unwrap_or(probe),
            );
            let past = |t: OffsetDateTime| {
                let l = local(t, clock);
                PrimitiveDateTime::new(l.date(), l.time()) >= wanted
            };
            if !past(hi) {
                // Not a jump Remotely can place (two changes in two days): the later reading.
                return Occurrence { at: hi, note: None };
            }
            while hi - lo > Duration::minutes(1) {
                let mid = whole_minute(lo + (hi - lo) / 2);
                if mid <= lo || mid >= hi {
                    break;
                }
                if past(mid) {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            let shown = local(hi, clock);
            Occurrence {
                at: hi,
                note: Some(format!(
                    "{when} doesn't exist as the clocks go forward: it runs at {:02}:{:02}",
                    shown.hour(),
                    shown.minute()
                )),
            }
        }
    }
}

/// "29 Mar".
fn short_date(date: Date) -> String {
    let month = match date.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!("{} {month}", date.day())
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::fakes::clock::{FakeClock, FakeZone};

    fn at(hour: u8, minute: u8) -> WallTime {
        WallTime::new(hour, minute).unwrap()
    }

    fn europe() -> FakeClock {
        FakeClock::new(datetime!(2026-01-01 00:00 UTC), FakeZone::central_europe())
    }

    fn us() -> FakeClock {
        FakeClock::new(datetime!(2026-01-01 00:00 UTC), FakeZone::us_eastern())
    }

    fn runs(timing: &Timing, from: OffsetDateTime, n: usize, clock: &dyn Clock) -> Vec<Occurrence> {
        let mut out = Vec::new();
        let mut cursor = from;
        for _ in 0..n {
            let next = timing.next_after(cursor, clock).unwrap();
            cursor = next.at;
            out.push(next);
        }
        out
    }

    fn locals(runs: &[Occurrence], clock: &dyn Clock) -> Vec<String> {
        runs.iter()
            .map(|r| {
                let l = local(r.at, clock);
                format!("{} {:02}:{:02}", l.date(), l.hour(), l.minute())
            })
            .collect()
    }

    #[test]
    fn wall_times_read_and_write_as_hh_mm() {
        assert_eq!(WallTime::try_from("8:05".to_owned()).unwrap(), at(8, 5));
        assert_eq!(String::from(at(8, 5)), "08:05");
        for bad in ["24:00", "12:60", "noon", "1230", "12:5", ""] {
            assert!(WallTime::try_from(bad.to_owned()).is_err(), "{bad}");
        }
        let json = serde_json::to_string(&Timing::Daily { at: at(2, 30) }).unwrap();
        assert_eq!(json, r#"{"kind":"daily","at":"02:30"}"#);
    }

    #[test]
    fn daily_runs_every_day_at_the_local_time() {
        let clock = europe();
        let timing = Timing::Daily { at: at(2, 0) };
        let got = runs(&timing, datetime!(2026-06-10 12:00 UTC), 3, &clock);
        assert_eq!(
            locals(&got, &clock),
            ["2026-06-11 02:00", "2026-06-12 02:00", "2026-06-13 02:00"]
        );
        // Summer time in Europe is UTC+2.
        assert_eq!(got[0].at, datetime!(2026-06-11 00:00 UTC));
        assert!(got.iter().all(|r| r.note.is_none()));
    }

    #[test]
    fn a_run_at_the_same_instant_as_after_is_not_next() {
        let clock = europe();
        let timing = Timing::Daily { at: at(2, 0) };
        let first = timing.next_after(datetime!(2026-06-11 00:00 UTC), &clock).unwrap();
        assert_eq!(first.at, datetime!(2026-06-12 00:00 UTC));
    }

    #[test]
    fn hourly_runs_at_the_minute_every_hour() {
        let clock = europe();
        let timing = Timing::Hourly { minute: 15 };
        let got = runs(&timing, datetime!(2026-06-10 12:20 UTC), 3, &clock);
        assert_eq!(
            locals(&got, &clock),
            ["2026-06-10 15:15", "2026-06-10 16:15", "2026-06-10 17:15"]
        );
    }

    #[test]
    fn hourly_in_a_half_hour_zone_still_runs_at_the_local_minute() {
        let clock = FakeClock::new(
            datetime!(2026-01-01 00:00 UTC),
            FakeZone::fixed(UtcOffset::from_hms(5, 30, 0).unwrap()),
        );
        let timing = Timing::Hourly { minute: 0 };
        let got = runs(&timing, datetime!(2026-06-10 12:00 UTC), 2, &clock);
        assert_eq!(locals(&got, &clock), ["2026-06-10 18:00", "2026-06-10 19:00"]);
        assert_eq!(got[0].at, datetime!(2026-06-10 12:30 UTC));
    }

    #[test]
    fn weekly_runs_on_the_chosen_days_only() {
        let clock = europe();
        let timing = Timing::Weekly {
            days: vec![Day::Mon, Day::Fri],
            at: at(8, 0),
        };
        // 2026-06-10 is a Wednesday.
        let got = runs(&timing, datetime!(2026-06-10 12:00 UTC), 3, &clock);
        assert_eq!(
            locals(&got, &clock),
            ["2026-06-12 08:00", "2026-06-15 08:00", "2026-06-19 08:00"]
        );
    }

    #[test]
    fn spring_forward_runs_a_skipped_time_at_the_first_minute_after_the_jump_and_says_so() {
        // Europe: 29 Mar 2026, 02:00 local becomes 03:00 (01:00 UTC).
        let clock = europe();
        let timing = Timing::Daily { at: at(2, 30) };
        let got = runs(&timing, datetime!(2026-03-27 12:00 UTC), 3, &clock);
        assert_eq!(
            locals(&got, &clock),
            ["2026-03-28 02:30", "2026-03-29 03:00", "2026-03-30 02:30"]
        );
        assert_eq!(got[1].at, datetime!(2026-03-29 01:00 UTC));
        assert_eq!(
            got[1].note.as_deref(),
            Some("02:30 on 29 Mar doesn't exist as the clocks go forward: it runs at 03:00")
        );
        assert!(got[0].note.is_none() && got[2].note.is_none());
    }

    #[test]
    fn fall_back_runs_a_doubled_time_once_and_says_so() {
        // Europe: 25 Oct 2026, 03:00 local goes back to 02:00 (01:00 UTC), so 02:30 comes twice.
        let clock = europe();
        let timing = Timing::Daily { at: at(2, 30) };
        let got = runs(&timing, datetime!(2026-10-23 12:00 UTC), 3, &clock);
        assert_eq!(
            locals(&got, &clock),
            ["2026-10-24 02:30", "2026-10-25 02:30", "2026-10-26 02:30"]
        );
        // The first 02:30 is still summer time (UTC+2).
        assert_eq!(got[1].at, datetime!(2026-10-25 00:30 UTC));
        assert_eq!(
            got[1].note.as_deref(),
            Some("02:30 on 25 Oct comes twice as the clocks go back: it runs once, at the first")
        );
        // The second 02:30 (01:30 UTC) is not a run of its own.
        let after_first = timing.next_after(got[1].at, &clock).unwrap();
        assert_eq!(after_first.at, got[2].at);
    }

    #[test]
    fn us_rules_change_at_two_in_the_morning_local() {
        let clock = us();
        let timing = Timing::Daily { at: at(2, 15) };
        // 8 Mar 2026: 02:00 EST becomes 03:00 EDT.
        let spring = timing.next_after(datetime!(2026-03-08 05:00 UTC), &clock).unwrap();
        assert_eq!(locals(std::slice::from_ref(&spring), &clock), ["2026-03-08 03:00"]);
        assert!(spring.note.unwrap().contains("doesn't exist"));
        // 1 Nov 2026: 02:00 EDT goes back to 01:00 EST, so 01:15 comes twice.
        let doubled = Timing::Daily { at: at(1, 15) };
        let fall = doubled.next_after(datetime!(2026-11-01 04:00 UTC), &clock).unwrap();
        assert_eq!(fall.at, datetime!(2026-11-01 05:15 UTC));
        assert!(fall.note.unwrap().contains("comes twice"));
    }

    #[test]
    fn hourly_stays_an_hour_apart_across_both_changes() {
        let clock = europe();
        let timing = Timing::Hourly { minute: 30 };
        for from in [datetime!(2026-03-28 23:00 UTC), datetime!(2026-10-24 22:00 UTC)] {
            let got = runs(&timing, from, 6, &clock);
            for pair in got.windows(2) {
                assert_eq!(
                    pair[1].at - pair[0].at,
                    Duration::hours(1),
                    "{:?}",
                    locals(&got, &clock)
                );
            }
            assert!(got.iter().all(|r| r.note.is_none()));
        }
        // The repeated hour on the local clock: 02:30 twice in a row, each a real hour.
        let fall = runs(&timing, datetime!(2026-10-24 23:00 UTC), 4, &clock);
        assert_eq!(
            locals(&fall, &clock),
            [
                "2026-10-25 01:30",
                "2026-10-25 02:30",
                "2026-10-25 02:30",
                "2026-10-25 03:30"
            ]
        );
    }

    #[test]
    fn idle_timing_has_no_clock_runs() {
        let clock = europe();
        let timing = Timing::Idle {
            minutes: 30,
            cpu_below_pct: 5,
        };
        assert!(timing.next_after(datetime!(2026-06-10 12:00 UTC), &clock).is_none());
        assert_eq!(timing.describe(), "When idle for 30 minutes (CPU under 5%)");
    }

    #[test]
    fn missed_runs_are_counted_with_the_first_and_last() {
        let clock = europe();
        let timing = Timing::Hourly { minute: 0 };
        let (count, first, last) = timing.due_between(
            datetime!(2026-06-10 10:00 UTC),
            datetime!(2026-06-10 14:30 UTC),
            &clock,
            1000,
        );
        assert_eq!(count, 4);
        assert_eq!(first, Some(datetime!(2026-06-10 11:00 UTC)));
        assert_eq!(last, Some(datetime!(2026-06-10 14:00 UTC)));
    }

    #[test]
    fn timings_are_checked_and_described() {
        assert!(Timing::Hourly { minute: 60 }.normalized().is_err());
        assert!(Timing::Weekly {
            days: vec![],
            at: at(8, 0)
        }
        .normalized()
        .is_err());
        assert!(Timing::Idle {
            minutes: 5,
            cpu_below_pct: 5
        }
        .normalized()
        .is_err());
        assert!(Timing::Idle {
            minutes: 30,
            cpu_below_pct: 0
        }
        .normalized()
        .is_err());
        let weekly = Timing::Weekly {
            days: vec![Day::Fri, Day::Mon, Day::Wed, Day::Thu, Day::Tue, Day::Mon],
            at: at(8, 0),
        }
        .normalized()
        .unwrap();
        assert_eq!(weekly.describe(), "Weekdays at 08:00");
        assert_eq!(
            Timing::Weekly {
                days: vec![Day::Sat, Day::Sun],
                at: at(10, 0)
            }
            .describe(),
            "Weekends at 10:00"
        );
        assert_eq!(
            Timing::Weekly {
                days: vec![Day::Mon, Day::Wed],
                at: at(7, 5)
            }
            .describe(),
            "Mon, Wed at 07:05"
        );
        assert_eq!(Timing::Hourly { minute: 5 }.describe(), "Every hour at :05");
        assert_eq!(Timing::Daily { at: at(2, 0) }.describe(), "Daily at 02:00");
        assert_eq!(
            Timing::Idle {
                minutes: 120,
                cpu_below_pct: 3
            }
            .describe(),
            "When idle for 2 hours (CPU under 3%)"
        );
    }
}
