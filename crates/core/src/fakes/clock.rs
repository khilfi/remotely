//! VM-14, VM-27: a clock and time zones for the scheduler's tests. Time moves only when a test says so, and the zones
//! follow daylight-saving rules of their own (no time zone database, nothing read from the PC), so a test is the
//! same everywhere and nothing sleeps.

use std::sync::Mutex;

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};

use crate::locks;
use crate::schedules::clock::Clock;

/// Which daylight-saving rule a zone follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstRule {
    /// The EU's: one hour more from the last Sunday of March to the last Sunday of October, at 01:00 UTC.
    Europe,
    /// The US's: one hour more from the second Sunday of March to the first Sunday of November, at 02:00 local.
    UnitedStates,
}

/// A time zone: a standard offset, and maybe one hour more in summer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeZone {
    standard: UtcOffset,
    rule: Option<DstRule>,
}

impl FakeZone {
    pub fn fixed(offset: UtcOffset) -> Self {
        Self {
            standard: offset,
            rule: None,
        }
    }

    /// UTC+1, and UTC+2 in summer (Paris, Berlin).
    pub fn central_europe() -> Self {
        Self {
            standard: UtcOffset::from_hms(1, 0, 0).unwrap_or(UtcOffset::UTC),
            rule: Some(DstRule::Europe),
        }
    }

    /// UTC-5, and UTC-4 in summer (New York).
    pub fn us_eastern() -> Self {
        Self {
            standard: UtcOffset::from_hms(-5, 0, 0).unwrap_or(UtcOffset::UTC),
            rule: Some(DstRule::UnitedStates),
        }
    }

    pub fn offset_at(&self, at: OffsetDateTime) -> UtcOffset {
        let Some(rule) = self.rule else {
            return self.standard;
        };
        let year = at.to_offset(UtcOffset::UTC).year();
        let summer = UtcOffset::from_whole_seconds(self.standard.whole_seconds() + 3600).unwrap_or(self.standard);
        let (start, end) = match rule {
            DstRule::Europe => (
                utc(last_sunday(year, Month::March), 1),
                utc(last_sunday(year, Month::October), 1),
            ),
            DstRule::UnitedStates => (
                // 02:00 standard time, and 02:00 summer time.
                utc(nth_sunday(year, Month::March, 2), 2) - Duration::seconds(self.standard.whole_seconds().into()),
                utc(nth_sunday(year, Month::November, 1), 2) - Duration::seconds(summer.whole_seconds().into()),
            ),
        };
        if at >= start && at < end {
            summer
        } else {
            self.standard
        }
    }
}

fn utc(date: Date, hour: u8) -> OffsetDateTime {
    PrimitiveDateTime::new(date, Time::from_hms(hour, 0, 0).unwrap_or(Time::MIDNIGHT)).assume_utc()
}

fn last_sunday(year: i32, month: Month) -> Date {
    let days = month.length(year);
    let mut date = Date::from_calendar_date(year, month, days).unwrap_or(Date::MIN);
    while date.weekday() != Weekday::Sunday {
        date = date.previous_day().unwrap_or(date);
    }
    date
}

fn nth_sunday(year: i32, month: Month, n: u8) -> Date {
    let mut date = Date::from_calendar_date(year, month, 1).unwrap_or(Date::MIN);
    while date.weekday() != Weekday::Sunday {
        date = date.next_day().unwrap_or(date);
    }
    date + Duration::weeks(i64::from(n.saturating_sub(1)))
}

/// A clock that moves only when told to, in a [`FakeZone`].
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<OffsetDateTime>,
    zone: FakeZone,
}

impl FakeClock {
    pub fn new(now: OffsetDateTime, zone: FakeZone) -> Self {
        Self {
            now: Mutex::new(now),
            zone,
        }
    }

    /// Central Europe, at `now`.
    pub fn europe(now: OffsetDateTime) -> Self {
        Self::new(now, FakeZone::central_europe())
    }

    pub fn set(&self, now: OffsetDateTime) {
        *locks::lock(&self.now) = now;
    }

    pub fn advance(&self, by: Duration) {
        let mut now = locks::lock(&self.now);
        *now += by;
    }

    pub fn zone(&self) -> FakeZone {
        self.zone
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *locks::lock(&self.now)
    }

    fn offset_at(&self, at: OffsetDateTime) -> UtcOffset {
        self.zone.offset_at(at)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn the_zones_change_when_their_rules_say() {
        let europe = FakeZone::central_europe();
        let hours = |zone: &FakeZone, at| zone.offset_at(at).whole_hours();
        assert_eq!(hours(&europe, datetime!(2026-03-29 00:59 UTC)), 1);
        assert_eq!(hours(&europe, datetime!(2026-03-29 01:00 UTC)), 2);
        assert_eq!(hours(&europe, datetime!(2026-10-25 00:59 UTC)), 2);
        assert_eq!(hours(&europe, datetime!(2026-10-25 01:00 UTC)), 1);
        let us = FakeZone::us_eastern();
        assert_eq!(hours(&us, datetime!(2026-03-08 06:59 UTC)), -5);
        assert_eq!(hours(&us, datetime!(2026-03-08 07:00 UTC)), -4);
        assert_eq!(hours(&us, datetime!(2026-11-01 05:59 UTC)), -4);
        assert_eq!(hours(&us, datetime!(2026-11-01 06:00 UTC)), -5);
    }
}
