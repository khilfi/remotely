//! VM-14, VM-27: the scheduler's clock. The wall clock decides when a schedule is due (the PC may sleep, so no
//! timer counts the time down), and local time follows Windows' time zone, daylight saving included. Tests give
//! their own clock and zone (`fakes::clock`), so nothing sleeps.

use time::{OffsetDateTime, UtcOffset};

/// Now, and the local time zone at any instant.
pub trait Clock: Send + Sync {
    /// The current instant (UTC).
    fn now(&self) -> OffsetDateTime;
    /// Local time's offset from UTC at `at`, daylight saving included.
    fn offset_at(&self, at: OffsetDateTime) -> UtcOffset;
}

/// The PC's own clock and time zone.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn offset_at(&self, at: OffsetDateTime) -> UtcOffset {
        // Windows answers from the zone's rules for that date. Elsewhere `time` may refuse in a program with
        // several threads; UTC is the answer then (Remotely runs on Windows only).
        UtcOffset::local_offset_at(at).unwrap_or(UtcOffset::UTC)
    }
}
