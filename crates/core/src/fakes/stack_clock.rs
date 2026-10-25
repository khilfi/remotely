//! VM-08: a fake [`StackClock`] for a stack job's readiness waits and delays. A sleep moves the fake time on at once
//! (nothing really waits), runs whatever a test set to happen by then ([`FakeStackClock::at`], e.g. a guest's port
//! opening), and is recorded, so a test can say exactly how long a job waited.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::locks;
use crate::stacks::StackClock;

type Hook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
pub struct FakeStackClock {
    now: Mutex<Duration>,
    sleeps: Mutex<Vec<Duration>>,
    hooks: Mutex<Vec<(Duration, Hook)>>,
}

impl FakeStackClock {
    /// Runs `then` once the fake time reaches `when`.
    pub fn at(&self, when: Duration, then: impl FnOnce() + Send + 'static) {
        locks::lock(&self.hooks).push((when, Box::new(then)));
    }

    /// Every sleep asked for, in order.
    pub fn sleeps(&self) -> Vec<Duration> {
        locks::lock(&self.sleeps).clone()
    }

    /// The fake time now: the sum of every sleep.
    pub fn elapsed(&self) -> Duration {
        *locks::lock(&self.now)
    }
}

#[async_trait]
impl StackClock for FakeStackClock {
    fn now(&self) -> Duration {
        *locks::lock(&self.now)
    }

    async fn sleep(&self, how_long: Duration) {
        let now = {
            let mut now = locks::lock(&self.now);
            *now += how_long;
            *now
        };
        locks::lock(&self.sleeps).push(how_long);
        let due: Vec<Hook> = {
            let mut hooks = locks::lock(&self.hooks);
            let (due, later): (Vec<_>, Vec<_>) = hooks.drain(..).partition(|(when, _)| *when <= now);
            *hooks = later;
            due.into_iter().map(|(_, hook)| hook).collect()
        };
        for hook in due {
            hook();
        }
        tokio::task::yield_now().await;
    }
}
