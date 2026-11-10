use std::time::Duration;

use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};

pub struct CleanupTimer {
    interval: Interval,
}

impl CleanupTimer {
    pub fn new(epoch: Instant, period: Duration) -> Self {
        Self {
            interval: Self::interval(epoch, period),
        }
    }

    pub fn tick(&mut self) -> impl Future<Output = Instant>{
        self.interval.tick()
    }

    fn interval(epoch: Instant, interval: Duration) -> Interval {
        let mut interval = interval_at(epoch, interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval
    }
}

pub fn elapsed_since(epoch: Instant) -> u32 {
    epoch.elapsed().as_millis() as u32
}