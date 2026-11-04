use std::time::Duration;

use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};

pub struct CleanupTimer {
    epoch: Instant,
    interval: Interval,
}

impl CleanupTimer {
    pub fn new(period: Duration) -> Self {
        let epoch = Instant::now();
        Self {
            epoch,
            interval: Self::interval(epoch, period),
        }
    }

    pub fn epoch(&self) -> Instant {
        self.epoch
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