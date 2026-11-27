use std::{
    sync::atomic::{AtomicU64, Ordering::Relaxed}
};
use tokio::time::{Instant, Duration, MissedTickBehavior, interval};

pub struct Activity {
    base: Instant,
    last_secs: AtomicU64,
}

impl Activity {
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            last_secs: AtomicU64::new(0),
        }
    }

    pub fn touch(&self) {
        let now = self.base.elapsed().as_secs();
        // 同一秒内不重复写,避免多核 cache line 抖动
        if self.last_secs.load(Relaxed) != now {
            self.last_secs.store(now, Relaxed);
        }
    }

    pub fn idle_for(&self) -> Duration {
        let now = self.base.elapsed().as_secs();
        Duration::from_secs(now.saturating_sub(self.last_secs.load(Relaxed)))
    }
}

pub async fn idle_timeouts(act: &Activity, check_every: Duration, timeouts: Duration) {
    let mut tick = interval(check_every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // 第一个 tick 立即返回,先消耗掉
    loop {
        tick.tick().await;
        if act.idle_for() >= timeouts {
            return;
        }
    }
}
