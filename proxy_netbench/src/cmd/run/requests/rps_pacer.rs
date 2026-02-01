use std::time::Duration;

use rand::{Rng as _, SeedableRng as _};
use tokio::time::{Instant, sleep};

/// Token bucket RPS pacer.
///
/// The pacer maintains a floating point token count.
/// Tokens refill continuously at `target_rps` per second, capped by `burst_size`.
/// Emitting a request consumes one token.
/// If there is not enough token balance, the pacer sleeps until at least one token is available.
///
/// Jitter is applied to the computed sleep duration.
/// Token accounting is not jittered so the long term average converges to the configured rate.
pub(super) struct RpsPacer {
    target_rps: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
    jitter: f64,
    rng: rand::rngs::SmallRng,
}

impl RpsPacer {
    pub(super) fn new(target_rps: u32, burst_size: u32, jitter: f64) -> Self {
        Self::new_with_rng(
            target_rps,
            burst_size,
            jitter,
            rand::rngs::SmallRng::from_os_rng(),
        )
    }

    fn new_with_rng(
        target_rps: u32,
        burst_size: u32,
        jitter: f64,
        rng: rand::rngs::SmallRng,
    ) -> Self {
        let normalised_target_rps = target_rps.max(1) as f64;
        let capacity = burst_size.max(1) as f64;

        Self {
            target_rps: normalised_target_rps,
            capacity,
            tokens: capacity,
            last: Instant::now(),
            jitter: jitter.clamp(0.0, 1.0),
            rng,
        }
    }

    pub(super) async fn wait_one(&mut self) {
        loop {
            self.refill();

            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }

            let missing = 1.0 - self.tokens;
            let base_wait = Duration::from_secs_f64(missing / self.target_rps);

            let wait = self.jittered(base_wait);

            // Guard against sleeping for zero when we still need to wait.
            let wait = if wait.is_zero() {
                Duration::from_nanos(1)
            } else {
                wait
            };

            sleep(wait).await;
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;

        self.tokens = (self.tokens + dt * self.target_rps).min(self.capacity);
    }

    fn jittered(&mut self, d: Duration) -> Duration {
        if self.jitter <= 0.0 {
            return d;
        }

        let lo = 1.0 - self.jitter;
        let hi = 1.0 + self.jitter;
        let m = self.rng.random_range(lo..=hi);

        Duration::from_secs_f64((d.as_secs_f64() * m).max(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{task::yield_now, time};

    fn seeded_pacer(target_rps: u32, burst_size: u32, jitter: f64, seed: u64) -> RpsPacer {
        let rng = rand::rngs::SmallRng::seed_from_u64(seed);
        RpsPacer::new_with_rng(target_rps, burst_size, jitter, rng)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn burst_allows_immediate_tokens() {
        time::pause();

        let mut p = seeded_pacer(10, 3, 0.0, 1);

        // Should not sleep for the initial burst.
        p.wait_one().await;
        p.wait_one().await;
        p.wait_one().await;

        // Next one should block because no time has advanced to refill.
        let h = tokio::spawn(async move {
            let mut p = p;
            p.wait_one().await;
            p
        });

        yield_now().await;
        assert!(!h.is_finished());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refills_at_target_rps_after_time_advances() {
        time::pause();

        let mut p = seeded_pacer(2, 1, 0.0, 2);

        // Consume the single burst token.
        p.wait_one().await;

        // Next wait should need 0.5 seconds at 2 rps.
        let h = tokio::spawn(async move {
            let mut p = p;
            p.wait_one().await;
            p
        });

        yield_now().await;
        assert!(!h.is_finished());

        time::advance(Duration::from_millis(499)).await;
        yield_now().await;
        assert!(!h.is_finished());

        time::advance(Duration::from_millis(1)).await;
        let _p = h.await.expect("task join");
    }

    #[test]
    fn jitter_bounds_are_respected() {
        let mut p = seeded_pacer(10, 1, 0.25, 3);
        let d = Duration::from_secs(10);

        let j = p.jittered(d);
        let secs = j.as_secs_f64();

        // jitter 0.25 means multiplier in [0.75, 1.25]
        assert!(secs >= 7.5);
        assert!(secs <= 12.5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refill_caps_at_capacity() {
        time::pause();

        let mut p = seeded_pacer(100, 5, 0.0, 4);

        // Put pacer in a depleted state.
        p.tokens = 0.0;
        p.last = Instant::now();

        time::advance(Duration::from_secs(1)).await;

        p.refill();
        assert_eq!(p.tokens, 5.0);
    }
}
