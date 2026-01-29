use super::{Counters, FailureKind, Phase, Reporter, RequestResultEvent};

pub struct HumanReporter {
    interval: std::time::Duration,
    last_tick: std::time::Duration,
    interval_counts: Counters,
    total_counts: Counters,
    last_pos: Option<(Phase, usize, usize)>,
}

impl HumanReporter {
    pub fn new(interval: std::time::Duration) -> Self {
        Self {
            interval,
            last_tick: std::time::Duration::ZERO,
            interval_counts: Counters::default(),
            total_counts: Counters::default(),
            last_pos: None,
        }
    }

    pub(super) fn apply_counts(c: &mut Counters, ev: &RequestResultEvent) {
        c.total += 1;
        if ev.outcome.ok {
            c.ok += 1;
            return;
        }
        match ev.outcome.failure {
            Some(FailureKind::HttpStatus) => c.http_fail += 1,
            _ => c.other_fail += 1,
        }
    }
}

impl Reporter for HumanReporter {
    fn on_result(&mut self, ev: &RequestResultEvent) {
        Self::apply_counts(&mut self.interval_counts, ev);
        Self::apply_counts(&mut self.total_counts, ev);
        self.last_pos = Some((ev.phase, ev.iteration, ev.index));
    }

    fn on_tick(&mut self, now: std::time::Duration) {
        if now.saturating_sub(self.last_tick) < self.interval {
            return;
        }
        self.last_tick = now;

        let rps = self.interval_counts.total as f64 / self.interval.as_secs_f64();
        let (phase, it, idx) = self.last_pos.unwrap_or((Phase::Warmup, 0, 0));

        println!(
            "t={:.1}s phase={:?} it={} idx={} rps={:.1} ok={} http_fail={} other_fail={} total_ok={} total_fail={}",
            now.as_secs_f64(),
            phase,
            it,
            idx,
            rps,
            self.interval_counts.ok,
            self.interval_counts.http_fail,
            self.interval_counts.other_fail,
            self.total_counts.ok,
            self.total_counts.total - self.total_counts.ok,
        );

        self.interval_counts = Counters::default();
    }

    fn finish(&mut self) {
        println!(
            "done ok={} http_fail={} other_fail={} total={}",
            self.total_counts.ok,
            self.total_counts.http_fail,
            self.total_counts.other_fail,
            self.total_counts.total,
        );
    }
}
