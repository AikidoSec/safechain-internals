use super::{Counters, FailureKind, Phase, Reporter, RequestResultEvent, human::HumanReporter};

pub struct JsonlReporter {
    interval: std::time::Duration,
    last_tick: std::time::Duration,
    interval_counts: Counters,
    total_counts: Counters,
    last_pos: Option<(Phase, usize, usize)>,
    emit_events: bool,
}

impl JsonlReporter {
    pub fn new(interval: std::time::Duration, emit_events: bool) -> Self {
        Self {
            interval,
            last_tick: std::time::Duration::ZERO,
            interval_counts: Counters::default(),
            total_counts: Counters::default(),
            last_pos: None,
            emit_events,
        }
    }
}

impl Reporter for JsonlReporter {
    fn on_result(&mut self, ev: &RequestResultEvent) {
        HumanReporter::apply_counts(&mut self.interval_counts, ev);
        HumanReporter::apply_counts(&mut self.total_counts, ev);
        self.last_pos = Some((ev.phase, ev.iteration, ev.index));

        if self.emit_events {
            let line = serde_json::json!({
                "type": "event",
                "t_ms": ev.elapsed.as_millis(),
                "phase": match ev.phase { Phase::Warmup => "warmup", Phase::Main => "main" },
                "iteration": ev.iteration,
                "index": ev.index,
                "latency_ms": ev.latency.as_millis(),
                "ok": ev.outcome.ok,
                "status": ev.outcome.status,
                "failure": match ev.outcome.failure {
                    Some(FailureKind::HttpStatus) => Some("http_status"),
                    Some(FailureKind::Other) => Some("other"),
                    None => None,
                },
            });
            println!("{}", line);
        }
    }

    fn on_tick(&mut self, now: std::time::Duration) {
        if now.saturating_sub(self.last_tick) < self.interval {
            return;
        }
        self.last_tick = now;

        let interval_secs = self.interval.as_secs_f64();
        let rps = if interval_secs == 0. {
            0.
        } else {
            self.interval_counts.total as f64 / interval_secs
        };
        let (phase, iteration, idx) = self.last_pos.unwrap_or((Phase::Warmup, 0, 0));

        let line = serde_json::json!({
            "type": "summary",
            "t_ms": now.as_millis(),
            "phase": match phase { Phase::Warmup => "warmup", Phase::Main => "main" },
            "iteration": iteration,
            "index": idx,
            "interval_ms": self.interval.as_millis(),
            "rps": rps,
            "interval": {
                "total": self.interval_counts.total,
                "ok": self.interval_counts.ok,
                "http_fail": self.interval_counts.http_fail,
                "other_fail": self.interval_counts.other_fail,
            },
            "total": {
                "total": self.total_counts.total,
                "ok": self.total_counts.ok,
                "http_fail": self.total_counts.http_fail,
                "other_fail": self.total_counts.other_fail,
            }
        });
        println!("{}", line);

        self.interval_counts = Counters::default();
    }

    fn finish(&mut self) {
        let line = serde_json::json!({
            "type": "final",
            "total": {
                "total": self.total_counts.total,
                "ok": self.total_counts.ok,
                "http_fail": self.total_counts.http_fail,
                "other_fail": self.total_counts.other_fail,
            }
        });
        println!("{}", line);
    }
}
