use std::path::PathBuf;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::Request,
    telemetry::tracing,
};
use safechain_proxy_lib::storage::{self};
use tokio::time::{Instant, sleep};

use crate::{
    cmd::run::requests::{
        rps_pacer::RpsPacer,
        source::{self, Cursor, DelayKind, Source, mock},
    },
    config::ProductValues,
};

#[cfg(not(test))]
use crate::http::har;

/// Generates requests from either a mock source or a replay source.
///
/// Intent
/// This type coordinates three concerns:
/// 1. Source selection and per source cursor advancement
/// 2. Warmup to main transition
/// 3. Pacing and delay application
///
/// The source decides what it wants to emit next via `plan_next` and `produce_next`.
/// The generator is responsible for honoring the pacing decision in a consistent way.
pub struct RequestGenerator {
    source: Source,
    pacer: RpsPacer,
    pacing: PacingConfig,
    state: GenState,
}

pub struct RequestGeneratorMockConfig {
    pub data: PathBuf,
    pub iterations: usize,
    pub target_rps: u32,
    pub burst_size: u32,
    pub jitter: f64,
    pub request_count_per_iteration: usize,
    pub request_count_per_warmup: usize,
    pub products: Option<ProductValues>,
    pub malware_ratio: f64,
}

pub struct RequestGeneratorReplayConfig {
    pub har: PathBuf,
    pub iterations: usize,
    pub target_rps: u32,
    pub burst_size: u32,
    pub jitter: f64,
    pub emulate_timing: bool,
}

impl RequestGenerator {
    pub async fn new_mock_gen(cfg: RequestGeneratorMockConfig) -> Result<Self, OpaqueError> {
        tokio::fs::create_dir_all(&cfg.data)
            .await
            .with_context(|| format!("create data directory at path '{}'", cfg.data.display()))?;
        let data_storage = storage::SyncCompactDataStorage::try_new(cfg.data.clone())
            .with_context(|| {
                format!(
                    "create compact data storage using dir at path '{}'",
                    cfg.data.display()
                )
            })?;
        tracing::info!(path = ?cfg.data, "data directory ready to be used");

        let (requests, warmup) = mock::rand_requests(
            data_storage,
            cfg.iterations,
            cfg.request_count_per_iteration,
            cfg.request_count_per_warmup,
            cfg.products,
            cfg.malware_ratio,
        )
        .await?;

        let source = Source::Mock(source::MockSource { requests, warmup });

        Ok(Self::new_internal(
            source,
            PacingConfig {
                target_rps: cfg.target_rps,
                burst_size: cfg.burst_size,
                jitter: cfg.jitter,
                emulate_replay_timing: false, // only possible for replay-based generator
            },
        ))
    }

    pub async fn new_replay_gen(cfg: RequestGeneratorReplayConfig) -> Result<Self, OpaqueError> {
        #[cfg(not(test))]
        let entries = har::load_har_entries(cfg.har)
            .await
            .context("load replay HAR file")?;

        #[cfg(test)]
        let entries = Default::default(); // TODO can be changed if we ever want to test this method

        let source = Source::Replay(source::ReplaySource {
            entries,
            iterations: cfg.iterations,
            warmup_iterations: 1,
            emulate_timing: cfg.emulate_timing,
        });

        Ok(Self::new_internal(
            source,
            PacingConfig {
                target_rps: cfg.target_rps,
                burst_size: cfg.burst_size,
                jitter: cfg.jitter,
                emulate_replay_timing: cfg.emulate_timing, // only possible for replay-based generator
            },
        ))
    }

    fn new_internal(source: Source, pacing: PacingConfig) -> Self {
        let pacer = RpsPacer::new(pacing.target_rps, pacing.burst_size, pacing.jitter);

        Self {
            source,
            pacer,
            pacing,
            state: GenState::new(),
        }
    }

    /// Produces the next request and applies the required delay before returning it.
    ///
    /// Returns `None` when the generator is fully exhausted.
    pub async fn next_request(&mut self) -> Option<GeneratedRequest> {
        self.state.advance_if_needed(&self.source);

        let plan = self.source.plan_next(&self.state)?;
        self.apply_delay(plan.delay_kind).await;

        self.source.produce_next(&mut self.state, plan)
    }

    async fn apply_delay(&mut self, delay: DelayKind) {
        match delay {
            DelayKind::Rps => self.pacer.wait_one().await,
            DelayKind::ReplayEmulation { start_offset } => {
                // Replay emulation is only honored for main traffic and only when enabled.
                // Rationale: warmup is intended for stabilization, not timing fidelity.
                if !self.state.is_main() || !self.pacing.emulate_replay_timing {
                    self.pacer.wait_one().await;
                    return;
                }

                let base = self
                    .state
                    .replay_base_instant
                    .get_or_insert_with(Instant::now);

                let target = *base + start_offset;
                let now = Instant::now();
                if target > now {
                    sleep(target - now).await;
                }
            }
        }
    }

    #[cfg(test)]
    fn state(&self) -> &GenState {
        &self.state
    }
}

/// Configuration for pacing.
///
/// `target_rps`
/// Average requests per second when using the RPS pacer.
///
/// `burst_size`
/// Maximum number of requests that can be emitted immediately when tokens are available.
///
/// `jitter`
/// Random multiplier on the computed wait time, in the range `[0.0, 1.0]`.
///
/// `emulate_replay_timing`
/// When true, and when the source requests replay timing, and when in main phase,
/// the generator sleeps until the recorded offset from the start of the iteration.
#[derive(Clone, Copy, Debug)]
pub(super) struct PacingConfig {
    pub(super) target_rps: u32,
    pub(super) burst_size: u32,
    pub(super) jitter: f64,
    pub(super) emulate_replay_timing: bool,
}

/// Output of the generator.
#[derive(Debug)]
pub struct GeneratedRequest {
    pub req: Request,
    pub index: usize,
    pub iteration: usize,
    pub warmup: bool,
}

/// Tracks whether we are in warmup or main and holds the active cursor.
///
/// The cursor is source specific, the generator only resets it at the phase boundary.
pub(super) struct GenState {
    pub(super) warmup: bool,
    pub(super) cursor: Cursor,

    /// Replay emulation uses an absolute schedule relative to a base instant.
    /// This is set on the first emitted request of each main iteration.
    pub(super) replay_base_instant: Option<Instant>,
}

impl GenState {
    pub(super) fn new() -> Self {
        Self {
            warmup: true,
            cursor: Cursor::new(),
            replay_base_instant: None,
        }
    }

    pub(super) fn is_warmup(&self) -> bool {
        self.warmup
    }

    pub(super) fn is_main(&self) -> bool {
        !self.warmup
    }

    /// Transitions from warmup to main when the source indicates warmup is exhausted.
    ///
    /// This is intentionally centralized here so the rest of the generator can treat the state
    /// as always consistent.
    pub(super) fn advance_if_needed(&mut self, source: &Source) {
        if self.warmup && source.warmup_is_done(&self.cursor) {
            self.warmup = false;
            self.cursor.reset_for_main();
            self.replay_base_instant = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::Body;
    use std::{collections::VecDeque, time::Duration};
    use tokio::task::yield_now;
    use tokio::time;

    use crate::cmd::run::requests::source::{HarEntry, HarRequest, MockSource, ReplaySource};

    fn pacing(emulate: bool) -> PacingConfig {
        PacingConfig {
            target_rps: 1,
            burst_size: 10,
            jitter: 0.0,
            emulate_replay_timing: emulate,
        }
    }

    fn req() -> Request {
        Request::builder()
            .uri("http://localhost/")
            .body(Body::empty())
            .expect("request")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transitions_from_warmup_to_main_and_emits_main_request() {
        // Warmup is empty, so the first call should transition to main immediately.
        let mock = MockSource {
            warmup: VecDeque::new(),
            requests: vec![VecDeque::from([req()])],
        };

        let mut generator = RequestGenerator::new_internal(Source::Mock(mock), pacing(false));

        let out = generator.next_request().await.expect("generated");
        assert!(!out.warmup);
        assert_eq!(out.iteration, 0);
        assert_eq!(out.index, 0);
        assert!(generator.state().is_main());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_emulation_blocks_until_offset_when_enabled() {
        time::pause();

        // This assumes HarEntry start_offset is stored in microseconds, as in your source module.
        // It also assumes HarEntry and its request can be constructed in tests.
        let entry = HarEntry {
            start_offset: 1_000_000,
            request: HarRequest,
        };

        let replay = ReplaySource {
            entries: vec![entry],
            iterations: 1,
            warmup_iterations: 0,
            emulate_timing: true,
        };

        let mut generator = RequestGenerator::new_internal(Source::Replay(replay), pacing(true));

        // Spawn next_request so we can observe it blocking under paused time.
        let h = tokio::spawn(async move { generator.next_request().await });

        yield_now().await;
        assert!(!h.is_finished());

        // Advance just short of the offset.
        time::advance(Duration::from_millis(999)).await;
        yield_now().await;
        assert!(!h.is_finished());

        // Advance to reach the offset.
        time::advance(Duration::from_millis(1)).await;
        let out = h.await.expect("join").expect("generated");
        assert!(!out.warmup);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_emulation_is_ignored_during_warmup_or_when_disabled() {
        time::pause();

        let entry = HarEntry {
            start_offset: 2_000_000,
            request: HarRequest,
        };

        let replay = ReplaySource {
            entries: vec![entry],
            iterations: 1,
            warmup_iterations: 0,
            emulate_timing: true,
        };

        // Emulation disabled at generator level, so the delay should fall back to RPS.
        // We give a large burst so it does not sleep.
        let mut generator = RequestGenerator::new_internal(Source::Replay(replay), pacing(false));

        let out = generator.next_request().await.expect("generated");
        assert!(!out.warmup);
    }
}
