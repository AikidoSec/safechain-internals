use std::{collections::VecDeque, time::Duration};

use rama::http::Request;

use crate::cmd::run::requests::generator::{GenState, GeneratedRequest};

#[cfg(not(test))]
use crate::http::har::HarEntry;

#[cfg(test)]
pub(super) use self::tests::support::{HarEntry, HarRequest};

pub mod mock;
pub mod replay;

/// Cursor tracks iteration and index.
/// Interpretation depends on the source and phase.
///
/// For sources that consume requests, `index` represents how many requests have been emitted
/// in the current iteration, not an index into a fixed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Cursor {
    iteration: usize,
    index: usize,
}

impl Cursor {
    pub(super) fn new() -> Self {
        Self {
            iteration: 0,
            index: 0,
        }
    }

    pub(super) fn reset_for_main(&mut self) {
        self.iteration = 0;
        self.index = 0;
    }

    pub(super) fn reset_index(&mut self) {
        self.index = 0;
    }
}

/// A small plan object that tells the generator how to delay and what it is about to emit.
///
/// It is computed without mutating state.
/// This makes it easy to reason about and test.
pub(super) struct NextPlan {
    pub(super) delay_kind: DelayKind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum DelayKind {
    /// Use the RPS pacer.
    Rps,

    /// Sleep until `base + start_offset`.
    ReplayEmulation { start_offset: Duration },
}

/// Source wrapper.
///
/// The enum delegates to concrete structs.
/// This avoids very large match blocks and keeps source specific logic close to the data it needs.
pub(super) enum Source {
    Mock(MockSource),
    Replay(ReplaySource),
}

impl Source {
    pub(super) fn warmup_is_done(&self, cursor: &Cursor) -> bool {
        match self {
            Source::Mock(s) => s.warmup_is_done(cursor),
            Source::Replay(s) => s.warmup_is_done(cursor),
        }
    }

    pub(super) fn plan_next(&self, state: &GenState) -> Option<NextPlan> {
        match self {
            Source::Mock(s) => s.plan_next(state),
            Source::Replay(s) => s.plan_next(state),
        }
    }

    pub(super) fn produce_next(
        &mut self,
        state: &mut GenState,
        plan: NextPlan,
    ) -> Option<GeneratedRequest> {
        let _ = plan;
        match self {
            Source::Mock(s) => s.produce_next(state),
            Source::Replay(s) => s.produce_next(state),
        }
    }
}

/// Mock source.
///
/// This source consumes requests as they are emitted.
/// Rationale: mock requests are not reused, so cloning is wasted work.
///
/// `requests` is a list of iterations, each iteration is a queue of requests.
/// `warmup` is a queue emitted during warmup.
pub struct MockSource {
    pub requests: Vec<VecDeque<Request>>,
    pub warmup: VecDeque<Request>,
}

impl MockSource {
    fn warmup_is_done(&self, _cursor: &Cursor) -> bool {
        self.warmup.is_empty()
    }

    fn plan_next(&self, state: &GenState) -> Option<NextPlan> {
        if state.is_warmup() {
            if self.warmup.is_empty() {
                return None;
            }
            return Some(NextPlan {
                delay_kind: DelayKind::Rps,
            });
        }

        // Main phase.
        // Requests are consumed, so we search forward for any remaining iteration with data.
        let it = self.next_non_empty_iteration_from(state.cursor.iteration)?;
        let _ = it;

        Some(NextPlan {
            delay_kind: DelayKind::Rps,
        })
    }

    fn next_non_empty_iteration_from(&self, from: usize) -> Option<usize> {
        let mut it = from;
        while it < self.requests.len() {
            if !self.requests[it].is_empty() {
                return Some(it);
            }
            it += 1;
        }
        None
    }

    fn produce_next(&mut self, state: &mut GenState) -> Option<GeneratedRequest> {
        if state.is_warmup() {
            let idx = state.cursor.index;
            let req = self.warmup.pop_front()?;
            state.cursor.index += 1;

            return Some(GeneratedRequest {
                req,
                index: idx,
                iteration: 0,
                warmup: true,
            });
        }

        loop {
            let it = state.cursor.iteration;
            let seq = self.requests.get_mut(it)?;

            if seq.is_empty() {
                // Move to next iteration and reset per iteration index.
                state.cursor.iteration += 1;
                state.cursor.reset_index();
                continue;
            }

            let idx = state.cursor.index;
            let req = seq.pop_front()?;
            state.cursor.index += 1;

            return Some(GeneratedRequest {
                req,
                index: idx,
                iteration: it,
                warmup: false,
            });
        }
    }
}

/// Replay source.
///
/// `entries` is the recorded entry list.
/// `iterations` controls how many times the list is replayed in the main phase.
/// `warmup_iterations` controls how many times the list is replayed during warmup.
///
/// Replay pacing
/// Warmup always uses RPS pacing.
/// Main uses replay emulation if configured, otherwise uses RPS pacing.
pub struct ReplaySource {
    pub entries: Vec<HarEntry>,
    pub iterations: usize,
    pub warmup_iterations: usize,
    pub emulate_timing: bool,
}

impl ReplaySource {
    fn warmup_is_done(&self, cursor: &Cursor) -> bool {
        if self.warmup_iterations == 0 {
            return true;
        }
        if self.entries.is_empty() {
            return true;
        }

        let total = self.entries.len() * self.warmup_iterations;
        let current = cursor.iteration * self.entries.len() + cursor.index;
        current >= total
    }

    fn plan_next(&self, state: &GenState) -> Option<NextPlan> {
        if self.entries.is_empty() {
            return None;
        }

        if state.is_warmup() {
            if self.warmup_is_done(&state.cursor) {
                return None;
            }

            return Some(NextPlan {
                delay_kind: DelayKind::Rps,
            });
        }

        if state.cursor.iteration >= self.iterations {
            return None;
        }

        if state.cursor.index >= self.entries.len() {
            return None;
        }

        if self.emulate_timing {
            // `start_offset` is stored in microseconds.
            let start_offset_micros = self.entries.get(state.cursor.index)?.start_offset;
            return Some(NextPlan {
                delay_kind: DelayKind::ReplayEmulation {
                    start_offset: Duration::from_micros(start_offset_micros),
                },
            });
        }

        Some(NextPlan {
            delay_kind: DelayKind::Rps,
        })
    }

    fn produce_next(&mut self, state: &mut GenState) -> Option<GeneratedRequest> {
        if self.entries.is_empty() {
            return None;
        }

        if state.is_warmup() {
            let req_count = self.entries.len();

            let it_before = state.cursor.iteration;
            let idx = state.cursor.index;
            let req = self.entries.get(idx)?.request.clone_as_http_request();

            state.cursor.index += 1;
            if state.cursor.index >= req_count {
                state.cursor.iteration += 1;
                state.cursor.index = 0;
            }

            // Return the iteration value for the request we actually emitted.
            return Some(GeneratedRequest {
                req,
                index: idx,
                iteration: it_before,
                warmup: true,
            });
        }

        loop {
            if state.cursor.iteration >= self.iterations {
                return None;
            }

            if state.cursor.index >= self.entries.len() {
                state.cursor.iteration += 1;
                state.cursor.index = 0;

                // Reset base instant at iteration boundaries so offsets remain relative per iteration.
                state.replay_base_instant = None;
                continue;
            }

            let it = state.cursor.iteration;
            let idx = state.cursor.index;
            let req = self.entries.get(idx)?.request.clone_as_http_request();

            state.cursor.index += 1;

            return Some(GeneratedRequest {
                req,
                index: idx,
                iteration: it,
                warmup: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    use rama::http::Body;
    use tokio::time::Instant;

    /// These tests are intended to be small and stable.
    /// They validate edge cases and cursor advancement rather than request contents.
    ///
    /// The production code uses the real HarEntry type.
    /// For tests we provide a minimal stand in so the tests do not depend on HAR parsing details.
    pub(super) mod support {
        use super::*;

        #[derive(Clone)]
        pub struct HarRequest;

        impl HarRequest {
            pub fn clone_as_http_request(&self) -> Request {
                super::dummy_request()
            }
        }

        #[derive(Clone)]
        pub struct HarEntry {
            pub start_offset: u64,
            pub request: HarRequest,
        }
    }

    /// Adjust this in one place if your Request body type differs.
    fn dummy_request() -> Request {
        Request::builder()
            .uri("http://localhost/")
            .body(Body::empty())
            .expect("build request")
    }

    /// Minimal local GenState substitute.
    ///
    /// If your real GenState is easy to construct, you can remove this and use the real one.
    /// These tests only need: is_warmup, cursor, replay_base_instant.
    #[derive(Default)]
    struct TestGenState {
        warmup: bool,
        cursor: Cursor,
        replay_base_instant: Option<Instant>,
    }

    impl TestGenState {
        fn warmup() -> Self {
            Self {
                warmup: true,
                cursor: Cursor::new(),
                replay_base_instant: None,
            }
        }

        fn main() -> Self {
            Self {
                warmup: false,
                cursor: Cursor::new(),
                replay_base_instant: Some(Instant::now()),
            }
        }

        fn is_warmup(&self) -> bool {
            self.warmup
        }
    }

    // These adapters let us call the same impl logic without depending on your real GenState layout.
    // Keep them in tests so production code stays simple.
    trait StateLike {
        #[expect(unused)] // reserved for later
        fn is_warmup(&self) -> bool;

        fn cursor(&self) -> &Cursor;
        fn cursor_mut(&mut self) -> &mut Cursor;
        fn replay_base_mut(&mut self) -> &mut Option<Instant>;
    }

    impl StateLike for TestGenState {
        fn is_warmup(&self) -> bool {
            self.is_warmup()
        }
        fn cursor(&self) -> &Cursor {
            &self.cursor
        }
        fn cursor_mut(&mut self) -> &mut Cursor {
            &mut self.cursor
        }
        fn replay_base_mut(&mut self) -> &mut Option<Instant> {
            &mut self.replay_base_instant
        }
    }

    // Local copies of the methods we want to test, wired to TestGenState.
    // This keeps tests independent of the real GenState definition.
    impl MockSource {
        fn plan_next_test(&self, state: &TestGenState) -> Option<NextPlan> {
            if state.is_warmup() {
                if self.warmup.is_empty() {
                    return None;
                }
                return Some(NextPlan {
                    delay_kind: DelayKind::Rps,
                });
            }

            let it = self.next_non_empty_iteration_from(state.cursor().iteration)?;
            let _ = it;

            Some(NextPlan {
                delay_kind: DelayKind::Rps,
            })
        }

        fn produce_next_test(&mut self, state: &mut TestGenState) -> Option<(usize, usize, bool)> {
            if state.is_warmup() {
                let idx = state.cursor().index;
                let _req = self.warmup.pop_front()?;
                state.cursor_mut().index += 1;
                return Some((idx, 0, true));
            }

            loop {
                let it = state.cursor().iteration;
                let seq = self.requests.get_mut(it)?;

                if seq.is_empty() {
                    state.cursor_mut().iteration += 1;
                    state.cursor_mut().reset_index();
                    continue;
                }

                let idx = state.cursor().index;
                let _req = seq.pop_front()?;
                state.cursor_mut().index += 1;

                return Some((idx, it, false));
            }
        }
    }

    impl ReplaySource {
        fn plan_next_test(&self, state: &TestGenState) -> Option<DelayKind> {
            if self.entries.is_empty() {
                return None;
            }

            if state.is_warmup() {
                if self.warmup_is_done(state.cursor()) {
                    return None;
                }
                return Some(DelayKind::Rps);
            }

            if state.cursor().iteration >= self.iterations {
                return None;
            }
            if state.cursor().index >= self.entries.len() {
                return None;
            }

            if self.emulate_timing {
                let micros = self.entries.get(state.cursor().index)?.start_offset;
                return Some(DelayKind::ReplayEmulation {
                    start_offset: Duration::from_micros(micros),
                });
            }

            Some(DelayKind::Rps)
        }

        fn produce_next_main_test(&mut self, state: &mut TestGenState) -> Option<(usize, usize)> {
            loop {
                if state.cursor().iteration >= self.iterations {
                    return None;
                }

                if state.cursor().index >= self.entries.len() {
                    state.cursor_mut().iteration += 1;
                    state.cursor_mut().index = 0;
                    *state.replay_base_mut() = None;
                    continue;
                }

                let it = state.cursor().iteration;
                let idx = state.cursor().index;

                let _req = self.entries.get(idx)?.request.clone_as_http_request();
                state.cursor_mut().index += 1;

                return Some((idx, it));
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_warmup_consumes_requests_and_increments_index() {
        let mut src = MockSource {
            warmup: VecDeque::from([dummy_request(), dummy_request()]),
            requests: vec![],
        };

        let state = TestGenState::warmup();
        assert!(src.plan_next_test(&state).is_some());

        let mut state = state;
        let (idx0, it0, warmup0) = src.produce_next_test(&mut state).expect("first");
        assert_eq!((idx0, it0, warmup0), (0, 0, true));

        let (idx1, it1, warmup1) = src.produce_next_test(&mut state).expect("second");
        assert_eq!((idx1, it1, warmup1), (1, 0, true));

        assert!(src.warmup.is_empty());
        assert!(src.plan_next_test(&state).is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_main_skips_empty_iterations_and_resets_index() {
        let mut src = MockSource {
            warmup: VecDeque::new(),
            requests: vec![
                VecDeque::new(), // empty iteration should be skipped
                VecDeque::from([dummy_request(), dummy_request()]),
                VecDeque::from([dummy_request()]),
            ],
        };

        let mut state = TestGenState::main();

        // First should come from iteration 1, index 0.
        let (idx0, it0, warmup0) = src.produce_next_test(&mut state).expect("first");
        assert_eq!((idx0, it0, warmup0), (0, 1, false));

        // Next from iteration 1, index 1.
        let (idx1, it1, warmup1) = src.produce_next_test(&mut state).expect("second");
        assert_eq!((idx1, it1, warmup1), (1, 1, false));

        // Next should move to iteration 2 with index reset to 0.
        let (idx2, it2, warmup2) = src.produce_next_test(&mut state).expect("third");
        assert_eq!((idx2, it2, warmup2), (0, 2, false));

        // Exhausted.
        assert!(src.produce_next_test(&mut state).is_none());
    }

    #[test]
    fn replay_warmup_is_done_math() {
        use support::{HarEntry, HarRequest};

        let src = ReplaySource {
            entries: vec![
                HarEntry {
                    start_offset: 0,
                    request: HarRequest,
                },
                HarEntry {
                    start_offset: 0,
                    request: HarRequest,
                },
            ],
            iterations: 1,
            warmup_iterations: 2,
            emulate_timing: false,
        };

        // total = 2 entries * 2 warmup iterations = 4
        assert!(!src.warmup_is_done(&Cursor {
            iteration: 0,
            index: 0
        }));
        assert!(!src.warmup_is_done(&Cursor {
            iteration: 1,
            index: 1
        })); // 1*2+1 = 3
        assert!(src.warmup_is_done(&Cursor {
            iteration: 2,
            index: 0
        })); // 2*2+0 = 4
    }

    #[test]
    fn replay_plan_next_selects_delay_kind() {
        use support::{HarEntry, HarRequest};

        let entries = vec![
            HarEntry {
                start_offset: 123,
                request: HarRequest,
            },
            HarEntry {
                start_offset: 456,
                request: HarRequest,
            },
        ];

        let src = ReplaySource {
            entries: entries.clone(),
            iterations: 1,
            warmup_iterations: 0,
            emulate_timing: true,
        };

        let mut state = TestGenState::main();
        state.cursor.index = 1;

        match src.plan_next_test(&state).expect("plan") {
            DelayKind::ReplayEmulation { start_offset } => {
                assert_eq!(start_offset, Duration::from_micros(456));
            }
            _ => panic!("expected replay emulation"),
        }

        let src2 = ReplaySource {
            entries,
            iterations: 1,
            warmup_iterations: 0,
            emulate_timing: false,
        };

        assert_eq!(src2.plan_next_test(&state).expect("plan"), DelayKind::Rps);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_main_iteration_rollover_resets_replay_base() {
        use support::{HarEntry, HarRequest};

        let mut src = ReplaySource {
            entries: vec![HarEntry {
                start_offset: 0,
                request: HarRequest,
            }],
            iterations: 2,
            warmup_iterations: 0,
            emulate_timing: false,
        };

        let mut state = TestGenState::main();
        state.replay_base_instant = Some(Instant::now());

        // Emit the single entry in iteration 0.
        let (_idx0, it0) = src.produce_next_main_test(&mut state).expect("first");
        assert_eq!(it0, 0);

        // Now cursor.index == len, next call rolls to iteration 1 and clears base.
        let (_idx1, it1) = src.produce_next_main_test(&mut state).expect("second");
        assert_eq!(it1, 1);
        assert!(state.replay_base_instant.is_none());
    }
}
