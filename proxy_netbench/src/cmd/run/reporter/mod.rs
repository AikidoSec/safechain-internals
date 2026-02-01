mod human;
mod json;

pub use self::{human::HumanReporter, json::JsonlReporter};

pub trait Reporter: Send + Sync + 'static {
    fn on_result(&mut self, ev: &RequestResultEvent);
    fn on_tick(&mut self, now: std::time::Duration);
    fn finish(&mut self);
}

#[derive(Default)]
pub struct Counters {
    total: u64,
    ok: u64,
    http_fail: u64,
    other_fail: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum Phase {
    Warmup,
    Main,
}

#[derive(Debug)]
pub enum FailureKind {
    HttpStatus,
    Other,
}

#[derive(Debug)]
pub struct RequestOutcome {
    pub ok: bool,
    pub status: Option<u16>,
    pub failure: Option<FailureKind>,
}

#[derive(Debug)]
pub struct RequestResultEvent {
    pub ts: std::time::SystemTime,
    pub elapsed: std::time::Duration,
    pub phase: Phase,
    pub iteration: usize,
    pub index: usize,
    pub latency: std::time::Duration,
    pub outcome: RequestOutcome,
}
