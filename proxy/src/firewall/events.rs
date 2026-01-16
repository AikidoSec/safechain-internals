use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockedArtifact {
    Npm { name: String, version: String },
    Pypi { name: String, version: String },
    VscodeExtension { id: String },
    ChromeExtension { id: String },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BlockedEventInfo {
    pub product: String,
    pub artifact: BlockedArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    #[serde(rename = "ts_ms", alias = "unix_ts_ms")]
    pub unix_ts_ms: u64,
    pub product: String,
    pub artifact: BlockedArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEventsResponse {
    #[serde(rename = "now_ms", alias = "now_unix_ms")]
    pub now_unix_ms: u64,
    pub retention_ms: u64,
    pub total_retained: usize,
    pub events: Vec<BlockedEvent>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventsQuery {
    #[serde(alias = "since_ms")]
    pub since_unix_ms: Option<u64>,
    #[serde(alias = "until_ms")]
    pub until_unix_ms: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Debug)]
pub struct BlockedEventsStore {
    state: Mutex<StoreState>,
    retention: Duration,
    max_events: usize,
}

#[derive(Debug, Default)]
struct StoreState {
    events: VecDeque<BlockedEvent>,
}

impl BlockedEventsStore {
    pub fn new(retention: Duration, max_events: usize) -> Self {
        Self {
            state: Mutex::new(StoreState::default()),
            retention,
            max_events: max_events.max(1),
        }
    }

    pub fn record(&self, info: BlockedEventInfo) {
        let now_unix_ms = now_unix_ms();

        let mut state = self.state.lock();
        prune_locked(&mut state, now_unix_ms, self.retention);

        state.events.push_back(BlockedEvent {
            unix_ts_ms: now_unix_ms,
            product: info.product,
            artifact: info.artifact,
        });

        while state.events.len() > self.max_events {
            state.events.pop_front();
        }
    }

    pub fn query(&self, query: EventsQuery) -> BlockedEventsResponse {
        let now_unix_ms = now_unix_ms();

        let mut state = self.state.lock();
        prune_locked(&mut state, now_unix_ms, self.retention);

        let since_ms = query.since_unix_ms.unwrap_or(0);
        let until_ms = query.until_unix_ms.unwrap_or(u64::MAX);

        let mut events: Vec<BlockedEvent> = state
            .events
            .iter()
            .filter(|e| e.unix_ts_ms >= since_ms && e.unix_ts_ms <= until_ms)
            .cloned()
            .collect();

        if let Some(limit) = query.limit
            && events.len() > limit
        {
            // Prefer the most recent events.
            events.drain(0..(events.len() - limit));
        }

        BlockedEventsResponse {
            now_unix_ms,
            retention_ms: self.retention.as_millis() as u64,
            total_retained: state.events.len(),
            events,
        }
    }
}

fn prune_locked(state: &mut StoreState, now_ms: u64, retention: Duration) {
    let retention_ms = retention.as_millis() as u64;
    let min_ts = now_ms.saturating_sub(retention_ms);

    while state.events.front().is_some_and(|e| e.unix_ts_ms < min_ts) {
        state.events.pop_front();
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
