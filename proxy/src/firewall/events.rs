use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedArtifact {
    /// The product type (e.g., "npm", "pypi", "vscode", "chrome")
    pub product: ArcStr,
    /// The name or identifier of the artifact
    pub identifier: ArcStr,
    /// Optional version
    pub version: Option<ArcStr>,
}

#[derive(Debug, Clone)]
pub struct BlockedEventInfo {
    pub artifact: BlockedArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    pub ts_ms: u64,
    pub artifact: BlockedArtifact,
}
/// Stores blocked events in-memory as a small ring buffer.
///
/// Keep the last N events for diagnostics and potential
/// future inspection, while also transmitting events asynchronously.
#[derive(Debug)]
pub struct BlockedEventsStore {
    max_events: usize,
    events: Mutex<VecDeque<BlockedEvent>>,
}

impl BlockedEventsStore {
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events: max_events.max(1),
            events: Mutex::new(VecDeque::new()),
        }
    }

    pub fn record(&self, info: BlockedEventInfo) -> BlockedEvent {
        let event = BlockedEvent {
            ts_ms: now_unix_ms(),
            artifact: info.artifact,
        };
        self.push_event(event.clone());
        event
    }

    #[cfg(test)]
    pub(crate) fn record_at(&self, unix_ts_ms: u64, info: BlockedEventInfo) -> BlockedEvent {
        let event = BlockedEvent {
            ts_ms: unix_ts_ms,
            artifact: info.artifact,
        };
        self.push_event(event.clone());
        event
    }

    fn push_event(&self, event: BlockedEvent) {
        let mut events = self
            .events
            .lock()
            .expect("blocked events store mutex poisoned");

        events.push_back(event);
        while events.len() > self.max_events {
            events.pop_front();
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_tests(&self) -> Vec<BlockedEvent> {
        self.events
            .lock()
            .expect("blocked events store mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
