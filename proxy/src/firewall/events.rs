use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossbeam_skiplist::SkipMap;
use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};

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
    /// Unix timestamp in milliseconds
    #[serde(rename = "ts_ms", alias = "unix_ts_ms")]
    pub unix_ts_ms: u64,
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

/// Key for events in the skip map: (timestamp_ms, sequence_number)
type EventKey = (u64, u64);

/// Stores blocked events with concurrent access and efficient range queries.
///
/// The store uses a skip map for efficient concurrent access and range-based queries.
/// Events are automatically pruned based on retention duration and memory limits.
#[derive(Debug)]
pub struct BlockedEventsStore {
    map: SkipMap<EventKey, BlockedEvent>,
    retention: Duration,
    max_events: usize,
    seq: AtomicU64,
    last_pruned_ms: AtomicU64,
    min_prune_interval: Duration,
}

impl BlockedEventsStore {
    pub fn new(retention: Duration, max_events: usize) -> Self {
        Self {
            map: SkipMap::new(),
            retention,
            max_events: max_events.max(1),
            seq: AtomicU64::new(0),
            last_pruned_ms: AtomicU64::new(0),
            min_prune_interval: Duration::from_secs(60),
        }
    }

    pub fn record(&self, info: BlockedEventInfo) {
        let now_unix_ms = now_unix_ms();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);

        let event = BlockedEvent {
            unix_ts_ms: now_unix_ms,
            artifact: info.artifact,
        };

        self.map.insert((now_unix_ms, seq), event);

        // Prune based on two-layered condition:
        // 1. Check if we exceed max events (cheap check)
        // 2. Only prune if we haven't pruned recently
        if self.map.len() > self.max_events {
            let last_pruned_ms = self.last_pruned_ms.load(Ordering::Relaxed);
            if now_unix_ms.saturating_sub(last_pruned_ms)
                > self.min_prune_interval.as_millis() as u64
            {
                self.prune(now_unix_ms);
            }
        }
    }

    pub fn query(&self, query: EventsQuery) -> BlockedEventsResponse {
        let now_unix_ms = now_unix_ms();

        // Always prune on query to remove expired events
        self.prune(now_unix_ms);

        let since_ms = query.since_unix_ms.unwrap_or_default();
        let until_ms = query.until_unix_ms.unwrap_or(u64::MAX);

        // Use range query for efficient retrieval
        let mut events: Vec<BlockedEvent> = self
            .map
            .range((since_ms, 0)..=(until_ms, u64::MAX))
            .map(|entry| entry.value().clone())
            .collect();

        if let Some(limit) = query.limit {
            if events.len() > limit {
                // Prefer the most recent events
                events.drain(0..(events.len() - limit));
            }
        }

        BlockedEventsResponse {
            now_unix_ms,
            retention_ms: self.retention.as_millis() as u64,
            total_retained: self.map.len(),
            events,
        }
    }

    /// Prunes events older than retention duration.
    fn prune(&self, now_unix_ms: u64) {
        let retention_ms = self.retention.as_millis() as u64;
        let min_ts = now_unix_ms.saturating_sub(retention_ms);

        // Remove all events before min_ts using range-based removal
        while let Some(entry) = self.map.front() {
            if entry.key().0 < min_ts {
                entry.remove();
            } else {
                break;
            }
        }

        self.last_pruned_ms.store(now_unix_ms, Ordering::Relaxed);
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
