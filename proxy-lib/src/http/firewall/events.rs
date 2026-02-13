use crate::package::version::PackageVersion;
use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};
use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedArtifact {
    /// The product type (e.g., "npm", "pypi", "vscode", "chrome")
    pub product: ArcStr,
    /// The name or identifier of the artifact
    pub identifier: ArcStr,
    /// Optional version
    pub version: Option<PackageVersion>,
}

#[derive(Debug, Clone)]
pub struct BlockedEventInfo {
    pub artifact: BlockedArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    pub ts_ms: i64,
    pub artifact: BlockedArtifact,
}

impl BlockedEvent {
    pub fn from_info(info: BlockedEventInfo) -> Self {
        Self {
            ts_ms: now_unix_ms(),
            artifact: info.artifact,
        }
    }
}

fn now_unix_ms() -> i64 {
    // Cache the initial unix instance,
    // as making this syscall for each call is pretty expensive
    static START: OnceLock<(Instant, i64)> = OnceLock::new();

    let (start_instant, start_unix_ms) = START.get_or_init(|| {
        let unix_ms = unix_timestamp_millis();
        (Instant::now(), unix_ms)
    });

    start_unix_ms + start_instant.elapsed().as_millis() as i64
}

// inspired by chrono crate of Rust,
// should always be positive unless your system clock is BEFORE epoch datetime (1970),
// in which case it will be negative...
//
// i64 is also the type used by most systems,
// and easily fits any real timestamp (by a margin of millions of years)
fn unix_timestamp_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
