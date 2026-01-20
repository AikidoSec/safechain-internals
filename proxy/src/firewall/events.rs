use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::firewall::malware_list::PackageVersion;

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
    pub ts_ms: u64,
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
