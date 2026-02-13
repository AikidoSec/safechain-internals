use rama::utils::{str::arcstr::ArcStr, time::now_unix_ms};
use serde::{Deserialize, Serialize};

use crate::package::version::PackageVersion;

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

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
