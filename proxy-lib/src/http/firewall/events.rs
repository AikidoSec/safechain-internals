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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// Blocked because the artifact is on the malware list.
    Malware,
    /// Blocked because the package is in the `rejected_packages` list.
    Rejected,
    /// Blocked because `block_all_installs` is enabled for this ecosystem.
    BlockAll,
    /// Blocked because `request_installs` is enabled — install pending approval.
    RequestInstall,
}

#[derive(Debug, Clone)]
pub struct BlockedEventInfo {
    pub artifact: BlockedArtifact,
    pub block_reason: BlockReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    pub ts_ms: i64,
    pub artifact: BlockedArtifact,
    pub block_reason: BlockReason,
}

impl BlockedEvent {
    pub fn from_info(info: BlockedEventInfo) -> Self {
        Self {
            ts_ms: now_unix_ms(),
            artifact: info.artifact,
            block_reason: info.block_reason,
        }
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
