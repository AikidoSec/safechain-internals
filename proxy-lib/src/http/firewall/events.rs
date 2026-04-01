use rama::net::address::Domain;
use rama::utils::str::{arcstr::ArcStr, smol_str::SmolStr};
use serde::{Deserialize, Serialize};

use crate::package::version::PackageVersion;
use crate::utils::time::SystemTimestampMilliseconds;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// The product type (e.g., "npm", "pypi", "vscode", "chrome")
    pub product: ArcStr,
    /// The name or identifier of the artifact
    pub identifier: ArcStr,
    /// Optional human-readable name of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<ArcStr>,
    /// Optional version
    pub version: Option<PackageVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Blocked because the package was released less time ago than the minimum package age (not yet vetted).
    NewPackage,
}

#[derive(Debug, Clone)]
pub struct BlockedEventInfo {
    pub artifact: Artifact,
    pub block_reason: BlockReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEvent {
    pub ts_ms: SystemTimestampMilliseconds,
    pub artifact: Artifact,
    pub block_reason: BlockReason,
}

impl BlockedEvent {
    pub fn from_info(info: BlockedEventInfo) -> Self {
        Self {
            ts_ms: SystemTimestampMilliseconds::now(),
            artifact: info.artifact,
            block_reason: info.block_reason,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinPackageAgeEvent {
    pub ts_ms: SystemTimestampMilliseconds,
    pub artifact: Artifact,
    pub suppressed_versions: Vec<PackageVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsTerminationFailedEvent {
    pub ts_ms: i64,
    pub sni: Domain,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<SmolStr>,
    pub error: String,
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod tests;
