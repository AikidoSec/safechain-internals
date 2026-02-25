use std::collections::HashMap;

use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub version: ArcStr,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<ArcStr>,
    pub permission_group_id: u64,
    pub permission_group_name: ArcStr,
    /// Per-ecosystem configurations (npm, maven, pypi, etc.).
    #[serde(default)]
    pub ecosystems: HashMap<ArcStr, EcosystemConfig>,
}

/// Configuration for a specific package ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub block_all_installs: bool,

    #[serde(default)]
    pub request_installs: bool,

    #[serde(default)]
    pub minimum_allowed_age_value: Option<u64>,

    #[serde(default)]
    pub minimum_allowed_age_unit: Option<ArcStr>,

    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub exception_type: ArcStr,

    #[serde(default)]
    pub permission_group_ids: Vec<u64>,

    #[serde(default)]
    pub related_packages: Vec<ArcStr>,
}

fn default_true() -> bool {
    true
}
