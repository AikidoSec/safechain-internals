use std::collections::HashMap;

use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub permission_group: PermissionGroup,
    /// Per-ecosystem configurations (npm, maven, pypi, etc.).
    #[serde(default)]
    pub ecosystems: HashMap<ArcStr, EcosystemConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroup {
    pub id: u64,
    pub name: ArcStr,
}

/// Configuration for a specific package ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    #[serde(default)]
    pub block_all_installs: bool,

    #[serde(default)]
    pub request_installs: bool,

    #[serde(default)]
    pub minimum_allowed_age_timestamp: Option<i64>,

    #[serde(default)]
    pub exceptions: ExceptionLists,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionLists {
    #[serde(default)]
    pub allowed_packages: Vec<ArcStr>,
    #[serde(default)]
    pub rejected_packages: Vec<ArcStr>,
}
