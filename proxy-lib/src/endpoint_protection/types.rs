use std::collections::{HashMap, HashSet};

use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Deserializer, Serialize};

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

    // TODO: implement minimum age enforcement during response evaluation
    #[serde(default)]
    pub minimum_allowed_age_timestamp: Option<i64>,

    #[serde(default)]
    pub exceptions: ExceptionLists,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionLists {
    /// Packages explicitly allowed, even if `block_all_installs` is set or the package appears
    /// in the malware list. Entries are lowercased at deserialization time so comparisons
    /// against already-normalized package names are always consistent.
    #[serde(default, deserialize_with = "deserialize_lowercase_set")]
    pub allowed_packages: HashSet<ArcStr>,

    /// Packages explicitly blocked regardless of the malware list.
    /// Entries are lowercased at deserialization time.
    #[serde(default, deserialize_with = "deserialize_lowercase_set")]
    pub rejected_packages: HashSet<ArcStr>,
}

fn deserialize_lowercase_set<'de, D>(deserializer: D) -> Result<HashSet<ArcStr>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::<String>::deserialize(deserializer)?;
    Ok(vec
        .into_iter()
        .map(|s| ArcStr::from(s.to_lowercase()))
        .collect())
}
