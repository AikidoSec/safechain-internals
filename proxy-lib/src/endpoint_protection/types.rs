use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
};

use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::utils::time::SystemTimestampMilliseconds;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub permission_group: PermissionGroup,
    /// Per-ecosystem configurations (npm, maven, pypi, etc.).
    #[serde(default)]
    pub ecosystems: HashMap<EcosystemKey, EcosystemConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcosystemKey(EcosystemKeyInner);

#[derive(Clone)]
enum EcosystemKeyInner {
    Const(&'static str),
    Runtime(ArcStr),
}

impl EcosystemKeyInner {
    #[inline(always)]
    fn as_str(&self) -> &str {
        match self {
            EcosystemKeyInner::Const(s) => s,
            EcosystemKeyInner::Runtime(s) => s.as_str(),
        }
    }
}

impl fmt::Debug for EcosystemKeyInner {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(s) => s.fmt(f),
            Self::Runtime(s) => s.fmt(f),
        }
    }
}

impl PartialEq for EcosystemKeyInner {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for EcosystemKeyInner {}

impl PartialOrd for EcosystemKeyInner {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EcosystemKeyInner {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl std::hash::Hash for EcosystemKeyInner {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl EcosystemKey {
    #[inline(always)]
    pub fn from_raw_str(s: &str) -> Self {
        Self(EcosystemKeyInner::Runtime(
            s.trim().to_ascii_lowercase().into(),
        ))
    }

    pub const fn from_static(s: &'static str) -> Self {
        assert!(is_valid_ecosystem_key(s));
        Self(EcosystemKeyInner::Const(s))
    }
}

const fn is_valid_ecosystem_key(s: &str) -> bool {
    let bytes = s.as_bytes();

    if bytes.is_empty() {
        return false;
    }

    if bytes[0] == b' ' || bytes[bytes.len() - 1] == b' ' {
        return false;
    }

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        if b.is_ascii_uppercase() {
            return false;
        }

        i += 1;
    }

    true
}

impl<'de> Deserialize<'de> for EcosystemKey {
    #[inline(always)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Cow::<'de, str>::deserialize(deserializer)?;
        Ok(EcosystemKey::from_raw_str(&s))
    }
}

impl Serialize for EcosystemKey {
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroup {
    pub id: u64,
    pub name: ArcStr,
}

/// Configuration for a specific package ecosystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EcosystemConfig {
    #[serde(default)]
    pub block_all_installs: bool,
    #[serde(default)]
    pub request_installs: bool,
    #[serde(default, with = "crate::utils::time::option_system_time_serde_seconds")]
    pub minimum_allowed_age_timestamp: Option<SystemTimestampMilliseconds>,
    #[serde(default)]
    pub exceptions: ExceptionLists,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionLists {
    #[serde(default)]
    pub allowed_packages: HashSet<ArcStr>,
    #[serde(default)]
    pub rejected_packages: HashSet<ArcStr>,
}
