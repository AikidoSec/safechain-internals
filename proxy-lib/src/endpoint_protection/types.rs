use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
};

use rama::utils::str::arcstr::ArcStr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::package::name_formatter::PackageNameFormatter;

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "F::PackageName: Serialize",
    deserialize = "F::PackageName: Deserialize<'de> + Eq + std::hash::Hash",
))]
pub struct EndpointConfig<F: PackageNameFormatter> {
    pub permission_group: PermissionGroup,
    /// Per-ecosystem configurations (npm, maven, pypi, etc.).
    #[serde(default)]
    pub ecosystems: HashMap<EcosystemKey, EcosystemConfig<F>>,
}

impl<F: PackageNameFormatter> fmt::Debug for EndpointConfig<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointConfig")
            .field("permission_group", &self.permission_group)
            .field("ecosystems", &self.ecosystems)
            .finish()
    }
}

impl<F: PackageNameFormatter> Clone for EndpointConfig<F> {
    fn clone(&self) -> Self {
        Self {
            permission_group: self.permission_group.clone(),
            ecosystems: self.ecosystems.clone(),
        }
    }
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
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "F::PackageName: Serialize",
    deserialize = "F::PackageName: Deserialize<'de> + Eq + std::hash::Hash",
))]
pub struct EcosystemConfig<F: PackageNameFormatter> {
    #[serde(default)]
    pub block_all_installs: bool,
    #[serde(default)]
    pub request_installs: bool,
    #[serde(default)]
    pub minimum_allowed_age_timestamp: Option<i64>,
    #[serde(default)]
    pub exceptions: ExceptionLists<F>,
}

impl<F: PackageNameFormatter> fmt::Debug for EcosystemConfig<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcosystemConfig")
            .field("block_all_installs", &self.block_all_installs)
            .field("request_installs", &self.request_installs)
            .field(
                "minimum_allowed_age_timestamp",
                &self.minimum_allowed_age_timestamp,
            )
            .field("exceptions", &self.exceptions)
            .finish()
    }
}

impl<F: PackageNameFormatter> Default for EcosystemConfig<F> {
    fn default() -> Self {
        Self {
            block_all_installs: Default::default(),
            request_installs: Default::default(),
            minimum_allowed_age_timestamp: Default::default(),
            exceptions: Default::default(),
        }
    }
}

impl<F: PackageNameFormatter> Clone for EcosystemConfig<F> {
    fn clone(&self) -> Self {
        Self {
            block_all_installs: self.block_all_installs,
            request_installs: self.request_installs,
            minimum_allowed_age_timestamp: self.minimum_allowed_age_timestamp,
            exceptions: self.exceptions.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "F::PackageName: Serialize",
    deserialize = "F::PackageName: Deserialize<'de> + Eq + std::hash::Hash",
))]
pub struct ExceptionLists<F: PackageNameFormatter> {
    #[serde(default)]
    pub allowed_packages: HashSet<F::PackageName>,
    #[serde(default)]
    pub rejected_packages: HashSet<F::PackageName>,
}

impl<F: PackageNameFormatter> Default for ExceptionLists<F> {
    fn default() -> Self {
        Self {
            allowed_packages: Default::default(),
            rejected_packages: Default::default(),
        }
    }
}

impl<F: PackageNameFormatter> fmt::Debug for ExceptionLists<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExceptionLists").finish()
    }
}

impl<F: PackageNameFormatter> Clone for ExceptionLists<F> {
    fn clone(&self) -> Self {
        Self {
            allowed_packages: self.allowed_packages.clone(),
            rejected_packages: self.rejected_packages.clone(),
        }
    }
}
