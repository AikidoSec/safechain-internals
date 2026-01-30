use std::{borrow::Cow, fmt, hash, str::FromStr};

use rama::{telemetry::tracing, utils::str::arcstr::ArcStr};
use serde::{Deserialize, Serialize};

use super::PragmaticSemver;

#[derive(Debug, Clone)]
pub enum PackageVersion {
    /// examples: 1, 1.0, 1.2.3, 1.0.0-pre.8, 1.0.0-pre8, 1.0.0-pre8+build.1, ...
    Semver(PragmaticSemver),
    /// *
    Any,
    /// Empty or undefined
    None,
    /// Version which failed to be parsed into something known,
    /// keep it here anyway so that breaking changes in version formats,
    /// do not break existing proxies
    Unknown(ArcStr),
}

impl PartialEq for PackageVersion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Semver(l0), Self::Semver(r0)) => l0 == r0,
            (Self::Unknown(l0), Self::Unknown(r0)) => l0.trim().eq_ignore_ascii_case(r0.trim()),
            (Self::Unknown(s), Self::None) | (Self::None, Self::Unknown(s)) => s.trim().is_empty(),
            (Self::Any, _) | (_, Self::Any) => true,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl hash::Hash for PackageVersion {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            PackageVersion::Semver(pragmatic_semver) => pragmatic_semver.hash(state),
            PackageVersion::Any => "*".hash(state),
            PackageVersion::None => "".hash(state),
            PackageVersion::Unknown(arc_str) => arc_str.hash(state),
        }
    }
}

impl Eq for PackageVersion {}

impl FromStr for PackageVersion {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(PackageVersion::None);
        }

        if s == "*" {
            return Ok(PackageVersion::Any);
        }

        Ok(match PragmaticSemver::from_str(s) {
            Ok(v) => PackageVersion::Semver(v),
            Err(err) => {
                tracing::trace!(
                    "failed to parse version as None, Any or Semver (err = {err}); return as unknown package version (format)"
                );
                PackageVersion::Unknown(s.into())
            }
        })
    }
}

impl PartialEq<PragmaticSemver> for PackageVersion {
    fn eq(&self, other: &PragmaticSemver) -> bool {
        match self {
            PackageVersion::Semver(v) => v == other,
            PackageVersion::Any => true,
            _ => false,
        }
    }
}

impl PartialEq<PackageVersion> for PragmaticSemver {
    fn eq(&self, other: &PackageVersion) -> bool {
        other.eq(self)
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageVersion::Semver(version) => version.fmt(f),
            PackageVersion::Any => "*".fmt(f),
            PackageVersion::None => "".fmt(f),
            PackageVersion::Unknown(arc_str) => arc_str.fmt(f),
        }
    }
}

impl Serialize for PackageVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PackageVersion::Semver(version) => Some(version).serialize(serializer),
            PackageVersion::Any => Some("*").serialize(serializer),
            PackageVersion::None => Some("").serialize(serializer),
            PackageVersion::Unknown(arc_str) => Some(arc_str).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PackageVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let maybe_raw = <Option<Cow<'de, str>>>::deserialize(deserializer)?;

        let Some(raw) = maybe_raw else {
            return Ok(PackageVersion::None);
        };

        let Ok(v) = PackageVersion::from_str(&raw);
        Ok(v)
    }
}
