use std::{collections::BTreeSet, str::FromStr, time::UNIX_EPOCH};

use rama::utils::str::arcstr::{ArcStr, arcstr};

use crate::package::{
    released_packages_list::RemoteReleasedPackagesList,
    version::{PackageVersion, PragmaticSemver},
};

use super::super::parser::{
    PackageInfo, normalize_package_name, parse_package_info_from_filename,
    parse_package_info_from_url,
};
use super::JsonRewriteResult;

pub(super) enum JsonRewriteKind {
    Legacy,
    Simple,
}

impl JsonRewriteKind {
    pub(super) const fn as_str(&self) -> &'static str {
        match self {
            Self::Legacy => "legacy-json",
            Self::Simple => "simple-json",
        }
    }
}

enum FileDecision {
    Keep,
    Remove {
        package_name: ArcStr,
        version: String,
    },
}

/// Rewrite a PyPI JSON metadata response.
///
/// Supports both JSON shapes PyPI serves:
/// - legacy JSON via `/pypi/<package>/json`: exposes `info`, `releases`, and `urls`
/// - simple JSON via `/simple/<package>/`: exposes `files`
pub(super) fn rewrite_response(
    bytes: &[u8],
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> Option<(JsonRewriteKind, JsonRewriteResult)> {
    let json: serde_json::Value = serde_json::from_slice(bytes).ok()?;

    if json.get("releases").and_then(|r| r.as_object()).is_some() {
        return rewrite_legacy(json, cutoff_secs, released_packages)
            .map(|rewrite| (JsonRewriteKind::Legacy, rewrite));
    }

    rewrite_simple(json, cutoff_secs, released_packages)
        .map(|rewrite| (JsonRewriteKind::Simple, rewrite))
}

/// Rewrite the legacy `/pypi/<package>/json` response shape.
///
/// Too-young versions are removed from `releases`, then `info.version` and
/// `urls` are downgraded to the newest remaining stable version.
fn rewrite_legacy(
    mut json: serde_json::Value,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> Option<JsonRewriteResult> {
    let package_name = package_name_from_legacy_json(&json);
    let mut suppressed: BTreeSet<String> = BTreeSet::new();

    json.get_mut("releases")?
        .as_object_mut()?
        .retain(|version, files| {
            legacy_keep_release(
                package_name.as_str(),
                version,
                files,
                cutoff_secs,
                released_packages,
                &mut suppressed,
            )
        });

    if suppressed.is_empty() {
        return None;
    }

    downgrade_info_version_and_urls(&mut json);
    build_rewrite_result(json, package_name, suppressed)
}

fn legacy_keep_release(
    package_name: &str,
    version: &str,
    files: &serde_json::Value,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
    suppressed: &mut BTreeSet<String>,
) -> bool {
    let version =
        PackageVersion::from_str(version).unwrap_or(PackageVersion::Unknown(version.into()));
    // Check time stamp, fall back to new package list file if time can't be parsed
    let is_recent = earliest_upload_secs(files).is_some_and(|t| t > cutoff_secs)
        || released_packages.is_recently_released(package_name, Some(&version), cutoff_secs);

    if is_recent {
        suppressed.insert(version.to_string());
    }

    !is_recent
}

/// Returns the earliest upload time (in seconds) across all distribution files for a release.
///
/// A single PyPI release version ships multiple files: typically a platform-independent
/// wheel (`.whl`) and a source distribution (`.tar.gz`), and sometimes additional
/// platform-specific wheels for different OS/CPU combinations. Each file is uploaded
/// separately and carries its own `upload_time_iso_8601` timestamp.
///
/// We take the minimum so that a version is only suppressed when *all* of its files
/// postdate the cutoff — a freshly added platform wheel cannot slip through just because
/// the source dist was uploaded days earlier.
fn earliest_upload_secs(files: &serde_json::Value) -> Option<i64> {
    files
        .as_array()?
        .iter()
        .filter_map(|f| parse_upload_time_secs(f, "upload_time_iso_8601"))
        .min()
}

fn parse_upload_time_secs(file: &serde_json::Value, field: &str) -> Option<i64> {
    let ts = file.get(field)?.as_str()?;
    let t = humantime::parse_rfc3339(ts).ok()?;
    let secs = t.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(secs as i64)
}

/// Rewrite the simple `/simple/<package>/` JSON response shape.
///
/// Too-young distributions are removed from the `files` array.
fn rewrite_simple(
    mut json: serde_json::Value,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> Option<JsonRewriteResult> {
    let mut suppressed: BTreeSet<String> = BTreeSet::new();
    let mut package_name: Option<ArcStr> = None;

    json.get_mut("files")?.as_array_mut()?.retain(|file| {
        match simple_keep_file(file, cutoff_secs, released_packages) {
            FileDecision::Keep => true,
            FileDecision::Remove {
                package_name: removed_package_name,
                version,
            } => {
                package_name.get_or_insert(removed_package_name);
                suppressed.insert(version);
                false
            }
        }
    });

    if suppressed.is_empty() {
        return None;
    }

    build_rewrite_result(json, package_name?, suppressed)
}

fn simple_keep_file(
    file: &serde_json::Value,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> FileDecision {
    let Some(package) = parse_package_from_metadata_file(file) else {
        return FileDecision::Keep;
    };

    // Check time stamp, fall back to new package list file if time can't be parsed
    let is_recent = parse_upload_time_secs(file, "upload-time").is_some_and(|t| t > cutoff_secs)
        || released_packages.is_recently_released(
            package.name.as_str(),
            Some(&package.version),
            cutoff_secs,
        );

    if !is_recent {
        return FileDecision::Keep;
    }

    FileDecision::Remove {
        package_name: ArcStr::from(package.name.as_str()),
        version: package.version.to_string(),
    }
}

/// Align `info.version` and `urls` with the newest remaining stable release after filtering.
fn downgrade_info_version_and_urls(json: &mut serde_json::Value) {
    let newest_stable = (|| -> Option<_> {
        let releases = json.get("releases")?.as_object()?;
        releases
            .iter()
            .filter_map(|(version, files)| {
                let semver = PragmaticSemver::parse(version).ok()?;
                is_stable_version(version).then_some((semver, version.as_str(), files))
            })
            .max_by(|left, right| left.0.cmp(&right.0))
            .map(|(_, version, files)| (version.to_owned(), files.clone()))
    })();

    let (new_version, new_urls) = match newest_stable {
        Some((version, files)) => (Some(version), files),
        None => (None, serde_json::json!([])),
    };

    if let Some(info) = json.get_mut("info").and_then(|i| i.as_object_mut()) {
        match new_version {
            Some(ref v) => {
                info.insert("version".to_owned(), serde_json::json!(v));
            }
            None => {
                info.remove("version");
            }
        }
    }

    json["urls"] = new_urls;
}

fn package_name_from_legacy_json(json: &serde_json::Value) -> ArcStr {
    json.get("info")
        .and_then(|info| info.get("name"))
        .and_then(|name| name.as_str())
        .map(|package_name| ArcStr::from(normalize_package_name(package_name).as_str()))
        .unwrap_or_else(|| arcstr!("unknown-package"))
}

fn build_rewrite_result(
    json: serde_json::Value,
    package_name: ArcStr,
    suppressed: BTreeSet<String>,
) -> Option<JsonRewriteResult> {
    Some(JsonRewriteResult {
        bytes: serde_json::to_vec(&json).ok()?,
        package_name,
        suppressed_versions: suppressed.into_iter().collect(),
    })
}

fn parse_package_from_metadata_file(file: &serde_json::Value) -> Option<PackageInfo> {
    file.get("filename")
        .and_then(|filename| filename.as_str())
        .and_then(parse_package_info_from_filename)
        .or_else(|| {
            file.get("url")
                .and_then(|url| url.as_str())
                .and_then(parse_package_info_from_url)
        })
}

/// Returns whether a PyPI version should be treated as a final/stable release
/// when downgrading `info.version`.
///
/// This intentionally excludes pre-release and development markers such as
/// `a`, `b`, `rc`, and `dev`, while still allowing post releases like
/// `1.2.3.post1`.
fn is_stable_version(version: &str) -> bool {
    if version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }

    version
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .filter(|token| !token.is_empty())
        .all(|token| token.eq_ignore_ascii_case("post"))
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
