use std::str::FromStr as _;

use rama::{telemetry::tracing, utils::str::arcstr::ArcStr};

use crate::{package::version::PackageVersion, utils::time::SystemTimestampMilliseconds};

use super::{OpenVsxPackageName, OpenVsxRemoteReleasedPackagesList};

#[derive(Debug)]
pub(super) struct RewriteResult {
    pub(super) bytes: Vec<u8>,
    pub(super) suppressed_versions: Vec<(ArcStr, PackageVersion)>,
}

pub(super) fn rewrite_json(
    bytes: &[u8],
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
) -> Option<RewriteResult> {
    let mut json: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!("OpenVSX response is not valid JSON, passing through: {err}");
            return None;
        }
    };

    let suppressed = dispatch_filter_by_shape(&mut json, released_packages_list, cutoff_ts);
    if suppressed.is_empty() {
        return None;
    }

    let new_bytes = match serde_json::to_vec(&json) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!("failed to serialize modified OpenVSX metadata response: {err}");
            return None;
        }
    };

    Some(RewriteResult {
        bytes: new_bytes,
        suppressed_versions: suppressed,
    })
}

/// Detects which of the three OpenVSX response shapes the JSON value matches
/// and applies the corresponding per-extension filter, mutating `json` in place.
/// Returns the `(extension_id, version)` pairs that were stripped — empty if the
/// shape is unknown or every version is old enough to keep.
fn dispatch_filter_by_shape(
    json: &mut serde_json::Value,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
) -> Vec<(ArcStr, PackageVersion)> {
    let mut suppressed: Vec<(ArcStr, PackageVersion)> = Vec::new();

    /// VS-Marketplace-shaped mirror (Cursor's `marketplace.cursorapi.com`,
    ///    OpenVSX's own `/vscode/gallery/extensionquery`):
    ///    ```json
    ///    { "results": [ { "extensions": [ { "publisher": {"publisherName": "..."},
    ///                                       "extensionName": "...",
    ///                                       "versions": [ {"version": "..."} , ... ] } ] } ] }
    ///    ```
    if let Some(results) = json.get_mut("results").and_then(|r| r.as_array_mut()) {
        for result in results.iter_mut() {
            let Some(extensions) = result.get_mut("extensions").and_then(|e| e.as_array_mut())
            else {
                continue;
            };
            for extension in extensions {
                filter_vsmarketplace_extension(
                    extension,
                    released_packages_list,
                    cutoff_ts,
                    &mut suppressed,
                );
            }
        }
    }

    /// Native OpenVSX query (`/api/-/query` or `/api/v2/-/query`):
    ///    ```json
    ///    { "extensions": [ { "namespace": "...", "name": "...", "allVersions": {...}, ... } ] }
    ///    ```
    else if let Some(extensions) = json.get_mut("extensions").and_then(|e| e.as_array_mut()) {
        for extension in extensions {
            filter_openvsx_extension(
                extension,
                released_packages_list,
                cutoff_ts,
                &mut suppressed,
            );
        }
    }

    /// Native OpenVSX single-extension (`/api/{namespace}/{name}`):
    ///    ```json
    ///    { "namespace": "...", "name": "...", "version": "...",
    ///      "allVersions": { "1.2.3": "url", "1.2.2": "url", ... } }
    ///    ```
    else if json.get("namespace").is_some() && json.get("name").is_some() {
        filter_openvsx_extension(json, released_packages_list, cutoff_ts, &mut suppressed);
    }

    // else: unknown shape — leave json untouched, return empty vec.

    suppressed
}

/// Native OpenVSX per-extension filter. Expects an object shaped like:
/// `{ "namespace": "...", "name": "...", "version": "...", "allVersions": {...} }`.
fn filter_openvsx_extension(
    extension: &mut serde_json::Value,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
    suppressed: &mut Vec<(ArcStr, PackageVersion)>,
) {
    let namespace = extension
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = extension
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if namespace.is_empty() || name.is_empty() {
        return;
    }

    let raw_id = format!("{namespace}/{name}");
    let lookup_key = OpenVsxPackageName::from(raw_id.as_str());
    let extension_id: ArcStr = raw_id.into();

    let Some(all_versions) = extension
        .get_mut("allVersions")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    let keys: Vec<String> = all_versions.keys().cloned().collect();
    for key in keys {
        let Ok(version) = PackageVersion::from_str(&key);
        if released_packages_list.is_recently_released(&lookup_key, Some(&version), cutoff_ts) {
            all_versions.remove(&key);
            suppressed.push((extension_id.clone(), version));
        }
    }
}

/// VS-Marketplace-shaped per-extension filter. Expects an object shaped like:
/// `{ "publisher": {"publisherName": "..."}, "extensionName": "...", "versions": [ {"version": "..."} ] }`.
fn filter_vsmarketplace_extension(
    extension: &mut serde_json::Value,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
    suppressed: &mut Vec<(ArcStr, PackageVersion)>,
) {
    let publisher = extension
        .get("publisher")
        .and_then(|p| p.get("publisherName"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = extension
        .get("extensionName")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if publisher.is_empty() || name.is_empty() {
        return;
    }

    let raw_id = format!("{publisher}/{name}");
    let lookup_key = OpenVsxPackageName::from(raw_id.as_str());
    let extension_id: ArcStr = raw_id.into();

    let Some(versions) = extension.get_mut("versions").and_then(|v| v.as_array_mut()) else {
        return;
    };

    // Track which version numbers have already been recorded to avoid duplicates
    // from platform-specific entries (e.g. darwin-arm64, darwin-x64, win32-x64).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    versions.retain(|v| {
        let Some((version_str, version)) =
            version_entry_to_suppress(v, &lookup_key, released_packages_list, cutoff_ts)
        else {
            return true;
        };
        if seen.insert(version_str) {
            suppressed.push((extension_id.clone(), version));
        }
        false
    });
}

/// Pure classifier for a single VS-Marketplace `versions[]` entry.
///
/// Returns `Some((version_str, parsed_version))` when the entry should be stripped
/// because the released-packages list flags this `(extension, version)` pair as
/// too recently released. Returns `None` for entries we should keep — either the
/// version is old enough, or the entry has no readable `version` field.
fn version_entry_to_suppress(
    entry: &serde_json::Value,
    lookup_key: &OpenVsxPackageName,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
) -> Option<(String, PackageVersion)> {
    let version_str = entry.get("version").and_then(|s| s.as_str())?;
    let Ok(version) = PackageVersion::from_str(version_str);
    if released_packages_list.is_recently_released(lookup_key, Some(&version), cutoff_ts) {
        Some((version_str.to_owned(), version))
    } else {
        None
    }
}
