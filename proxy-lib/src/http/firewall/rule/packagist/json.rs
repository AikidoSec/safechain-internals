use std::{str::FromStr, time::UNIX_EPOCH};

use rama::telemetry::tracing;
use serde_json::{Map, Value};

use crate::package::version::PackageVersion;

/// Parse a Packagist `/p2/vendor/package.json` body and de-minify its entries.
///
/// Returns the canonical JSON key for the package (may differ in casing from the
/// URL-derived name) and the de-minified entry list, or `None` if the body cannot
/// be parsed or the package key is not found.
pub(super) fn parse_and_deminify(
    bytes: &[u8],
    package_name: &str,
) -> Option<(String, Vec<Map<String, Value>>)> {
    let json: Value = serde_json::from_slice(bytes)
        .inspect_err(|e| tracing::debug!("packagist: failed to parse metadata JSON: {e}"))
        .ok()?;

    let packages_obj = json.get("packages")?.as_object()?;

    let package_key = packages_obj
        .keys()
        .find(|k| k.to_ascii_lowercase() == package_name)?
        .clone();

    let versions_array = packages_obj.get(&package_key)?.as_array()?;

    Some((package_key, deminify(versions_array)))
}

/// Serialize a filtered package entry list back to Packagist metadata JSON.
///
/// Produces `{ "packages": { "<key>": [...kept...] } }` without the `minified`
/// key so that every entry is self-contained.
pub(super) fn serialize(package_key: String, kept: Vec<Value>) -> Option<Vec<u8>> {
    let mut packages = Map::new();
    packages.insert(package_key, Value::Array(kept));
    let output = serde_json::json!({ "packages": packages });
    serde_json::to_vec(&output)
        .inspect_err(|e| tracing::debug!("packagist: failed to serialize rewritten metadata: {e}"))
        .ok()
}

/// Parse the `time` field of a de-minified entry as Unix seconds.
pub(super) fn time_from_entry(entry: &Map<String, Value>) -> Option<i64> {
    let ts = entry.get("time")?.as_str()?;
    let t = humantime::parse_rfc3339(ts).ok()?;
    let secs = t.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(secs as i64)
}

/// Parse a `version` string from a de-minified entry into a `PackageVersion`.
pub(super) fn version_from_entry(entry: &Map<String, Value>) -> Option<PackageVersion> {
    let s = entry.get("version")?.as_str()?;
    Some(PackageVersion::from_str(s).unwrap_or_else(|_| PackageVersion::Unknown(s.into())))
}

/// Expand minified Composer 2.x package entries to full field sets.
///
/// Walks entries in order, maintaining a running accumulator. Each entry patches
/// the accumulator: present fields override, `"__unset"` fields are removed.
/// The returned vec contains one fully-expanded map per input entry.
pub(super) fn deminify(entries: &[Value]) -> Vec<Map<String, Value>> {
    let mut accumulator: Map<String, Value> = Map::new();
    let mut result = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(obj) = entry.as_object() {
            for (key, value) in obj {
                if value.as_str() == Some("__unset") {
                    accumulator.remove(key);
                } else {
                    accumulator.insert(key.clone(), value.clone());
                }
            }
        }
        result.push(accumulator.clone());
    }

    result
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
