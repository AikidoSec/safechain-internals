use std::{str::FromStr, time::UNIX_EPOCH};

use rama::telemetry::tracing;
use serde_json::{Map, Value};

use crate::{
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator},
    package::{released_packages_list::RemoteReleasedPackagesList, version::PackageVersion},
};

#[derive(Debug)]
pub(super) struct RewriteResult {
    pub bytes: Vec<u8>,
    pub package_name: String,
    pub suppressed_malware: Vec<PackageVersion>,
    pub suppressed_min_age: Vec<PackageVersion>,
}

/// Rewrite a Packagist `/p2/vendor/package.json` response.
///
/// De-minifies the Composer 2.x minified format (`"minified": "composer/2.0"`),
/// removes versions that are listed as malware or were released within the
/// configured minimum age window, and re-serializes without the `minified` key.
///
/// Returns `None` if the response does not need rewriting (no versions suppressed
/// or the package is explicitly allowed by policy).
pub(super) fn rewrite_response(
    bytes: &[u8],
    package_name: &str,
    cutoff_secs: i64,
    is_malware: impl Fn(&str, &PackageVersion) -> bool,
    released_packages: &RemoteReleasedPackagesList,
    policy_evaluator: Option<&PolicyEvaluator>,
) -> Option<RewriteResult> {
    let json: Value = serde_json::from_slice(bytes)
        .inspect_err(|e| tracing::debug!("packagist: failed to parse metadata JSON: {e}"))
        .ok()?;

    let packages_obj = json.get("packages")?.as_object()?;

    // Find the canonical key in the JSON (may differ in casing from the URL-derived name).
    let package_key = packages_obj
        .keys()
        .find(|k| k.to_ascii_lowercase() == package_name)?
        .clone();

    let versions_array = packages_obj.get(&package_key)?.as_array()?;

    // If the package is explicitly allowed by policy, skip all filtering.
    if let Some(evaluator) = policy_evaluator {
        if matches!(
            evaluator.evaluate_package_install("packagist", package_name),
            PackagePolicyDecision::Allow
        ) {
            return None;
        }
    }

    // De-minify: expand each entry to a full field set via an accumulator walk.
    // The Composer 2.x minified format only carries changed fields per entry;
    // `"__unset"` explicitly removes a field for that version.
    let expanded = deminify(versions_array);

    let mut suppressed_malware: Vec<PackageVersion> = Vec::new();
    let mut suppressed_min_age: Vec<PackageVersion> = Vec::new();
    let mut kept: Vec<Value> = Vec::new();

    for entry in &expanded {
        let Some(version_str) = entry.get("version").and_then(|v| v.as_str()) else {
            kept.push(Value::Object(entry.clone()));
            continue;
        };

        let version = PackageVersion::from_str(version_str)
            .unwrap_or_else(|_| PackageVersion::Unknown(version_str.into()));

        if is_malware(package_name, &version) {
            tracing::info!(
                package = %package_name,
                version = %version_str,
                "packagist: suppressing malware version from metadata response"
            );
            suppressed_malware.push(version);
            continue;
        }

        // Use the `time` field when available; fall back to the releases list.
        let is_recent = time_from_entry(entry).is_some_and(|t| t > cutoff_secs)
            || released_packages.is_recently_released(package_name, Some(&version), cutoff_secs);

        if is_recent {
            tracing::info!(
                package = %package_name,
                version = %version_str,
                "packagist: suppressing too-new version from metadata response"
            );
            suppressed_min_age.push(version);
            continue;
        }

        kept.push(Value::Object(entry.clone()));
    }

    if suppressed_malware.is_empty() && suppressed_min_age.is_empty() {
        return None;
    }

    // Build output without the `minified` key so every entry is self-contained.
    let mut packages = Map::new();
    packages.insert(package_key, Value::Array(kept));
    let output = serde_json::json!({ "packages": packages });

    let out_bytes = serde_json::to_vec(&output)
        .inspect_err(|e| tracing::debug!("packagist: failed to serialize rewritten metadata: {e}"))
        .ok()?;

    Some(RewriteResult {
        bytes: out_bytes,
        package_name: package_name.to_owned(),
        suppressed_malware,
        suppressed_min_age,
    })
}

/// Expand minified Composer 2.x package entries to full field sets.
///
/// Walks entries in order, maintaining a running accumulator. Each entry patches
/// the accumulator: present fields override, `"__unset"` fields are removed.
/// The returned vec contains one fully-expanded map per input entry.
fn deminify(entries: &[Value]) -> Vec<Map<String, Value>> {
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

fn time_from_entry(entry: &Map<String, Value>) -> Option<i64> {
    let ts = entry.get("time")?.as_str()?;
    let t = humantime::parse_rfc3339(ts).ok()?;
    let secs = t.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(secs as i64)
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
