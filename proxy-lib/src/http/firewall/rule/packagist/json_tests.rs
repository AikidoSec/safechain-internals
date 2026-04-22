use std::time::{Duration, SystemTime};

use rama::utils::time::now_unix_ms;

use crate::package::{
    released_packages_list::{
        LowerCaseReleasedPackageFormatter, ReleasedPackageData, RemoteReleasedPackagesList,
    },
    version::{PackageVersion, PragmaticSemver},
};

use super::*;

fn timestamp_hours_from_now(hours: i64) -> String {
    if hours >= 0 {
        let t = SystemTime::now() + Duration::from_secs(hours as u64 * 3600);
        humantime::format_rfc3339(t).to_string()
    } else {
        let t = SystemTime::now() - Duration::from_secs((-hours) as u64 * 3600);
        humantime::format_rfc3339(t).to_string()
    }
}

fn no_releases() -> RemoteReleasedPackagesList {
    let now_secs = now_unix_ms() / 1000;
    RemoteReleasedPackagesList::from_entries_for_tests(
        vec![],
        now_secs,
        LowerCaseReleasedPackageFormatter,
    )
}

fn releases(entries: &[(&str, &str, i64)]) -> RemoteReleasedPackagesList {
    let now_secs = now_unix_ms() / 1000;
    RemoteReleasedPackagesList::from_entries_for_tests(
        entries
            .iter()
            .map(|(name, version, hours_ago)| ReleasedPackageData {
                package_name: (*name).to_owned(),
                version: version.parse().unwrap(),
                released_on: now_secs - (*hours_ago * 3600),
            })
            .collect(),
        now_secs,
        LowerCaseReleasedPackageFormatter,
    )
}

fn cutoff() -> i64 {
    now_unix_ms() / 1000 - 48 * 3600
}

fn rewrite_min_age(
    json: serde_json::Value,
    pkg: &str,
    released: &[(&str, &str, i64)],
) -> Option<serde_json::Value> {
    let bytes = serde_json::to_vec(&json).unwrap();
    let rl = releases(released);
    let result = rewrite_response(&bytes, pkg, cutoff(), |_, _| false, &rl, None)?;
    serde_json::from_slice(&result.bytes).ok()
}

fn rewrite_malware(
    json: serde_json::Value,
    pkg: &str,
    malware: &[(&str, &str)],
) -> Option<serde_json::Value> {
    let bytes = serde_json::to_vec(&json).unwrap();
    let rl = no_releases();
    let result = rewrite_response(
        &bytes,
        pkg,
        cutoff(),
        |name, version| {
            malware.iter().any(|(m_name, m_ver)| {
                name == *m_name
                    && version
                        == &m_ver
                            .parse()
                            .unwrap_or(PackageVersion::Unknown((*m_ver).into()))
            })
        },
        &rl,
        None,
    )?;
    serde_json::from_slice(&result.bytes).ok()
}

fn versions_in(out: &serde_json::Value, pkg: &str) -> Vec<String> {
    out["packages"][pkg]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v["version"].as_str().map(str::to_owned))
        .collect()
}

// --- no filtering needed ---

#[test]
fn no_versions_filtered_returns_none() {
    let json = serde_json::json!({
        "minified": "composer/2.0",
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "1.0.0", "time": timestamp_hours_from_now(-72)},
                {"version": "0.9.0", "time": timestamp_hours_from_now(-200)}
            ]
        }
    });
    assert!(rewrite_min_age(json, "vendor/pkg", &[]).is_none());
}

#[test]
fn wrong_package_key_returns_none() {
    let json = serde_json::json!({
        "packages": {
            "other/package": [
                {"name": "other/package", "version": "1.0.0", "time": timestamp_hours_from_now(-1)}
            ]
        }
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    assert!(
        rewrite_response(
            &bytes,
            "vendor/pkg",
            cutoff(),
            |_, _| false,
            &no_releases(),
            None
        )
        .is_none()
    );
}

// --- min-age filtering via `time` field ---

#[test]
fn removes_recent_version_via_time_field() {
    let json = serde_json::json!({
        "minified": "composer/2.0",
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "2.0.0", "time": timestamp_hours_from_now(1)},
                {"version": "1.0.0", "time": timestamp_hours_from_now(-72)}
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[]).unwrap();
    let versions = versions_in(&out, "vendor/pkg");
    assert!(
        !versions.contains(&"2.0.0".to_owned()),
        "too-new version should be removed"
    );
    assert!(
        versions.contains(&"1.0.0".to_owned()),
        "old version should remain"
    );
}

#[test]
fn removes_recent_version_via_releases_list_fallback() {
    // No `time` field in entries — falls back to the releases list.
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "2.0.0"},
                {"version": "1.0.0"}
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[("vendor/pkg", "2.0.0", 1)]).unwrap();
    let versions = versions_in(&out, "vendor/pkg");
    assert!(!versions.contains(&"2.0.0".to_owned()));
    assert!(versions.contains(&"1.0.0".to_owned()));
}

#[test]
fn all_versions_removed_yields_empty_array() {
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "1.0.0", "time": timestamp_hours_from_now(10)}
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[]).unwrap();
    let arr = out["packages"]["vendor/pkg"].as_array().unwrap();
    assert!(arr.is_empty());
}

// --- malware filtering ---

#[test]
fn removes_malware_version_keeps_safe_version() {
    let json = serde_json::json!({
        "minified": "composer/2.0",
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "1.0.0", "time": timestamp_hours_from_now(-72)},
                {"version": "0.9.0", "time": timestamp_hours_from_now(-200)}
            ]
        }
    });
    let out = rewrite_malware(json, "vendor/pkg", &[("vendor/pkg", "1.0.0")]).unwrap();
    let versions = versions_in(&out, "vendor/pkg");
    assert!(
        !versions.contains(&"1.0.0".to_owned()),
        "malware version must be removed"
    );
    assert!(
        versions.contains(&"0.9.0".to_owned()),
        "safe version must remain"
    );
}

#[test]
fn malware_check_not_triggered_for_different_package() {
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "1.0.0", "time": timestamp_hours_from_now(-72)}
            ]
        }
    });
    // Malware list has "other/pkg" @ 1.0.0, not "vendor/pkg"
    assert!(rewrite_malware(json, "vendor/pkg", &[("other/pkg", "1.0.0")]).is_none());
}

// --- de-minification ---

#[test]
fn deminify_propagates_fields_from_first_entry() {
    // The `require` field is only in the first entry (newest). After de-minification
    // the second entry must also carry it when we serialize the output.
    let json = serde_json::json!({
        "minified": "composer/2.0",
        "packages": {
            "vendor/pkg": [
                {
                    "name": "vendor/pkg",
                    "version": "2.0.0",
                    "time": timestamp_hours_from_now(1),
                    "require": {"php": "^8.0"}
                },
                {
                    "version": "1.0.0",
                    "time": timestamp_hours_from_now(-72)
                }
            ]
        }
    });
    // 2.0.0 is too new → removed; 1.0.0 should be kept WITH the inherited `require`.
    let out = rewrite_min_age(json, "vendor/pkg", &[]).unwrap();
    let remaining = &out["packages"]["vendor/pkg"][0];
    assert_eq!(remaining["version"], "1.0.0");
    assert_eq!(
        remaining["require"]["php"], "^8.0",
        "require must be inherited via de-minification"
    );
}

#[test]
fn deminify_handles_unset_sentinel() {
    // The second entry removes `homepage` via `"__unset"`.
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {
                    "name": "vendor/pkg",
                    "version": "2.0.0",
                    "time": timestamp_hours_from_now(1),
                    "homepage": "https://example.com"
                },
                {
                    "version": "1.0.0",
                    "time": timestamp_hours_from_now(-72),
                    "homepage": "__unset"
                }
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[]).unwrap();
    let remaining = &out["packages"]["vendor/pkg"][0];
    assert_eq!(remaining["version"], "1.0.0");
    assert!(
        remaining.get("homepage").is_none(),
        "homepage should be unset for 1.0.0"
    );
}

// --- case insensitivity ---

#[test]
fn package_name_lookup_is_case_insensitive() {
    // JSON key uses uppercase; package_name from URL is lowercase.
    let json = serde_json::json!({
        "packages": {
            "Vendor/Pkg": [
                {"name": "Vendor/Pkg", "version": "1.0.0", "time": timestamp_hours_from_now(1)}
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[]).unwrap();
    // Output preserves original JSON key casing.
    assert!(out["packages"]["Vendor/Pkg"].is_array());
}

// --- dev suffix versions ---

#[test]
fn dev_version_filtered_by_releases_list() {
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "1.0.0-alpha.1"},
                {"version": "0.9.0"}
            ]
        }
    });
    let out = rewrite_min_age(json, "vendor/pkg", &[("vendor/pkg", "1.0.0-alpha.1", 1)]).unwrap();
    let versions = versions_in(&out, "vendor/pkg");
    assert!(!versions.contains(&"1.0.0-alpha.1".to_owned()));
    assert!(versions.contains(&"0.9.0".to_owned()));
}

// --- result metadata ---

#[test]
fn result_contains_correct_suppressed_lists() {
    let json = serde_json::json!({
        "packages": {
            "vendor/pkg": [
                {"name": "vendor/pkg", "version": "2.0.0", "time": timestamp_hours_from_now(1)},
                {"version": "1.0.0", "time": timestamp_hours_from_now(-72)},
                {"version": "0.9.0", "time": timestamp_hours_from_now(-200)}
            ]
        }
    });
    let bytes = serde_json::to_vec(&json).unwrap();
    let rl = no_releases();
    let result = rewrite_response(
        &bytes,
        "vendor/pkg",
        cutoff(),
        |name, version| {
            name == "vendor/pkg"
                && version == &PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0))
        },
        &rl,
        None,
    )
    .unwrap();

    assert_eq!(
        result.suppressed_min_age.len(),
        1,
        "2.0.0 should be in suppressed_min_age"
    );
    assert_eq!(
        result.suppressed_malware.len(),
        1,
        "1.0.0 should be in suppressed_malware"
    );
    assert_eq!(
        result.suppressed_min_age[0],
        PackageVersion::Semver(PragmaticSemver::new_semver(2, 0, 0))
    );
    assert_eq!(
        result.suppressed_malware[0],
        PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0))
    );
}
