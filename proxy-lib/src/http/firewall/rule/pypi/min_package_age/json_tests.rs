use std::time::{Duration, SystemTime};

use crate::{
    package::{
        name_formatter::LowerCasePackageName,
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;

fn timestamp_hours_ago(hours: u64) -> String {
    let t = SystemTime::now() - Duration::from_secs(hours * 3600);
    humantime::format_rfc3339(t).to_string()
}

fn released(entries: &[(&str, &str, i64)]) -> RemoteReleasedPackagesList<LowerCasePackageName> {
    let now_ts = SystemTimestampMilliseconds::now();
    RemoteReleasedPackagesList::from_entries_for_tests(
        entries
            .iter()
            .map(|(name, version, hours_ago)| ReleasedPackageData {
                package_name: (*name).to_owned(),
                version: version.parse().unwrap(),
                released_on: now_ts - SystemDuration::hours((*hours_ago).max(0) as u16),
            })
            .collect(),
        now_ts,
    )
}

fn rewrite(json: serde_json::Value, entries: &[(&str, &str, i64)]) -> Option<serde_json::Value> {
    let bytes = serde_json::to_vec(&json).unwrap();
    let list = released(entries);
    let cutoff = SystemTimestampMilliseconds::now() - SystemDuration::hours(48);
    let result = rewrite_response(&bytes, cutoff, &list)?;
    serde_json::from_slice(&result.1.bytes).ok()
}

// --- legacy JSON (/pypi/<pkg>/json) ---

#[test]
fn legacy_no_versions_filtered_returns_none() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "1.0.0"},
        "releases": {"1.0.0": [{"filename": "pkg-1.0.0.tar.gz"}]},
        "urls": []
    });
    assert!(rewrite(json, &[("pkg", "1.0.0", 72)]).is_none());
}

#[test]
fn legacy_removes_recent_and_downgrades_info_version() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "pkg-2.0.0.tar.gz"}]
        },
        "urls": [{"filename": "pkg-2.0.0.tar.gz"}]
    });
    let out = rewrite(json, &[("pkg", "2.0.0", 1), ("pkg", "1.0.0", 72)]).unwrap();

    assert_eq!(out["info"]["version"], "1.0.0");
    assert!(out["releases"]["1.0.0"].is_array());
    assert!(out["releases"].get("2.0.0").is_none());
    assert_eq!(
        out["urls"],
        serde_json::json!([{"filename": "pkg-1.0.0.tar.gz"}])
    );
}

#[test]
fn legacy_all_versions_filtered_clears_info_version_and_urls() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "1.0.0"},
        "releases": {"1.0.0": [{"filename": "pkg-1.0.0.tar.gz"}]},
        "urls": [{"filename": "pkg-1.0.0.tar.gz"}]
    });
    let out = rewrite(json, &[("pkg", "1.0.0", 1)]).unwrap();

    assert!(out["info"].get("version").is_none());
    assert_eq!(out["urls"], serde_json::json!([]));
    assert!(out["releases"].as_object().unwrap().is_empty());
}

#[test]
fn legacy_prerelease_not_promoted_to_info_version() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "2.0.0"},
        "releases": {
            "2.0.0": [{"filename": "pkg-2.0.0.tar.gz"}],
            "3.0.0a1": [{"filename": "pkg-3.0.0a1.tar.gz"}]
        },
        "urls": [{"filename": "pkg-2.0.0.tar.gz"}]
    });
    // 2.0.0 is recent; only 3.0.0a1 (pre-release) remains
    let out = rewrite(json, &[("pkg", "2.0.0", 1), ("pkg", "3.0.0a1", 72)]).unwrap();

    assert!(
        out["info"].get("version").is_none(),
        "pre-release must not become info.version"
    );
    assert_eq!(out["urls"], serde_json::json!([]));
}

#[test]
fn legacy_picks_highest_semver_as_new_info_version() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "3.0.0"},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "pkg-2.0.0.tar.gz"}],
            "3.0.0": [{"filename": "pkg-3.0.0.tar.gz"}]
        },
        "urls": [{"filename": "pkg-3.0.0.tar.gz"}]
    });
    let out = rewrite(
        json,
        &[
            ("pkg", "3.0.0", 1),
            ("pkg", "2.0.0", 72),
            ("pkg", "1.0.0", 120),
        ],
    )
    .unwrap();

    assert_eq!(
        out["info"]["version"], "2.0.0",
        "must pick highest remaining stable semver"
    );
}

#[test]
fn legacy_non_latest_version_filtered_leaves_info_version_unchanged() {
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "pkg-2.0.0.tar.gz"}]
        },
        "urls": [{"filename": "pkg-2.0.0.tar.gz"}]
    });
    // 1.0.0 is recent, 2.0.0 (the latest) is old — info.version must stay 2.0.0
    let out = rewrite(json, &[("pkg", "1.0.0", 1), ("pkg", "2.0.0", 72)]).unwrap();

    assert_eq!(out["info"]["version"], "2.0.0");
    assert!(out["releases"].get("1.0.0").is_none());
}

// --- parse_package_from_metadata_file ---

#[test]
fn parse_package_from_metadata_file_uses_filename() {
    let file = serde_json::json!({"filename": "requests-2.31.0.tar.gz"});
    let info = parse_package_from_metadata_file(&file).unwrap();
    assert_eq!(info.name.to_string(), "requests");
    assert_eq!(info.version.to_string(), "2.31.0");
}

#[test]
fn parse_package_from_metadata_file_falls_back_to_url() {
    let file = serde_json::json!({
        "url": "https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz"
    });
    let info = parse_package_from_metadata_file(&file).unwrap();
    assert_eq!(info.name.to_string(), "requests");
    assert_eq!(info.version.to_string(), "2.31.0");
}

#[test]
fn parse_package_from_metadata_file_returns_none_when_unparseable() {
    let file = serde_json::json!({"not_a_filename": "something"});
    assert!(parse_package_from_metadata_file(&file).is_none());
}

// --- timestamp-based filtering (upload_time_iso_8601 / upload-time) ---

#[test]
fn legacy_suppresses_recent_version_via_timestamp_alone() {
    // The releases list is empty — suppression must come from upload_time_iso_8601.
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": timestamp_hours_ago(72)}],
            "2.0.0": [{"filename": "pkg-2.0.0.tar.gz", "upload_time_iso_8601": timestamp_hours_ago(1)}]
        },
        "urls": [{"filename": "pkg-2.0.0.tar.gz"}]
    });
    let out = rewrite(json, &[]).unwrap();

    assert_eq!(out["info"]["version"], "1.0.0");
    assert!(out["releases"].get("2.0.0").is_none());
}

#[test]
fn legacy_keeps_version_when_timestamp_predates_cutoff_and_not_in_releases_list() {
    // Old timestamp + absent from releases list → no filtering, returns None.
    let json = serde_json::json!({
        "info": {"name": "pkg", "version": "1.0.0"},
        "releases": {
            "1.0.0": [{"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": timestamp_hours_ago(72)}]
        },
        "urls": [{"filename": "pkg-1.0.0.tar.gz"}]
    });
    assert!(rewrite(json, &[]).is_none());
}

#[test]
fn simple_suppresses_recent_file_via_timestamp_alone() {
    // The releases list is empty — suppression must come from upload-time.
    let json = serde_json::json!({
        "name": "pkg",
        "files": [
            {"filename": "pkg-1.0.0.tar.gz", "upload-time": timestamp_hours_ago(72)},
            {"filename": "pkg-2.0.0.tar.gz", "upload-time": timestamp_hours_ago(1)}
        ]
    });
    let out = rewrite(json, &[]).unwrap();
    let files = out["files"].as_array().unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["filename"], "pkg-1.0.0.tar.gz");
}

// --- simple JSON (/simple/<pkg>/) ---

#[test]
fn simple_no_files_filtered_returns_none() {
    let json = serde_json::json!({
        "name": "pkg",
        "files": [{"filename": "pkg-1.0.0.tar.gz"}]
    });
    assert!(rewrite(json, &[("pkg", "1.0.0", 72)]).is_none());
}

#[test]
fn simple_removes_recent_file_keeps_old() {
    let json = serde_json::json!({
        "name": "pkg",
        "files": [
            {"filename": "pkg-1.0.0.tar.gz"},
            {"filename": "pkg-2.0.0.tar.gz"}
        ]
    });
    let out = rewrite(json, &[("pkg", "2.0.0", 1), ("pkg", "1.0.0", 72)]).unwrap();
    let files = out["files"].as_array().unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["filename"], "pkg-1.0.0.tar.gz");
}

#[test]
fn simple_file_without_parseable_filename_is_kept() {
    let json = serde_json::json!({
        "name": "pkg",
        "files": [
            {"filename": "pkg-2.0.0.tar.gz"},
            {"not_a_filename_key": "something"}
        ]
    });
    let out = rewrite(json, &[("pkg", "2.0.0", 1)]).unwrap();
    let files = out["files"].as_array().unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["not_a_filename_key"], "something");
}
