use std::time::{Duration, SystemTime};

use serde_json::{Map, Value, json};

use super::*;

fn ts(hours_from_now: i64) -> String {
    if hours_from_now >= 0 {
        let t = SystemTime::now() + Duration::from_secs(hours_from_now as u64 * 3600);
        humantime::format_rfc3339(t).to_string()
    } else {
        let t = SystemTime::now() - Duration::from_secs((-hours_from_now) as u64 * 3600);
        humantime::format_rfc3339(t).to_string()
    }
}

fn entry(fields: Value) -> Map<String, Value> {
    fields.as_object().unwrap().clone()
}

// --- parse_and_deminify ---

#[test]
fn parse_returns_none_for_wrong_package_key() {
    let body = json!({ "packages": { "other/pkg": [{"version": "1.0.0"}] } });
    let bytes = serde_json::to_vec(&body).unwrap();
    assert!(parse_and_deminify(&bytes, "vendor/pkg").is_none());
}

#[test]
fn parse_finds_key_case_insensitively() {
    let body = json!({ "packages": { "Vendor/Pkg": [{"version": "1.0.0"}] } });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (key, entries) = parse_and_deminify(&bytes, "vendor/pkg").unwrap();
    assert_eq!(key, "Vendor/Pkg");
    assert_eq!(entries.len(), 1);
}

#[test]
fn parse_returns_none_for_invalid_json() {
    assert!(parse_and_deminify(b"not json", "vendor/pkg").is_none());
}

// --- deminify ---

#[test]
fn deminify_propagates_fields_from_first_entry() {
    let entries = vec![
        json!({"name": "vendor/pkg", "version": "2.0.0", "require": {"php": "^8.0"}}),
        json!({"version": "1.0.0"}),
    ];
    let expanded = deminify(&entries);
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded[1]["version"], "1.0.0");
    assert_eq!(
        expanded[1]["require"]["php"], "^8.0",
        "require must be inherited from first entry"
    );
}

#[test]
fn deminify_handles_unset_sentinel() {
    let entries = vec![
        json!({"version": "2.0.0", "homepage": "https://example.com"}),
        json!({"version": "1.0.0", "homepage": "__unset"}),
    ];
    let expanded = deminify(&entries);
    assert_eq!(expanded[1]["version"], "1.0.0");
    assert!(
        expanded[1].get("homepage").is_none(),
        "homepage should be removed by __unset"
    );
}

#[test]
fn deminify_later_entry_overrides_earlier_value() {
    let entries = vec![
        json!({"version": "2.0.0", "description": "old"}),
        json!({"version": "1.0.0", "description": "new"}),
    ];
    let expanded = deminify(&entries);
    assert_eq!(expanded[1]["description"], "new");
}

// --- time_from_entry ---

#[test]
fn time_from_entry_parses_valid_timestamp() {
    let e = entry(json!({"time": "2020-06-01T00:00:00+00:00"}));
    assert!(time_from_entry(&e).is_some());
}

#[test]
fn time_from_entry_returns_none_when_field_absent() {
    let e = entry(json!({"version": "1.0.0"}));
    assert!(time_from_entry(&e).is_none());
}

#[test]
fn time_from_entry_returns_none_for_invalid_timestamp() {
    let e = entry(json!({"time": "not-a-date"}));
    assert!(time_from_entry(&e).is_none());
}

#[test]
fn time_from_entry_future_timestamp_is_greater_than_past() {
    let past = entry(json!({"time": ts(-72)}));
    let future = entry(json!({"time": ts(1)}));
    let past_secs = time_from_entry(&past).unwrap();
    let future_secs = time_from_entry(&future).unwrap();
    assert!(future_secs > past_secs);
}

// --- serialize ---

#[test]
fn serialize_produces_packages_object_without_minified_key() {
    let out = serialize("vendor/pkg".to_owned(), vec![json!({"version": "1.0.0"})]).unwrap();
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("minified").is_none(),
        "minified key must be absent"
    );
    assert!(parsed["packages"]["vendor/pkg"].is_array());
}

#[test]
fn serialize_preserves_empty_array_when_all_filtered() {
    let out = serialize("vendor/pkg".to_owned(), vec![]).unwrap();
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let arr = parsed["packages"]["vendor/pkg"].as_array().unwrap();
    assert!(arr.is_empty());
}
