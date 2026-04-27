use std::time::SystemTime;

use rama::http::{Body, BodyExtractExt as _};

use super::*;

fn timestamp_hours_ago(hours: u64) -> String {
    let t = SystemTime::now() - std::time::Duration::from_secs(hours * 3600);
    humantime::format_rfc3339_millis(t).to_string()
}

fn cutoff_secs_ago(hours: u64) -> SystemTimestampMilliseconds {
    let t = SystemTime::now() - std::time::Duration::from_secs(hours * 3600);
    SystemTimestampMilliseconds::from(t)
}

fn make_single_extension_response(
    publisher: &str,
    extension: &str,
    versions: &[(&str, &str)],
) -> Response {
    let versions_json: String = versions
        .iter()
        .map(|(ver, ts)| format!(r#"{{"version":"{ver}","lastUpdated":"{ts}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"publisher":{{"publisherName":"{publisher}"}},"extensionName":"{extension}","versions":[{versions_json}]}}"#
    );
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn make_extensionquery_response(
    publisher: &str,
    extension: &str,
    versions: &[(&str, &str)],
) -> Response {
    let versions_json: String = versions
        .iter()
        .map(|(ver, ts)| format!(r#"{{"version":"{ver}","lastUpdated":"{ts}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"results":[{{"extensions":[{{"publisher":{{"publisherName":"{publisher}"}},"extensionName":"{extension}","versions":[{versions_json}]}}]}}]}}"#
    );
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

// --- single-extension response tests ---

#[tokio::test]
async fn single_removes_version_newer_than_cutoff() {
    let recent = timestamp_hours_ago(1);
    let old = timestamp_hours_ago(50);
    let resp = make_single_extension_response("pub", "ext", &[("1.0.0", &old), ("1.0.1", &recent)]);
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let versions: Vec<&str> = json["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0"]);
}

#[tokio::test]
async fn single_keeps_version_older_than_cutoff() {
    let old = timestamp_hours_ago(50);
    let resp = make_single_extension_response("pub", "ext", &[("1.0.0", &old)]);
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let versions: Vec<&str> = json["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0"]);
}

#[tokio::test]
async fn single_removes_all_versions_when_all_too_new() {
    let recent = timestamp_hours_ago(1);
    let resp =
        make_single_extension_response("pub", "ext", &[("1.0.0", &recent), ("1.0.1", &recent)]);
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();
    assert!(
        json["versions"].as_array().unwrap().is_empty(),
        "all versions should be removed when all are too new"
    );
}

// --- extensionquery batch response tests ---

#[tokio::test]
async fn batch_removes_version_newer_than_cutoff() {
    let recent = timestamp_hours_ago(1);
    let old = timestamp_hours_ago(50);
    let resp = make_extensionquery_response("pub", "ext", &[("1.0.0", &old), ("1.0.1", &recent)]);
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let versions: Vec<&str> = json["results"][0]["extensions"][0]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0"]);
}

#[tokio::test]
async fn batch_keeps_version_older_than_cutoff() {
    let old = timestamp_hours_ago(50);
    let resp = make_extensionquery_response("pub", "ext", &[("1.0.0", &old)]);
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let versions: Vec<&str> = json["results"][0]["extensions"][0]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0"]);
}

// --- cache header tests ---

#[tokio::test]
async fn strips_cache_headers_when_response_is_rewritten() {
    let recent = timestamp_hours_ago(1);
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(format!(
            r#"{{"publisher":{{"publisherName":"pub"}},"extensionName":"ext","versions":[{{"version":"1.0.0","lastUpdated":"{recent}"}}]}}"#
        )))
        .unwrap();
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    assert!(
        result.headers().get("etag").is_none(),
        "etag should be stripped"
    );
    assert!(
        result.headers().get("last-modified").is_none(),
        "last-modified should be stripped"
    );
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn preserves_cache_headers_when_nothing_removed() {
    let old = timestamp_hours_ago(50);
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("cache-control", "max-age=3600")
        .body(Body::from(format!(
            r#"{{"publisher":{{"publisherName":"pub"}},"extensionName":"ext","versions":[{{"version":"1.0.0","lastUpdated":"{old}"}}]}}"#
        )))
        .unwrap();
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    assert_eq!(result.headers().get("etag").unwrap(), "abc123");
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "max-age=3600"
    );
}

// --- passthrough tests ---

#[tokio::test]
async fn passthrough_invalid_json() {
    let resp = Response::builder()
        .header("content-type", "application/json")
        .body(Body::from("not valid json {{{"))
        .unwrap();
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let body = result.try_into_string().await.unwrap();
    assert_eq!(body, "not valid json {{{");
}

#[tokio::test]
async fn passthrough_non_json_content_type() {
    let resp = Response::builder()
        .header("content-type", "text/plain")
        .body(Body::from("plain text"))
        .unwrap();
    let min_package_age = MinPackageAgeVSCode::new(None);
    let result = min_package_age
        .remove_new_versions(resp, cutoff_secs_ago(24))
        .await
        .unwrap();
    let body = result.try_into_string().await.unwrap();
    assert_eq!(body, "plain text");
}
