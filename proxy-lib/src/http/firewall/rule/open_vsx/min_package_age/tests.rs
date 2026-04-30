use rama::http::{Body, BodyExtractExt as _};

use crate::{
    package::released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;

fn make_json_response(body: &str) -> Response {
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// `entries` is `(package_name, version, hours_ago_released)` — package_name
/// is in OpenVSX `publisher/extension` form, lowercase.
fn make_released_packages(
    entries: &[(&str, &str, u64)],
) -> RemoteReleasedPackagesList<OpenVsxPackageName> {
    let now_ts = SystemTimestampMilliseconds::now();
    RemoteReleasedPackagesList::from_entries_for_tests(
        entries
            .iter()
            .map(|(package_name, version, hours_ago)| ReleasedPackageData {
                package_name: (*package_name).to_owned(),
                version: version.parse().unwrap(),
                released_on: now_ts - SystemDuration::hours(*hours_ago as u16),
            })
            .collect(),
        now_ts,
    )
}

fn cutoff_24h_ago() -> SystemTimestampMilliseconds {
    SystemTimestampMilliseconds::now() - SystemDuration::hours(24)
}

// --- VS-Marketplace shape (Cursor's marketplace) ---

#[tokio::test]
async fn vs_marketplace_strips_too_young_versions() {
    let body = r#"{
      "results":[{"extensions":[{
        "publisher":{"publisherName":"pub"},
        "extensionName":"ext",
        "versions":[
          {"version":"1.0.0"},
          {"version":"1.0.1"}
        ]
      }]}]
    }"#;
    // 1.0.1 was released 1h ago (too young against 24h cutoff); 1.0.0 not in list (treated as old).
    let released = make_released_packages(&[("pub/ext", "1.0.1", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
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
async fn vs_marketplace_keeps_old_versions_unchanged() {
    let body = r#"{
      "results":[{"extensions":[{
        "publisher":{"publisherName":"pub"},
        "extensionName":"ext",
        "versions":[{"version":"1.0.0"}]
      }]}]
    }"#;
    // Empty release list → nothing is "recent" → nothing stripped.
    let released = make_released_packages(&[]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
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
async fn vs_marketplace_lookup_is_case_insensitive() {
    // Cursor returns mixed-case publisher/name; the OpenVSX release-list key is lowercase.
    let body = r#"{
      "results":[{"extensions":[{
        "publisher":{"publisherName":"PubLisher"},
        "extensionName":"ExtName",
        "versions":[{"version":"1.0.0"}]
      }]}]
    }"#;
    let released = make_released_packages(&[("publisher/extname", "1.0.0", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
        .await
        .unwrap();

    let json: serde_json::Value = result.try_into_json().await.unwrap();
    assert!(
        json["results"][0]["extensions"][0]["versions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "case-mismatched response should still resolve against the lowercase release key"
    );
}

#[tokio::test]
async fn vs_marketplace_keeps_allowlisted_extension_versions() {
    let body = r#"{
      "results":[{"extensions":[{
        "publisher":{"publisherName":"pub"},
        "extensionName":"ext",
        "versions":[{"version":"1.0.1"}]
      }]}]
    }"#;
    let released = make_released_packages(&[("pub/ext", "1.0.1", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |id| id == "pub/ext",
        )
        .await
        .unwrap();

    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let versions: Vec<&str> = json["results"][0]["extensions"][0]["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.1"]);
}

// --- Native OpenVSX single-extension shape (`/api/{ns}/{name}`) ---

#[tokio::test]
async fn single_extension_strips_too_young_from_all_versions_map() {
    let body = r#"{
      "namespace":"pub",
      "name":"ext",
      "version":"1.0.1",
      "allVersions":{
        "1.0.1":"https://example.test/1.0.1",
        "1.0.0":"https://example.test/1.0.0"
      }
    }"#;
    let released = make_released_packages(&[("pub/ext", "1.0.1", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
        .await
        .unwrap();

    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let keys: Vec<&str> = json["allVersions"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["1.0.0"]);
}

#[tokio::test]
async fn single_extension_keeps_old_versions_unchanged() {
    let body = r#"{
      "namespace":"pub",
      "name":"ext",
      "version":"1.0.0",
      "allVersions":{"1.0.0":"https://example.test/1.0.0"}
    }"#;
    let released = make_released_packages(&[]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
        .await
        .unwrap();

    let json: serde_json::Value = result.try_into_json().await.unwrap();
    assert_eq!(
        json["allVersions"].as_object().unwrap().len(),
        1,
        "no rewrite should occur when nothing is recently released"
    );
}

// --- Native OpenVSX query shape (`/api/-/query`) ---

#[tokio::test]
async fn query_response_strips_too_young_from_extensions_array() {
    let body = r#"{
      "extensions":[{
        "namespace":"pub",
        "name":"ext",
        "allVersions":{
          "1.0.1":"https://example.test/1.0.1",
          "1.0.0":"https://example.test/1.0.0"
        }
      }]
    }"#;
    let released = make_released_packages(&[("pub/ext", "1.0.1", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(
            make_json_response(body),
            &released,
            cutoff_24h_ago(),
            |_| false,
        )
        .await
        .unwrap();

    let json: serde_json::Value = result.try_into_json().await.unwrap();
    let keys: Vec<&str> = json["extensions"][0]["allVersions"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["1.0.0"]);
}

// --- Cache header behavior ---

#[tokio::test]
async fn strips_cache_headers_when_response_is_rewritten() {
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(
            r#"{"results":[{"extensions":[{"publisher":{"publisherName":"pub"},"extensionName":"ext","versions":[{"version":"1.0.0"}]}]}]}"#,
        ))
        .unwrap();
    let released = make_released_packages(&[("pub/ext", "1.0.0", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    assert!(result.headers().get("etag").is_none());
    assert!(result.headers().get("last-modified").is_none());
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn preserves_cache_headers_when_nothing_rewritten() {
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("cache-control", "max-age=3600")
        .body(Body::from(
            r#"{"results":[{"extensions":[{"publisher":{"publisherName":"pub"},"extensionName":"ext","versions":[{"version":"1.0.0"}]}]}]}"#,
        ))
        .unwrap();
    let released = make_released_packages(&[]); // nothing recent

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    assert_eq!(result.headers().get("etag").unwrap(), "abc123");
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "max-age=3600"
    );
}

// --- Passthrough paths ---

#[tokio::test]
async fn passthrough_non_json_content_type() {
    let resp = Response::builder()
        .header("content-type", "text/html")
        .body(Body::from("<html></html>"))
        .unwrap();
    let released = make_released_packages(&[("pub/ext", "1.0.0", 1)]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    assert_eq!(result.try_into_string().await.unwrap(), "<html></html>");
}

#[tokio::test]
async fn passthrough_invalid_json() {
    let resp = make_json_response("not valid json {{{");
    let released = make_released_packages(&[]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    assert_eq!(
        result.try_into_string().await.unwrap(),
        "not valid json {{{"
    );
}

#[tokio::test]
async fn passthrough_unknown_json_shape() {
    // Valid JSON but doesn't match any of the three known shapes.
    let resp = make_json_response(r#"{"foo":"bar","baz":42}"#);
    let released = make_released_packages(&[]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    let body = result.try_into_string().await.unwrap();
    assert_eq!(body, r#"{"foo":"bar","baz":42}"#);
}

#[tokio::test]
async fn passthrough_when_content_length_exceeds_cap() {
    let oversized = (MAX_METADATA_BODY_BYTES as usize) + 1;
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("content-length", oversized.to_string())
        .body(Body::from("ignored — never read"))
        .unwrap();
    let released = make_released_packages(&[]);

    let result = MinPackageAgeOpenVsx::new(None)
        .remove_new_versions(resp, &released, cutoff_24h_ago(), |_| false)
        .await
        .unwrap();

    // Body should be returned untouched (not parsed, not rewritten).
    assert_eq!(
        result.try_into_string().await.unwrap(),
        "ignored — never read"
    );
}
