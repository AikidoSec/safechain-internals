use super::*;

use rama::http::{Body, BodyExtractExt as _};

fn make_request(accept: Option<&str>) -> Request {
    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    if let Some(accept) = accept {
        req.headers_mut()
            .insert("accept", HeaderValue::from_str(accept).unwrap());
    }
    req
}

fn make_json_response(body: &str) -> Response {
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn timestamp_hours_ago(hours: u64) -> String {
    let t = SystemTime::now() - Duration::from_secs(hours * 3600);
    humantime::format_rfc3339_millis(t).to_string()
}

#[test]
fn replaces_npm_install_accept_header() {
    let mut req = make_request(Some("application/vnd.npm.install-v1+json"));
    MinPackageAge::modify_request_headers(&mut req);
    assert_eq!(req.headers().get("accept").unwrap(), "application/json");
}

#[test]
fn no_accept_header_is_unchanged() {
    let mut req = make_request(None);
    MinPackageAge::modify_request_headers(&mut req);
    assert!(req.headers().get("accept").is_none());
}

#[test]
fn non_matching_accept_header_is_unchanged() {
    let mut req = make_request(Some("application/json"));
    MinPackageAge::modify_request_headers(&mut req);
    assert_eq!(req.headers().get("accept").unwrap(), "application/json");
}

#[test]
fn unrelated_accept_header_is_unchanged() {
    let mut req = make_request(Some("text/html"));
    MinPackageAge::modify_request_headers(&mut req);
    assert_eq!(req.headers().get("accept").unwrap(), "text/html");
}

#[tokio::test]
async fn removes_versions_newer_than_24h() {
    let recent = timestamp_hours_ago(1);
    let body = format!(
        r#"{{"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z","1.0.1":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    let time = result_json["time"].as_object().unwrap();
    assert!(time.contains_key("created"));
    assert!(time.contains_key("modified"));
    assert!(time.contains_key("1.0.0"));
    assert!(
        !time.contains_key("1.0.1"),
        "recent version should be removed"
    );
}

#[tokio::test]
async fn keeps_versions_older_than_24h() {
    let old = timestamp_hours_ago(48);
    let body = format!(r#"{{"time":{{"created":"2020-01-01T00:00:00.000Z","1.0.0":"{old}"}}}}"#);
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    let time = result_json["time"].as_object().unwrap();
    assert!(time.contains_key("1.0.0"), "old version should be kept");
}

#[tokio::test]
async fn keeps_created_and_modified_always() {
    let recent = timestamp_hours_ago(1);
    let body = format!(r#"{{"time":{{"created":"{recent}","modified":"{recent}"}}}}"#);
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    let time = result_json["time"].as_object().unwrap();
    assert!(
        time.contains_key("created"),
        "created should always be kept"
    );
    assert!(
        time.contains_key("modified"),
        "modified should always be kept"
    );
}

#[tokio::test]
async fn passthrough_non_json_response() {
    let resp = Response::builder()
        .header("content-type", "application/octet-stream")
        .body(Body::from("binary data"))
        .unwrap();
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    assert_eq!(
        result.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
}

#[tokio::test]
async fn passthrough_invalid_json_body() {
    let resp = make_json_response("not valid json {{{");
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let body_str = result.try_into_string().await.unwrap();
    assert_eq!(body_str, "not valid json {{{");
}

#[tokio::test]
async fn updates_latest_tag_when_latest_is_removed() {
    let recent = timestamp_hours_ago(1);
    let old = timestamp_hours_ago(48);
    let body = format!(
        r#"{{"name":"my-package","dist-tags":{{"latest":"1.0.1"}},"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{old}","1.0.1":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert_eq!(result_json["dist-tags"]["latest"], "1.0.0");
}

#[tokio::test]
async fn updates_latest_to_most_recent_stable_version() {
    let recent = timestamp_hours_ago(1);
    let older = timestamp_hours_ago(72);
    let newer = timestamp_hours_ago(48);
    let body = format!(
        r#"{{"name":"my-package","dist-tags":{{"latest":"1.0.2"}},"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{older}","1.0.1":"{newer}","1.0.2":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert_eq!(result_json["dist-tags"]["latest"], "1.0.1");
}

#[tokio::test]
async fn removes_latest_tag_when_no_stable_versions_remain() {
    let recent = timestamp_hours_ago(1);
    let body = format!(
        r#"{{"name":"my-package","dist-tags":{{"latest":"1.0.0"}},"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert!(
        result_json["dist-tags"]
            .as_object()
            .unwrap()
            .get("latest")
            .is_none(),
        "latest should be removed when no stable versions remain"
    );
}

#[tokio::test]
async fn preserves_latest_tag_when_latest_is_not_removed() {
    let recent = timestamp_hours_ago(1);
    let old = timestamp_hours_ago(48);
    let body = format!(
        r#"{{"name":"my-package","dist-tags":{{"latest":"1.0.0"}},"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{old}","1.0.1":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert_eq!(result_json["dist-tags"]["latest"], "1.0.0");
}

#[tokio::test]
async fn excludes_prerelease_versions_from_latest_tag() {
    let recent = timestamp_hours_ago(1);
    let old = timestamp_hours_ago(48);
    let body = format!(
        r#"{{"name":"my-package","dist-tags":{{"latest":"1.0.0"}},"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{recent}","1.0.1-beta":"{old}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert!(
        result_json["dist-tags"]
            .as_object()
            .unwrap()
            .get("latest")
            .is_none(),
        "pre-release versions should not become latest"
    );
}

#[tokio::test]
async fn no_dist_tags_is_unchanged() {
    let recent = timestamp_hours_ago(1);
    let body = format!(
        r#"{{"name":"my-package","time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"{recent}"}}}}"#
    );
    let resp = make_json_response(&body);
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();
    assert!(
        result_json.as_object().unwrap().get("dist-tags").is_none(),
        "dist-tags key should not be added when absent"
    );
}

// fn make_json_response_with_headers(body: &str, headers: &[(&str, &str)]) -> Response {
//     let mut builder = Response::builder().header("content-type", "application/json");
//     for (name, value) in headers {
//         builder = builder.header(*name, *value);
//     }
//     builder.body(Body::from(body.to_owned())).unwrap()
// }
// const MINIMAL_JSON: &str = r#"{{"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z","1.0.1":"2026-02-13T10:00:00.000Z"}}}}"#;

#[tokio::test]
async fn removes_response_caching() {
    let recent = timestamp_hours_ago(1);
    let body = format!(
        r#"{{"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z","1.0.1":"{recent}"}}}}"#
    );
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body))
        .unwrap();

    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();

    assert!(
        result.headers().get("etag").is_none(),
        "etag should be stripped from JSON responses"
    );
    assert!(
        result.headers().get("last-modified").is_none(),
        "etag should be stripped from JSON responses"
    );
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "no-cache",
        "existing cache-control should be overwritten with no-cache"
    );
}

#[tokio::test]
async fn does_not_strip_headers_for_non_json_response() {
    let resp = Response::builder()
        .header("content-type", "application/octet-stream")
        .header("etag", r#""abc123""#)
        .body(Body::from("binary data"))
        .unwrap();
    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();
    assert_eq!(
        result.headers().get("etag").unwrap(),
        r#""abc123""#,
        "etag should be preserved for non-JSON responses"
    );
}

#[tokio::test]
async fn does_not_strip_cache_headers_when_json_is_not_modified() {
    let older_than_24_hours = timestamp_hours_ago(30);
    let body = format!(
        r#"{{"time":{{"created":"2020-01-01T00:00:00.000Z","modified":"2020-01-02T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z","1.0.1":"{older_than_24_hours}"}}}}"#
    );
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body))
        .unwrap();

    let result = MinPackageAge::remove_new_packages(resp, Duration::from_hours(24))
        .await
        .unwrap();

    assert_eq!(
        result.headers().get("etag").unwrap(),
        "abc123",
        "existing etag should still be there"
    );
    assert_eq!(
        result.headers().get("last-modified").unwrap(),
        "Wed, 01 Jan 2020 00:00:00 GMT",
        "existing last-modified should still be there"
    );
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "max-age=3600",
        "existing cache-control should still be there"
    );
}
