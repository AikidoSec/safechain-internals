use rama::http::{Body, BodyExtractExt as _};

use crate::{
    package::{
        name_formatter::LowerCasePackageName,
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;

fn make_json_response(body: &str) -> Response {
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn make_released_packages(
    entries: &[(&str, &str, u64)],
) -> RemoteReleasedPackagesList<LowerCasePackageName> {
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

fn default_cutoff_ts() -> SystemTimestampMilliseconds {
    SystemTimestampMilliseconds::now() - SystemDuration::hours(48)
}

#[tokio::test]
async fn removes_recent_releases_from_legacy_json() {
    let body = serde_json::json!({
        "info": {"name": "my-package", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "my_package-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "my_package-2.0.0.tar.gz"}]
        },
        "urls": [{"filename": "my_package-2.0.0.tar.gz"}]
    })
    .to_string();
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(make_json_response(&body), &list, default_cutoff_ts())
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(result_json["info"]["version"], "1.0.0");
    assert!(result_json["releases"]["1.0.0"].is_array());
    assert!(result_json["releases"].get("2.0.0").is_none());
    assert_eq!(
        result_json["urls"],
        serde_json::json!([{ "filename": "my_package-1.0.0.tar.gz" }])
    );
}

#[tokio::test]
async fn removes_recent_files_from_simple_json() {
    let body = serde_json::json!({
        "name": "my-package",
        "files": [
            {"filename": "my_package-1.0.0.tar.gz"},
            {"filename": "my_package-2.0.0.tar.gz"}
        ]
    })
    .to_string();
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(make_json_response(&body), &list, default_cutoff_ts())
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(result_json["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        result_json["files"][0]["filename"],
        "my_package-1.0.0.tar.gz"
    );
}

#[tokio::test]
async fn passthrough_non_json_non_html_response() {
    let resp = Response::builder()
        .header("content-type", "application/octet-stream")
        .body(Body::from("binary data"))
        .unwrap();
    let list = make_released_packages(&[]);

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(resp, &list, default_cutoff_ts())
        .await
        .unwrap();

    assert_eq!(
        result.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
}

#[tokio::test]
async fn passthrough_invalid_json_body() {
    let list = make_released_packages(&[]);
    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(
            make_json_response("not valid json {{{"),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();

    assert_eq!(
        result.try_into_string().await.unwrap(),
        "not valid json {{{"
    );
}

#[tokio::test]
async fn removes_response_caching_when_modified() {
    let body = serde_json::json!({
        "info": {"name": "my-package", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "my_package-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "my_package-2.0.0.tar.gz"}]
        },
        "urls": [{"filename": "my_package-2.0.0.tar.gz"}]
    })
    .to_string();
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body))
        .unwrap();

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(resp, &list, default_cutoff_ts())
        .await
        .unwrap();

    assert!(result.headers().get("etag").is_none());
    assert!(result.headers().get("last-modified").is_none());
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");
}

#[tokio::test]
async fn does_not_strip_cache_headers_when_not_modified() {
    let body = serde_json::json!({
        "info": {"name": "my-package", "version": "1.0.0"},
        "releases": {"1.0.0": [{"filename": "my_package-1.0.0.tar.gz"}]},
        "urls": [{"filename": "my_package-1.0.0.tar.gz"}]
    })
    .to_string();
    let list = make_released_packages(&[("my-package", "1.0.0", 72)]);
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body))
        .unwrap();

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(resp, &list, default_cutoff_ts())
        .await
        .unwrap();

    assert_eq!(result.headers().get("etag").unwrap(), "abc123");
    assert_eq!(
        result.headers().get("last-modified").unwrap(),
        "Wed, 01 Jan 2020 00:00:00 GMT"
    );
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "max-age=3600"
    );
}

#[tokio::test]
async fn removes_recent_links_from_simple_html() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-2.0.0.tar.gz">new</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);
    let resp = Response::builder()
        .header("content-type", "text/html")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body.to_owned()))
        .unwrap();

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(resp, &list, default_cutoff_ts())
        .await
        .unwrap();

    // Cache headers are always stripped for HTML (streaming — we can't defer headers).
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");

    let html = result.try_into_string().await.unwrap();
    assert!(html.contains("my_package-1.0.0.tar.gz"));
    assert!(!html.contains("my_package-2.0.0.tar.gz"));
}

#[tokio::test]
async fn html_always_strips_cache_headers_even_when_unmodified() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "1.0.0", 72)]);
    let resp = Response::builder()
        .header("content-type", "text/html")
        .header("etag", "abc123")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body.to_owned()))
        .unwrap();

    let result = MinPackageAgePyPI::new(None)
        .remove_new_packages(resp, &list, default_cutoff_ts())
        .await
        .unwrap();

    // Even when nothing is filtered, HTML responses are always marked no-cache
    // because the streaming path cannot defer header writes until body completion.
    assert!(result.headers().get("etag").is_none());
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");

    let html = result.try_into_string().await.unwrap();
    assert!(html.contains("my_package-1.0.0.tar.gz"));
}
