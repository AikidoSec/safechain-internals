use rama::http::{Body, BodyExtractExt as _};

use crate::{
    package::{
        name_formatter::LowerCasePackageName,
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;

fn make_list_response(body: &str) -> Response {
    Response::builder()
        .header("content-type", "text/plain; charset=UTF-8")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn make_list_response_with_cache(body: &str) -> Response {
    Response::builder()
        .header("content-type", "text/plain; charset=UTF-8")
        .header("cache-control", "public, max-age=60")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
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
async fn filters_recently_released_versions() {
    let body = "v1.0.0\nv2.0.0\n";
    let list = make_released_packages(&[
        ("github.com/gorilla/mux", "1.0.0", 72), // old — keep
        ("github.com/gorilla/mux", "2.0.0", 1),  // new — suppress
    ]);

    let result = MinPackageAgeGolang::new(None)
        .rewrite_list_response(
            make_list_response(body),
            "github.com/gorilla/mux",
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();

    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");
    let text = result.try_into_string().await.unwrap();
    assert!(text.contains("v1.0.0"), "old version should be kept");
    assert!(!text.contains("v2.0.0"), "new version should be suppressed");
}

#[tokio::test]
async fn passthrough_when_nothing_filtered() {
    let body = "v1.0.0\nv1.1.0\n";
    let list = make_released_packages(&[
        ("github.com/gorilla/mux", "1.0.0", 72),
        ("github.com/gorilla/mux", "1.1.0", 96),
    ]);
    let resp = make_list_response_with_cache(body);

    let result = MinPackageAgeGolang::new(None)
        .rewrite_list_response(resp, "github.com/gorilla/mux", &list, default_cutoff_ts())
        .await
        .unwrap();

    // cache headers must be preserved when nothing was filtered
    assert_eq!(result.headers().get("etag").unwrap(), "abc123");
    assert_eq!(
        result.headers().get("cache-control").unwrap(),
        "public, max-age=60"
    );
    let text = result.try_into_string().await.unwrap();
    assert!(text.contains("v1.0.0"));
    assert!(text.contains("v1.1.0"));
}

#[tokio::test]
async fn filters_deep_multi_segment_module_path() {
    // Mirrors a real malware-list entry:
    // { "package_name": "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/es",
    //   "version": "v1.3.84", "released_on": 1776804062 }
    let body = "v1.3.83\nv1.3.84\n";
    let list = make_released_packages(&[
        (
            "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/es",
            "1.3.83",
            72,
        ),
        (
            "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/es",
            "1.3.84",
            1,
        ),
    ]);

    let result = MinPackageAgeGolang::new(None)
        .rewrite_list_response(
            make_list_response(body),
            "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/es",
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();

    let text = result.try_into_string().await.unwrap();
    assert!(text.contains("v1.3.83"), "old version should be kept");
    assert!(
        !text.contains("v1.3.84"),
        "new version should be suppressed"
    );
}

#[tokio::test]
async fn keeps_unparseable_version_lines() {
    let body = "v1.0.0\nnot-a-version\n";
    let list = make_released_packages(&[("github.com/gorilla/mux", "1.0.0", 72)]);

    let result = MinPackageAgeGolang::new(None)
        .rewrite_list_response(
            make_list_response(body),
            "github.com/gorilla/mux",
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();

    let text = result.try_into_string().await.unwrap();
    assert!(text.contains("v1.0.0"));
    assert!(
        text.contains("not-a-version"),
        "unparseable lines must be kept"
    );
}

#[tokio::test]
async fn strips_cache_headers_only_when_modified() {
    let body = "v1.0.0\nv2.0.0\n";
    let list = make_released_packages(&[
        ("github.com/gorilla/mux", "1.0.0", 72),
        ("github.com/gorilla/mux", "2.0.0", 1),
    ]);
    let resp = make_list_response_with_cache(body);

    let result = MinPackageAgeGolang::new(None)
        .rewrite_list_response(resp, "github.com/gorilla/mux", &list, default_cutoff_ts())
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
