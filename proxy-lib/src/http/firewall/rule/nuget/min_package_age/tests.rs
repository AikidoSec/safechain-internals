use rama::http::{Body, BodyExtractExt as _, Response, Uri};

use crate::{
    package::{
        name_formatter::LowerCasePackageName,
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::catalog_list::CatalogList;
use super::flat_version_list::FlatVersionList;

// FlatVersionList matches GET /v3-flatcontainer/{package}/index.json

#[test]
fn test_flat_version_list_match_uri_returns_package_name() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/index.json",
    );
    assert_eq!(
        FlatVersionList { notifier: None }.match_uri(&uri),
        Some("microsoft.extensions.logging".into())
    );
}

#[test]
fn test_flat_version_list_match_uri_no_match_for_package_download() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/9.0.1/microsoft.extensions.logging.9.0.1.nupkg",
    );
    assert_eq!(FlatVersionList { notifier: None }.match_uri(&uri), None);
}

#[test]
fn test_flat_version_list_match_uri_no_match_for_wrong_base_path() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/index.json",
    );
    assert_eq!(FlatVersionList { notifier: None }.match_uri(&uri), None);
}

// CatalogList matches GET /v3/registration5-gz-semver2/{package}/...

#[test]
fn test_catalog_list_match_uri_returns_package_name_for_index() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/index.json",
    );
    assert_eq!(
        CatalogList { notifier: None }.match_uri(&uri),
        Some("microsoft.extensions.logging".into())
    );
}

#[test]
fn test_catalog_list_match_uri_returns_package_name_for_page_request() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/page/9.0.1/11.0.0-preview.3.26207.106.json",
    );
    assert_eq!(
        CatalogList { notifier: None }.match_uri(&uri),
        Some("microsoft.extensions.logging".into())
    );
}

#[test]
fn test_catalog_list_match_uri_no_match_for_wrong_base_path() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/index.json",
    );
    assert_eq!(CatalogList { notifier: None }.match_uri(&uri), None);
}

// FlatVersionList::remove_new_packages

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
async fn removes_recent_version_from_flat_index() {
    let body = serde_json::json!({ "versions": ["1.0.0", "2.0.0"] }).to_string();
    let list = make_released_packages(&[
        ("my-package", "2.0.0", 1),
        ("my-package", "1.0.0", 72),
    ]);

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(
            make_json_response(&body),
            "my-package".into(),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(result_json["versions"], serde_json::json!(["1.0.0"]));
}

#[tokio::test]
async fn keeps_all_versions_when_none_are_recent() {
    let body = serde_json::json!({ "versions": ["1.0.0", "2.0.0"] }).to_string();
    let list = make_released_packages(&[
        ("my-package", "1.0.0", 72),
        ("my-package", "2.0.0", 96),
    ]);

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(
            make_json_response(&body),
            "my-package".into(),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(result_json["versions"], serde_json::json!(["1.0.0", "2.0.0"]));
}

#[tokio::test]
async fn passthrough_invalid_json_body() {
    let list = make_released_packages(&[]);

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(
            make_json_response("not valid json {{{"),
            "my-package".into(),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();

    assert_eq!(result.try_into_string().await.unwrap(), "not valid json {{{");
}

#[tokio::test]
async fn passthrough_json_without_versions_field() {
    let body = serde_json::json!({ "other": "data" }).to_string();
    let list = make_released_packages(&[("my-package", "1.0.0", 1)]);

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(
            make_json_response(&body),
            "my-package".into(),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(result_json["other"], "data");
    assert!(result_json.get("versions").is_none());
}

#[tokio::test]
async fn strips_cache_headers_when_versions_removed() {
    let body = serde_json::json!({ "versions": ["1.0.0", "2.0.0"] }).to_string();
    let list = make_released_packages(&[("my-package", "2.0.0", 1)]);
    let resp = Response::builder()
        .header("content-type", "application/json")
        .header("etag", "abc123")
        .header("last-modified", "Wed, 01 Jan 2020 00:00:00 GMT")
        .header("cache-control", "max-age=3600")
        .body(Body::from(body))
        .unwrap();

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(resp, "my-package".into(), &list, default_cutoff_ts())
        .await
        .unwrap();

    assert!(result.headers().get("etag").is_none());
    assert!(result.headers().get("last-modified").is_none());
    assert_eq!(result.headers().get("cache-control").unwrap(), "no-cache");
}


#[tokio::test]
async fn keeps_unparseable_version_strings() {
    let body = serde_json::json!({ "versions": ["1.0.0", "not-a-semver"] }).to_string();
    let list = make_released_packages(&[("my-package", "1.0.0", 1)]);

    let result = FlatVersionList { notifier: None }
        .remove_new_packages(
            make_json_response(&body),
            "my-package".into(),
            &list,
            default_cutoff_ts(),
        )
        .await
        .unwrap();
    let result_json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(
        result_json["versions"],
        serde_json::json!(["not-a-semver"])
    );
}
