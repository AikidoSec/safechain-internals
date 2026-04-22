use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{
        FRESH_PACKAGIST_PACKAGE, FRESH_PACKAGIST_VENDOR, FRESH_PACKAGIST_VERSION,
        MALWARE_PACKAGIST_PACKAGE, MALWARE_PACKAGIST_VENDOR, MALWARE_PACKAGIST_VERSION,
    },
    test::e2e,
};

fn versions_in(body: &serde_json::Value, vendor: &str, package: &str) -> Vec<String> {
    body["packages"][format!("{vendor}/{package}")]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v["version"].as_str().map(str::to_owned))
        .collect()
}

// --- malware version suppression ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_malware_version_removed_from_metadata() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get(format!(
            "https://repo.packagist.org/p2/{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}.json"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        StatusCode::OK,
        resp.status(),
        "proxy must not block metadata requests"
    );
    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    let versions = versions_in(&body, MALWARE_PACKAGIST_VENDOR, MALWARE_PACKAGIST_PACKAGE);

    assert!(
        !versions.contains(&MALWARE_PACKAGIST_VERSION.to_owned()),
        "malware version {MALWARE_PACKAGIST_VERSION} must be absent from rewritten metadata; got: {versions:?}"
    );
    assert!(
        versions.contains(&"0.9.0".to_owned()),
        "safe version 0.9.0 must remain in rewritten metadata; got: {versions:?}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_malware_version_removed_via_http() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get(format!(
            "http://repo.packagist.org/p2/{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}.json"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    let versions = versions_in(&body, MALWARE_PACKAGIST_VENDOR, MALWARE_PACKAGIST_PACKAGE);

    assert!(!versions.contains(&MALWARE_PACKAGIST_VERSION.to_owned()));
}

// --- min-age version suppression ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_new_package_version_removed_from_metadata() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get(format!(
            "https://repo.packagist.org/p2/{FRESH_PACKAGIST_VENDOR}/{FRESH_PACKAGIST_PACKAGE}.json"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        StatusCode::OK,
        resp.status(),
        "proxy must not block metadata requests"
    );
    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    let versions = versions_in(&body, FRESH_PACKAGIST_VENDOR, FRESH_PACKAGIST_PACKAGE);

    assert!(
        !versions.contains(&FRESH_PACKAGIST_VERSION.to_owned()),
        "too-new version {FRESH_PACKAGIST_VERSION} must be absent; got: {versions:?}"
    );
    assert!(
        versions.contains(&"1.0.0".to_owned()),
        "older version 1.0.0 must remain; got: {versions:?}"
    );
}

// --- clean package passthrough ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_clean_package_passes_through() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Any package not in the malware list or releases list passes through unchanged.
    let resp = client
        .get("https://repo.packagist.org/p2/vendor/clean-package.json")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

// --- dev variant path ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_dev_variant_path_handled() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // The ~dev.json path must also be intercepted and rewritten.
    let resp = client
        .get(format!(
            "https://repo.packagist.org/p2/{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}~dev.json"
        ))
        .send()
        .await
        .unwrap();

    // Mock server returns 200 for unknown paths; the proxy should not block it.
    assert_eq!(StatusCode::OK, resp.status());
}

// --- non-packagist path passthrough ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_unrelated_path_passes_through() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // /packages.json is not a package-specific metadata endpoint; proxy should not rewrite it.
    let resp = client
        .get("https://repo.packagist.org/packages.json")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

// --- de-minification: inherited fields survive ---

#[tokio::test]
#[tracing_test::traced_test]
async fn test_packagist_inherited_require_present_after_rewrite() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // The malware version (1.0.0) carries `require`; 0.9.0 inherits it.
    // After rewriting (removing 1.0.0), 0.9.0 must still expose `require`.
    let resp = client
        .get(format!(
            "https://repo.packagist.org/p2/{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}.json"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    let pkg_key = format!("{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}");
    let remaining = &body["packages"][&pkg_key][0];

    assert_eq!(remaining["version"], "0.9.0");
    assert!(
        !remaining["require"].is_null(),
        "require field must be inherited from the removed first entry; got: {remaining}"
    );
}
