use rama::{
    http::{StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_chrome_blocks_extension_with_version() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://clients2.googleusercontent.com/crx/blobs/somehash/lajondecmobodlejlcjllhojikagldgd_1_0_0_0.crx")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_chrome_case_insensitive_blocking() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Extension ID in uppercase - should still be blocked
    let resp = client
        .get("https://clients2.googleusercontent.com/crx/blobs/somehash/LAJONDECMOBODLEJLCJLLHOJIKAGLDGD_1_0_0_0.crx")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_chrome_allows_non_malware_extension() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // A safe extension ID that's not in the malware list
    let resp = client
        .get("https://clients2.googleusercontent.com/crx/blobs/somehash/safeextension12345_1_0_0_0.crx")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_chrome_blocks_exact_version_match() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // With exact version 6.45.0.0 - should be blocked
    let resp = client
        .get("https://clients2.googleusercontent.com/crx/blobs/somehash/faeadnfmdfamenfhaipofoffijhlnkif_6_45_0_0.crx")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_chrome_allows_different_version() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // With different version 7.0.0.0 - should be allowed
    let resp = client
        .get("https://clients2.googleusercontent.com/crx/blobs/somehash/faeadnfmdfamenfhaipofoffijhlnkif_7_0_0_0.crx")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
