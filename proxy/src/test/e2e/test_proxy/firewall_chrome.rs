use rama::{
    Service,
    http::{StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_google_har_replay_blocked_plugin() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let req = e2e::har::parse_har_request(
        r##"{
    "method": "GET",
    "url": "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=arm64&os_arch=arm64&prod=chromecrx&prodchannel=&prodversion=143.0.7499.111&lang=en-US&acceptformat=crx3,puff&x=id%3Dlajondecmobodlejlcjllhojikagldgd%26installsource%3Dondemand%26uc&authuser=0",
    "httpVersion": "2",
    "cookies": [],
    "headers": [],
    "queryString": [],
    "postData": null,
    "headersSize": 4075,
    "bodySize": 0,
    "comment": "http(s) MITM egress client"
}"##,
    );

    let resp = client.serve(req).await.unwrap();

    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "expected update2 response to be allowed (2xx/3xx), got {}",
        resp.status()
    );
}

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
