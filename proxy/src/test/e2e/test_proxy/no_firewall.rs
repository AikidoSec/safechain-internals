use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_http_example_com_proxy_http() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client.get("http://example.com").send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_http_example_com_proxy_socks5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    let resp = client.get("http://example.com").send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_https_example_com_proxy_http() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client.get("https://example.com").send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_https_example_com_proxy_socks5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    let resp = client.get("https://example.com").send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}
