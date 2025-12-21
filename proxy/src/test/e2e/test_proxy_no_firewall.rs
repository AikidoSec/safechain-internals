use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    net::{
        Protocol,
        address::ProxyAddress,
        user::{ProxyCredential, credentials::basic},
    },
    telemetry::tracing,
    tls::boring::core::x509::X509,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_example_com_no_proxy_http() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, false).await;

    let resp = client.get("http://example.com").send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_http_example_com_proxy_http() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, false).await;

    let resp = client
        .get("http://example.com")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_http_example_com_proxy_socks5() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, false).await;

    let resp = client
        .get("http://example.com")
        .extension(ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_https_example_com_proxy_http() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, true).await;

    let resp = client
        .get("https://example.com")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_https_example_com_proxy_socks5() {
    let runtime = e2e::runtime::get().await;

    let client = e2e::client::new_web_client(&runtime, true).await;

    let resp = client
        .get("https://example.com")
        .extension(ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}
