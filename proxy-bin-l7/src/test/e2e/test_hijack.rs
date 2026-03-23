use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use safechain_proxy_lib::http::service::hijack::HIJACK_DOMAIN;

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn test_hijack_https_failure_no_trust() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_fail_fast();

    assert!(
        client
            .get(format!("https://{HIJACK_DOMAIN}"))
            .extension(runtime.http_proxy_addr())
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_hijack_http() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    for path in ["", "/", "/ping"] {
        let resp = client
            .get(format!("http://{HIJACK_DOMAIN}{path}"))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        if path == "/ping" {
            continue;
        }

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("<!doctype html>"));
        assert!(payload.contains("Aikido"));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_hijack_http_over_sock5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    for path in ["", "/", "/ping"] {
        let resp = client
            .get(format!("http://{HIJACK_DOMAIN}{path}"))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        if path == "/ping" {
            continue;
        }

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("<!doctype html>"));
        assert!(payload.contains("Aikido"));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_hijack_http_with_username() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy_and_username("test").await;

    for path in ["", "/", "/ping"] {
        let resp = client
            .get(format!("http://{HIJACK_DOMAIN}{path}"))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        if path == "/ping" {
            continue;
        }

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("<!doctype html>"));
        assert!(payload.contains("Aikido"));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_hijack_https() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    for path in ["", "/", "/ping"] {
        let resp = client
            .get(format!("https://{HIJACK_DOMAIN}{path}"))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        if path == "/ping" {
            continue;
        }

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("<!doctype html>"));
        assert!(payload.contains("Aikido"));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_hijack_https_over_socks5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    for path in ["", "/", "/ping"] {
        let resp = client
            .get(format!("https://{HIJACK_DOMAIN}{path}"))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        if path == "/ping" {
            continue;
        }

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("<!doctype html>"));
        assert!(payload.contains("Aikido"));
    }
}
