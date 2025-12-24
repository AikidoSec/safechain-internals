use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{server::connectivity::CONNECTIVITY_DOMAIN, test::e2e};

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn test_connectivity_failure_no_proxy() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_fail_fast();

    assert!(
        client
            .get(format!("http://{CONNECTIVITY_DOMAIN}"))
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn test_connectivity_https_failure_no_trust() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_fail_fast();

    assert!(
        client
            .get(format!("https://{CONNECTIVITY_DOMAIN}"))
            .extension(runtime.http_proxy_addr())
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_connectivity_http() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_connectivity_http_over_sock5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_connectivity_http_with_username_labels() {
    let runtime = e2e::runtime::get().await;
    let client = runtime
        .client_with_http_proxy_and_username("test-foo-min_pkg_age-1h_30m")
        .await;

    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_connectivity_https() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get(format!("https://{CONNECTIVITY_DOMAIN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_connectivity_https_over_socks5() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_socks5_proxy().await;

    let resp = client
        .get(format!("https://{CONNECTIVITY_DOMAIN}"))
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}
