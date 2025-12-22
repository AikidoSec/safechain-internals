use rama::{
    Service,
    error::OpaqueError,
    http::{BodyExtractExt, Request, Response, StatusCode, service::client::HttpClientExt as _},
    net::{
        Protocol,
        address::ProxyAddress,
        user::{ProxyCredential, credentials::basic},
    },
    telemetry::tracing,
};

use crate::{server::connectivity::CONNECTIVITY_DOMAIN, test::e2e};

#[tokio::test]
#[tracing_test::traced_test]
#[ignore]
async fn test_connectivity_failure() {
    let runtime = e2e::runtime::get().await;
    let client = e2e::client::new_web_client(&runtime, false).await;

    test_connectivity_failure_no_proxy(&runtime, &client).await;
    test_connectivity_https_failure_no_trust(&runtime, &client).await;
}

async fn test_connectivity_failure_no_proxy(
    _runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    assert!(
        client
            .get(format!("http://{CONNECTIVITY_DOMAIN}"))
            .send()
            .await
            .is_err()
    );
}

async fn test_connectivity_https_failure_no_trust(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    assert!(
        client
            .get(format!("https://{CONNECTIVITY_DOMAIN}"))
            .extension(ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: runtime.proxy_addr().into(),
                credential: None,
            })
            .send()
            .await
            .is_err()
    );
}

pub(super) async fn test_connectivity(runtime: &e2e::runtime::Runtime) {
    let client = e2e::client::new_web_client(runtime, true).await;

    tokio::join!(
        test_connectivity_http(runtime, &client),
        test_connectivity_http_over_sock5(runtime, &client),
        test_connectivity_http_with_username_labels(runtime, &client),
        test_connectivity_https(runtime, &client),
        test_connectivity_https_over_socks5(runtime, &client),
    );
}

async fn test_connectivity_http(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
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

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

async fn test_connectivity_http_over_sock5(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
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

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

async fn test_connectivity_http_with_username_labels(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get(format!("http://{CONNECTIVITY_DOMAIN}"))
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: Some(ProxyCredential::Basic(basic!(
                "test-foo-min_pkg_age-1h_30m"
            ))),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

async fn test_connectivity_https(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get(format!("https://{CONNECTIVITY_DOMAIN}"))
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

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}

async fn test_connectivity_https_over_socks5(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get(format!("https://{CONNECTIVITY_DOMAIN}"))
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

    assert!(payload.contains("<!doctype html>"));
    assert!(payload.contains(crate::utils::env::project_name()));
}
