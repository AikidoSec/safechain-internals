use rama::{
    Service,
    error::OpaqueError,
    http::{BodyExtractExt, Request, Response, StatusCode, service::client::HttpClientExt as _},
    net::{Protocol, address::ProxyAddress},
};

use crate::test::e2e;

pub(super) async fn test_http_example_com_proxy_http(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
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

pub(super) async fn test_http_example_com_proxy_socks5(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
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

pub(super) async fn test_https_example_com_proxy_http(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
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

pub(super) async fn test_https_example_com_proxy_socks5(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
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
