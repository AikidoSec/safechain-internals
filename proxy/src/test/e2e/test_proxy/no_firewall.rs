use rama::{
    Service,
    error::OpaqueError,
    http::{BodyExtractExt, Request, Response, StatusCode, service::client::HttpClientExt as _},
};

use crate::test::e2e;

pub(super) async fn test_http_example_com_proxy_http(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client.get("http://example.com").send().await.unwrap();

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
        .extension(runtime.socks5_proxy_addr())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}

pub(super) async fn test_https_example_com_proxy_http(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client.get("https://example.com").send().await.unwrap();

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
        .extension(runtime.socks5_proxy_addr())
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());

    let payload = resp.try_into_string().await.unwrap();

    assert!(payload.contains("example.com"), "payload: {payload}");
}
