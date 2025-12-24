use rama::{
    Service,
    error::OpaqueError,
    http::{Request, Response, StatusCode, service::client::HttpClientExt as _},
};

pub(super) async fn test_npm_https_package_malware_blocked(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_npm_https_package_ok(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
