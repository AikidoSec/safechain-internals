use rama::{
    Service,
    error::OpaqueError,
    http::{Request, Response, StatusCode, service::client::HttpClientExt as _},
    net::{Protocol, address::ProxyAddress},
};

use crate::test::e2e;

pub(super) async fn test_pypi_http_metadata_request_allowed(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://pypi.org/pypi/safe-chain-pi-test/json")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

pub(super) async fn test_pypi_http_simple_metadata_allowed(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://pypi.org/simple/safe-chain-pi-test/")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

pub(super) async fn test_pypi_http_malware_wheel_blocked(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_pypi_http_malware_sdist_blocked(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://files.pythonhosted.org/packages/source/s/safe-chain-pi-test/safe-chain-pi-test-0.1.0.tar.gz")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_pypi_http_safe_package_allowed(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("http://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

pub(super) async fn test_pypi_https_metadata_request_allowed(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://pypi.org/pypi/safe-chain-pi-test/json")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

pub(super) async fn test_pypi_https_malware_wheel_blocked(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

pub(super) async fn test_pypi_https_safe_package_allowed(
    runtime: &e2e::runtime::Runtime,
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
) {
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .extension(ProxyAddress {
            protocol: Some(Protocol::HTTP),
            address: runtime.proxy_addr().into(),
            credential: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
