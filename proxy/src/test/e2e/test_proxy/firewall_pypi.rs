use rama::{
    http::{StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_http_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("http://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_http_package_malware_blocked_underscore_variant() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Per PEP 427, wheels always use underscores in the distribution name
    let resp = client
        .get("http://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_http_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("http://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_malware_blocked_underscore_variant() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Per PEP 427, wheels always use underscores in the distribution name
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
