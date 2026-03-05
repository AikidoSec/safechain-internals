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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_http_sdist_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Test sdist with hyphens (sdist can use hyphens per PyPI conventions)
    let resp = client
        .get("http://files.pythonhosted.org/packages/source/s/safe-chain-pi-test/safe-chain-pi-test-0.1.0.tar.gz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_http_sdist_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("http://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_sdist_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Test sdist with underscores (also valid)
    let resp = client
        .get("https://files.pythonhosted.org/packages/source/s/safe_chain_pi_test/safe_chain_pi_test-0.1.0.tar.gz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_sdist_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_allowed_by_endpoint_policy_exception() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-allow-requests-pypi", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-pypi", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "requests" is not malware, but block_all_installs blocks it
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-reject-requests-pypi", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "requests" is in rejected_packages — blocked even though it's not malware
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}
