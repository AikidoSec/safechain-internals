use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_PYPI_PACKAGE_NAME, FRESH_PYPI_PACKAGE_VERSION},
    test::e2e,
};

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
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-safe-chain-pi-test-pypi",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "safe-chain-pi-test" is malware, but the allowed_packages exception overrides the malware check.
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_blocked_by_endpoint_policy_request_installs() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-request-installs-pypi", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "requests" is not malware, but request_installs requires approval for all installs.
    let resp = client
        .get("https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // brand-new-pypi-pkg is in the released packages list (released far in the future
    // relative to a 48h cutoff) and is NOT in the malware list — should be blocked as new package.
    let url = format!(
        "https://files.pythonhosted.org/packages/abc/def/{name}-{ver}-py3-none-any.whl",
        name = FRESH_PYPI_PACKAGE_NAME.replace('-', "_"),
        ver = FRESH_PYPI_PACKAGE_VERSION,
    );
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("vetted")
            || payload.to_lowercase().contains("minimum package"),
        "expected blocked response to mention vetting or minimum package age, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_pypi_https_package_new_package_not_blocked_via_policy_cutoff() {
    // The policy sets minimum_allowed_age_timestamp far in the future, making the
    // cutoff larger than our test entry's released_on (year ~2255) — so the package is no
    // longer considered "recent" and is allowed through.
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-pypi",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://files.pythonhosted.org/packages/abc/def/{name}-{ver}-py3-none-any.whl",
        name = FRESH_PYPI_PACKAGE_NAME.replace('-', "_"),
        ver = FRESH_PYPI_PACKAGE_VERSION,
    );
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
