use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_NPM_PACKAGE_NAME, FRESH_NPM_PACKAGE_VERSION},
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-safe-chain-test-npm",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "safe-chain-test" is malware, but the allowed_packages exception overrides the malware check.
    let resp = client
        .get("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-npm", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "lodash" is not malware, but block_all_installs blocks it.
    let resp = client
        .get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-reject-lodash-npm", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "lodash" is in rejected_packages — blocked even though it's not malware.
    let resp = client
        .get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_blocked_by_endpoint_policy_request_installs() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-request-installs-npm", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "lodash" is not malware, but request_installs requires approval for all installs.
    let resp = client
        .get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_npm_https_package_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // fresh-npm-package is in the released packages list (released far in the future
    // relative to a 48h cutoff) and is NOT in the malware list — should be blocked as new package.
    let url = format!(
        "https://registry.npmjs.org/{FRESH_NPM_PACKAGE_NAME}/-/{FRESH_NPM_PACKAGE_NAME}-{FRESH_NPM_PACKAGE_VERSION}.tgz"
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
async fn test_npm_https_package_new_package_not_blocked_via_policy_cutoff() {
    // The policy sets minimum_allowed_age_timestamp far in the future, making the
    // cutoff larger than our test entry's released_on (year ~2255) — so the package is no
    // longer considered "recent" and is allowed through.
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-npm",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://registry.npmjs.org/{FRESH_NPM_PACKAGE_NAME}/-/{FRESH_NPM_PACKAGE_NAME}-{FRESH_NPM_PACKAGE_VERSION}.tgz"
    );
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
