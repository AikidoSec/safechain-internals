use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_RUBY_GEM_NAME, FRESH_RUBY_GEM_VERSION},
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://rubygems.org/gems/safe-chain-ruby-test-1.0.0.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_http_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("http://rubygems.org/gems/safe-chain-ruby-test-1.0.0.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://rubygems.org/gems/rake-13.4.2.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_with_platform_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Platform suffix should be stripped before lookup
    let resp = client
        .get("https://rubygems.org/gems/safe-chain-ruby-test-1.0.0-x86_64-linux.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_non_gem_path_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // API/metadata paths must not be blocked
    let resp = client
        .get("https://rubygems.org/api/v1/gems/rake.json")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-safe-chain-ruby-test",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "safe-chain-ruby-test" is malware, but the allowed_packages exception overrides it.
    let resp = client
        .get("https://rubygems.org/gems/safe-chain-ruby-test-1.0.0.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-ruby", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "rake" is not malware, but block_all_installs blocks it.
    let resp = client
        .get("https://rubygems.org/gems/rake-13.4.2.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-reject-rake-ruby", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "rake" is in rejected_packages — blocked even though it's not malware.
    let resp = client
        .get("https://rubygems.org/gems/rake-13.4.2.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_blocked_by_endpoint_policy_request_installs() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-request-installs-ruby", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "rake" is not malware, but request_installs requires approval for all installs.
    let resp = client
        .get("https://rubygems.org/gems/rake-13.4.2.gem")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_ruby_https_package_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // fresh-ruby-gem is in the released packages list (released far in the future
    // relative to a 48h cutoff) and is NOT in the malware list — should be blocked as new package.
    let url = format!(
        "https://rubygems.org/gems/{name}-{ver}.gem",
        name = FRESH_RUBY_GEM_NAME,
        ver = FRESH_RUBY_GEM_VERSION,
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
async fn test_ruby_https_package_new_package_not_blocked_via_policy_cutoff() {
    // The policy sets minimum_allowed_age_timestamp far in the future (year ~2286), making the
    // cutoff larger than our test entry's released_on (year ~2255) — so the package is no
    // longer considered "recent" and is allowed through.
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-ruby",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://rubygems.org/gems/{name}-{ver}.gem",
        name = FRESH_RUBY_GEM_NAME,
        ver = FRESH_RUBY_GEM_VERSION,
    );
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
