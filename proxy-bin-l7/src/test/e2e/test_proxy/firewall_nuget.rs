use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_NUGET_PACKAGE_NAME, FRESH_NUGET_PACKAGE_VERSION},
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_api_v3_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/safechaintest/0.0.1-security/safechaintest.0.0.1-security.nupkg?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_api_v2_https_package_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://www.nuget.org/api/v2/package/safechaintest/0.0.1-security?a=b")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_api_v2_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.4/newtonsoft.json.13.0.4.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_api_v3_https_package_ok() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://www.nuget.org/api/v2/package/newtonsoft.json/13.0.4")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_package_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-safechaintest-nuget",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "safechaintest" is malware, but the allowed_packages exception overrides the malware check.
    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/safechaintest/0.0.1-security/safechaintest.0.0.1-security.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-nuget", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "newtonsoft.json" is not malware, but block_all_installs blocks it.
    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.4/newtonsoft.json.13.0.4.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-reject-newtonsoft-nuget",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "newtonsoft.json" is in rejected_packages — blocked even though it's not malware.
    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.4/newtonsoft.json.13.0.4.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_package_blocked_by_endpoint_policy_request_installs() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-request-installs-nuget",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "newtonsoft.json" is not malware, but request_installs requires approval for all installs.
    let resp = client
        .get("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.4/newtonsoft.json.13.0.4.nupkg")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://api.nuget.org/v3-flatcontainer/{FRESH_NUGET_PACKAGE_NAME}/{FRESH_NUGET_PACKAGE_VERSION}/{FRESH_NUGET_PACKAGE_NAME}.{FRESH_NUGET_PACKAGE_VERSION}.nupkg"
    );
    let resp = client.get(&url).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains(
            "blocked because the package was published less than the configured minimum package"
        ),
        "expected blocked response to mention package released too recently, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_nuget_new_package_not_blocked_via_policy_cutoff() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-nuget",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!(
        "https://api.nuget.org/v3-flatcontainer/{FRESH_NUGET_PACKAGE_NAME}/{FRESH_NUGET_PACKAGE_VERSION}/{FRESH_NUGET_PACKAGE_NAME}.{FRESH_NUGET_PACKAGE_VERSION}.nupkg"
    );
    let resp = client.get(&url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
