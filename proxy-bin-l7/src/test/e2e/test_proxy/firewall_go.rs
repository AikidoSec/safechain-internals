use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_GOLANG_MODULE_NAME, FRESH_GOLANG_MODULE_VERSION},
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // github.com/gorilla/mux v1.8.0 is listed as malware in the mock list
    let resp = client
        .get("https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.0.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_safe_package_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // gin is not in the malware list
    let resp = client
        .get("https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_non_zip_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // .mod files are not intercepted — only .zip downloads are blocked
    let resp = client
        .get("https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.0.mod")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_list_endpoint_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // /@v/list is metadata, not intercepted
    let resp = client
        .get("https://proxy.golang.org/github.com/gorilla/mux/@v/list")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_allows_different_version() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // gorilla/mux v1.7.0 is not in the malware list (only v1.8.0 is)
    let resp = client
        .get("https://proxy.golang.org/github.com/gorilla/mux/@v/v1.7.0.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_package_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-gorilla-mux-golang",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // gorilla/mux v1.8.0 is malware, but the allowed_packages exception overrides the malware check
    let resp = client
        .get("https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.0.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-golang", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // gin is not malware, but block_all_installs blocks it
    let resp = client
        .get("https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-reject-gin-golang", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // gin is in rejected_packages — blocked even though it's not malware
    let resp = client
        .get("https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_package_blocked_by_endpoint_policy_request_installs() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-request-installs-golang",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // gin is not malware, but request_installs requires approval for all installs
    let resp = client
        .get("https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.zip")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let module = FRESH_GOLANG_MODULE_NAME;
    let ver = FRESH_GOLANG_MODULE_VERSION;
    let url = format!("https://proxy.golang.org/{module}/@v/v{ver}.zip");

    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("24 hours") || payload.to_lowercase().contains("vetted"),
        "expected blocked response to mention 24-hour vetting, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_go_new_package_not_blocked_via_policy_cutoff() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-golang",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let module = FRESH_GOLANG_MODULE_NAME;
    let ver = FRESH_GOLANG_MODULE_VERSION;
    let url = format!("https://proxy.golang.org/{module}/@v/v{ver}.zip");

    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
