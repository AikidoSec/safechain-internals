use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_git_upload_pack_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/asklokesh/claudeskill-loki-mode/git-upload-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let payload = resp.try_into_string().await.unwrap();
    assert!(
        payload.to_lowercase().contains("malware"),
        "expected blocked response to mention malware, got: {payload}"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_git_upload_pack_dotgit_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/asklokesh/claudeskill-loki-mode.git/git-upload-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_info_refs_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/asklokesh/claudeskill-loki-mode/info/refs?service=git-upload-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_git_receive_pack_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/asklokesh/claudeskill-loki-mode/git-receive-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_case_insensitive_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/AskLokesh/ClaudeSkill-Loki-Mode/git-upload-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_safe_repo_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    let resp = client
        .get("https://github.com/octocat/Hello-World.git/info/refs?service=git-upload-pack")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
