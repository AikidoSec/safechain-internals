use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{client::mock_server::malware_list::FRESH_SKILLS_SH_REPO, test::e2e};

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

#[tokio::test]
#[tracing_test::traced_test]
async fn test_github_git_upload_pack_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // freshowner/freshrepo is in the released packages list (released far in the future
    // relative to a 48h cutoff) and is NOT in the malware list — should be blocked as new package.
    let url = format!("https://github.com/{FRESH_SKILLS_SH_REPO}/git-upload-pack");
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
async fn test_github_git_upload_pack_new_package_not_blocked_via_policy_cutoff() {
    // The policy sets minimum_allowed_age_timestamp far in the future (year ~2286), making the
    // cutoff larger than our test entry's released_on (year ~2255) — so the repo is no
    // longer considered "recent" and is allowed through.
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-skills-sh",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let url = format!("https://github.com/{FRESH_SKILLS_SH_REPO}/git-upload-pack");
    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
