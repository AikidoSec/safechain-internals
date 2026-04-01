use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::{
    client::mock_server::malware_list::{FRESH_MAVEN_PACKAGE_NAME, FRESH_MAVEN_PACKAGE_VERSION},
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_central_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Block malware entry: org.example:malicious-lib version 1.0.0
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/1.0.0/malicious-lib-1.0.0.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_central_safe_package_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Safe package not in malware list
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/junit/junit/4.13.2/junit-4.13.2.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_apache_mirror_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Block malware entry from Apache mirror: org.apache:dangerous-commons version 2.5.1
    let resp = client
        .get("https://repository.apache.org/content/repositories/releases/org/apache/dangerous-commons/2.5.1/dangerous-commons-2.5.1.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_allows_different_version() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // Same package but different version (1.0.0 instead of 2.0.0) should be allowed
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/2.0.0/malicious-lib-2.0.0.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_pom_file_allowed() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // POM files are metadata and are not blocked
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/1.0.0/malicious-lib-1.0.0.pom")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_package_allowed_by_endpoint_policy_exception() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-allow-malicious-lib-maven",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "org.example:malicious-lib" is malware, but the allowed_packages exception overrides the malware check.
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/1.0.0/malicious-lib-1.0.0.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_package_blocked_by_endpoint_policy_block_all() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-block-maven", "mock_device", &[]).await;
    let client = runtime.client_with_http_proxy().await;

    // "org.junit:junit" is not malware, but block_all_installs blocks it.
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/junit/junit/4.13.2/junit-4.13.2.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_package_blocked_by_endpoint_policy_rejected_package() {
    let runtime =
        e2e::runtime::spawn_with_agent_identity("policy-reject-junit-maven", "mock_device", &[])
            .await;
    let client = runtime.client_with_http_proxy().await;

    // "org.junit:junit" is in rejected_packages — blocked even though it's not malware.
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/junit/junit/4.13.2/junit-4.13.2.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_package_blocked_by_endpoint_policy_request_installs() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-request-installs-maven",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    // "org.junit:junit" is not malware, but request_installs requires approval for all installs.
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/junit/junit/4.13.2/junit-4.13.2.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_new_package_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // com.example:fresh-artifact → group path com/example, artifact fresh-artifact
    let (group_artifact, artifact_id) = FRESH_MAVEN_PACKAGE_NAME.split_once(':').unwrap();
    let group_path = group_artifact.replace('.', "/");
    let ver = FRESH_MAVEN_PACKAGE_VERSION;
    let url = format!(
        "https://repo.maven.apache.org/maven2/{group_path}/{artifact_id}/{ver}/{artifact_id}-{ver}.jar"
    );

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
async fn test_maven_new_package_not_blocked_via_policy_cutoff() {
    let runtime = e2e::runtime::spawn_with_agent_identity(
        "policy-bypass-new-package-maven",
        "mock_device",
        &[],
    )
    .await;
    let client = runtime.client_with_http_proxy().await;

    let (group_artifact, artifact_id) = FRESH_MAVEN_PACKAGE_NAME.split_once(':').unwrap();
    let group_path = group_artifact.replace('.', "/");
    let ver = FRESH_MAVEN_PACKAGE_VERSION;
    let url = format!(
        "https://repo.maven.apache.org/maven2/{group_path}/{artifact_id}/{ver}/{artifact_id}-{ver}.jar"
    );

    let resp = client.get(url).send().await.unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}
