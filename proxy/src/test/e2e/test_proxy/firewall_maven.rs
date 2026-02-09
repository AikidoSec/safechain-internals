use rama::{
    http::{StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

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

    // Same package but different version (1.0.0 instead of 1.0.0) should be allowed
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/2.0.0/malicious-lib-2.0.0.jar")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, resp.status());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_maven_pom_file_malware_blocked() {
    let runtime = e2e::runtime::get().await;
    let client = runtime.client_with_http_proxy().await;

    // POM file for malware package should also be blocked
    let resp = client
        .get("https://repo.maven.apache.org/maven2/org/example/malicious-lib/1.0.0/malicious-lib-1.0.0.pom")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::FORBIDDEN, resp.status());
}
