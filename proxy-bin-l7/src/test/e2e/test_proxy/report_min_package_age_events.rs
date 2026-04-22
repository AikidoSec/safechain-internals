use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    rt::Executor,
    telemetry::tracing,
};

use safechain_proxy_lib::http::firewall::events::MinPackageAgeEvent;

use crate::{
    client::mock_server::malware_list::{
        FRESH_PYPI_PACKAGE_NAME, FRESH_PYPI_PACKAGE_VERSION, FRESH_VSCODE_EXTENSION_NAME,
        FRESH_VSCODE_EXTENSION_PUBLISHER, FRESH_VSCODE_EXTENSION_VERSION,
    },
    test::e2e,
};

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_min_package_age_events_posts_json_to_endpoint() {
    let capture_client = crate::client::new_http_client_for_internal(Executor::default()).unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/min-package-age-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    let runtime =
        e2e::runtime::spawn_with_args(&["--reporting-endpoint", "http://assert-test.internal"])
            .await;

    // Request the npm package info for our test package. The proxy will detect
    // version 2.0.0 as too recent and suppress it, firing a MinPackageAgeEvent.
    let client = runtime.client_with_http_proxy().await;
    let resp = client
        .get("https://registry.npmjs.org/min-age-test-package")
        .header("accept", "application/vnd.npm.install-v1+json")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp.status());

    let mut captured: Vec<MinPackageAgeEvent> = Vec::new();
    for _ in 0..40 {
        let resp = capture_client
            .get("http://assert-test.internal/min-package-age-events/take")
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());
        captured = resp.try_into_json().await.unwrap();

        if !captured.is_empty() {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        !captured.is_empty(),
        "expected at least one min-package-age event notification to be captured"
    );

    let first = captured.first().unwrap();

    tracing::info!(
        product = %first.artifact.product,
        identifier = %first.artifact.identifier,
        suppressed_versions = ?first.suppressed_versions,
        "captured min-package-age event"
    );

    assert_eq!("npm", first.artifact.product.as_str());
    assert_eq!("min-age-test-package", first.artifact.identifier.as_str());
    assert_eq!(1, first.suppressed_versions.len());
    assert_eq!("2.0.0", first.suppressed_versions[0].to_string());
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_pypi_min_package_age_events_posts_json_to_endpoint() {
    let capture_client = crate::client::new_http_client_for_internal(Executor::default()).unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/min-package-age-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    let runtime =
        e2e::runtime::spawn_with_args(&["--reporting-endpoint", "http://assert-test.internal"])
            .await;

    let client = runtime.client_with_http_proxy().await;
    let resp = client
        .get(format!(
            "https://pypi.org/pypi/{FRESH_PYPI_PACKAGE_NAME}/json"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp.status());

    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    assert_eq!(body["info"]["version"], serde_json::json!("0.9.0"));
    assert!(body["releases"].get(FRESH_PYPI_PACKAGE_VERSION).is_none());
    assert!(body["releases"].get("0.9.0").is_some());

    let mut captured: Vec<MinPackageAgeEvent> = Vec::new();
    for _ in 0..40 {
        let resp = capture_client
            .get("http://assert-test.internal/min-package-age-events/take")
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());
        captured = resp.try_into_json().await.unwrap();

        if !captured.is_empty() {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        !captured.is_empty(),
        "expected at least one min-package-age event notification to be captured"
    );

    let first = captured.first().unwrap();

    assert_eq!("pypi", first.artifact.product.as_str());
    assert_eq!(FRESH_PYPI_PACKAGE_NAME, first.artifact.identifier.as_str());
    assert_eq!(1, first.suppressed_versions.len());
    assert_eq!(
        FRESH_PYPI_PACKAGE_VERSION,
        first.suppressed_versions[0].to_string()
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_vscode_min_package_age_events_posts_json_to_endpoint() {
    let capture_client = crate::client::new_http_client_for_internal(Executor::default()).unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/min-package-age-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    let runtime =
        e2e::runtime::spawn_with_args(&["--reporting-endpoint", "http://assert-test.internal"])
            .await;

    let client = runtime.client_with_http_proxy().await;
    let resp = client
        .post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery")
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp.status());

    let body: serde_json::Value = resp.try_into_json().await.unwrap();
    let versions = &body["results"][0]["extensions"][0]["versions"];
    let version_strings: Vec<&str> = versions
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["version"].as_str())
        .collect();
    assert!(
        !version_strings.contains(&FRESH_VSCODE_EXTENSION_VERSION),
        "fresh version should have been suppressed from the response"
    );
    assert!(
        version_strings.contains(&"0.9.0"),
        "old stable version should remain in the response"
    );

    let mut captured: Vec<MinPackageAgeEvent> = Vec::new();
    for _ in 0..40 {
        let resp = capture_client
            .get("http://assert-test.internal/min-package-age-events/take")
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());
        captured = resp.try_into_json().await.unwrap();

        if !captured.is_empty() {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        !captured.is_empty(),
        "expected at least one min-package-age event notification to be captured"
    );

    let first = captured.first().unwrap();

    tracing::info!(
        product = %first.artifact.product,
        identifier = %first.artifact.identifier,
        suppressed_versions = ?first.suppressed_versions,
        "captured vscode min-package-age event"
    );

    let expected_id = format!("{FRESH_VSCODE_EXTENSION_PUBLISHER}.{FRESH_VSCODE_EXTENSION_NAME}");
    assert_eq!("vscode", first.artifact.product.as_str());
    assert_eq!(expected_id, first.artifact.identifier.as_str());
    assert_eq!(1, first.suppressed_versions.len());
    assert_eq!(
        FRESH_VSCODE_EXTENSION_VERSION,
        first.suppressed_versions[0].to_string()
    );
}
