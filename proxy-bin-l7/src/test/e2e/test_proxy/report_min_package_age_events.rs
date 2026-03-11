use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use safechain_proxy_lib::http::firewall::events::MinPackageAgeEvent;

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_min_package_age_events_posts_json_to_endpoint() {
    let capture_client = crate::client::new_web_client().unwrap();

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
