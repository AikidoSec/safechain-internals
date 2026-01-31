use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::firewall::events::BlockedEvent;
use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_blocked_events_posts_json_to_endpoint() {
    let capture_client = crate::client::new_web_client().unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/blocked-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    // Spawn a dedicated proxy instance so we can pass custom CLI flags.
    let runtime = e2e::runtime::spawn_with_args(&[
        "--reporting-endpoint",
        "http://assert-test.internal/blocked-events",
    ])
    .await;

    // Trigger a block, which should cause the notifier to emit one event.
    let client = runtime.client_with_http_proxy().await;
    let resp = client
        .get("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::FORBIDDEN, resp.status());

    let mut captured: Vec<BlockedEvent> = Vec::new();
    for _ in 0..40 {
        let resp = capture_client
            .get("http://assert-test.internal/blocked-events/take")
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
        "expected at least one blocked-event notification to be captured"
    );

    // We currently expect at least one notification for the blocked request.
    let first = captured
        .first()
        .expect("expected at least one blocked-event notification");

    let product = first.artifact.product.as_str();
    let identifier = first.artifact.identifier.as_str();

    tracing::info!(product, identifier, "captured blocked-event notification");

    assert_eq!("npm", product);
    assert!(identifier.contains("safe-chain-test"));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_blocked_events_dedupes_same_artifact_within_30s() {
    let capture_client = crate::client::new_web_client().unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/blocked-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    let runtime = e2e::runtime::spawn_with_args(&[
        "--reporting-endpoint",
        "http://assert-test.internal/blocked-events",
    ])
    .await;

    let client = runtime.client_with_http_proxy().await;
    for _ in 0..2 {
        let resp = client
            .get("https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz")
            .send()
            .await
            .unwrap();
        assert_eq!(StatusCode::FORBIDDEN, resp.status());
    }

    let mut captured: Vec<BlockedEvent> = Vec::new();
    for _ in 0..40 {
        let resp = capture_client
            .get("http://assert-test.internal/blocked-events/take")
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

    assert_eq!(
        1,
        captured.len(),
        "expected a single blocked-event notification after two identical blocked requests"
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_blocked_events_does_not_dedupe_different_versions_within_30s() {
    let capture_client = crate::client::new_web_client().unwrap();

    let resp = capture_client
        .get("http://assert-test.internal/blocked-events/clear")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::NO_CONTENT, resp.status());

    let runtime = e2e::runtime::spawn_with_args(&[
        "--reporting-endpoint",
        "http://assert-test.internal/blocked-events",
    ])
    .await;

    let client = runtime.client_with_http_proxy().await;

    // Two distinct package versions should yield two distinct blocked-event notifications.
    for url in [
        "https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz",
        "https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.2-security.tgz",
    ] {
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(StatusCode::FORBIDDEN, resp.status());
    }

    let mut captured: Vec<BlockedEvent> = Vec::new();
    for _ in 0..60 {
        let resp = capture_client
            .get("http://assert-test.internal/blocked-events/take")
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());
        captured = resp.try_into_json().await.unwrap();

        if captured.len() >= 2 {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        2,
        captured.len(),
        "expected two blocked-event notifications for two different versions"
    );
}
