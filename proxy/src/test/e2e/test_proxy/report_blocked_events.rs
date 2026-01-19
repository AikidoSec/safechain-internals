use rama::{
    http::{BodyExtractExt as _, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
};

use crate::test::e2e;

#[tokio::test]
#[tracing_test::traced_test]
async fn test_report_blocked_events_posts_json_to_endpoint() {
    // Use the in-crate mock egress server to capture POSTs made by the notifier.
    let capture_client = crate::client::new_web_client().unwrap();

    // Ensure test isolation in case other tests already hit this endpoint.
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

    // Poll until the notifier worker has had a chance to POST to the capture endpoint.
    let mut captured: Vec<serde_json::Value> = Vec::new();
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

    let first = &captured[0];
    let obj = first
        .as_object()
        .expect("blocked-event notification should be a JSON object");

    assert!(obj.contains_key("ts_ms"));
    assert!(obj.contains_key("artifact"));

    let artifact = obj
        .get("artifact")
        .and_then(|v| v.as_object())
        .expect("artifact should be a JSON object");

    let product = artifact
        .get("product")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let identifier = artifact
        .get("identifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    tracing::info!(product, identifier, "captured blocked-event notification");

    assert_eq!("npm", product);
    assert!(identifier.contains("safe-chain-test"));
}
