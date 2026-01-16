use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
    tls::boring::core::x509::X509,
};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{firewall::events::BlockedEventsResponse, test::e2e};

mod http {
    use super::*;

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_root() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let payload = client
            .get(format!("http://{}", runtime.meta_socket_addr()))
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();

        assert!(payload.contains("<!doctype html>"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_ping() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("http://{}/ping", runtime.meta_socket_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        assert_eq!("pong", payload);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_ca() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("http://{}/ca", runtime.meta_socket_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        // simple test to ensure a valid cert is returned
        let _ = X509::from_pem(payload.as_bytes()).unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_pac() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("http://{}/pac", runtime.meta_socket_addr()))
            .send()
            .await
            .unwrap();

        // should only be available over tls
        assert_eq!(StatusCode::NOT_FOUND, resp.status());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_events_reports_blocked_pypi_download() {
        let runtime = e2e::runtime::get().await;
        let proxy_client = runtime.client_with_http_proxy().await;
        let meta_client = runtime.client_with_ca_trust().await;

        let start_ms = now_unix_ms();

        let resp = proxy_client
            .get("http://files.pythonhosted.org/packages/abc/def/safe_chain_pi_test-0.1.0-py3-none-any.whl")
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, resp.status());

        let end_ms = now_unix_ms();

        let query_start = start_ms.saturating_sub(2_000);
        let query_end = end_ms.saturating_add(2_000);

        let payload: BlockedEventsResponse = meta_client
            .get(format!(
                "http://{}/events?since_unix_ms={query_start}&until_unix_ms={query_end}",
                runtime.meta_socket_addr()
            ))
            .send()
            .await
            .unwrap()
            .try_into_json()
            .await
            .unwrap();

        assert!(
            payload.events.iter().any(|e| e.product == "PyPI"),
            "expected at least one PyPI blocked event in window; got: {payload:?}"
        );
    }
}

mod https {
    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore]
    async fn test_endpoint_root_failure() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_fail_fast();

        assert!(
            client
                .get(format!("https://{}", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore]
    async fn test_endpoint_ping_failure() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_fail_fast();

        assert!(
            client
                .get(format!("https://{}/ping", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore]
    async fn test_endpoint_ca_failure() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_fail_fast();

        assert!(
            client
                .get(format!("https://{}/ca", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore]
    async fn test_endpoint_pac_failure() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_fail_fast();

        assert!(
            client
                .get(format!("https://{}/pac", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_root() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let payload = client
            .get(format!("https://{}", runtime.meta_domain_addr()))
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();

        assert!(payload.contains("<!doctype html>"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_ping() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("https://{}/ping", runtime.meta_domain_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        assert_eq!("pong", payload);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_ca() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("https://{}/ca", runtime.meta_domain_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        // simple test to ensure a valid cert is returned
        let _ = X509::from_pem(payload.as_bytes()).unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_pac() {
        let runtime = e2e::runtime::get().await;
        let client = runtime.client_with_ca_trust().await;

        let resp = client
            .get(format!("https://{}/pac", runtime.meta_domain_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        assert!(payload.contains("function FindProxyForURL(url, host) {"));
    }
}
