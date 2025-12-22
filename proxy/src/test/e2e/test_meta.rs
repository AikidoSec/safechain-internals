use rama::{
    http::{BodyExtractExt, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
    tls::boring::core::x509::X509,
};

use crate::test::e2e;

mod http {
    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_endpoint_root() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, false).await;
        let payload = client
            .get(format!("http://{}", runtime.meta_addr()))
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

        let client = e2e::client::new_web_client(&runtime, false).await;

        let resp = client
            .get(format!("http://{}/ping", runtime.meta_addr()))
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

        let client = e2e::client::new_web_client(&runtime, false).await;

        let resp = client
            .get(format!("http://{}/ca", runtime.meta_addr()))
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

        let client = e2e::client::new_web_client(&runtime, false).await;

        let resp = client
            .get(format!("http://{}/pac", runtime.meta_addr()))
            .send()
            .await
            .unwrap();

        // should only be available over tls
        assert_eq!(StatusCode::NOT_FOUND, resp.status());
    }
}

mod https {
    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore]
    async fn test_endpoint_root_failure() {
        let runtime = e2e::runtime::get().await;
        let client = e2e::client::new_web_client(&runtime, false).await;

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
    async fn test_endpoint_root() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, true).await;
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
    #[ignore]
    async fn test_endpoint_ping_failure() {
        let runtime = e2e::runtime::get().await;
        let client = e2e::client::new_web_client(&runtime, false).await;

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
    async fn test_endpoint_ping() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, true).await;

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
    #[ignore]
    async fn test_endpoint_ca_failure() {
        let runtime = e2e::runtime::get().await;
        let client = e2e::client::new_web_client(&runtime, false).await;

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
    async fn test_endpoint_ca() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, true).await;

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
    #[ignore]
    async fn test_endpoint_pac_failure() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, false).await;

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
    async fn test_endpoint_pac() {
        let runtime = e2e::runtime::get().await;

        let client = e2e::client::new_web_client(&runtime, true).await;

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
