use rama::{
    Service,
    error::OpaqueError,
    http::{BodyExtractExt, Request, Response, StatusCode, service::client::HttpClientExt as _},
    telemetry::tracing,
    tls::boring::core::x509::X509,
};

use crate::test::e2e;

pub(super) async fn test_endpoint(runtime: &e2e::runtime::Runtime) {
    tokio::join!(
        self::http::test_endpoint(runtime),
        self::https::test_endpoint(runtime),
    );
}

mod http {
    use super::*;

    pub(super) async fn test_endpoint(runtime: &e2e::runtime::Runtime) {
        let client = e2e::client::new_web_client(runtime, true).await;

        tokio::join!(
            test_endpoint_root(runtime, &client),
            test_endpoint_ping(runtime, &client),
            test_endpoint_ca(runtime, &client),
            test_endpoint_pac(runtime, &client),
        );
    }

    async fn test_endpoint_root(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
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

    async fn test_endpoint_ping(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        let resp = client
            .get(format!("http://{}/ping", runtime.meta_socket_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        assert_eq!("pong", payload);
    }

    async fn test_endpoint_ca(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
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

    async fn test_endpoint_pac(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        let resp = client
            .get(format!("http://{}/pac", runtime.meta_socket_addr()))
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
    async fn test_endpoint_failure() {
        let runtime = e2e::runtime::get().await;
        let client = e2e::client::new_web_client(&runtime, false).await;

        test_endpoint_root_failure(&runtime, &client).await;
        test_endpoint_ping_failure(&runtime, &client).await;
        test_endpoint_ca_failure(&runtime, &client).await;
        test_endpoint_pac_failure(&runtime, &client).await;
    }

    async fn test_endpoint_root_failure(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        assert!(
            client
                .get(format!("https://{}", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    async fn test_endpoint_ping_failure(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        assert!(
            client
                .get(format!("https://{}/ping", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    async fn test_endpoint_ca_failure(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        assert!(
            client
                .get(format!("https://{}/ca", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    async fn test_endpoint_pac_failure(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        assert!(
            client
                .get(format!("https://{}/pac", runtime.meta_domain_addr()))
                .send()
                .await
                .is_err()
        );
    }

    pub(super) async fn test_endpoint(runtime: &e2e::runtime::Runtime) {
        let client = e2e::client::new_web_client(runtime, true).await;

        tokio::join!(
            test_endpoint_root(runtime, &client),
            test_endpoint_ping(runtime, &client),
            test_endpoint_ca(runtime, &client),
            test_endpoint_pac(runtime, &client),
        );
    }

    async fn test_endpoint_root(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
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

    async fn test_endpoint_ping(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
        let resp = client
            .get(format!("https://{}/ping", runtime.meta_domain_addr()))
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, resp.status());

        let payload = resp.try_into_string().await.unwrap();

        assert_eq!("pong", payload);
    }

    async fn test_endpoint_ca(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
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

    async fn test_endpoint_pac(
        runtime: &e2e::runtime::Runtime,
        client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    ) {
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
