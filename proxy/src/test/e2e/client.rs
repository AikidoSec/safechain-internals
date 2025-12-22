use std::{sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    http::{
        Body, BodyExtractExt as _, Request, Response,
        client::EasyHttpWebClient,
        layer::{
            map_request_body::MapRequestBodyLayer,
            retry::{ManagedPolicy, RetryLayer},
        },
        service::client::HttpClientExt,
    },
    layer::{MapErrLayer, TimeoutLayer},
    tls::boring::{
        client::TlsConnectorDataBuilder,
        core::x509::{
            X509,
            store::{X509Store, X509StoreBuilder},
        },
    },
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

use super::runtime::Runtime;

pub async fn new_web_client(
    runtime: &Runtime,
    trusted: bool,
) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    let default_client = new_web_client_inner(None);
    if !trusted {
        return default_client;
    }

    let resp = default_client
        .get(format!("http://{}/ca", runtime.meta_addr()))
        .send()
        .await
        .unwrap();
    let payload = resp.try_into_string().await.unwrap();

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder
        .add_cert(X509::from_pem(payload.as_bytes()).unwrap())
        .unwrap();
    let store = Arc::new(store_builder.build());

    let tls_config =
        Arc::new(TlsConnectorDataBuilder::new_http_auto().with_server_verify_cert_store(store));

    new_web_client_inner(Some(tls_config))
}

fn new_web_client_inner(
    tls_config: Option<Arc<TlsConnectorDataBuilder>>,
) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    let inner_https_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_custom_connector(TimeoutLayer::new(Duration::from_secs(15)))
        .with_default_http_connector()
        .try_with_default_connection_pool()
        .expect("create connection pool for proxy web client")
        .build_client();

    (
        MapErrLayer::new(OpaqueError::from_std),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(20),
                    0.01,
                    HasherRng::default,
                )
                .expect("create exponential backoff impl"),
            ),
        ),
        MapRequestBodyLayer::new(Body::new),
    )
        .into_layer(inner_https_client)
}
