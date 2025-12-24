use std::sync::Arc;

use rama::{
    Service,
    error::OpaqueError,
    http::{
        BodyExtractExt as _, Request, Response, client::EasyHttpWebClient,
        service::client::HttpClientExt,
    },
    tls::boring::{
        client::TlsConnectorDataBuilder,
        core::x509::{X509, store::X509StoreBuilder},
    },
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
        .get(format!("http://{}/ca", runtime.meta_socket_addr()))
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
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector()
        .build_client()
}
