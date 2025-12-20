use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::{ExtensionsMut as _, ExtensionsRef as _},
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        },
        service::web::response::IntoResponse,
    },
    net::tls::{SecureTransport, client::ClientConfig},
    telemetry::tracing,
    tls::boring::client::TlsConnectorDataBuilder,
};

use crate::firewall::Firewall;

#[derive(Debug, Clone)]
pub(super) struct HttpClient<S> {
    inner: S,
}

pub(super) fn new_https_client(
    firewall: Firewall,
) -> Result<HttpClient<impl Service<Request, Output = Response, Error = OpaqueError>>, OpaqueError>
{
    let inner = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        firewall.into_evaluate_request_layer(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        MapResponseBodyLayer::new(Body::new),
        DecompressionLayer::new(),
    )
        .into_layer(
            // TODO: mock in #[cfg(test)] for e2e-like tests
            EasyHttpWebClient::connector_builder()
                .with_default_transport_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .with_tls_support_using_boringssl(None)
                .with_default_http_connector()
                .try_with_default_connection_pool()
                .context("create connection pool for proxy web client")?
                .build_client(),
        );

    Ok(HttpClient { inner })
}

impl<S> Service<Request> for HttpClient<S>
where
    S: Service<Request, Output = Response, Error = OpaqueError>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();
        tracing::debug!(uri = %uri, "serving http(s) over proxy (egress) client");

        let mut mod_req = req;

        if let Some(tls_client_hello) = mod_req
            .extensions()
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .cloned()
        {
            match TlsConnectorDataBuilder::try_from(&ClientConfig::from(tls_client_hello)) {
                Ok(mirror_tls_cfg) => {
                    tracing::trace!(
                        "inject TLS Connector data builder based on input TLS ClientHello"
                    );
                    mod_req.extensions_mut().insert(mirror_tls_cfg);
                }
                Err(err) => {
                    tracing::debug!(
                        "failed to create TLS Connector data builder based on input TLS ClientHello: err = {err}; proceed anyway with default rama boring CH"
                    );
                }
            }
        }

        match self.inner.serve(mod_req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(uri = %uri, "error forwarding request: {err:?}");
                let resp = StatusCode::BAD_GATEWAY.into_response();
                Ok(resp)
            }
        }
    }
}
