use std::borrow::Cow;

use rama::{
    Layer as _, Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    http::{
        Request, Response, StatusCode,
        layer::{
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        },
        matcher::HttpMatcher,
        service::web::response::IntoResponse,
    },
    layer::{AddInputExtensionLayer, HijackLayer},
    net::{address::ProxyAddress, user::UserId},
    telemetry::tracing::{self, Instrument as _},
};

use safechain_proxy_lib::http::{
    firewall::Firewall,
    service::connectivity::{CONNECTIVITY_DOMAIN, new_connectivity_http_svc},
};

#[derive(Debug, Clone)]
pub(super) struct HttpClient<S> {
    inner: S,
}

pub(super) fn new_https_client(
    firewall: Firewall,
    upstream_proxy_address: Option<ProxyAddress>,
) -> Result<HttpClient<impl Service<Request, Output = Response, Error = BoxError>>, BoxError> {
    let inner = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        firewall.clone().into_evaluate_response_layer(),
        firewall.into_evaluate_request_layer(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new(),
        HijackLayer::new(
            HttpMatcher::domain(CONNECTIVITY_DOMAIN),
            new_connectivity_http_svc(),
        ),
        upstream_proxy_address.map(AddInputExtensionLayer::new),
    )
        .into_layer(crate::client::new_web_client()?);

    Ok(HttpClient { inner })
}

impl<S> Service<Request> for HttpClient<S>
where
    S: Service<Request, Output = Response, Error = BoxError>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();
        tracing::debug!(uri = %uri, "serving http(s) over proxy (egress) client");

        let proxy_user: Cow<'static, str> = req
            .extensions()
            .get::<UserId>()
            .map(|id| match id {
                UserId::Username(username) => Cow::Owned(username.clone()),
                UserId::Token(_) => Cow::Borrowed("<TOKEN>"),
                UserId::Anonymous => Cow::Borrowed("anonymous"),
            })
            .unwrap_or_else(|| Cow::Borrowed("anonymous"));

        tracing::debug!("start MITM HTTP(S) web request for user = {proxy_user}");

        match self
            .inner
            .serve(req)
            .instrument(tracing::debug_span!(
                "MITM HTTP(S) web request",
                proxy.user = %proxy_user,
                otel.kind = "client",
                network.protocol.name = "http",
            ))
            .await
        {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(uri = %uri, "error forwarding request: {err:?}");
                let resp = StatusCode::BAD_GATEWAY.into_response();
                Ok(resp)
            }
        }
    }
}
