use rama::{
    Layer as _, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        },
        service::web::response::IntoResponse as _,
    },
    net::{address::DomainTrie, proxy::ProxyTarget},
    telemetry::tracing,
};

use crate::firewall::{
    BLOCK_DOMAINS_VSCODE, BlockRule as _, DynBlockRule, vscode::BlockRuleVSCode,
};

#[derive(Debug, Clone)]
pub(super) struct HttpClient<S> {
    inner: S,
    block_rules: DomainTrie<DynBlockRule>,
}

pub(super) fn new_https_client()
-> Result<HttpClient<impl Service<Request, Output = Response, Error = OpaqueError>>, OpaqueError> {
    let inner = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        MapResponseBodyLayer::new(Body::new),
        DecompressionLayer::new(),
    )
        .into_layer(
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

    // TODO: this should be managed to allow updates and other
    // dynamic featurues (in future)
    let mut block_rules = DomainTrie::new();
    let vscode_rule = BlockRuleVSCode::new().into_dyn();
    for domain in BLOCK_DOMAINS_VSCODE {
        block_rules.insert_domain(domain, vscode_rule.clone());
    }

    Ok(HttpClient { inner, block_rules })
}

impl<S> Service<Request> for HttpClient<S>
where
    S: Service<Request, Output = Response, Error = OpaqueError>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        let uri = req.uri().clone();
        tracing::info!(uri = %uri, "serving http(s) over proxy");

        let Some(ProxyTarget(target)) = req.extensions().get() else {
            tracing::error!(uri = %uri, "error forwarding request: missing proxy target");
            return Ok(StatusCode::BAD_GATEWAY.into_response());
        };

        if let Some(domain) = target.host.as_domain()
            && let Some(m) = self.block_rules.match_parent(domain)
        {
            match m.value.block_request(req).await? {
                Some(r) => req = r,
                None => {
                    // TODO: generate clean response per Content-Type
                    return Ok(StatusCode::FORBIDDEN.into_response());
                }
            }
        }

        match self.inner.serve(req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(uri = %uri, "error forwarding request: {err:?}");
                let resp = StatusCode::BAD_GATEWAY.into_response();
                Ok(resp)
            }
        }
    }
}
