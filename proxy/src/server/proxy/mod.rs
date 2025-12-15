use rama::{
    Layer, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    graceful::ShutdownGuard,
    http::{
        Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{
        address::DomainTrie, http::RequestContext, proxy::ProxyTarget,
        stream::layer::http::BodyLimitLayer,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self},
};

use crate::{
    Args,
    firewall::{BLOCK_DOMAINS_VSCODE, BlockRule, DynBlockRule, vscode::BlockRuleVSCode},
};

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

pub async fn run_proxy_server(args: Args, guard: ShutdownGuard) -> Result<(), OpaqueError> {
    let tcp_service = TcpListener::build()
        .bind(args.bind)
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind TCP network interface for proxy")?;

    let proxy_addr = tcp_service
        .local_addr()
        .context("fetch local addr of bound TCP port for proxy")?;

    let http_client = new_http_client()?;

    // TODO Also add SOCKS5 version :)

    // TODO: also support compression

    let exec = Executor::graceful(guard.clone());
    let http_service = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            ConsumeErrLayer::default(),
            UpgradeLayer::new(
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                // TOOD: MITM proxy
                ConsumeErrLayer::default().into_layer(Forwarder::ctx()),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
            RemoveRequestHeaderLayer::hop_by_hop(),
        )
            .into_layer(http_client),
    );

    tracing::info!(proxy.address = %proxy_addr, "local proxy ready");

    tcp_service
        .serve_graceful(
            guard,
            BodyLimitLayer::symmetric(MAX_BODY_SIZE).into_layer(http_service),
        )
        .await;

    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!(uri = %req.uri(), "error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

#[derive(Debug, Clone)]
struct HttpClient<S> {
    inner: S,
    block_rules: DomainTrie<DynBlockRule>,
}

fn new_http_client()
-> Result<HttpClient<impl Service<Request, Output = Response, Error = OpaqueError>>, OpaqueError> {
    let inner = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(None)
        .with_default_http_connector()
        .try_with_default_connection_pool()
        .context("create connection pool for proxy web client")?
        .build_client();

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
