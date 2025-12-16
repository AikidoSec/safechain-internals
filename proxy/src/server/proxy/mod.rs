use rama::{
    Layer,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, StatusCode,
        layer::{
            compression::CompressionLayer, map_response_body::MapResponseBodyLayer,
            trace::TraceLayer, upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{http::RequestContext, proxy::ProxyTarget, stream::layer::http::BodyLimitLayer},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, Level},
    tls::boring::server::TlsAcceptorLayer,
};

use crate::Args;

mod client;
mod server;

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

pub async fn run_proxy_server(
    args: Args,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
) -> Result<(), OpaqueError> {
    let tcp_service = TcpListener::build()
        .bind(args.bind)
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind TCP network interface for proxy")?;

    let proxy_addr = tcp_service
        .local_addr()
        .context("fetch local addr of bound TCP port for proxy")?;

    let https_client = self::client::new_https_client()?;
    let mitm_server = self::server::new_mitm_server(guard.clone(), tls_acceptor)?;

    // TODO Also add SOCKS5 version :)

    let exec = Executor::graceful(guard.clone());
    let http_service = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            ConsumeErrLayer::trace(Level::DEBUG),
            UpgradeLayer::new(
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                mitm_server,
            ),
            // =============================================
            // HTTP (plain-text) connections
            MapResponseBodyLayer::new(Body::new),
            CompressionLayer::new(),
            // =============================================
        )
            .into_layer(https_client),
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
