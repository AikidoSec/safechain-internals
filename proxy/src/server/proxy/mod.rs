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
    net::{
        address::SocketAddress, http::RequestContext, proxy::ProxyTarget,
        stream::layer::http::BodyLimitLayer,
    },
    proxy::socks5::{self, Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, Level},
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(feature = "har")]
use rama::{
    http::layer::har::extensions::RequestComment, layer::AddInputExtensionLayer,
    utils::str::arcstr::arcstr,
};

use crate::Args;
#[cfg(feature = "har")]
use crate::diagnostics::har::HARExportLayer;

mod client;
mod server;

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

pub async fn run_proxy_server(
    args: Args,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    proxy_addr_tx: tokio::sync::oneshot::Sender<SocketAddress>,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
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

    // TODO: Support (basic auth) username labels for
    // preferences, e.g. --proxy-user 'safechain-min_package_age-48h:'

    let http_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        args.mitm_all,
        tls_acceptor.clone(),
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;
    let socks5_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        args.mitm_all,
        tls_acceptor,
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;

    let socks5_proxy_router = Socks5PeekRouter::new(
        Socks5Acceptor::new()
            .with_connector(socks5::server::LazyConnector::new(socks5_proxy_mitm_server)),
    );

    let exec = Executor::graceful(guard.clone());
    let http_service = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            ConsumeErrLayer::trace(Level::DEBUG),
            #[cfg(feature = "har")]
            (
                AddInputExtensionLayer::new(RequestComment(arcstr!("http(s) proxy connect"))),
                har_export_layer,
            ),
            UpgradeLayer::new(
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                http_proxy_mitm_server,
            ),
            // =============================================
            // HTTP (plain-text) connections
            MapResponseBodyLayer::new(Body::new),
            CompressionLayer::new(),
            // =============================================
        )
            .into_layer(https_client),
    );

    let tcp_inner_svc = socks5_proxy_router.with_fallback(http_service);

    tracing::info!(proxy.address = %proxy_addr, "local HTTP(S)/SOCKS5 proxy ready");
    crate::server::write_server_socket_address_as_file(&args.data, "proxy", proxy_addr.into())
        .await?;
    if proxy_addr_tx.send(proxy_addr.into()).is_err() {
        return Err(OpaqueError::from_display(
            "failed to send proxy addr to meta server task",
        ));
    }

    // sent proxy addr to firewall

    tcp_service
        .serve_graceful(
            guard,
            BodyLimitLayer::symmetric(MAX_BODY_SIZE).into_layer(tcp_inner_svc),
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
