use std::sync::Arc;

use rama::{
    Layer,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    graceful::ShutdownGuard,
    http::{
        layer::{
            compression::CompressionLayer,
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            trace::TraceLayer,
            upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, stream::layer::http::BodyLimitLayer},
    proxy::socks5::{self, Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use safechain_proxy_lib::{http::firewall::Firewall, tls::RootCaKeyPair};

#[cfg(feature = "har")]
use safechain_proxy_lib::diagnostics::har::HARExportLayer;

use crate::{Args, client::new_http_client_for_proxy, utils::PEEK_TIMEOUT};

mod auth;
mod server;

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

/// Runs the MITM HTTP(S)/SOCKS(5) Proxy server,
/// including the firewall for blocking relevant requests
/// and modifying responses.
pub async fn run_proxy_server(
    args: Args,
    guard: ShutdownGuard,
    root_ca_key_pair: RootCaKeyPair,
    proxy_addr_tx: tokio::sync::oneshot::Sender<SocketAddress>,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<(), BoxError> {
    let exec = Executor::graceful(guard.clone());

    let tcp_service = TcpListener::build(exec.clone())
        .bind_address(args.bind)
        .await
        .context("bind TCP network interface for proxy")?;

    let proxy_addr = tcp_service
        .local_addr()
        .context("fetch local addr of bound TCP port for proxy")?;

    let https_client = self::server::http_relay_middleware(
        exec.clone(),
        firewall.clone(),
        root_ca_key_pair
            .certificate()
            .to_pem()
            .context("root ca cert as pem")?
            .leak(),
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )
    .into_layer(
        new_http_client_for_proxy(exec.clone())
            .context("create inner web client for plain-text web traffic")?,
    );

    let http_proxy_mitm_server = self::server::new_app_mitm_server(
        guard.clone(),
        args.mitm_all,
        root_ca_key_pair.clone(),
        args.proxy.clone(),
        firewall.clone(),
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;
    let socks5_proxy_mitm_server = self::server::new_app_mitm_server(
        guard.clone(),
        args.mitm_all,
        root_ca_key_pair,
        args.proxy,
        firewall,
        #[cfg(feature = "har")]
        har_export_layer,
    )?;

    let socks5_proxy_router = Socks5PeekRouter::new(
        Socks5Acceptor::new(exec.clone())
            .with_auth_optional(true)
            .with_authorizer(self::auth::ZeroAuthority::new())
            .with_connector(socks5::server::LazyConnector::new(Arc::new(
                socks5_proxy_mitm_server,
            ))),
    )
    .with_peek_timeout(PEEK_TIMEOUT);

    let http_inner_svc = (
        TraceLayer::new_for_http(),
        ConsumeErrLayer::trace_as_debug(),
        ProxyAuthLayer::new(self::auth::ZeroAuthority::new()).with_allow_anonymous(true),
        UpgradeLayer::new(
            exec.clone(),
            MethodMatcher::CONNECT,
            DefaultHttpProxyConnectReplyService::new(),
            Arc::new(http_proxy_mitm_server),
        ),
        // =============================================
        // HTTP (plain-text) (proxy) connections
        MapResponseBodyLayer::new_boxed_streaming_body(),
        CompressionLayer::new(),
        // =============================================
    )
        .into_layer(https_client);

    let mut http_connect_proxy_server = HttpServer::auto(exec);
    // allow HTTP Proxy Connect over H2 (rare, but legit)
    http_connect_proxy_server
        .h2_mut()
        .set_enable_connect_protocol();

    let http_service = http_connect_proxy_server.service(Arc::new(http_inner_svc));
    let tcp_inner_svc = socks5_proxy_router.with_fallback(http_service);

    tracing::info!(proxy.address = %proxy_addr, "local HTTP(S)/SOCKS5 proxy ready");
    crate::server::write_server_socket_address_as_file(&args.data, "proxy", proxy_addr.into())
        .await?;
    if proxy_addr_tx.send(proxy_addr.into()).is_err() {
        return Err(
            BoxError::from("failed to send proxy address to meta server task")
                .context_field("address", proxy_addr),
        );
    }

    // sent proxy addr to firewall

    tcp_service
        .serve(BodyLimitLayer::symmetric(MAX_BODY_SIZE).into_layer(tcp_inner_svc))
        .await;

    Ok(())
}
