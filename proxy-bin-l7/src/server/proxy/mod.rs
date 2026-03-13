use std::sync::Arc;

use rama::{
    Layer,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Request, Response, StatusCode,
        layer::{
            compression::CompressionLayer, header_config::extract_header_config,
            map_response_body::MapResponseBodyLayer, proxy_auth::ProxyAuthLayer, trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
        utils::HeaderValueErr,
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
    telemetry::tracing::{self},
    tls::boring::server::TlsAcceptorLayer,
};

use safechain_proxy_lib::http::firewall::Firewall;

#[cfg(feature = "har")]
use {
    rama::{
        http::layer::har::extensions::RequestComment, layer::AddInputExtensionLayer,
        utils::str::arcstr::arcstr,
    },
    safechain_proxy_lib::diagnostics::har::HARExportLayer,
};

use crate::Args;

mod client;
mod forwarder;
mod server;

mod auth;

pub use self::auth::{FirewallUserConfig, HEADER_NAME_X_AIKIDO_SAFE_CHAIN_CONFIG};

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

/// Runs the MITM HTTP(S)/SOCKS(5) Proxy server,
/// including the firewall for blocking relevant requests
/// and modifying responses.
pub async fn run_proxy_server(
    args: Args,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    proxy_addr_tx: tokio::sync::oneshot::Sender<SocketAddress>,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<(), BoxError> {
    let exec = Executor::graceful(guard.clone());

    let tcp_service = TcpListener::build(exec.clone())
        .bind(args.bind)
        .await
        .context("bind TCP network interface for proxy")?;

    let proxy_addr = tcp_service
        .local_addr()
        .context("fetch local addr of bound TCP port for proxy")?;

    let https_client = self::client::new_https_client(firewall.clone(), args.proxy.clone())?;

    let http_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        args.mitm_all,
        args.proxy.clone(),
        tls_acceptor.clone(),
        firewall.clone(),
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;
    let socks5_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        args.mitm_all,
        args.proxy,
        tls_acceptor,
        firewall,
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;

    let socks5_proxy_router = Socks5PeekRouter::new(
        Socks5Acceptor::new(exec.clone())
            .with_auth_optional(true)
            .with_authorizer(self::auth::ZeroAuthority::new())
            .with_connector(socks5::server::LazyConnector::new(Arc::new(
                socks5_proxy_mitm_server,
            ))),
    );

    let http_inner_svc = (
        TraceLayer::new_for_http(),
        ConsumeErrLayer::trace_as_debug(),
        #[cfg(feature = "har")]
        (
            AddInputExtensionLayer::new(RequestComment(arcstr!("http(s) proxy connect"))),
            har_export_layer,
        ),
        ProxyAuthLayer::new(self::auth::ZeroAuthority::new())
            .with_allow_anonymous(true)
            // The use of proxy authentication is a common practice for
            // proxy users to pass configs via a concept called username labels.
            // See `docs/proxy/auth-flow.md` for more informtion.
            //
            // We make use use the void trailer parser to ensure we drop any ignored label.
            .with_labels::<((), self::auth::FirewallUserConfigParser)>(),
        UpgradeLayer::new(
            exec.clone(),
            MethodMatcher::CONNECT,
            service_fn(http_connect_accept),
            Arc::new(http_proxy_mitm_server),
        ),
        // =============================================
        // HTTP (plain-text) (proxy) connections
        MapResponseBodyLayer::new_boxed_streaming_body(),
        CompressionLayer::new(),
        // =============================================
    )
        .into_layer(https_client);

    let http_service = HttpServer::auto(exec).service(Arc::new(http_inner_svc));

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

    // next to (proxy (basic) username labels) we also allow for secure
    // targets that a custom proxy connect (http) request header is used to
    // pass the config (html form encoded) as an alternative way as well
    //
    // See `docs/proxy/auth-flow.md` for more informtion.
    match extract_header_config(&req, &HEADER_NAME_X_AIKIDO_SAFE_CHAIN_CONFIG) {
        Ok(cfg @ FirewallUserConfig { .. }) => {
            tracing::debug!(
                "aikido safechain cfg header ({HEADER_NAME_X_AIKIDO_SAFE_CHAIN_CONFIG:?}) parsed: {cfg:?}",
            );
            req.extensions_mut().insert(cfg);
        }
        Err(HeaderValueErr::HeaderMissing(name)) => {
            tracing::trace!("aikido safechain cfg header ({name}): ignore");
        }
        Err(HeaderValueErr::HeaderInvalid(name)) => {
            tracing::debug!("aikido safechain cfg header ({name}) failed to parse: ignore");
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}
