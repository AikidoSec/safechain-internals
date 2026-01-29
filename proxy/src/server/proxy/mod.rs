use std::{path::Path, sync::Arc};

use rama::{
    Layer, Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, StatusCode,
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
        address::{ProxyAddress, SocketAddress},
        http::RequestContext,
        proxy::ProxyTarget,
        socket::Interface,
        stream::layer::http::BodyLimitLayer,
    },
    proxy::socks5::{self, Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    service::service_fn,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{self, Level},
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(feature = "har")]
use rama::{
    http::layer::har::extensions::RequestComment, layer::AddInputExtensionLayer,
    utils::str::arcstr::arcstr,
};

use crate::firewall::Firewall;

#[cfg(feature = "har")]
use crate::diagnostics::har::HARExportLayer;

mod client;
mod forwarder;
mod server;

mod auth;

pub use self::auth::{FirewallUserConfig, HEADER_NAME_X_AIKIDO_SAFE_CHAIN_CONFIG};

/// Maximum allowed body size for proxied requests and responses.
/// Protects against memory exhaustion from excessively large payloads.
const MAX_BODY_SIZE: usize = 500 * 1024 * 1024; // 500 MB

#[derive(Debug)]
/// The MITM HTTP(S)/SOCKS(5) Proxy server,
/// including the firewall for blocking relevant requests
/// and modifying responses.
///
/// You can create it using [`build_proxy_server`]
/// or build and run it directly using [`run_proxy_server`].
///
/// The first is useful for lib usage, while the latter is mostly
/// for the proxycli use-case.
pub struct ProxyServer<S> {
    service: S,
    socket_address: SocketAddress,
    listener: TcpListener,
}

impl<S> ProxyServer<S>
where
    S: Service<TcpStream> + Clone,
{
    /// The (local) address this proxy server is bound to.
    pub fn socket_address(&self) -> SocketAddress {
        self.socket_address
    }

    /// proxy connections from this (proxy) server.
    pub async fn serve(self) -> Result<(), OpaqueError> {
        self.listener
            .serve(BodyLimitLayer::symmetric(MAX_BODY_SIZE).into_layer(self.service))
            .await;
        Ok(())
    }
}

pub async fn build_proxy_server(
    bind: Interface,
    upstream_proxy_addr: Option<ProxyAddress>,
    mitm_all: bool,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<ProxyServer<impl Service<TcpStream> + Clone>, OpaqueError> {
    let exec = Executor::graceful(guard.clone());

    let tcp_service = TcpListener::build(exec.clone())
        .bind(bind)
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind TCP network interface for proxy")?;

    let proxy_addr = tcp_service
        .local_addr()
        .context("fetch local addr of bound TCP port for proxy")?;

    let https_client = self::client::new_https_client(
        exec.clone(),
        firewall.clone(),
        upstream_proxy_addr.clone(),
    )?;

    let http_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        upstream_proxy_addr.clone(),
        mitm_all,
        tls_acceptor.clone(),
        firewall.clone(),
        #[cfg(feature = "har")]
        har_export_layer.clone(),
    )?;
    let socks5_proxy_mitm_server = self::server::new_mitm_server(
        guard.clone(),
        upstream_proxy_addr,
        mitm_all,
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
        ConsumeErrLayer::trace(Level::DEBUG),
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
        MapResponseBodyLayer::new(Body::new),
        CompressionLayer::new(),
        // =============================================
    )
        .into_layer(https_client);

    let http_service = HttpServer::auto(exec).service(Arc::new(http_inner_svc));

    let tcp_inner_svc = socks5_proxy_router.with_fallback(http_service);

    tracing::info!(proxy.address = %proxy_addr, "local HTTP(S)/SOCKS5 proxy ready");

    Ok(ProxyServer {
        service: tcp_inner_svc,
        socket_address: proxy_addr.into(),
        listener: tcp_service,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_proxy_server(
    bind: Interface,
    upstream_proxy_addr: Option<ProxyAddress>,
    data: &Path,
    mitm_all: bool,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    proxy_addr_tx: tokio::sync::oneshot::Sender<SocketAddress>,
    firewall: Firewall,
    #[cfg(feature = "har")] har_export_layer: HARExportLayer,
) -> Result<(), OpaqueError> {
    let proxy_server = build_proxy_server(
        bind,
        upstream_proxy_addr,
        mitm_all,
        guard,
        tls_acceptor,
        firewall,
        #[cfg(feature = "har")]
        har_export_layer,
    )
    .await?;

    let proxy_addr = proxy_server.socket_address();

    crate::server::write_server_socket_address_as_file(data, "proxy", proxy_addr).await?;
    if proxy_addr_tx.send(proxy_addr).is_err() {
        return Err(OpaqueError::from_display(
            "failed to send proxy addr to meta server task",
        ));
    }

    proxy_server.serve().await
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
