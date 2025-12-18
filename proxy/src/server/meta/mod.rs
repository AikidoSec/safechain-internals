use std::time::Duration;

use rama::{
    Layer,
    error::{ErrorContext, OpaqueError},
    extensions::ExtensionsRef as _,
    graceful::ShutdownGuard,
    http::{
        HeaderValue, Request, StatusCode,
        header::CONTENT_TYPE,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{Router, response::IntoResponse},
    },
    layer::TimeoutLayer,
    net::{
        address::SocketAddress,
        tls::{SecureTransport, server::TlsPeekRouter},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::server::TlsAcceptorLayer,
};

#[cfg(feature = "har")]
use crate::diagnostics::har::HarClient;

use crate::{Args, tls::RootCA};

mod pac;

pub async fn run_meta_https_server(
    args: Args,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    root_ca: RootCA,
    proxy_addr_rx: tokio::sync::oneshot::Receiver<SocketAddress>,
    #[cfg(feature = "har")] har_client: HarClient,
) -> Result<(), OpaqueError> {
    let proxy_addr = tokio::time::timeout(Duration::from_secs(8), proxy_addr_rx)
        .await
        .context("wait to recv proxy addr from proxy task")?
        .context("recv proxy addr from proxy task")?;

    tracing::info!("meta HTTP(S) server received proxy address from proxy task: {proxy_addr}");

    #[cfg_attr(not(feature = "har"), allow(unused_mut))]
    let mut http_router = Router::new()
        .with_get("/ping", "pong")
        .with_get("/ca", move || {
            let response = root_ca.as_http_response();
            std::future::ready(response)
        })
        .with_get("/pac", move |req: Request| {
            if !req.extensions().contains::<SecureTransport>() {
                tracing::debug!("/pac endpoint only available for TLS connections (as MITM proxy would anyway fail if Root CA is not trusted)");
                return std::future::ready(StatusCode::NOT_FOUND.into_response());
            }

            // TODO:
            // - inject domains into a stateful svc
            // - inject actual bound proxy addr into a stateful svc
            let response = (
                [(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
                )],
                self::pac::generate_pac_script(proxy_addr),
            )
                .into_response();
            std::future::ready(response)
        });

    #[cfg(feature = "har")]
    {
        http_router.set_post("/har/toggle", move || {
            let har_client = har_client.clone();
            async move {
                har_client
                    .switch()
                    .await
                    .map(|previous| (!previous).to_string())
                    .into_response()
            }
        });
    }

    let http_svc = (
        TraceLayer::new_for_http(),
        AddRequiredResponseHeadersLayer::new()
            .with_server_header_value(HeaderValue::from_static(crate::utils::env::project_name())),
    )
        .into_layer(http_router);

    let http_server = HttpServer::auto(Executor::graceful(guard.clone())).service(http_svc);

    let tcp_svc = TimeoutLayer::new(Duration::from_secs(60)).into_layer(
        TlsPeekRouter::new(tls_acceptor.into_layer(http_server.clone())).with_fallback(http_server),
    );

    let tcp_listener = TcpListener::bind(args.meta_bind)
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind proxy meta http(s) server")?;

    let meta_addr = tcp_listener
        .local_addr()
        .context("get bound address for proxy meta http(s) server")?;

    tracing::info!("meta http(s) server bound to: {meta_addr}");
    crate::server::write_server_socket_address_as_file(&args.data, "meta", meta_addr.into())
        .await?;

    tcp_listener.serve_graceful(guard, tcp_svc).await;

    Ok(())
}
