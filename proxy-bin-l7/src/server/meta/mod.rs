use std::{sync::Arc, time::Duration};

use rama::{
    Layer,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef as _,
    graceful::ShutdownGuard,
    http::{
        HeaderValue, Request, StatusCode,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{
            Router,
            response::{Html, IntoResponse},
        },
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

use safechain_proxy_lib::{http::firewall::Firewall, utils::env::network_service_identifier};

#[cfg(feature = "har")]
use safechain_proxy_lib::diagnostics::har::HarClient;

use crate::{Args, tls::RootCA};

pub async fn run_meta_https_server(
    args: Args,
    guard: ShutdownGuard,
    tls_acceptor: TlsAcceptorLayer,
    root_ca: RootCA,
    proxy_addr_rx: tokio::sync::oneshot::Receiver<SocketAddress>,
    firewall: Firewall,
    #[cfg(feature = "har")] har_client: HarClient,
) -> Result<(), BoxError> {
    let proxy_addr = tokio::time::timeout(Duration::from_secs(8), proxy_addr_rx)
        .await
        .context("wait to recv proxy addr from proxy task")?
        .context("recv proxy addr from proxy task")?;

    tracing::info!("meta HTTP(S) server received proxy address from proxy task: {proxy_addr}");

    #[cfg_attr(not(feature = "har"), allow(unused_mut))]
    let mut http_router = Router::new()
        .with_get("/", Html(META_SITE_INDEX_HTML))
        .with_get("/ping", "pong")
        .with_get("/ca", move || {
            let response = root_ca.as_http_response();
            std::future::ready(response)
        })
        // See `docs/proxy/pac.md` for in-depth documentation regarding
        // Proxy Auto Configuration (PAC in short).
        .with_get("/pac", move |req: Request| {
            if !req.extensions().contains::<SecureTransport>() {
                tracing::debug!("/pac endpoint only available for TLS connections (as MITM proxy would anyway fail if Root CA is not trusted)");
                return std::future::ready(StatusCode::NOT_FOUND.into_response());
            }

            let response = firewall.generate_pac_script_response(proxy_addr, req);
            std::future::ready(response)
        });

    #[cfg(feature = "har")]
    {
        http_router.set_post("/har/toggle", move || {
            let har_client = har_client.clone();
            async move {
                har_client
                    .toggle()
                    .await
                    .map(|previous| (!previous).to_string())
                    .into_response()
            }
        });
    }

    let http_svc = (
        TraceLayer::new_for_http(),
        AddRequiredResponseHeadersLayer::new()
            .with_server_header_value(HeaderValue::from_static(network_service_identifier())),
    )
        .into_layer(http_router);

    let exec = Executor::graceful(guard.clone());
    let http_server = HttpServer::auto(exec.clone()).service(Arc::new(http_svc));

    let tcp_svc = TimeoutLayer::new(Duration::from_secs(60)).into_layer(
        TlsPeekRouter::new(tls_acceptor.into_layer(http_server.clone())).with_fallback(http_server),
    );

    let tcp_listener = TcpListener::bind(args.meta_bind, exec)
        .await
        .context("bind proxy meta http(s) server")?;

    let meta_addr = tcp_listener
        .local_addr()
        .context("get bound address for proxy meta http(s) server")?;

    tracing::info!("meta http(s) server bound to: {meta_addr}");
    crate::server::write_server_socket_address_as_file(&args.data, "meta", meta_addr.into())
        .await?;

    tcp_listener.serve(tcp_svc).await;

    Ok(())
}

const META_SITE_INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Safechain Proxy</title>
<style>
html,body{height:100%}body{margin:0;font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:radial-gradient(900px 500px at 50% 0,rgba(120,110,255,.25),transparent 60%),#05061c;color:#f4f5ff;display:grid;place-items:center}
main{text-align:center;padding:24px}
h1{margin:0;font-weight:800;letter-spacing:-.03em;font-size:clamp(40px,6vw,72px);line-height:1.05}
p{margin:16px auto 0;max-width:46ch;color:rgba(255,255,255,.7)}
a{display:inline-block;margin-top:28px;padding:12px 20px;border-radius:999px;background:#6f6cff;color:#fff;text-decoration:none;font-weight:700}
a:hover{filter:brightness(1.05)}
</style>
</head>
<body>
<main>
<h1>Safechain Proxy</h1>
<p>
    The Proxy's CA has to be installed and trusted
    by the System in order for the Safechain proxy to operate
</p>
<p><a href="/ca" download="safechain-proxy-ca.pem">Download Proxy CA (PEM)</a></p>
</main>
</body>
</html>
"##;
