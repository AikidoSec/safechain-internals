use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Request, Response, Uri,
        layer::{
            compression::stream::StreamCompressionLayer,
            decompression::DecompressionLayer,
            dpi_proxy_credential::DpiProxyCredentialExtractorLayer,
            map_response_body::MapResponseBodyLayer,
            upgrade::{
                HttpProxyConnectRelayServiceRequestMatcher, mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::DomainMatcher,
        proxy::mitm::HttpMitmRelay,
        ws::handshake::matcher::HttpWebSocketRelayServiceRequestMatcher,
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer},
    net::{
        apple::networkextension::{TcpFlow, tproxy::TransparentProxyServiceContext},
        client::ConnectorService,
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    tcp::{client::service::TcpConnector, proxy::IoToProxyBridgeIoLayer},
    telemetry::tracing,
    tls::boring::proxy::{TlsMitmRelay, cert_issuer::BoringMitmCertIssuer},
};

use safechain_proxy_lib::{
    client,
    http::{
        firewall::Firewall,
        service::hijack::{self, HIJACK_DOMAIN},
    },
    storage,
    tls::mitm_relay_policy::TlsMitmRelayPolicyLayer,
    utils::token::AgentIdentity,
};

use crate::config::ProxyConfig;

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(2);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_RETRIES: u32 = 5;

pub(super) async fn try_new_service(
    ctx: TransparentProxyServiceContext,
) -> Result<impl Service<TcpFlow, Output = (), Error = Infallible>, BoxError> {
    let demo_config = ProxyConfig::from_opaque_config(ctx.opaque_config())?;
    let executor = ctx.executor.clone();
    let data_path = crate::utils::storage::storage_dir().context("(app) data path is missing")?;
    std::fs::create_dir_all(&data_path)
        .context("create (app) data directory")
        .with_context_debug_field("path", || data_path.clone())?;
    let data_storage = storage::SyncCompactDataStorage::try_new(data_path.clone())
        .context("create compact data storage using (app) storage dir")
        .with_context_debug_field("path", || data_path.clone())?;
    let root_ca = match crate::tls::load_root_ca_key_pair(demo_config.use_vpn_shared_identity)
        .context("load managed identity MITM CA Crt/Key pair")?
    {
        Some(root_ca) => root_ca,
        None => {
            let secret_storage = storage::SyncSecrets::try_new(
                crate::utils::env::project_name(),
                storage::SecretStorageKind::AppleProtected {
                    access_group: None,
                    cloud_sync: false,
                },
            )
            .context("create Apple Protected secrets storage for MITM CA")?;

            safechain_proxy_lib::tls::load_or_create_root_ca_key_pair(
                &secret_storage,
                &data_storage,
            )
            .context("load/create self-managed MITM CA Crt/Key pair")?
        }
    };
    let ca_crt = root_ca.certificate().clone();
    let ca_key = root_ca.private_key().clone();

    let ca_crt_pem_bytes: &[u8] = root_ca
        .certificate_pem()
        .as_ref()
        .as_bytes()
        .to_vec()
        .leak();

    let guard = ctx
        .executor
        .guard()
        .cloned()
        .context("L4 engine runtime is expected to inject shutdown guard")?;

    let config = ProxyConfig::from_opaque_config(ctx.opaque_config())
        .context("decode proxy config (json)")?;

    tracing::debug!("creating firewall state for transparent proxy extension");
    let firewall = create_firewall(
        guard,
        Some(data_path),
        config.agent_identity,
        config.reporting_endpoint,
        config.aikido_url,
    )
    .await?;

    let tls_mitm_relay_policy = TlsMitmRelayPolicyLayer::new(firewall.clone());
    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    let mitm_svc = new_tcp_service_inner(
        executor.clone(),
        demo_config,
        tls_mitm_relay_policy,
        tls_mitm_relay,
        firewall,
        ca_crt_pem_bytes,
        false,
    );

    Ok((
        ConsumeErrLayer::trace_as_debug(),
        IoToProxyBridgeIoLayer::extension_proxy_target_with_connector(tcp_connector_service(
            executor,
        )),
    )
        .into_layer(mitm_svc))
}

fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    demo_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
    within_connect_tunnel: bool,
) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
{
    let peek_duration = Duration::from_secs_f64(demo_config.peek_duration_s.max(0.5));

    let http_mitm_svc =
        HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
            exec,
            demo_config,
            tls_mitm_relay_policy.clone(),
            tls_mitm_relay.clone(),
            firewall,
            ca_crt_pem_bytes,
            within_connect_tunnel,
        ));

    let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
        .with_peek_timeout(peek_duration)
        .with_fallback(IoForwardService::new());

    let app_mitm_layer = PeekTlsClientHelloService::new(
        (tls_mitm_relay_policy, tls_mitm_relay).into_layer(maybe_http_mitm_svc.clone()),
    )
    .with_peek_timeout(peek_duration)
    .with_fallback(maybe_http_mitm_svc);

    if within_connect_tunnel {
        return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
    }

    let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());
    let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay)
        .with_peek_timeout(peek_duration)
        .with_fallback(app_mitm_layer);

    Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
}

fn http_relay_middleware<S, Issuer>(
    exec: Executor,
    demo_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
    within_connect_tunnel: bool,
) -> impl Layer<S, Service: Service<Request, Output = Response, Error = BoxError> + Clone>
+ Send
+ Sync
+ 'static
+ Clone
where
    S: Service<Request, Output = Response, Error = BoxError>,
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
{
    let http_conn_upgrade_svc = if within_connect_tunnel {
        ConsumeErrLayer::trace_as_debug()
            .into_layer(IoForwardService::new())
            .boxed()
    } else {
        new_tcp_service_inner(
            exec.clone(),
            demo_config,
            tls_mitm_relay_policy,
            tls_mitm_relay,
            firewall.clone(),
            ca_crt_pem_bytes,
            true,
        )
        .boxed()
    };

    (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        StreamCompressionLayer::new(),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(hijack::new_service(ca_crt_pem_bytes)),
        ),
        firewall.clone().into_evaluate_response_layer(),
        firewall.into_evaluate_request_layer(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new(),
        HttpUpgradeMitmRelayLayer::new(
            exec,
            (
                HttpWebSocketRelayServiceRequestMatcher::new(
                    // NOTE: change service of HttpWebSocketRelayServiceRequestMatcher with WS MitmRelay
                    // if you ever to inspect Websocket traffic :)
                    ConsumeErrLayer::trace_as_debug().into_layer(IoForwardService::new()),
                ),
                HttpProxyConnectRelayServiceRequestMatcher::new(http_conn_upgrade_svc),
            ),
        ),
        DpiProxyCredentialExtractorLayer::new(),
        ArcLayer::new(),
    )
}

fn tcp_connector_service(
    exec: Executor,
) -> impl ConnectorService<rama::tcp::client::Request, Connection: Io + Unpin> + Clone {
    TcpConnector::new(exec).with_connector(Arc::new(SocketOptions {
        keep_alive: Some(true),
        tcp_keep_alive: Some(TcpKeepAlive {
            time: Some(TCP_KEEPALIVE_TIME),
            interval: Some(TCP_KEEPALIVE_INTERVAL),
            retries: Some(TCP_KEEPALIVE_RETRIES),
        }),
        ..SocketOptions::default_tcp()
    }))
}

async fn create_firewall(
    guard: ShutdownGuard,
    maybe_data_path: Option<PathBuf>,
    agent_identity: Option<AgentIdentity>,
    reporting_endpoint: Option<Uri>,
    aikido_url: Uri,
) -> Result<Firewall, BoxError> {
    let data_path = maybe_data_path.context("(app) data path is missing")?;

    tokio::fs::create_dir_all(&data_path)
        .await
        .context("create (app) data directory")
        .with_context_debug_field("path", || data_path.clone())?;

    let data_storage = storage::SyncCompactDataStorage::try_new(data_path.clone())
        .context("create compact data storage using (app) storage dir")
        .with_context_debug_field("path", || data_path.clone())?;
    tracing::info!(path = ?data_path, "(app) data directory ready to be used");

    // NOTE: HAR support not yet enable for L4 proxy,
    // check with Glen if this is ever a desired feature :)

    // ensure to not wait for firewall creation in case shutdown was initiated,
    // this can happen for example in case remote lists need to be fetched and the
    // something on the network on either side is not working
    tokio::select! {
        result = Firewall::try_new(
            guard.clone(),
            client::new_web_client()?,
            data_storage,
            reporting_endpoint,
            agent_identity,
            aikido_url,
        ) => {
            result
        }

        _ = guard.downgrade().into_cancelled() => {
            Err(BoxError::from(
                "shutdown initiated prior to firewall created; exit process immediately",
            ))
        }
    }
}
