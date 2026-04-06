use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        Request, Response, Uri,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
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
        address::SocketAddress,
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        socket::{
            SocketOptions,
            opts::{Domain as SocketDomain, TcpKeepAlive},
        },
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    tcp::{TcpStream, proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing,
    tls::boring::proxy::{TlsMitmRelay, cert_issuer::BoringMitmCertIssuer},
};

use safechain_proxy_lib::{
    http::{
        client::new_http_client_for_internal,
        firewall::{Firewall, FirewallDecompressionMatcher},
        service::hijack::{self, HIJACK_DOMAIN},
        ws_relay::WebSocketMitmRelayService,
    },
    storage::{SyncCompactDataStorage, SyncSecrets},
    tcp::new_tcp_connector_service_for_proxy,
    tls::{self, mitm_relay_policy::TlsMitmRelayPolicyLayer},
    utils::token::AgentIdentity,
};

mod proxy_target;

#[allow(clippy::too_many_arguments)]
pub async fn start_tcp_server(
    bind: SocketAddr,
    executor: Executor,
    peek_duration: Duration,
    agent_identity: Option<AgentIdentity>,
    reporting_endpoint: Option<Uri>,
    aikido_url: Uri,
    data_storage: SyncCompactDataStorage,
    secret_storage: SyncSecrets,
) -> Result<SocketAddress, BoxError> {
    let tcp_svc = try_new_tcp_service(
        executor.clone(),
        peek_duration,
        agent_identity,
        reporting_endpoint,
        aikido_url,
        data_storage,
        secret_storage,
    )
    .await
    .context("create tcp service")?;

    let tcp_listener = try_new_tcp_listener(executor, bind.into())
        .await
        .context("create tcp listener")?;

    let tcp_addr = tcp_listener
        .local_addr()
        .context("retrieve local socket addr of (tcp) server (listener)")?;

    tokio::task::spawn(tcp_listener.serve(tcp_svc));

    Ok(tcp_addr.into())
}

async fn try_new_tcp_listener(
    executor: Executor,
    bind: SocketAddress,
) -> Result<TcpListener, BoxError> {
    let mut opts = SocketOptions::default_tcp();

    #[cfg(target_os = "linux")]
    {
        opts.ip_transparent = Some(true);
        opts.freebind = Some(true);
        opts.reuse_address = Some(true);
        opts.reuse_port = Some(true);
    }

    opts.tcp_no_delay = Some(true);
    opts.keep_alive = Some(true);
    opts.tcp_keep_alive = Some(TcpKeepAlive {
        time: Some(Duration::from_mins(2)),
        interval: Some(Duration::from_secs(30)),
        #[cfg(not(target_os = "windows"))]
        retries: Some(5),
    });

    opts.address = Some(bind);

    let socket = tokio::task::spawn_blocking(move || {
        opts.try_build_socket(if bind.ip_addr.is_ipv4() {
            SocketDomain::IPv4
        } else {
            SocketDomain::IPv6
        })
    })
    .await
    .context("wait blocking socket (tcp) bind task")?
    .context("bind tcp socket")?;
    socket
        .listen(32_768)
        .context("mark tcp socket ready for accepting connections")?;

    TcpListener::try_from_socket(socket, executor).context("create tcp listener from tcp socket")
}

async fn try_new_tcp_service(
    executor: Executor,
    peek_duration: Duration,
    agent_identity: Option<AgentIdentity>,
    reporting_endpoint: Option<Uri>,
    aikido_url: Uri,
    data_storage: SyncCompactDataStorage,
    secret_storage: SyncSecrets,
) -> Result<impl Service<TcpStream, Output = (), Error = Infallible> + Clone, BoxError> {
    let root_ca_key_pair = tls::load_or_create_root_ca_key_pair(&secret_storage, &data_storage)
        .context("prepare proxy traffic CA crt/key pair")?;

    let ca_crt_pem_bytes: &[u8] = root_ca_key_pair
        .certificate()
        .to_pem()
        .context("convert cert to pem")?
        .leak();

    let (ca_crt, ca_key) = root_ca_key_pair.into_pair();

    let guard = executor
        .guard()
        .cloned()
        .context("L4 engine runtime is expected to inject shutdown guard")?;

    tracing::debug!("creating firewall state for transparent proxy extension");
    let firewall = create_firewall(
        guard,
        data_storage,
        agent_identity,
        reporting_endpoint,
        aikido_url,
    )
    .await?;

    tracing::debug!("creating middleware and other services");

    let tls_mitm_relay_policy = TlsMitmRelayPolicyLayer::new(firewall.clone());
    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);

    let mitm_svc = new_tcp_service_inner(
        executor.clone(),
        peek_duration,
        tls_mitm_relay_policy,
        tls_mitm_relay,
        firewall,
        ca_crt_pem_bytes,
        false,
    );

    Ok(Arc::new(
        (
            ConsumeErrLayer::trace_as_debug(),
            self::proxy_target::new_proxy_target_from_input_layer(),
            IoToProxyBridgeIoLayer::extension_proxy_target_with_connector(
                new_tcp_connector_service_for_proxy(executor),
            ),
        )
            .into_layer(mitm_svc),
    ))
}

fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    peek_duration: Duration,
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
    let http_mitm_svc =
        HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
            exec,
            peek_duration,
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
    peek_duration: Duration,
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
            peek_duration,
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
        StreamCompressionLayer::new().with_compress_predicate(MirrorDecompressed::new()),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(hijack::new_service(ca_crt_pem_bytes)),
        ),
        firewall,
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new()
            .with_insert_accept_encoding_header(false)
            .with_matcher(FirewallDecompressionMatcher),
        HttpUpgradeMitmRelayLayer::new(
            exec,
            (
                HttpWebSocketRelayServiceRequestMatcher::new(
                    ConsumeErrLayer::trace_as_debug().into_layer(WebSocketMitmRelayService::new()),
                )
                .with_store_handshake_request_header(true),
                HttpProxyConnectRelayServiceRequestMatcher::new(http_conn_upgrade_svc),
            ),
        ),
        DpiProxyCredentialExtractorLayer::new(),
        ArcLayer::new(),
    )
}

async fn create_firewall(
    guard: ShutdownGuard,
    data_storage: SyncCompactDataStorage,
    agent_identity: Option<AgentIdentity>,
    reporting_endpoint: Option<Uri>,
    aikido_url: Uri,
) -> Result<Firewall, BoxError> {
    let https_client = new_http_client_for_internal(Executor::graceful(guard.clone()))
        .context("create firewall's inner http(s) client")?;

    // ensure to not wait for firewall creation in case shutdown was initiated,
    // this can happen for example in case remote lists need to be fetched and the
    // something on the network on either side is not working
    tokio::select! {
        result = Firewall::try_new(
            guard.clone(),
            https_client,
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
