use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use rama::{
    Layer, Service,
    bytes::Bytes,
    combinators::Either,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    extensions::ExtensionsRef,
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
        apple::networkextension::{
            NwTcpStream, TcpFlow,
            tproxy::{TransparentProxyFlowMeta, TransparentProxyServiceContext},
        },
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    telemetry::tracing,
    tls::boring::proxy::{TlsMitmRelay, cert_issuer::BoringMitmCertIssuer},
};

use crate::{
    config::ProxyConfig,
    state::{LiveCa, SharedCaState},
};
use safechain_proxy_lib::{
    endpoint_protection::remote_app_passthrough_list::PassthroughMatchContext,
    http::{
        client::new_http_client_for_internal,
        firewall::{Firewall, FirewallDecompressionMatcher},
        service::hijack::{self, HIJACK_DOMAIN},
        ws_relay::WebSocketMitmRelayService,
    },
    storage,
    tls::mitm_relay_policy::TlsMitmRelayPolicyLayer,
    utils::token::AgentIdentity,
};

struct TcpMitmServiceInner {
    proxy_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    firewall: Firewall,
    state: SharedCaState,
}

#[derive(Clone)]
pub(super) struct TcpMitmService(Arc<TcpMitmServiceInner>);

impl TcpMitmService {
    pub(super) async fn try_new(
        ctx: TransparentProxyServiceContext,
    ) -> Result<(Self, SharedCaState), BoxError> {
        let proxy_config = ProxyConfig::from_opaque_config(ctx.opaque_config())
            .context("decode proxy config (json)")?;

        let legacy_pems = match (
            proxy_config.ca_cert_pem.as_deref(),
            proxy_config.ca_key_pem.as_deref(),
        ) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (Some(_), None) | (None, Some(_)) => {
                return Err(OpaqueError::from_static_str(
                    "legacy MITM CA passthrough requires both `ca_cert_pem` and `ca_key_pem`",
                )
                .into_box_error());
            }
            (None, None) => None,
        };

        let active = crate::tls::load_or_create_active_ca(legacy_pems)
            .context("load or mint active MITM CA")?;
        let live = LiveCa {
            active: Arc::new(active),
            pending: None,
        };
        let state: SharedCaState = Arc::new(ArcSwap::from_pointee(live));

        let data_path =
            crate::utils::storage::storage_dir().context("(app) data path is missing")?;

        let guard = ctx
            .executor
            .guard()
            .cloned()
            .context("L4 engine runtime is expected to inject shutdown guard")?;

        tracing::debug!("creating firewall state for transparent proxy extension");
        let firewall = create_firewall(
            guard,
            Some(data_path),
            proxy_config.agent_identity.clone(),
            proxy_config.reporting_endpoint.clone(),
            proxy_config.aikido_url.clone(),
            proxy_config.no_firewall,
        )
        .await?;

        tracing::debug!("creating tcp mitm state for transparent proxy extension");

        let service = Self(Arc::new(TcpMitmServiceInner {
            proxy_config,
            tls_mitm_relay_policy: TlsMitmRelayPolicyLayer::new(firewall.clone()),
            firewall,
            state: state.clone(),
        }));

        Ok((service, state))
    }

    pub(super) fn proxy_config(&self) -> &ProxyConfig {
        &self.0.proxy_config
    }

    pub(super) fn new_intercept_service(
        &self,
        exec: Executor,
        tls_peek_duration: Duration,
        http_peek_duration: Duration,
    ) -> TcpInterceptService {
        TcpInterceptService {
            mitm: self.clone(),
            exec,
            tls_peek_duration,
            http_peek_duration,
        }
    }

    pub fn is_passthrough_flow(&self, meta: &TransparentProxyFlowMeta) -> bool {
        let Some(ref bundle_id) = meta.source_app_bundle_identifier else {
            return false;
        };

        self.0
            .firewall
            .is_passthrough_traffic(&PassthroughMatchContext {
                app_bundle_id: Some(bundle_id),
                domain: None,
            })
    }

    pub fn is_passthrough_destination(&self, addr: std::net::IpAddr) -> bool {
        self.0.firewall.is_passthrough_destination(addr)
    }

    fn new_bridge_service<Ingress, Egress>(
        &self,
        exec: Executor,
        within_connect_tunnel: bool,
        tls_peek_duration: Duration,
        http_peek_duration: Duration,
    ) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
    where
        Ingress: Io + Unpin + ExtensionsRef,
        Egress: Io + Unpin + ExtensionsRef,
    {
        // Snapshot the live CA state at flow-build time. Pending rotations
        // surface to new flows on the next bridge build; in-flight flows keep
        // serving with whatever they captured. This matches the rama
        // transparent-proxy demo's approach.
        let live: Arc<LiveCa> = self.0.state.load_full();
        let active_relay = live.active.relay.clone();
        let hijack_pem = live.hijack_cert_pem().clone();

        new_tcp_service_inner(
            exec,
            self.0.tls_mitm_relay_policy.clone(),
            active_relay,
            self.0.firewall.clone(),
            hijack_pem,
            within_connect_tunnel,
            tls_peek_duration,
            http_peek_duration,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    hijack_pem: Bytes,
    within_connect_tunnel: bool,
    tls_peek_duration: Duration,
    http_peek_duration: Duration,
) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    let http_mitm_svc =
        HttpMitmRelay::new(exec.clone()).with_http_middleware(http_relay_middleware(
            exec,
            tls_mitm_relay_policy.clone(),
            tls_mitm_relay.clone(),
            firewall,
            hijack_pem,
            within_connect_tunnel,
            tls_peek_duration,
            http_peek_duration,
        ));

    let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
        .with_peek_timeout(http_peek_duration)
        .with_fallback(IoForwardService::new());

    let app_mitm_layer = PeekTlsClientHelloService::new(
        (tls_mitm_relay_policy, tls_mitm_relay).into_layer(maybe_http_mitm_svc.clone()),
    )
    .with_peek_timeout(tls_peek_duration)
    .with_fallback(maybe_http_mitm_svc);

    if within_connect_tunnel {
        return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
    }

    let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());
    let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay)
        .with_peek_timeout(http_peek_duration)
        .with_fallback(app_mitm_layer);

    Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
}

#[allow(clippy::too_many_arguments)]
fn http_relay_middleware<S, Issuer>(
    exec: Executor,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    hijack_pem: Bytes,
    within_connect_tunnel: bool,
    tls_peek_duration: Duration,
    http_peek_duration: Duration,
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
            tls_mitm_relay_policy,
            tls_mitm_relay,
            firewall.clone(),
            hijack_pem.clone(),
            true,
            tls_peek_duration,
            http_peek_duration,
        )
        .boxed()
    };

    (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        StreamCompressionLayer::new().with_compress_predicate(MirrorDecompressed::new()),
        HijackLayer::new(
            DomainMatcher::exact(HIJACK_DOMAIN),
            Arc::new(hijack::new_service(hijack_pem, firewall.clone())),
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
    maybe_data_path: Option<PathBuf>,
    agent_identity: Option<AgentIdentity>,
    reporting_endpoint: Option<Uri>,
    aikido_url: Uri,
    no_firewall: bool,
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

    let https_client = new_http_client_for_internal(Executor::graceful(guard.clone()))
        .context("create firewall's inner http(s) client")?;

    if no_firewall {
        tracing::warn!("Starting without firewall due to the --no-firewall startup flag");
        return Firewall::empty().await;
    }

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
            Err(OpaqueError::from_static_str(
                "shutdown initiated prior to firewall created; exit process immediately",
            ).into_box_error())
        }
    }
}

#[derive(Clone)]
pub(super) struct TcpInterceptService {
    mitm: TcpMitmService,
    exec: Executor,
    tls_peek_duration: Duration,
    http_peek_duration: Duration,
}

impl Service<BridgeIo<TcpFlow, NwTcpStream>> for TcpInterceptService {
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        bridge: BridgeIo<TcpFlow, NwTcpStream>,
    ) -> Result<Self::Output, Self::Error> {
        let mitm_svc = self.mitm.new_bridge_service(
            self.exec.clone(),
            false,
            self.tls_peek_duration,
            self.http_peek_duration,
        );
        mitm_svc.serve(bridge).await
    }
}
