use rama::{
    Layer, Service,
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
            TcpFlow,
            tproxy::{TransparentProxyFlowMeta, TransparentProxyServiceContext},
        },
        client::{ConnectorService, EstablishedClientConnection},
        http::server::HttpPeekRouter,
        proxy::{IoForwardService, ProxyTarget},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    telemetry::tracing,
    tls::boring::proxy::{
        TlsMitmRelay,
        cert_issuer::{
            BoringMitmCertIssuer, CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer,
        },
    },
};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

use crate::config::ProxyConfig;
use safechain_proxy_lib::{
    endpoint_protection::remote_app_passthrough_list::PassthroughMatchContext,
    http::{
        client::new_http_client_for_internal,
        firewall::{Firewall, FirewallDecompressionMatcher},
        service::hijack::{self, HIJACK_DOMAIN},
        ws_relay::WebSocketMitmRelayService,
    },
    storage,
    tcp::new_tcp_connector_service_for_proxy,
    tls::{RootCaKeyPair, mitm_relay_policy::TlsMitmRelayPolicyLayer},
    utils::token::AgentIdentity,
};

type TcpTlsMitmRelay = TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>;

#[derive(Clone)]
pub(super) struct TcpMitmService {
    proxy_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TcpTlsMitmRelay,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
}

impl TcpMitmService {
    pub(super) async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, BoxError> {
        let proxy_config = ProxyConfig::from_opaque_config(ctx.opaque_config())
            .context("decode proxy config (json)")?;

        let Some((ca_crt_pem, ca_key_pem)) = proxy_config
            .ca_cert_pem
            .as_deref()
            .zip(proxy_config.ca_key_pem.as_deref())
        else {
            return Err(
                OpaqueError::from_static_str("CA crt or key missing in Opaque Config")
                    .into_box_error(),
            );
        };

        let data_path =
            crate::utils::storage::storage_dir().context("(app) data path is missing")?;
        let root_ca = RootCaKeyPair::try_form_pem(ca_crt_pem, ca_key_pem)
            .context("load config-provided ca crt/key pair")?;

        let ca_crt_pem_bytes: &[u8] = root_ca
            .certificate()
            .to_pem()
            .context("convert cert to pem")?
            .leak();

        let (ca_crt, ca_key) = root_ca.into_pair();

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
        )
        .await?;

        tracing::debug!("creating tcp mitm state for transparent proxy extension");

        Ok(Self {
            proxy_config,
            tls_mitm_relay_policy: TlsMitmRelayPolicyLayer::new(firewall.clone()),
            tls_mitm_relay: TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key),
            firewall,
            ca_crt_pem_bytes,
        })
    }

    pub(super) fn new_intercept_service(&self, exec: Executor) -> TcpInterceptService {
        TcpInterceptService {
            mitm: self.clone(),
            exec,
        }
    }

    pub fn is_passthrough_flow(&self, meta: &TransparentProxyFlowMeta) -> bool {
        let Some(ref bundle_id) = meta.source_app_bundle_identifier else {
            return false;
        };

        self.firewall
            .is_passthrough_traffic(&PassthroughMatchContext {
                app_bundle_id: Some(bundle_id),
                domain: None,
            })
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
        new_tcp_service_inner(
            exec,
            self.proxy_config.clone(),
            self.tls_mitm_relay_policy.clone(),
            self.tls_mitm_relay.clone(),
            self.firewall.clone(),
            self.ca_crt_pem_bytes,
            within_connect_tunnel,
            tls_peek_duration,
            http_peek_duration,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn new_tcp_service_inner<Issuer, Ingress, Egress>(
    exec: Executor,
    proxy_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
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
            proxy_config,
            tls_mitm_relay_policy.clone(),
            tls_mitm_relay.clone(),
            firewall,
            ca_crt_pem_bytes,
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
    proxy_config: ProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: TlsMitmRelay<Issuer>,
    firewall: Firewall,
    ca_crt_pem_bytes: &'static [u8],
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
            proxy_config,
            tls_mitm_relay_policy,
            tls_mitm_relay,
            firewall.clone(),
            ca_crt_pem_bytes,
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
}

impl Service<TcpFlow> for TcpInterceptService {
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, ingress: TcpFlow) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(egress_addr)) = ingress.extensions().get_ref().cloned() else {
            tracing::debug!("missing ProxyTarget in transparent proxy tcp service");
            return Ok(());
        };

        let connector = new_tcp_connector_service_for_proxy(self.exec.clone());
        let tcp_req = rama::tcp::client::Request::new_with_extensions(
            egress_addr.clone(),
            ingress.extensions().clone(),
        );

        let EstablishedClientConnection { conn: egress, .. } =
            match connector.connect(tcp_req).await {
                Ok(connection) => connection,
                Err(err) => {
                    tracing::debug!(
                        address = %egress_addr,
                        error = %err.into_box_error(),
                        "transparent proxy tcp connect failed"
                    );
                    return Ok(());
                }
            };

        let cfg = &self.mitm.proxy_config;
        let port = egress_addr.port;
        let tls_peek_duration = Duration::from_secs_f64(
            if is_known_tls_port(port) {
                cfg.peek_duration_s
            } else {
                cfg.peek_unknown_port_duration_s
            }
            .max(0.001),
        );
        let http_peek_duration = Duration::from_secs_f64(
            if is_known_http_port(port) {
                cfg.peek_duration_s
            } else {
                cfg.peek_unknown_port_duration_s
            }
            .max(0.001),
        );
        let mitm_svc = self.mitm.new_bridge_service(
            self.exec.clone(),
            false,
            tls_peek_duration,
            http_peek_duration,
        );
        let _ = mitm_svc.serve(BridgeIo(ingress, egress)).await;
        Ok(())
    }
}

#[inline]
fn is_known_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

#[inline]
fn is_known_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}
