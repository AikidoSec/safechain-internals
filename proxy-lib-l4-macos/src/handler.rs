use std::{convert::Infallible, future::Future, time::Duration};

use rama::{
    Service,
    error::BoxError,
    io::BridgeIo,
    net::{
        address::{Host, HostWithPort},
        apple::networkextension::{
            NwTcpStream, NwUdpSocket, TcpFlow, UdpFlow,
            tproxy::{
                FlowAction, TransparentProxyConfig, TransparentProxyFlowAction,
                TransparentProxyFlowMeta, TransparentProxyFlowProtocol, TransparentProxyHandler,
                TransparentProxyHandlerFactory, TransparentProxyNetworkRule,
                TransparentProxyRuleProtocol, TransparentProxyServiceContext,
            },
        },
    },
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
    utils::str::any_starts_with_ignore_ascii_case,
};
use safechain_proxy_lib::{
    nostd::net::is_passthrough_ip,
    tcp::{is_known_http_port, is_known_tls_port},
};

type UdpFlowService = BoxService<BridgeIo<UdpFlow, NwUdpSocket>, (), Infallible>;

#[derive(Debug, Clone)]
pub struct FlowHandlerFactory;

#[derive(Clone)]
pub struct FlowHandler {
    config: TransparentProxyConfig,
    tcp_mitm_service: crate::tcp::TcpMitmService,
}

impl FlowHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, BoxError> {
        let executor = ctx.executor.clone();
        let (tcp_mitm_service, ca_state) = crate::tcp::TcpMitmService::try_new(ctx).await?;

        let cfg = tcp_mitm_service.proxy_config();
        if cfg.xpc_service_name.is_some()
            || cfg.container_signing_identifier.is_some()
            || cfg.container_team_identifier.is_some()
        {
            // All XPC identity fields must be set together — the inner spawn enforces
            // that and fails closed if either is missing. We swallow the
            // result here so a misconfigured XPC config does not bring the
            // whole transparent proxy down: TLS interception keeps working,
            // only `generate-ca-crt` / `commit-ca-crt` become unavailable.
            if let Err(err) = crate::xpc_server::spawn(
                cfg.xpc_service_name.clone(),
                cfg.container_signing_identifier.clone(),
                cfg.container_team_identifier.clone(),
                ca_state,
                executor,
            ) {
                tracing::error!(
                    error = %err,
                    "failed to spawn aikido L4 sysext XPC server; CA generate/commit \
                     routes will be unavailable"
                );
            }
        } else {
            tracing::warn!(
                "xpc_service_name, container_signing_identifier, and \
                 container_team_identifier are all unset in opaque engine config; XPC \
                 server not spawned. `generate-ca-crt` / `commit-ca-crt` will not be \
                 available until all required identity fields are provided."
            );
        }

        let proxy_config = TransparentProxyConfig::new().with_rules(vec![
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Udp),
        ]);

        Ok(Self {
            config: proxy_config,
            tcp_mitm_service,
        })
    }
}

impl TransparentProxyHandlerFactory for FlowHandlerFactory {
    type Handler = FlowHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        FlowHandler::try_new(ctx)
    }
}

impl TransparentProxyHandler for FlowHandler {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.config.clone()
    }

    fn match_tcp_flow(
        &self,
        exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let action = if self.tcp_mitm_service.is_passthrough_flow(&meta) {
            tracing::debug!(
                app_bundle = ?meta.source_app_bundle_identifier,
                remote = ?meta.remote_endpoint,
                "passthrough: app bundle matches passthrough (for any domain)"
            );
            FlowAction::Passthrough
        } else if is_configured_cidr_passthrough(&meta, &self.tcp_mitm_service) {
            tracing::debug!(
                app_bundle = ?meta.source_app_bundle_identifier,
                remote = ?meta.remote_endpoint,
                "passthrough: CIDR for remote endpoint matches passthrough"
            );
            FlowAction::Passthrough
        } else {
            match flow_action(&meta) {
                TransparentProxyFlowAction::Intercept => {
                    let port = meta.remote_endpoint.as_ref().map(|e| e.port).unwrap_or(0);
                    let cfg = self.tcp_mitm_service.proxy_config();
                    let tls_peek_duration = peek_duration(if is_known_tls_port(port) {
                        cfg.peek_duration_s
                    } else {
                        cfg.peek_unknown_port_duration_s
                    });
                    let http_peek_duration = peek_duration(if is_known_http_port(port) {
                        cfg.peek_duration_s
                    } else {
                        cfg.peek_unknown_port_duration_s
                    });
                    FlowAction::Intercept {
                        service: self.tcp_mitm_service.new_intercept_service(
                            exec,
                            tls_peek_duration,
                            http_peek_duration,
                        ),
                        meta,
                    }
                }
                TransparentProxyFlowAction::Passthrough => FlowAction::Passthrough,
                TransparentProxyFlowAction::Blocked => FlowAction::Blocked,
            }
        };

        std::future::ready(action)
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<UdpFlow, NwUdpSocket>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let action = if self.tcp_mitm_service.is_passthrough_flow(&meta) {
            tracing::warn!(
                protocol = ?meta.source_app_bundle_identifier,
                "passthrough: app bundle matches passthrough for any domain"
            );
            FlowAction::Passthrough
        } else if is_configured_cidr_passthrough(&meta, &self.tcp_mitm_service) {
            FlowAction::Passthrough
        } else {
            match flow_action(&meta) {
                TransparentProxyFlowAction::Intercept => {
                    tracing::warn!(
                        protocol = ?meta.protocol,
                        remote = ?meta.remote_endpoint,
                        local = ?meta.local_endpoint,
                        "unexpected udp intercept decision; passing through"
                    );
                    FlowAction::<UdpFlowService>::Passthrough
                }
                TransparentProxyFlowAction::Passthrough => {
                    FlowAction::<UdpFlowService>::Passthrough
                }
                TransparentProxyFlowAction::Blocked => FlowAction::<UdpFlowService>::Blocked,
            }
        };

        std::future::ready(action)
    }
}

fn peek_duration(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds.max(0.001))
}

fn flow_action(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow intercept decision: evaluating"
    );

    let Some(remote_host) = remote_host_for_interception(meta) else {
        return TransparentProxyFlowAction::Passthrough;
    };

    match meta.protocol {
        TransparentProxyFlowProtocol::Tcp => {
            tracing::debug!(
                protocol = ?meta.protocol,
                remote = ?meta.remote_endpoint,
                local = ?meta.local_endpoint,
                app_bundle_id = ?meta.source_app_bundle_identifier,
                app_sign_id = ?meta.source_app_signing_identifier,
                "flow action: tcp traffic: intercept"
            );
            TransparentProxyFlowAction::Intercept
        }
        TransparentProxyFlowProtocol::Udp => flow_action_udp(meta, remote_host),
    }
}

fn flow_action_udp(
    meta: &TransparentProxyFlowMeta,
    remote_host: HostWithPort,
) -> TransparentProxyFlowAction {
    if remote_host.port != 443 {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "flow action: udp traffic with port != 443: passthrough"
        );
        return TransparentProxyFlowAction::Passthrough;
    }

    if meta
        .source_app_bundle_identifier
        .as_deref()
        .map(is_chromium_bundle_identifier)
        .unwrap_or(false)
    {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "flow action: udp traffic on port 443 for chromium browser: block"
        );
        return TransparentProxyFlowAction::Blocked;
    }

    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow action: udp traffic on port 443 for non-chromium app: passthrough"
    );
    TransparentProxyFlowAction::Passthrough
}

fn remote_host_for_interception(meta: &TransparentProxyFlowMeta) -> Option<HostWithPort> {
    let Some(target) = meta.remote_endpoint.as_ref() else {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "remote host is missing: passthrough traffic"
        );
        return None;
    };

    match &target.host {
        Host::Name(_) => Some(target.clone()),
        Host::Address(addr) => {
            if is_passthrough_ip(*addr) {
                tracing::debug!(
                    protocol = ?meta.protocol,
                    remote = ?meta.remote_endpoint,
                    local = ?meta.local_endpoint,
                    app_bundle_id = ?meta.source_app_bundle_identifier,
                    app_sign_id = ?meta.source_app_signing_identifier,
                    "remote host is within passthrough IP range: passthrough traffic"
                );
                None
            } else {
                Some(target.clone())
            }
        }
    }
}

fn is_configured_cidr_passthrough(
    meta: &TransparentProxyFlowMeta,
    mitm: &crate::tcp::TcpMitmService,
) -> bool {
    let Some(ref endpoint) = meta.remote_endpoint else {
        return false;
    };
    let Host::Address(addr) = &endpoint.host else {
        return false;
    };
    if mitm.is_passthrough_destination(*addr) {
        tracing::debug!(
            remote = ?meta.remote_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            "passthrough: remote IP is within configured CIDR passthrough range"
        );
        return true;
    }
    false
}

fn is_chromium_bundle_identifier(identifier: &str) -> bool {
    any_starts_with_ignore_ascii_case(
        identifier,
        [
            // Google Chrome
            "com.google.chrome",
            // Chromium and forks that reuse upstream id
            "org.chromium",
            // Microsoft Edge
            "com.microsoft.edgemac",
            "com.microsoft.msedge",
            // Brave
            "com.brave.browser",
            "com.brave.ios",
            // Opera
            "com.operasoftware.opera",
            // Vivaldi
            "com.vivaldi",
            // Arc
            "company.thebrowser",
            // Yandex
            "ru.yandex",
            // Common alt Chromium builds
            "com.github.eloston", // ungoogled chromium
        ],
    )
}
