use std::{convert::Infallible, future::Future};

use rama::{
    Service,
    error::BoxError,
    net::{
        address::{Host, HostWithPort},
        apple::networkextension::{
            TcpFlow, UdpFlow,
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
use safechain_proxy_lib::nostd::net::is_passthrough_ip;

type UdpFlowService = BoxService<UdpFlow, (), Infallible>;

#[derive(Debug, Clone)]
pub struct FlowHandlerFactory;

#[derive(Clone)]
pub struct FlowHandler {
    config: TransparentProxyConfig,
    tcp_mitm_service: crate::tcp::TcpMitmService,
}

impl FlowHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, BoxError> {
        let tcp_mitm_service = crate::tcp::TcpMitmService::try_new(ctx).await?;

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
    ) -> impl Future<Output = FlowAction<impl Service<TcpFlow, Output = (), Error = Infallible>>>
    + Send
    + '_ {
        let action = if self.tcp_mitm_service.passthrough_tcp(&meta) {
                tracing::warn!(
                    protocol = ?meta.source_app_bundle_identifier,
                    "passthrough: app bundle matches passthrough for any domain"
                );
            FlowAction::Passthrough
        } else {
            match flow_action(&meta) {
                TransparentProxyFlowAction::Intercept => FlowAction::Intercept {
                    service: self.tcp_mitm_service.new_intercept_service(exec),
                    meta,
                },
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
    ) -> impl Future<Output = FlowAction<impl Service<UdpFlow, Output = (), Error = Infallible>>>
    + Send
    + '_ {
        std::future::ready(match flow_action(&meta) {
            TransparentProxyFlowAction::Intercept => {
                tracing::warn!(
                    protocol = ?meta.protocol,
                    remote = ?meta.remote_endpoint,
                    local = ?meta.local_endpoint,
                    "unexpected udp intercept decision; passing through"
                );
                FlowAction::<UdpFlowService>::Passthrough
            }
            TransparentProxyFlowAction::Passthrough => FlowAction::<UdpFlowService>::Passthrough,
            TransparentProxyFlowAction::Blocked => FlowAction::<UdpFlowService>::Blocked,
        })
    }
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
