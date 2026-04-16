use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions::{self, ExtensionsRef},
    http::ws::handshake::{
        matcher::HttpWebSocketRelayHandshakeRequest, mitm::WebSocketRelayService,
    },
    io::{BridgeIo, Io},
    net::proxy::{IoForwardService, ProxyTarget},
    service::MirrorService,
    telemetry::tracing,
    utils::str::smol_str::ToSmolStr,
};

use crate::{
    http::firewall::{FirewallHttpRules, rule::WebSocketHandshakeInfo},
    utils::net::{get_app_source_bundle_id_from_ext, get_source_process_path_from_ext},
};

#[derive(Debug, Clone, Default)]
pub struct WebSocketMitmRelayService {
    mitm_all: bool,
}

impl WebSocketMitmRelayService {
    pub fn new() -> Self {
        Self { mitm_all: false }
    }

    rama::utils::macros::generate_set_and_with! {
        /// Configure the policy to MITM _all_ traffic,
        /// even if not required by the firewall.
        pub fn mitm_all(mut self, all: bool) -> Self {
            self.mitm_all = all;
            self
        }
    }
}

impl<Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for WebSocketMitmRelayService
where
    Ingress: Io + Unpin + extensions::ExtensionsMut,
    Egress: Io + Unpin + extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        bridge_io: BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let proxy_target = bridge_io.extensions().get::<ProxyTarget>().cloned();
        let source_app_bundle_id =
            get_app_source_bundle_id_from_ext(&bridge_io).map(|s| s.to_smolstr());
        let source_process_path =
            get_source_process_path_from_ext(&bridge_io).map(|s| s.to_smolstr());

        if let Some(http_rules) = bridge_io.extensions().get::<FirewallHttpRules>()
            && let Some(ws_rules) = http_rules.match_ws_rules(WebSocketHandshakeInfo {
                domain: proxy_target
                    .as_ref()
                    .and_then(|target| target.0.host.as_domain()),
                app_source_bundle_id: get_app_source_bundle_id_from_ext(&bridge_io),
                source_process_path: get_source_process_path_from_ext(&bridge_io),
                req_headers: bridge_io
                    .extensions()
                    .get::<HttpWebSocketRelayHandshakeRequest>()
                    .map(|req| req.0.as_ref()),
            })
        {
            tracing::debug!(
                ?source_app_bundle_id,
                ?source_process_path,
                ?proxy_target,
                "relay WS traffic (matched ws rules)"
            );
            WebSocketRelayService::new(ws_rules)
                .serve(bridge_io)
                .await
                .context("relay WS traffic (MITM) (matched ws rules)")
                .context_debug_field("source_app_bundle_id", source_app_bundle_id)
                .context_debug_field("source_process_path", source_process_path)
                .context_debug_field("proxy_target", proxy_target)
        } else if self.mitm_all {
            tracing::debug!(
                ?source_app_bundle_id,
                ?source_process_path,
                ?proxy_target,
                "relay WS traffic (mitm_all)"
            );
            WebSocketRelayService::new(MirrorService::new())
                .serve(bridge_io)
                .await
                .context("relay WS traffic (MITM) (mitm all)")
                .context_debug_field("source_app_bundle_id", source_app_bundle_id)
                .context_debug_field("source_process_path", source_process_path)
                .context_debug_field("proxy_target", proxy_target)
        } else {
            tracing::debug!(
                ?source_app_bundle_id,
                ?source_process_path,
                ?proxy_target,
                "WS traffic is not to be relayed... IO forwarding instead..."
            );
            IoForwardService::new()
                .serve(bridge_io)
                .await
                .context("Io-forward WS traffic (no MITM)")
                .context_debug_field("source_app_bundle_id", source_app_bundle_id)
                .context_debug_field("source_process_path", source_process_path)
                .context_debug_field("proxy_target", proxy_target)
        }
    }
}
