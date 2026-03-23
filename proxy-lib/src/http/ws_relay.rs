use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions::{self, ExtensionsRef},
    http::ws::handshake::{
        matcher::HttpWebSocketRelayHandshakeRequest, mitm::WebSocketRelayService,
    },
    io::{BridgeIo, Io},
    net::proxy::{IoForwardService, ProxyTarget},
    telemetry::tracing,
};

use crate::{
    http::firewall::{Firewall, rule::WebSocketHandshakeInfo},
    utils::net::get_app_source_bundle_id_from_ext,
};

#[derive(Debug, Clone)]
pub struct WebSocketMitmRelayService {
    firewall: Firewall,
    mitm_all: bool,
}

impl WebSocketMitmRelayService {
    pub fn new(firewall: Firewall) -> Self {
        Self {
            firewall,
            mitm_all: false,
        }
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
        let ws_handshake_info = WebSocketHandshakeInfo {
            domain: proxy_target
                .as_ref()
                .and_then(|target| target.0.host.as_domain()),
            req_headers: bridge_io
                .extensions()
                .get::<HttpWebSocketRelayHandshakeRequest>()
                .map(|req| req.0.as_ref()),
        };
        let source_app_bundle_id =
            get_app_source_bundle_id_from_ext(&bridge_io).map(ToOwned::to_owned);

        if !self.mitm_all && !self.firewall.match_ws_handshake(ws_handshake_info) {
            tracing::debug!(
                source_app_bundle_id,
                ?proxy_target,
                "WS traffic is not to be relayed... IO forwarding instead..."
            );
            return IoForwardService::new()
                .serve(bridge_io)
                .await
                .context("Io-forward WS traffic (no MITM)")
                .context_debug_field("source_app_bundle_id", source_app_bundle_id)
                .context_debug_field("proxy_target", proxy_target);
        }

        WebSocketRelayService::new(self.firewall.clone().into_evaluate_ws_relay_msg_service())
            .serve(bridge_io)
            .await
            .context("relay WS traffic (MITM)")
            .context_debug_field("source_app_bundle_id", source_app_bundle_id)
            .context_debug_field("proxy_target", proxy_target)
    }
}
