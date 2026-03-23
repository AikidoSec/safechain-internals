use rama::{
    error::BoxError,
    http::{
        Request, Response,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayOutput},
    },
    net::address::Domain,
};

use crate::http::service::hijack::HIJACK_DOMAIN;

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{RequestAction, Rule};

#[derive(Debug, Default)]
/// Hijack domain handled locally by the proxy.
///
/// See the [`HIJACK_DOMAIN`] documentation for full details.
///
/// Available endpoints:
///
/// - `/ping`:  returns `200 OK` when intercepted by the proxy
///   (connectivity / health check)
/// - `/data/root.ca.pem`:
///   download the proxy CA certificate
///
/// If any of these endpoints respond successfully,
/// traffic is flowing through the proxy and the MITM pipeline is active.
pub(in crate::http::firewall) struct RuleHijack;

impl RuleHijack {
    pub(in crate::http::firewall) fn new() -> Self {
        Self
    }
}

impl Rule for RuleHijack {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "ProxyHijackSvc"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        HIJACK_DOMAIN.eq(domain)
    }

    #[inline(always)]
    fn match_ws_handshake<'a>(&self, _: super::WebSocketHandshakeInfo<'a>) -> bool {
        false
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        generator.write_domain(&HIJACK_DOMAIN)
    }

    #[inline(always)]
    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        Ok(resp)
    }

    #[inline(always)]
    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        Ok(RequestAction::Allow(req))
    }

    #[inline(always)]
    async fn evaluate_ws_relay_msg(
        &self,
        _: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Result<WebSocketRelayOutput, BoxError> {
        Ok(data)
    }
}
