use std::sync::Arc;

use rama::{
    Service,
    error::BoxError,
    http::{
        Request, Response,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayOutput},
    },
};

use super::rule::{RequestAction, Rule as _};

#[derive(Debug, Clone)]
/// Matched firewall rules for http traffic and protocols built upon it.
///
/// Can be created via the Firewall by matching on the target domain.
pub struct FirewallHttpRules(pub(super) Arc<[super::rule::DynRule]>);

impl FirewallHttpRules {
    pub(super) async fn evaluate_http_request(
        &self,
        req: Request,
    ) -> Result<RequestAction, BoxError> {
        let mut mod_req = req;

        for rule in self.0.iter() {
            match rule.evaluate_request(mod_req).await? {
                RequestAction::Allow(new_mod_req) => mod_req = new_mod_req,
                RequestAction::Block(blocked) => {
                    return Ok(RequestAction::Block(blocked));
                }
            }
        }

        Ok(RequestAction::Allow(mod_req))
    }

    pub(super) async fn evaluate_http_response(
        &self,
        resp: Response,
    ) -> Result<Response, BoxError> {
        let mut mod_resp = resp;

        // Iterate rules in reverse order for symmetry with request evaluation
        for rule in self.0.iter().rev() {
            mod_resp = rule.evaluate_response(mod_resp).await?;
        }

        Ok(mod_resp)
    }

    pub fn match_ws_rules<'a>(
        &self,
        info: super::rule::WebSocketHandshakeInfo<'a>,
    ) -> Option<FirewallWebSocketRules> {
        let matched_rules: Arc<[super::rule::DynRule]> = self
            .0
            .iter()
            .filter(|rule| rule.match_ws_handshake(info))
            .cloned()
            .collect();

        if matched_rules.is_empty() {
            None
        } else {
            Some(FirewallWebSocketRules(matched_rules))
        }
    }
}

#[derive(Debug, Clone)]
/// Matched ws rules.
///
/// Is created via [`FirewallHttpRules`].
pub struct FirewallWebSocketRules(pub(super) Arc<[super::rule::DynRule]>);

impl Service<WebSocketRelayInput> for FirewallWebSocketRules {
    type Output = WebSocketRelayOutput;
    type Error = BoxError;

    async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
        let dir = input.direction;
        let mut output = input.into();

        match dir {
            WebSocketRelayDirection::Ingress => {
                for rule in self.0.iter() {
                    output = rule.evaluate_ws_relay_msg(dir, output).await?;
                }
            }
            WebSocketRelayDirection::Egress => {
                for rule in self.0.iter().rev() {
                    output = rule.evaluate_ws_relay_msg(dir, output).await?;
                }
            }
        }

        Ok(output)
    }
}
