use std::sync::Arc;

use rama::{
    Service,
    error::BoxError,
    extensions::{Extension, ExtensionsRef},
    http::{
        Request, Response,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayOutput},
    },
    matcher::service::{ServiceMatch, ServiceMatcher},
};

use super::rule::{HttpRequestMatcherView, HttpResponseMatcherView, RequestAction, Rule as _};

#[derive(Debug, Clone, Extension)]
/// Matched firewall rules for http traffic and protocols built upon it.
///
/// Can be created via the Firewall by matching on the target domain.
pub struct FirewallHttpRules(pub(super) Arc<[super::rule::DynRule]>);

impl FirewallHttpRules {
    pub fn has_http_response_payload_inspection_match<Body>(&self, req: &Request<Body>) -> bool {
        self.select_http_response_payload_inspection_rules(req)
            .is_some()
    }

    pub fn select_http_response_payload_inspection_rules<Body>(
        &self,
        req: &Request<Body>,
    ) -> Option<FirewallHttpResponsePayloadInspectionRules> {
        let req = HttpRequestMatcherView::new(req);
        let matched_rules: Arc<[super::rule::DynRule]> = self
            .0
            .iter()
            .filter(|rule| rule.match_http_response_payload_inspection_request(req))
            .cloned()
            .collect();

        if matched_rules.is_empty() {
            None
        } else {
            Some(FirewallHttpResponsePayloadInspectionRules(matched_rules))
        }
    }

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
pub struct FirewallHttpResponsePayloadInspectionRules(pub(super) Arc<[super::rule::DynRule]>);

impl FirewallHttpResponsePayloadInspectionRules {
    pub fn matches_http_response_payload_inspection<Body>(&self, resp: &Response<Body>) -> bool {
        let resp = HttpResponseMatcherView::new(resp);
        self.0
            .iter()
            .any(|rule| rule.match_http_response_payload_inspection_response(resp))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FirewallDecompressionMatcher;

impl<ReqBody> ServiceMatcher<Request<ReqBody>> for FirewallDecompressionMatcher
where
    ReqBody: Send + 'static,
{
    type Service = FirewallHttpResponsePayloadInspectionRules;
    type Error = std::convert::Infallible;
    type ModifiedInput = Request<ReqBody>;

    async fn match_service(
        &self,
        req: Request<ReqBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let service = req
            .extensions()
            .get_ref()
            .and_then(|rules: &FirewallHttpRules| {
                rules.select_http_response_payload_inspection_rules(&req)
            });

        Ok(ServiceMatch {
            input: req,
            service,
        })
    }
}

impl<ResBody> ServiceMatcher<Response<ResBody>> for FirewallHttpResponsePayloadInspectionRules
where
    ResBody: Send + 'static,
{
    type Service = ();
    type Error = std::convert::Infallible;
    type ModifiedInput = Response<ResBody>;

    async fn match_service(
        &self,
        resp: Response<ResBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: self
                .matches_http_response_payload_inspection(&resp)
                .then_some(()),
            input: resp,
        })
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

#[cfg(test)]
#[path = "matched_rules_tests.rs"]
mod tests;
