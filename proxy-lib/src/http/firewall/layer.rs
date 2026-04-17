use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{Request, Response},
};

use crate::{
    http::try_get_domain_for_req,
    utils::net::{get_app_source_bundle_id_from_ext, get_source_process_path_from_ext},
};

use super::{Firewall, rule::RequestAction};

impl<S> Layer<S> for Firewall {
    type Service = FirewallService<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        FirewallService {
            inner,
            firewall: self.clone(),
        }
    }

    #[inline(always)]
    fn into_layer(self, inner: S) -> Self::Service {
        FirewallService {
            inner,
            firewall: self,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FirewallService<S> {
    inner: S,
    firewall: Firewall,
}

impl<S> Service<Request> for FirewallService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        // If the request already had a TLS handshake we just take the rules that have been matched
        // if not the case (e.g. insecure http traffic), we match here with match_http_rules (same function being used during tls handshake)
        let maybe_http_rules = match req.extensions().get_ref().cloned() {
            Some(rules) => Some(rules),
            None => try_get_domain_for_req(&req).and_then(|domain| {
                self.firewall.match_http_rules(&super::IncomingFlowInfo {
                    domain: &domain,
                    app_bundle_id: get_app_source_bundle_id_from_ext(&req),
                    source_process_path: get_source_process_path_from_ext(&req).as_deref(),
                })
            }),
        };

        if let Some(http_rules) = maybe_http_rules {
            let mod_req = match http_rules.evaluate_http_request(req).await? {
                RequestAction::Allow(allowed_mod_req) => {
                    allowed_mod_req.extensions().insert(http_rules.clone());
                    allowed_mod_req
                }
                RequestAction::Block(blocked) => {
                    self.firewall
                        .record_blocked_event(blocked.info.clone())
                        .await;
                    return Ok(blocked.response);
                }
            };

            let resp = self.inner.serve(mod_req).await.into_box_error()?;
            Ok(http_rules.evaluate_http_response(resp).await?)
        } else {
            self.inner.serve(req).await.into_box_error()
        }
    }
}
