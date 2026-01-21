use std::{borrow::Cow, fmt};

use rama::{
    Service,
    error::OpaqueError,
    graceful::ShutdownGuard,
    http::{Request, Response, Uri, service::web::extract::Query},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::{
        arcstr::{ArcStr, arcstr},
        starts_with_ignore_ascii_case,
    },
};

use serde::Deserialize;

use crate::{
    firewall::{
        events::{BlockedArtifact, BlockedEventInfo},
        malware_list::RemoteMalwareList,
        pac::PacScriptGenerator,
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

pub(in crate::firewall) struct RuleChrome {
    target_domains: DomainTrie<()>,
    malware_list: RemoteMalwareList,
}

impl RuleChrome {
    pub(in crate::firewall) async fn try_new<S>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: S,
        data: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        S: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        Ok(Self {
            target_domains: ["clients2.google.com"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
            malware_list: RemoteMalwareList::try_new(
                guard,
                Uri::from_static("https://malware-list.aikido.dev/malware_chrome_extensions.json"),
                data.clone(),
                remote_malware_list_https_client,
            )
            .await?,
        })
    }
}

impl fmt::Debug for RuleChrome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleChrome").finish()
    }
}

// NOTE:
//
// Once there is a chrome malware list you'll
// want to fetch this package info from the (remote) Malware list

impl Rule for RuleChrome {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Chrome"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        // Pass through for now - response modification can be added in future PR
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        let Some(ChromeExtensionRequestInfo { domain, product_id }) =
            self.extract_chrome_ext_info_from_req(&req)
        else {
            return Ok(RequestAction::Allow(req));
        };

        // Note: product_id extraction logic might include version info after ampersand
        // We need to clean it up before checking against malware list
        let clean_product_id = match product_id.split('&').next() {
            Some(id) => id,
            None => product_id.as_str(),
        };

        tracing::trace!(
            http.url.full = %req.uri(),
            http.host = %domain,
            http.request.method = %req.method(),
            "inspect chrome extension product id: {clean_product_id} (original: {product_id})",
        );

        if self
            .malware_list
            .find_entries(clean_product_id)
            .entries()
            .is_some()
        {
            tracing::debug!(
                http.url.full = %req.uri(),
                http.host = %domain,
                http.request.method = %req.method(),
                "blocked Chrome extension: {clean_product_id}",
            );

            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_generic_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("chrome"),
                        identifier: ArcStr::from(clean_product_id),
                        version: None,
                    },
                },
            }));
        }

        tracing::trace!(
            http.url.full = %req.uri(),
            http.host = %domain,
            http.request.method = %req.method(),
            "chrome rule: extension can pass through: {clean_product_id}",
        );

        Ok(RequestAction::Allow(req))
    }
}

struct ChromeExtensionRequestInfo<'a> {
    domain: Cow<'a, Domain>,
    product_id: ArcStr,
}

impl RuleChrome {
    fn extract_chrome_ext_info_from_req<'a>(
        &self,
        req: &'a Request,
    ) -> Option<ChromeExtensionRequestInfo<'a>> {
        let Some(domain) = crate::http::try_get_domain_for_req(req)
            .and_then(|d| self.match_domain(&d).then_some(d))
        else {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "chrome rule: no matching domain found; req can passthrough",
            );
            return None;
        };

        if !starts_with_ignore_ascii_case(req.uri().path(), "/service/update2/crx") {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.host = %domain,
                http.request.method = %req.method(),
                "chrome rule: no matching path found; req can passthrough",
            );
            return None;
        }

        #[derive(Deserialize)]
        struct QueryParameters<'a> {
            /// cryptic single letter name chosen by Google... Don't blame me.
            ///
            /// It contains for the requests we care about the product id in the format
            /// `x=id=<product_id>`.
            x: Cow<'a, str>,
        }

        let Ok(Query(QueryParameters { x })) = Query::parse_query_str(req.uri().query()?) else {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.host = %domain,
                http.request.method = %req.method(),
                "chrome rule: query empty or failed to parse into a known value; req can passthrough",
            );
            return None;
        };

        let Some(product_id) = x.strip_prefix("id=").map(|s| s.trim()) else {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.host = %domain,
                http.request.method = %req.method(),
                "chrome rule: failed to extract product id from parsed query, req can passthrough",
            );
            return None;
        };

        let product_id = product_id
            .split_once('&')
            .map(|p| p.0)
            .unwrap_or(product_id)
            .into();

        Some(ChromeExtensionRequestInfo { domain, product_id })
    }
}
