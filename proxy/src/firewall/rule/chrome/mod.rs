use std::{borrow::Cow, fmt, str::FromStr};

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
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

use radix_trie::TrieCommon;

use crate::{
    firewall::{
        events::{BlockedArtifact, BlockedEventInfo},
        malware_list::{PackageVersion, RemoteMalwareList},
        pac::PacScriptGenerator,
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

pub(in crate::firewall) struct RuleChrome {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RuleChrome {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        Ok(Self {
            target_domains: ["clients2.google.com"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
            remote_malware_list,
        })
    }
}

impl fmt::Debug for RuleChrome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleChrome").finish()
    }
}

impl Rule for RuleChrome {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Chrome Plugin"
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
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Chrome rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let Some(ChromeExtensionRequestInfo {
            product_id,
            version,
        }) = self.extract_chrome_ext_info_from_req(&req)
        else {
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.full = %req.uri(),
            http.request.method = %req.method(),
            "inspect chrome extension product id: {product_id}, version: {:?}",
            version
        );

        if self.is_extension_id_malware(product_id.as_str()) {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "blocked Chrome extension: {product_id}, version: {:?}",
                version
            );

            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_generic_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("chrome"),
                        identifier: product_id,
                        version,
                    },
                },
            }));
        }
        Ok(RequestAction::Allow(req))
    }
}

struct ChromeExtensionRequestInfo {
    product_id: ArcStr,
    version: Option<PackageVersion>,
}

impl RuleChrome {
    fn is_extension_id_malware(&self, extension_id: &str) -> bool {
        // Chrome malware list format: "Full Title - Chrome Web Store@<extension-id>"
        let suffix = format!("@{}", extension_id);
        let suffix_lower = suffix.to_ascii_lowercase();

        let guard = self.remote_malware_list.find_entries("").guard;

        guard
            .iter()
            .any(|(key, _)| key.to_ascii_lowercase().ends_with(&suffix_lower))
    }
    fn extract_chrome_ext_info_from_req(
        &self,
        req: &Request,
    ) -> Option<ChromeExtensionRequestInfo> {
        if !starts_with_ignore_ascii_case(req.uri().path(), "/service/update2/crx") {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "chrome rule: no matching path found; req can passthrough",
            );
            return None;
        }

        // Example URLs we handle:
        // 1. Unencoded: https://clients2.google.com/service/update2/crx?x=id=abcdefghijklmnop&v=1.2.3
        // 2. URL-encoded: https://clients2.google.com/service/update2/crx?x=id%3Dabcdefghijklmnop%26v%3D1.2.3
        #[derive(Deserialize)]
        struct QueryParameters<'q> {
            x: Cow<'q, str>,
            #[serde(default)]
            v: Option<Cow<'q, str>>,
        }

        let Ok(Query(QueryParameters { x, v })) = Query::parse_query_str(req.uri().query()?) else {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "chrome rule: query empty or failed to parse into a known value; req can passthrough",
            );
            return None;
        };

        let Some(product_id) = x.strip_prefix("id=").map(|s| s.trim()) else {
            tracing::trace!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "chrome rule: failed to extract product id from parsed query, req can passthrough",
            );
            return None;
        };

        // Extract version from either:
        // 1. Separate query parameter: ?x=id=<id>&v=<version>
        // 2. Embedded in x parameter (URL encoded): ?x=id%3D<id>%26v%3D<version>
        let (product_id, version) = if let Some(version_param) = v {
            // Case 1: Version in separate query parameter
            let parsed_version = PackageVersion::from_str(version_param.as_ref()).ok();
            (product_id, parsed_version)
        } else if let Some((id, rest)) = product_id.split_once('&') {
            // Case 2: Version embedded in x parameter after &
            let parsed_version = rest
                .strip_prefix("v=")
                .and_then(|v| PackageVersion::from_str(v.trim()).ok());
            (id, parsed_version)
        } else {
            // No version found
            (product_id, None)
        };

        let product_id = ArcStr::from(product_id);

        Some(ChromeExtensionRequestInfo {
            product_id,
            version,
        })
    }
}

#[cfg(test)]
mod test;
