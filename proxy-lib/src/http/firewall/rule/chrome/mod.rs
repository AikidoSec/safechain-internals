use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};

use crate::{
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator},
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{malware_list::RemoteMalwareList, version::PackageVersion},
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

mod malware_key;
mod parser;

pub(in crate::http::firewall) struct RuleChrome {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    policy_evaluator: Option<PolicyEvaluator>,
}

impl RuleChrome {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage,
            remote_malware_list_https_client,
            malware_key::ChromeMalwareListEntryFormatter,
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        Ok(Self {
            target_domains: [
                "clients2.google.com",
                "update.googleapis.com",
                "clients2.googleusercontent.com",
                "play.google.com",
                "chromewebstore.google.com",
                "chromewebstore.googleapis.com",
                "com.google.Chrome.helper",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
            policy_evaluator,
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
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[inline(always)]
    fn match_ws_handshake<'a>(&self, _: super::WebSocketHandshakeInfo<'a>) -> bool {
        false
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        let Some((extension_id, version)) = Self::parse_crx_download_url(&req) else {
            tracing::debug!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "Chrome-target request did not match known CRX download URL format"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.full = %req.uri(),
            http.request.method = %req.method(),
            "CRX download - extension id: {extension_id}, version: {:?}",
            version
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision =
                policy_evaluator.evaluate_package_install("chrome", extension_id.as_str());

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                decision => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(&extension_id, &version),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.matches_malware_entry(extension_id.as_str(), &version) {
            tracing::info!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "blocked Chrome extension from CRX URL: {extension_id}, version: {:?}",
                version
            );

            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&extension_id, &version),
                BlockReason::Malware,
            )));
        }

        Ok(RequestAction::Allow(req))
    }
}

impl RuleChrome {
    fn blocked_artifact(extension_id: &ArcStr, version: &PackageVersion) -> Artifact {
        Artifact {
            product: arcstr!("chrome"),
            identifier: extension_id.clone(),
            display_name: None,
            version: Some(version.clone()),
        }
    }

    fn matches_malware_entry(&self, extension_id: &str, version: &PackageVersion) -> bool {
        let normalized_id = extension_id.to_ascii_lowercase();
        let entries = self.remote_malware_list.find_entries(&normalized_id);
        let Some(entries) = entries.entries() else {
            return false;
        };

        entries.iter().any(|e| e.version.eq(version))
    }

    fn parse_crx_download_url(req: &Request) -> Option<(ArcStr, PackageVersion)> {
        self::parser::parse_crx_download_url(req)
    }
}

#[cfg(test)]
mod test;
