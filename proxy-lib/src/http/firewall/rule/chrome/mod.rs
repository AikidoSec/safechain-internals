use std::{fmt, str::FromStr};

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
    utils::str::smol_str::StrExt,
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
mod webstore;

use webstore::ChromeWebStore;

pub(in crate::http::firewall) struct RuleChrome<C> {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    policy_evaluator: Option<PolicyEvaluator>,
    https_client: C,
}

impl<C> RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = BoxError> + Clone,
{
    pub(in crate::http::firewall) async fn try_new(
        guard: ShutdownGuard,
        https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
    ) -> Result<Self, BoxError> {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage,
            https_client.clone(),
            malware_key::ChromeMalwareListEntryFormatter,
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        Ok(Self {
            target_domains: [
                "clients2.google.com",
                "update.googleapis.com",
                "clients2.googleusercontent.com",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
            policy_evaluator,
            https_client,
        })
    }
}

impl<C: Send + Sync + 'static> fmt::Debug for RuleChrome<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleChrome").finish()
    }
}

impl<C> Rule for RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = BoxError> + Clone + Send + Sync + 'static,
{
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Chrome Plugin"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Chrome rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let Some((extension_id, version)) = Self::parse_crx_download_url(&req) else {
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
                    let display_name = self.lookup_display_name(&extension_id).await;
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(&extension_id, &version, display_name),
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

            let display_name = self.lookup_display_name(&extension_id).await;
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&extension_id, &version, display_name),
                BlockReason::Malware,
            )));
        }

        Ok(RequestAction::Allow(req))
    }
}

impl<C> RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = BoxError> + Clone,
{
    async fn lookup_display_name(&self, extension_id: &ArcStr) -> Option<ArcStr> {
        let normalized_id = extension_id.to_ascii_lowercase();
        match ChromeWebStore::get_extension_name(&self.https_client, &normalized_id).await {
            Ok(display_name) => display_name.map(ArcStr::from),
            Err(err) => {
                tracing::warn!(
                    extension_id = extension_id.as_str(),
                    error = %err,
                    "failed to look up Chrome extension name, extension id will be shown as-is."
                );
                None
            }
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
}

impl<C> RuleChrome<C> {
    fn blocked_artifact(
        extension_id: &ArcStr,
        version: &PackageVersion,
        display_name: Option<ArcStr>,
    ) -> Artifact {
        Artifact {
            product: arcstr!("chrome"),
            identifier: extension_id.clone(),
            display_name,
            version: Some(version.clone()),
        }
    }

    fn parse_crx_download_url(req: &Request) -> Option<(ArcStr, PackageVersion)> {
        // Example CRX download URL path (after redirect):
        //   /crx/lajondecmobodlejlcjllhojikagldgd_1_2_3_4.crx
        let path = req.uri().path();

        let (_, filename) = path.rsplit_once('/')?;
        let base = filename.strip_suffix(".crx")?;

        let (extension_id, version_raw) = base.split_once('_')?;

        if extension_id.is_empty() || version_raw.is_empty() {
            return None;
        }

        let version_string = version_raw.replace_smolstr("_", ".");

        let version =
            PackageVersion::from_str(version_string.as_str()).unwrap_or(PackageVersion::None);

        Some((ArcStr::from(extension_id), version))
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod webstore_test;
