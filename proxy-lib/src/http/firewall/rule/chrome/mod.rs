use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::{
        str::arcstr::{ArcStr, arcstr},
        time::now_unix_ms,
    },
};

use crate::{
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig},
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{
        malware_list::RemoteMalwareList,
        released_packages_list::{LowerCaseReleasedPackageFormatter, RemoteReleasedPackagesList},
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

mod malware_key;
mod parser;

pub(in crate::http::firewall) struct RuleChrome<C> {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    remote_released_packages_list: RemoteReleasedPackagesList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
    policy_evaluator: Option<PolicyEvaluator>,
    _https_client: std::marker::PhantomData<C>,
}

impl<C> RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
{
    pub(in crate::http::firewall) async fn try_new(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError> {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            malware_key::ChromeMalwareListEntryFormatter,
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/releases/chrome.json"),
            sync_storage,
            remote_malware_list_https_client.clone(),
            LowerCaseReleasedPackageFormatter,
        )
        .await
        .context("create remote released packages list for chrome block rule")?;

        Ok(Self {
            target_domains: [
                "clients2.google.com",
                "update.googleapis.com",
                "clients2.googleusercontent.com",
                "chromewebstore.google.com",
                "chromewebstore.googleapis.com",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            policy_evaluator,
            _https_client: std::marker::PhantomData,
        })
    }
}

impl<C> fmt::Debug for RuleChrome<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleChrome").finish()
    }
}

impl<C> Rule for RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + Sync + 'static,
{
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

        let cutoff_secs = self.get_package_age_cutoff_secs();
        let normalized_id = extension_id.to_ascii_lowercase();
        if self.remote_released_packages_list.is_recently_released(
            &normalized_id,
            None,
            cutoff_secs,
        ) {
            tracing::debug!(
                http.url.full = %req.uri(),
                "blocked Chrome extension: released too recently: {extension_id}"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&extension_id, &version),
                BlockReason::NewPackage,
            )));
        }

        Ok(RequestAction::Allow(req))
    }
}

impl<C> RuleChrome<C>
where
    C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
{
    const DEFAULT_MIN_PACKAGE_AGE_SECS: i64 = 48 * 3600;

    fn get_package_age_cutoff_secs(&self) -> i64 {
        let maybe_ts = self.remote_endpoint_config.as_ref().and_then(|c| {
            c.get_ecosystem_config("chrome")
                .config()
                .and_then(|cfg| cfg.minimum_allowed_age_timestamp)
        });
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        (now_unix_ms()) / 1000 - Self::DEFAULT_MIN_PACKAGE_AGE_SECS
    }

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
