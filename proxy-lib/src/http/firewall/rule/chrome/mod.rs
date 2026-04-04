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
    endpoint_protection::{
        EcosystemKey, PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig,
    },
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{
        malware_list::RemoteMalwareList, released_packages_list::RemoteReleasedPackagesList,
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

mod package_name;
mod parser;
use self::package_name::ChromePackageName;

type ChromeRemoteMalwareList = RemoteMalwareList<ChromePackageName>;
type ChromeRemoteReleasedPackageList = RemoteReleasedPackagesList<ChromePackageName>;

const CHROME_PRODUCT_KEY: ArcStr = arcstr!("chrome");
const CHROME_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("chrome");

pub(in crate::http::firewall) struct RuleChrome {
    target_domains: DomainMatcher,
    remote_malware_list: ChromeRemoteMalwareList,
    remote_released_packages_list: ChromeRemoteReleasedPackageList,
    policy_evaluator: Option<PolicyEvaluator<ChromePackageName>>,
}

impl RuleChrome {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_chrome.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
        )
        .await
        .context("create remote malware list for chrome block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/chrome.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for chrome block rule")?;

        let policy_evaluator = remote_endpoint_config.map(|config| {
            PolicyEvaluator::new(guard.clone(), CHROME_ECOSYSTEM_KEY.clone(), config)
        });

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
        let Some(package_info) = PackageInfo::from_http_req(&req) else {
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
            "CRX download - extension id: {}, version: {}",
            package_info.extension_id,
            package_info.version,
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision = policy_evaluator.evaluate_package_install(&package_info.extension_id);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                PackagePolicyDecision::BlockAll
                | PackagePolicyDecision::Rejected
                | PackagePolicyDecision::RequestInstall => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        package_info.into_blocked_artifact(),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.matches_malware_entry(&package_info) {
            tracing::info!(
                http.url.full = %req.uri(),
                http.request.method = %req.method(),
                "blocked Chrome extension from CRX URL: {}, version: {}",
                package_info.extension_id,
                package_info.version,
            );

            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                package_info.into_blocked_artifact(),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &package_info.extension_id,
            Some(&package_info.version),
            cutoff_ts,
        ) {
            tracing::debug!(
                http.url.full = %req.uri(),
                "blocked Chrome extension: released too recently: {}, version: {}",
                package_info.extension_id,
                package_info.version,
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                package_info.into_blocked_artifact(),
                BlockReason::NewPackage,
            )));
        }

        Ok(RequestAction::Allow(req))
    }
}

impl RuleChrome {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(2);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.policy_evaluator
            .as_ref()
            .map(|c| c.package_age_cutoff_ts(Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn matches_malware_entry(&self, package_info: &PackageInfo) -> bool {
        let entries = self
            .remote_malware_list
            .find_entries(&package_info.extension_id);
        let Some(entries) = entries.entries() else {
            return false;
        };

        entries.iter().any(|e| e.version.eq(&package_info.version))
    }
}

#[derive(Debug)]
struct PackageInfo {
    extension_id: ChromePackageName,
    version: PackageVersion,
}

impl PackageInfo {
    fn from_http_req(req: &Request) -> Option<Self> {
        let (extension_id, version) = self::parser::parse_crx_download_url(req)?;
        Some(PackageInfo {
            extension_id,
            version,
        })
    }

    fn into_blocked_artifact(self) -> Artifact {
        let Self {
            extension_id,
            version,
        } = self;
        Artifact {
            product: CHROME_PRODUCT_KEY,
            identifier: extension_id.into_arcstr(),
            display_name: None,
            version: Some(version),
        }
    }
}

#[cfg(test)]
mod test;
