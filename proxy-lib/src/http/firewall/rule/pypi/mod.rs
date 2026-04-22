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
        notifier::EventNotifier,
    },
    package::{
        malware_list::RemoteMalwareList, name_formatter::LowerCasePackageName,
        released_packages_list::RemoteReleasedPackagesList,
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, HttpRequestMatcherView, RequestAction, Rule};

mod min_package_age;
use self::min_package_age::MinPackageAgePyPI;

mod parser;
use parser::{PackageInfo, parse_package_info_from_path};

type PyPIPackageName = LowerCasePackageName;
type PyPIRemoteMalwareList = RemoteMalwareList<PyPIPackageName>;
type PyPIRemoteReleasedPackagesList = RemoteReleasedPackagesList<PyPIPackageName>;

const PYPI_PRODUCT_KEY: ArcStr = arcstr!("pypi");
const PYPI_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("pypi");

pub(in crate::http::firewall) struct RulePyPI {
    target_domains: DomainMatcher,
    remote_malware_list: PyPIRemoteMalwareList,
    remote_released_packages_list: PyPIRemoteReleasedPackagesList,
    maybe_min_package_age: Option<MinPackageAgePyPI>,
    policy_evaluator: Option<PolicyEvaluator<PyPIPackageName>>,
}

impl RulePyPI {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        notifier: Option<EventNotifier>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_pypi.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
        )
        .await
        .context("create remote malware list for pypi block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/pypi.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for pypi block rule")?;

        let policy_evaluator = remote_endpoint_config
            .clone()
            .map(|config| PolicyEvaluator::new(guard.clone(), PYPI_ECOSYSTEM_KEY.clone(), config));

        Ok(Self {
            target_domains: ["pypi.org", "files.pythonhosted.org", "pypi.python.org"]
                .into_iter()
                .collect(),
            remote_malware_list,
            remote_released_packages_list,
            maybe_min_package_age: Some(MinPackageAgePyPI::new(notifier)),
            policy_evaluator,
        })
    }

    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(2);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.policy_evaluator
            .as_ref()
            .map(|c| c.package_age_cutoff_ts(Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn is_blocked(&self, package_info: &PackageInfo) -> Result<bool, BoxError> {
        let entries = self.remote_malware_list.find_entries(&package_info.name);
        let Some(entries) = entries.entries() else {
            return Ok(false);
        };

        Ok(entries
            .iter()
            .any(|entry| entry.version == package_info.version))
    }

    fn blocked_artifact(package_info: PackageInfo) -> Artifact {
        Artifact {
            product: PYPI_PRODUCT_KEY,
            identifier: package_info.name.into_arcstr(),
            display_name: None,
            version: Some(package_info.version),
        }
    }
}

impl fmt::Debug for RulePyPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePyPI").finish()
    }
}

impl Rule for RulePyPI {
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

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        let Some(package_info) = parse_package_info_from_path(req.uri().path()) else {
            tracing::trace!("PyPI url: path not recognized: passthrough");
            return Ok(RequestAction::Allow(req));
        };

        // NOTE: metadata requests (version=None, e.g. /pypi/<pkg>/json or /simple/<pkg>/) are
        // not blocked at request time. Blocking metadata would break dependency resolution for
        // legitimate packages that depend on a blocked package. Instead, minimum-package-age
        // enforcement rewrites metadata responses to suppress too-young versions, while direct
        // package file downloads are still blocked when needed.
        if package_info.is_metadata_request() {
            tracing::trace!(package = %package_info.name, "allowing metadata request for PyPI package");
            return Ok(RequestAction::Allow(req));
        }

        // Apply endpoint policy (rejected packages, allow exceptions, block_all_installs).
        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision = policy_evaluator.evaluate_package_install(&package_info.name);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                decision @ (PackagePolicyDecision::BlockAll
                | PackagePolicyDecision::Rejected
                | PackagePolicyDecision::RequestInstall) => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(package_info),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_blocked(&package_info)? {
            tracing::debug!(package = %package_info.name, version = ?package_info.version, "blocked PyPI package download");
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(package_info),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &package_info.name,
            Some(&package_info.version),
            cutoff_ts,
        ) {
            tracing::info!(
                package = %package_info.name,
                version = ?package_info.version,
                "blocked PyPI package download: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(package_info),
                BlockReason::NewPackage,
            )));
        }

        Ok(RequestAction::Allow(req))
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        self.maybe_min_package_age.is_some()
            && parse_package_info_from_path(req.uri.path())
                .is_some_and(|package_info| package_info.is_metadata_request())
    }

    #[inline(always)]
    async fn evaluate_response(
        &self,
        resp: Response,
        _req_uri: &Uri,
    ) -> Result<Response, BoxError> {
        match &self.maybe_min_package_age {
            Some(min_package_age) => {
                min_package_age
                    .remove_new_packages(
                        resp,
                        &self.remote_released_packages_list,
                        self.get_package_age_cutoff_ts(),
                    )
                    .await
            }
            None => Ok(resp),
        }
    }
}

#[cfg(test)]
mod tests;
