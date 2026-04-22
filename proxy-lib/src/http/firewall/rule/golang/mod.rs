use std::fmt;

use rama::utils::time::now_unix_ms;
use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, StatusCode, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};

use crate::{
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig},
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        released_packages_list::{LowerCaseReleasedPackageFormatter, RemoteReleasedPackagesList},
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, HttpRequestMatcherView, HttpResponseMatcherView, RequestAction, Rule};

mod parser;
use parser::{GoPackage, is_zip_download, parse_package_from_path};

pub mod min_package_age;
use min_package_age::MinPackageAgeGolang;

pub(in crate::http::firewall) struct RuleGolang {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    remote_released_packages_list: RemoteReleasedPackagesList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
    policy_evaluator: Option<PolicyEvaluator>,
    maybe_min_package_age: Option<MinPackageAgeGolang>,
}

impl RuleGolang {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
        min_package_age: Option<MinPackageAgeGolang>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_golang.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for golang block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/releases/golang.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseReleasedPackageFormatter,
        )
        .await
        .context("create remote released packages list for golang block rule")?;

        Ok(Self {
            target_domains: ["proxy.golang.org"].into_iter().collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            policy_evaluator,
            maybe_min_package_age: min_package_age,
        })
    }
}

impl fmt::Debug for RuleGolang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleGolang").finish()
    }
}

impl Rule for RuleGolang {
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
        let path = req.uri().path();
        if !is_zip_download(path) {
            return Ok(RequestAction::Allow(req));
        }
        self.evaluate_zip_request(req).await
    }

    fn match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        self.maybe_min_package_age.is_some()
            && parser::parse_module_from_list_path(req.uri.path()).is_some()
    }

    fn match_http_response_payload_inspection_response(
        &self,
        resp: HttpResponseMatcherView<'_>,
    ) -> bool {
        resp.status == StatusCode::OK
    }

    async fn evaluate_response(&self, resp: Response, req_uri: &Uri) -> Result<Response, BoxError> {
        let Some(min_package_age) = &self.maybe_min_package_age else {
            return Ok(resp);
        };
        let Some(module_name) = parser::parse_module_from_list_path(req_uri.path()) else {
            return Ok(resp);
        };
        min_package_age
            .rewrite_list_response(
                resp,
                &module_name,
                &self.remote_released_packages_list,
                self.get_package_age_cutoff_secs(),
            )
            .await
    }
}

impl RuleGolang {
    const DEFAULT_MIN_PACKAGE_AGE_SECS: i64 = 48 * 3600;

    fn get_package_age_cutoff_secs(&self) -> i64 {
        let maybe_ts = self.remote_endpoint_config.as_ref().and_then(|c| {
            c.get_ecosystem_config("golang")
                .config()
                .and_then(|cfg| cfg.minimum_allowed_age_timestamp)
        });
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        (now_unix_ms() / 1000) - Self::DEFAULT_MIN_PACKAGE_AGE_SECS
    }

    fn blocked_artifact(package: &GoPackage) -> Artifact {
        Artifact {
            product: arcstr!("golang"),
            identifier: ArcStr::from(package.fully_qualified_name.as_str()),
            display_name: None,
            version: Some(PackageVersion::Semver(package.version.clone())),
        }
    }

    fn is_package_listed_as_malware(&self, package: &GoPackage) -> bool {
        self.remote_malware_list.has_entries_with_version(
            &package.fully_qualified_name,
            PackageVersion::Semver(package.version.clone()),
        )
    }

    async fn evaluate_zip_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        let path = req.uri().path().trim_start_matches('/');

        let Some(package) = parse_package_from_path(path) else {
            tracing::debug!("Golang url: {path} is not a module zip download: passthrough");
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package.name = %package.fully_qualified_name,
            package.version = %package.version,
            "Go module zip download request"
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision =
                policy_evaluator.evaluate_package_install("golang", &package.fully_qualified_name);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                decision => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(&package),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&package) {
            tracing::warn!("Blocked malware from {}", package.fully_qualified_name);
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&package),
                BlockReason::Malware,
            )));
        }

        let cutoff_secs = self.get_package_age_cutoff_secs();
        if self.remote_released_packages_list.is_recently_released(
            &package.fully_qualified_name,
            Some(&PackageVersion::Semver(package.version.clone())),
            cutoff_secs,
        ) {
            tracing::info!(
                http.url.path = %path,
                package = %package.fully_qualified_name,
                "blocked golang zip download: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&package),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!("Golang url: {path} does not contain malware: passthrough");
        Ok(RequestAction::Allow(req))
    }
}
