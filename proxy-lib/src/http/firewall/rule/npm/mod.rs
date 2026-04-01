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
        rule::npm::min_package_age::MinPackageAge,
    },
    package::{
        malware_list::RemoteMalwareList,
        name_formatter::{LowerCasePackageName, LowerCasePackageNameFormatter},
        released_packages_list::RemoteReleasedPackagesList,
        version::{PackageVersion, PragmaticSemver},
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

pub mod min_package_age;

type NpmPackageNameFormatter = LowerCasePackageNameFormatter;
type NpmPackageName = LowerCasePackageName;

type NpmRemoteMalwareList = RemoteMalwareList<NpmPackageNameFormatter>;
type NpmRemoteReleasedPackagesList = RemoteReleasedPackagesList<NpmPackageNameFormatter>;
type NpmRemoteEndpointConfig = RemoteEndpointConfig<NpmPackageNameFormatter>;
type NpmPolicyEvaluator = PolicyEvaluator<NpmPackageNameFormatter>;

const NPM_PRODUCT_KEY: ArcStr = arcstr!("npm");
const NPM_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("npm");

pub(in crate::http::firewall) struct RuleNpm {
    target_domains: DomainMatcher,
    remote_malware_list: NpmRemoteMalwareList,
    remote_released_packages_list: NpmRemoteReleasedPackagesList,
    remote_endpoint_config: Option<NpmRemoteEndpointConfig>,
    maybe_min_package_age: Option<MinPackageAge>,
    policy_evaluator: Option<NpmPolicyEvaluator>,
}

impl RuleNpm {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<NpmPolicyEvaluator>,
        min_package_age: Option<MinPackageAge>,
        remote_endpoint_config: Option<NpmRemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        // NOTE: should you ever need to share a remote malware list between different rules,
        // you would simply create it outside of the rule, clone and pass it in.
        // These remoter malware list resources are cloneable and will share the list,
        // so it only gets updated once
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_predictions.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            NpmPackageNameFormatter::new(),
        )
        .await
        .context("create remote malware list for npm block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/npm.json"),
            sync_storage,
            remote_malware_list_https_client,
            NpmPackageNameFormatter::new(),
        )
        .await
        .context("create remote released packages list for npm block rule")?;

        Ok(Self {
            // NOTE: should you ever make this list dynamic we would stop hardcoding these target domains here...
            target_domains: [
                "registry.npmjs.org",
                "registry.npmjs.com",
                "registry.yarnpkg.com",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            maybe_min_package_age: min_package_age,
            policy_evaluator,
        })
    }
}

impl fmt::Debug for RuleNpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleNpm").finish()
    }
}

impl Rule for RuleNpm {
    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_request(
        &self,
        _: super::HttpRequestMatcherView<'_>,
    ) -> bool {
        self.maybe_min_package_age.is_some()
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, mut req: Request) -> Result<RequestAction, BoxError> {
        if self.is_tarball_download(&req) {
            return self.evaluate_tarball_request(req).await;
        }

        if let Some(min_package_age) = &self.maybe_min_package_age {
            min_package_age.modify_request_headers(&mut req);
        }

        Ok(RequestAction::Allow(req))
    }

    #[inline(always)]
    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        match &self.maybe_min_package_age {
            Some(min_package_age) => min_package_age.remove_new_packages(resp).await,
            None => Ok(resp),
        }
    }
}

impl RuleNpm {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::hours(48);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.remote_endpoint_config
            .as_ref()
            .map(|c| c.get_package_age_cutoff_ts(&NPM_ECOSYSTEM_KEY, Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn is_tarball_download(&self, req: &Request) -> bool {
        let path = req.uri().path();
        path.ends_with(".tgz") && path.contains("/-/")
    }

    async fn evaluate_tarball_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        let path = req.uri().path().trim_start_matches('/');

        let Some(package) = parse_package_from_path(path) else {
            tracing::debug!("Npm url: {path} is not a tarball download: passthrough");
            return Ok(RequestAction::Allow(req));
        };

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision = policy_evaluator
                .evaluate_package_install(&NPM_ECOSYSTEM_KEY, &package.fully_qualified_name);

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
                        package.into_blocked_artifact(),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&package) {
            tracing::warn!(
                name = %package.fully_qualified_name,
                version = %package.version,
                "Blocked malware",
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                package.into_blocked_artifact(),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &package.fully_qualified_name,
            Some(&PackageVersion::Semver(package.version.clone())),
            cutoff_ts,
        ) {
            tracing::info!(
                package = %package.fully_qualified_name,
                "blocked npm tarball download: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                package.into_blocked_artifact(),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!("Npm url: {path} does not contain malware: passthrough");
        Ok(RequestAction::Allow(req))
    }

    fn is_package_listed_as_malware(&self, npm_package: &NpmPackage) -> bool {
        self.remote_malware_list.has_entries_with_version(
            &npm_package.fully_qualified_name,
            &PackageVersion::Semver(npm_package.version.clone()),
        )
    }
}

struct NpmPackage {
    fully_qualified_name: NpmPackageName,
    version: PragmaticSemver,
}

impl NpmPackage {
    fn new(name: &str, version: PragmaticSemver) -> NpmPackage {
        Self {
            fully_qualified_name: NpmPackageName::from(name),
            version,
        }
    }

    fn into_blocked_artifact(self) -> Artifact {
        let Self {
            fully_qualified_name,
            version,
        } = self;
        Artifact {
            product: NPM_PRODUCT_KEY,
            identifier: fully_qualified_name.into_arcstr(),
            display_name: None,
            version: Some(PackageVersion::Semver(version)),
        }
    }
}

fn parse_package_from_path(path: &str) -> Option<NpmPackage> {
    let (package_name, file_name) = path.trim_start_matches("/").split_once("/-/")?;

    let filename_prefix = if package_name.starts_with("@")
        && let Some((_, name)) = package_name.rsplit_once("/")
    {
        // Scoped packages are in the format @scope/package
        // The prefix however, doesn't have the scope
        name
    } else {
        package_name
    };

    let file_name_without_ext = file_name.strip_suffix(".tgz")?;
    let version = file_name_without_ext
        .strip_prefix(filename_prefix)?
        .strip_prefix("-")?;

    let version = PragmaticSemver::parse(version).inspect_err(|err| {
        tracing::debug!("failed to parse npm package ({package_name}) version (raw = {version}): err = {err}");
    }).ok()?;

    Some(NpmPackage::new(package_name, version))
}

#[cfg(test)]
mod tests;
