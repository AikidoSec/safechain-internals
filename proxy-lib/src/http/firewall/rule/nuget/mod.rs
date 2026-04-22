use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    extensions::ExtensionsRef,
    graceful::ShutdownGuard,
    http::{
        Request, Response, Uri,
        proto::RequestExtensions,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayOutput},
    },
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};

use crate::{
    endpoint_protection::{
        EcosystemKey, PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig,
    },
    http::{
        RequestMetaUri,
        firewall::{
            domain_matcher::DomainMatcher,
            events::{Artifact, BlockReason},
            rule::{
                BlockedRequest, RequestAction, Rule, nuget::min_package_age::MinPackageAgeNuget,
            },
        },
    },
    package::{
        malware_list::RemoteMalwareList,
        name_formatter::LowerCasePackageName,
        released_packages_list::RemoteReleasedPackagesList,
        version::{PackageVersion, PragmaticSemver},
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

type NugetPackageName = LowerCasePackageName;
type NugetRemoteMalwareList = RemoteMalwareList<NugetPackageName>;
type NugetRemoteReleasedPackageList = RemoteReleasedPackagesList<NugetPackageName>;

const NUGET_PRODUCT_KEY: ArcStr = arcstr!("nuget");
const NUGET_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("nuget");

pub mod min_package_age;

pub(in crate::http::firewall) struct RuleNuget {
    target_domains: DomainMatcher,
    remote_malware_list: NugetRemoteMalwareList,
    remote_released_packages_list: NugetRemoteReleasedPackageList,
    maybe_min_package_age: Option<MinPackageAgeNuget>,
    policy_evaluator: Option<PolicyEvaluator<NugetPackageName>>,
}

impl RuleNuget {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_nuget.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
        )
        .await
        .context("create remote malware list for nuget block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/nuget.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for nuget block rule")?;

        let policy_evaluator = remote_endpoint_config
            .clone()
            .map(|config| PolicyEvaluator::new(guard.clone(), NUGET_ECOSYSTEM_KEY.clone(), config));

        Ok(Self {
            target_domains: ["api.nuget.org", "www.nuget.org"].into_iter().collect(),
            remote_malware_list,
            remote_released_packages_list: remote_released_packages_list.clone(),
            maybe_min_package_age: Some(MinPackageAgeNuget::new(remote_released_packages_list)),
            policy_evaluator,
        })
    }
}

impl fmt::Debug for RuleNuget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleNuget").finish()
    }
}

impl Rule for RuleNuget {
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
        let path = req.uri().path();

        let Some(nuget_package) = Self::parse_package_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "Nuget url is not a nupkg download"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package.name = %nuget_package.fully_qualified_name,
            package.version = %nuget_package.version,
            "Nuget package download request"
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision =
                policy_evaluator.evaluate_package_install(&nuget_package.fully_qualified_name);

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
                        nuget_package.into_blocked_artifact(),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&nuget_package) {
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                nuget_package.into_blocked_artifact(),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &nuget_package.fully_qualified_name,
            Some(&PackageVersion::Semver(nuget_package.version.clone())),
            cutoff_ts,
        ) {
            tracing::info!(
                http.url.path = %path,
                package = %nuget_package,
                "blocked nuget package download: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                nuget_package.into_blocked_artifact(),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!(
            http.url.path = %path,
            "Nuget package does not contain malware: passthrough"
        );
        Ok(RequestAction::Allow(req))
    }

    #[inline(always)]
    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        let Some(min_package_age) = &self.maybe_min_package_age else {
            return Ok(resp);
        };
        let Some(req_uri) = resp
            .extensions()
            .get_ref::<RequestExtensions>()
            .and_then(|ext| ext.get_ref().map(|RequestMetaUri(uri)| uri.clone()))
        else {
            return Ok(resp);
        };

        let cutoff_secs = self.get_package_age_cutoff_ts();

        min_package_age
            .remove_new_packages(resp, &req_uri, cutoff_secs)
            .await
    }

    #[inline(always)]
    async fn evaluate_ws_relay_msg(
        &self,
        _: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Result<WebSocketRelayOutput, BoxError> {
        Ok(data)
    }

    #[inline(always)]
    fn match_http_response_payload_inspection_request(
        &self,
        _: super::HttpRequestMatcherView<'_>,
    ) -> bool {
        self.maybe_min_package_age.is_some()
    }
}

impl RuleNuget {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(1);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.policy_evaluator
            .as_ref()
            .map(|c| c.package_age_cutoff_ts(Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn is_package_listed_as_malware(&self, nuget_package: &NugetPackage) -> bool {
        self.remote_malware_list.has_entries_with_version(
            &nuget_package.fully_qualified_name,
            &PackageVersion::Semver(nuget_package.version.clone()),
        )
    }

    fn parse_package_from_path(path: &str) -> Option<NugetPackage> {
        if path.starts_with("/api/v2") {
            Self::parse_package_from_api_v2(path)
        } else {
            if !path.starts_with("/v3") {
                tracing::warn!(
                    http.url.path = %path,
                    "Nuget: path not starting with v3, still treating the url as v3 for parsing"
                );
            }
            Self::parse_package_from_api_v3(path)
        }
    }

    fn parse_package_from_api_v2(path: &str) -> Option<NugetPackage> {
        // Example url: /api/v2/package/safechaintest/0.0.1-security
        // 1st segment: matches "/api" and throw away
        let (_, remainder) = path.trim_start_matches("/").split_once("/")?;

        // 2nd segment: matches "v2"
        let (_, remainder) = remainder.split_once("/")?;

        // 3rd segment: matches "package"
        let (package_string, remainder) = remainder.split_once("/")?;
        if package_string != "package" {
            return None;
        }

        // 4th segment: matches package_name
        // 5th segment (remainder): matches package_version
        let (package_name, package_version_string) = remainder.split_once("/")?;

        let version = PragmaticSemver::parse(package_version_string).inspect_err(|err| {
            tracing::debug!("failed to parse nuget package ({package_name}) version (raw = {package_version_string}): err = {err}");
        }).ok()?;

        Some(NugetPackage::new(package_name, version))
    }

    fn parse_package_from_api_v3(path: &str) -> Option<NugetPackage> {
        // Example url: /v3-flatcontainer/newtonsoft.json/13.0.5-beta1/newtonsoft.json.13.0.5-beta1.nupkg
        // 1st segment: matches /v3-flatcontainer and throw away
        let (_, remainder) = path.trim_start_matches("/").split_once("/")?;

        // 2nd segment: matches package_name
        let (package_name, remainder) = remainder.split_once("/")?;

        // 3rd segment: matches package_version
        let (package_version_string, remainder) = remainder.split_once("/")?;

        // 4th segement (last): matches download name (packagename.version.nupkg)
        if !remainder.ends_with(".nupkg") {
            return None;
        }

        let version = PragmaticSemver::parse(package_version_string).inspect_err(|err| {
            tracing::debug!("failed to parse nuget package ({package_name}) version (raw = {package_version_string}): err = {err}");
        }).ok()?;

        Some(NugetPackage::new(package_name, version))
    }
}

struct NugetPackage {
    fully_qualified_name: NugetPackageName,
    version: PragmaticSemver,
}

impl NugetPackage {
    fn new(name: &str, version: PragmaticSemver) -> NugetPackage {
        Self {
            fully_qualified_name: NugetPackageName::from(name),
            version,
        }
    }

    fn into_blocked_artifact(self) -> Artifact {
        let Self {
            fully_qualified_name,
            version,
        } = self;
        Artifact {
            product: NUGET_PRODUCT_KEY,
            identifier: fully_qualified_name.into_arcstr(),
            display_name: None,
            version: Some(PackageVersion::Semver(version)),
        }
    }
}

impl fmt::Display for NugetPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.fully_qualified_name, self.version)
    }
}

#[cfg(test)]
mod tests;
