use std::{fmt, sync::Arc};

use rama::{
    Service,
    error::{ErrorContext, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};

use crate::{
    firewall::{
        domain_matcher::DomainMatcher,
        events::{BlockedArtifact, BlockedEventInfo},
        malware_list::{ListDataEntry, MalwareListEntryFormatter, RemoteMalwareList},
        pac::PacScriptGenerator,
        rule::{BlockedRequest, RequestAction, Rule},
        version::{PackageVersion, PragmaticSemver},
    },
    http::response::generate_malware_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

pub(in crate::firewall) struct RuleNuget {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleNuget {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_nuget.json"),
            sync_storage,
            remote_malware_list_https_client,
            Some(Arc::new(NugetMalwareLisetEntryFormatter)),
        )
        .await
        .context("create remote malware list for nuget block rule")?;

        Ok(Self {
            target_domains: ["api.nuget.org", "www.nuget.org"].into_iter().collect(),
            remote_malware_list,
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
    fn product_name(&self) -> &'static str {
        "Nuget"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
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
            return Ok(RequestAction::Allow(req));
        }

        let path = req.uri().path();

        let Some(nuget_package) = Self::parse_package_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "Nuget url is not a nupkg download"
            );
            return Ok(RequestAction::Allow(req));
        };

        let package_name = nuget_package.fully_qualified_name.to_string();
        let package_version = nuget_package.version.clone();

        tracing::debug!(
            http.url.path = %path,
            package.name = %package_name,
            package.version = %package_version,
            "Nuget package download request"
        );

        if self.is_extension_malware(nuget_package) {
            Ok(RequestAction::Block(BlockedRequest {
                response: generate_malware_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("nuget"),
                        identifier: ArcStr::from(package_name),
                        version: Some(PackageVersion::Semver(package_version)),
                    },
                },
            }))
        } else {
            tracing::debug!(
                http.url.path = %path,
                "Nuget package does not contain malware: passthrough"
            );
            Ok(RequestAction::Allow(req))
        }
    }
}

impl RuleNuget {
    fn is_extension_malware(&self, nuget_package: NugetPackage) -> bool {
        let normalized_id = normalize_package_name(nuget_package.fully_qualified_name);
        self.remote_malware_list
            .find_entries(&normalized_id)
            .entries()
            .is_some()
    }

    fn parse_package_from_path(path: &str) -> Option<NugetPackage<'_>> {
        if path.starts_with("/api/v2") {
            Self::parse_package_from_api_v2(path)
        } else {
            Self::parse_package_from_api_v3(path)
        }
    }

    fn parse_package_from_api_v2(path: &str) -> Option<NugetPackage<'_>> {
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

        Some(NugetPackage {
            fully_qualified_name: package_name,
            version,
        })
    }

    fn parse_package_from_api_v3(path: &str) -> Option<NugetPackage<'_>> {
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

        Some(NugetPackage {
            fully_qualified_name: package_name,
            version,
        })
    }
}

struct NugetPackage<'a> {
    fully_qualified_name: &'a str,
    version: PragmaticSemver,
}

struct NugetMalwareLisetEntryFormatter;

impl MalwareListEntryFormatter for NugetMalwareLisetEntryFormatter {
    fn format(&self, entry: &ListDataEntry) -> String {
        normalize_package_name(&entry.package_name)
    }
}

fn normalize_package_name(package_name: &str) -> String {
    package_name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
