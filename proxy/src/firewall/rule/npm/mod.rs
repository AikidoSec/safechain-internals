use std::{fmt, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
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
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        pac::PacScriptGenerator,
        rule::npm::min_package_age::MinPackageAge,
        version::{PackageVersion, PragmaticSemver},
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

mod min_package_age;

pub(in crate::firewall) struct RuleNpm {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleNpm {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = BoxError>,
    {
        // NOTE: should you ever need to share a remote malware list between different rules,
        // you would simply create it outside of the rule, clone and pass it in.
        // These remoter malware list resources are cloneable and will share the list,
        // so it only gets updated once
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_predictions.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for npm block rule")?;

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
    fn product_name(&self) -> &'static str {
        "Npm"
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

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        MinPackageAge::remove_new_packages(resp, Duration::from_hours(24)).await
    }

    async fn evaluate_request(&self, mut req: Request) -> Result<RequestAction, BoxError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Npm rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        if self.is_tarball_download(&req) {
            return self.evaluate_tarball_request(req).await;
        }

        MinPackageAge::modify_request_headers(&mut req);

        Ok(RequestAction::Allow(req))
    }
}

impl RuleNpm {
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

        if self.is_package_listed_as_malware(&package) {
            let package_name = package.fully_qualified_name;
            let package_version = package.version;
            tracing::warn!("Blocked malware from {package_name}");
            Ok(RequestAction::Block(BlockedRequest {
                response: generate_generic_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("npm"),
                        identifier: ArcStr::from(package_name),
                        version: Some(PackageVersion::Semver(package_version)),
                    },
                },
            }))
        } else {
            tracing::debug!("Npm url: {path} does not contain malware: passthrough");
            Ok(RequestAction::Allow(req))
        }
    }

    fn is_package_listed_as_malware(&self, npm_package: &NpmPackage) -> bool {
        self.remote_malware_list.has_entries_with_version(
            &npm_package.fully_qualified_name,
            PackageVersion::Semver(npm_package.version.clone()),
        )
    }
}

struct NpmPackage {
    fully_qualified_name: String,
    version: PragmaticSemver,
}

impl NpmPackage {
    fn new(name: &str, version: PragmaticSemver) -> NpmPackage {
        Self {
            fully_qualified_name: name.trim().to_ascii_lowercase(),
            version,
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
