use std::fmt;

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
        malware_list::{MalwareEntry, RemoteMalwareList},
        pac::PacScriptGenerator,
        version::{PackageVersion, PragmaticSemver},
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

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
            None,
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
        // Pass through for now - response modification can be added in future PR
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Npm rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let path = req.uri().path().trim_start_matches('/');
        let package = parse_package_from_path(path);

        if let Some(package) = package {
            if let Some(entries) = self
                .remote_malware_list
                .find_entries(package.fully_qualified_name)
                .entries()
                && entries.iter().any(|entry| package.matches(entry))
            {
                let package_name = package.fully_qualified_name.to_string();
                let package_version = package.version.clone();
                tracing::warn!("Blocked malware from {package_name}");
                return Ok(RequestAction::Block(BlockedRequest {
                    response: generate_generic_blocked_response_for_req(req),
                    info: BlockedEventInfo {
                        artifact: BlockedArtifact {
                            product: arcstr!("npm"),
                            identifier: ArcStr::from(package_name),
                            version: Some(PackageVersion::Semver(package_version)),
                        },
                    },
                }));
            } else {
                tracing::debug!("Npm url: {path} does not contain malware: passthrough");
                return Ok(RequestAction::Allow(req));
            }
        }

        tracing::debug!("Npm url: {path} is not a tarball download: passthrough");
        Ok(RequestAction::Allow(req))
    }
}

struct NpmPackage<'a> {
    fully_qualified_name: &'a str,
    version: PragmaticSemver,
}

impl NpmPackage<'_> {
    fn matches(&self, malware_entry: &MalwareEntry) -> bool {
        malware_entry.version.eq(&self.version)
    }
}

fn parse_package_from_path(path: &str) -> Option<NpmPackage<'_>> {
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

    Some(NpmPackage {
        fully_qualified_name: package_name,
        version,
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_parse_npm_package_from_path() {
        for (path, expected) in [
            (
                "lodash/-/lodash-4.17.21.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "lodash",
                    version: PragmaticSemver::new_semver(4, 17, 21),
                }),
            ),
            (
                "/lodash/-/lodash-4.17.21.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "lodash",
                    version: PragmaticSemver::new_semver(4, 17, 21),
                }),
            ),
            ("lodash/-/lodash-4.17.21", None),
            ("lodash", None),
            (
                "express/-/express-4.18.2.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "express",
                    version: PragmaticSemver::new_semver(4, 18, 2),
                }),
            ),
            (
                "safe-chain-test/-/safe-chain-test-1.0.0.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "safe-chain-test",
                    version: PragmaticSemver::new_semver(1, 0, 0),
                }),
            ),
            (
                "web-vitals/-/web-vitals-3.5.0.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "web-vitals",
                    version: PragmaticSemver::new_semver(3, 5, 0),
                }),
            ),
            (
                "safe-chain-test/-/safe-chain-test-0.0.1-security.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "safe-chain-test",
                    version: PragmaticSemver::new_semver(0, 0, 1).with_pre("security"),
                }),
            ),
            (
                "lodash/-/lodash-5.0.0-beta.1.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "lodash",
                    version: PragmaticSemver::new_semver(5, 0, 0).with_pre("beta.1"),
                }),
            ),
            (
                "react/-/react-18.3.0-canary-abc123.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "react",
                    version: PragmaticSemver::new_semver(18, 3, 0).with_pre("canary-abc123"),
                }),
            ),
            (
                "@babel/core/-/core-7.21.4.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@babel/core",
                    version: PragmaticSemver::new_semver(7, 21, 4),
                }),
            ),
            (
                "@types/node/-/node-20.10.5.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@types/node",
                    version: PragmaticSemver::new_semver(20, 10, 5),
                }),
            ),
            (
                "@angular/common/-/common-17.0.8.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@angular/common",
                    version: PragmaticSemver::new_semver(17, 0, 8),
                }),
            ),
            (
                "@safe-chain/test-package/-/test-package-2.1.0.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@safe-chain/test-package",
                    version: PragmaticSemver::new_semver(2, 1, 0),
                }),
            ),
            (
                "@aws-sdk/client-s3/-/client-s3-3.465.0.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@aws-sdk/client-s3",
                    version: PragmaticSemver::new_semver(3, 465, 0),
                }),
            ),
            (
                "@babel/core/-/core-8.0.0-alpha.1.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@babel/core",
                    version: PragmaticSemver::new_semver(8, 0, 0).with_pre("alpha.1"),
                }),
            ),
            (
                "@safe-chain/security-test/-/security-test-1.0.0-security.tgz",
                Some(NpmPackage {
                    fully_qualified_name: "@safe-chain/security-test",
                    version: PragmaticSemver::new_semver(1, 0, 0).with_pre("security"),
                }),
            ),
        ] {
            let result = parse_package_from_path(path);

            match (result, expected) {
                (Some(actual_package), Some(expected_package)) => {
                    assert_eq!(
                        expected_package.fully_qualified_name,
                        actual_package.fully_qualified_name
                    );
                    assert_eq!(expected_package.version, actual_package.version);
                }
                (None, None) => {}
                (Some(actual_package), None) => {
                    unreachable!(
                        "No package expected, but got '{}'",
                        actual_package.fully_qualified_name
                    );
                }
                (None, Some(expected_package)) => {
                    unreachable!(
                        "Expected '{}', but got None",
                        expected_package.fully_qualified_name
                    );
                }
            }
        }
    }
}
