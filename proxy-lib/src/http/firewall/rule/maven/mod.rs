use std::{fmt, str::FromStr};

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
    http::{
        firewall::{
            domain_matcher::DomainMatcher,
            events::{BlockedArtifact, BlockedEventInfo},
        },
        response::generate_generic_blocked_response_for_req,
    },
    package::{
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        version::{PackageVersion, PragmaticSemver},
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

#[cfg(test)]
mod test;

pub(in crate::http::firewall) struct RuleMaven {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleMaven {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = BoxError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_maven.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for maven block rule")?;

        Ok(Self {
            target_domains: [
                "repo.maven.apache.org",
                "repo1.maven.org",
                "central.maven.org",
                "repository.apache.org",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
        })
    }
}

impl fmt::Debug for RuleMaven {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleMaven").finish()
    }
}

impl Rule for RuleMaven {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Maven"
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
        let domain = match crate::http::try_get_domain_for_req(&req) {
            Some(domain) => domain,
            None => {
                tracing::trace!("Maven rule: no domain found in request");
                return Ok(RequestAction::Allow(req));
            }
        };

        if !self.match_domain(&domain) {
            return Ok(RequestAction::Allow(req));
        }

        let domain_str = domain.as_str();
        let path = req.uri().path().trim_start_matches('/');
        let artifact = Self::parse_artifact_from_path_for_domain(path, domain_str);

        let Some(artifact) = artifact else {
            tracing::debug!(
                http.url.path = %path,
                "Maven url is not an artifact download: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package.name = %artifact.fully_qualified_name,
            package.version = %artifact.version,
            "Maven package download request"
        );

        if self.is_package_listed_as_malware(&artifact) {
            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_generic_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("maven"),
                        identifier: artifact.fully_qualified_name.clone(),
                        version: Some(PackageVersion::Semver(artifact.version.clone())),
                    },
                },
            }));
        }

        tracing::debug!("Maven url: {path} does not contain malware: passthrough");
        Ok(RequestAction::Allow(req))
    }
}

struct MavenArtifact {
    fully_qualified_name: ArcStr,
    version: PragmaticSemver,
}

// Example: group_path = org/apache/commons/, artifact_id = commons-lang3, full name = org.apache.commons:commons-lang3
impl MavenArtifact {
    fn new(group_path: &str, artifact_id: &str, version: PragmaticSemver) -> Self {
        let artifact_id = artifact_id.trim();
        let mut name = String::with_capacity(group_path.len() + 1 + artifact_id.len());
        for ch in group_path.chars() {
            name.push(if ch == '/' { '.' } else { ch });
        }
        name.push(':');
        name.push_str(artifact_id);
        name.make_ascii_lowercase();

        Self {
            fully_qualified_name: ArcStr::from(name),
            version,
        }
    }
}

impl RuleMaven {
    fn is_package_listed_as_malware(&self, artifact: &MavenArtifact) -> bool {
        self.remote_malware_list.has_entries_with_version(
            artifact.fully_qualified_name.as_str(),
            PackageVersion::Semver(artifact.version.clone()),
        )
    }

    /// Parses a Maven repository artifact path into a normalized package identifier and version.
    ///
    /// Expected path shape:
    /// `/{groupId as directories}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}`
    fn parse_artifact_from_path(path: &str) -> Option<MavenArtifact> {
        let path = path.trim_matches('/');
        let (prefix, filename) = path.rsplit_once('/')?;
        let (prefix, version_dir) = prefix.rsplit_once('/')?;
        let (group_path, artifact_id) = prefix.rsplit_once('/')?;

        if group_path.is_empty() || artifact_id.is_empty() || version_dir.is_empty() {
            return None;
        }

        let (_stem, extension) = filename.rsplit_once('.')?;
        if !matches!(extension, "jar" | "war" | "aar") {
            return None;
        }

        let parsed_version = PragmaticSemver::from_str(version_dir).ok()?;

        // Verify filename starts with: {artifactId}-{version}
        let remainder = filename
            .strip_prefix(artifact_id)?
            .strip_prefix('-')?
            .strip_prefix(version_dir)?;

        if !(remainder.starts_with('-') || remainder.starts_with('.')) {
            return None;
        }

        Some(MavenArtifact::new(group_path, artifact_id, parsed_version))
    }

    fn parse_artifact_from_path_for_domain(path: &str, domain: &str) -> Option<MavenArtifact> {
        let path = path.trim_start_matches('/');
        Self::prefix_candidates_for_domain(domain)
            .iter()
            .find_map(|prefix| {
                Self::strip_path_prefix(path, prefix).and_then(Self::parse_artifact_from_path)
            })
    }

    fn prefix_candidates_for_domain(domain: &str) -> &'static [&'static str] {
        match domain {
            // Maven Central
            "repo.maven.apache.org" | "repo1.maven.org" | "central.maven.org" => &["maven2", ""],

            // Apache
            "repository.apache.org" => &[
                "content/repositories/releases",
                "content/repositories/snapshots",
                "content/groups/public",
                "",
            ],

            _ => &[""],
        }
    }

    fn strip_path_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
        if prefix.is_empty() {
            return Some(path);
        }
        match path.strip_prefix(prefix)? {
            "" => Some(""),
            rest => rest.strip_prefix('/'),
        }
    }
}
