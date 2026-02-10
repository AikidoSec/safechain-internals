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

#[cfg(test)]
mod test;

pub(in crate::firewall) struct RuleMaven {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleMaven {
    pub(in crate::firewall) async fn try_new<C>(
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
            None,
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
            tracing::trace!("Maven rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let domain_str = domain.as_str();
        let path = req.uri().path().trim_start_matches('/');
        let artifact = parse_artifact_from_path_for_domain(path, domain_str);

        if let Some(artifact) = artifact {
            if let Some(entries) = self
                .remote_malware_list
                .find_entries(artifact.fully_qualified_name.as_str())
                .entries()
                && entries.iter().any(|entry| artifact.matches(entry))
            {
                let artifact_name = artifact.fully_qualified_name.clone();
                let artifact_version = artifact.version.clone();
                tracing::warn!("Blocked malware from {artifact_name} (domain: {domain_str})");
                return Ok(RequestAction::Block(BlockedRequest {
                    response: generate_generic_blocked_response_for_req(req),
                    info: BlockedEventInfo {
                        artifact: BlockedArtifact {
                            product: arcstr!("maven"),
                            identifier: artifact_name,
                            version: Some(PackageVersion::Semver(artifact_version)),
                        },
                    },
                }));
            } else {
                tracing::debug!("Maven url: {path} does not contain malware: passthrough");
                return Ok(RequestAction::Allow(req));
            }
        }

        tracing::debug!("Maven url: {path} is not an artifact download: passthrough");
        Ok(RequestAction::Allow(req))
    }
}

struct MavenArtifact {
    fully_qualified_name: ArcStr,
    version: PragmaticSemver,
}

impl MavenArtifact {
    fn matches(&self, malware_entry: &MalwareEntry) -> bool {
        malware_entry.version.eq(&self.version)
    }
}

/// `/{groupId as directory}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}`
fn parse_artifact_from_path(path: &str) -> Option<MavenArtifact> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Must have at least groupId/artifactId/version/filename
    if segments.len() < 4 {
        return None;
    }

    let n = segments.len();
    let filename = segments.last().copied()?;
    let (_stem, extension) = filename.rsplit_once('.')?;

    if !matches!(extension, "jar" | "war" | "aar") {
        return None;
    }

    // Verify path structure using directories (more reliable than guessing from dashes).
    // Expected: .../{artifactId}/{version}/{artifactId}-{version}[-classifier].ext
    let version_dir = segments[n - 2];
    let artifact_id = segments[n - 3];

    let parsed_version = PragmaticSemver::from_str(version_dir).ok()?;

    let expected_prefix = format!("{artifact_id}-{version_dir}");
    if !filename.starts_with(&expected_prefix) {
        return None;
    }

    // Next char must be '-' (classifier) or '.' (extension)
    let remainder = &filename[expected_prefix.len()..];
    if !(remainder.starts_with('-') || remainder.starts_with('.')) {
        return None;
    }

    // Everything before artifactId directory is groupId
    let group_id_segments = &segments[..n - 3];
    if group_id_segments.is_empty() {
        return None;
    }

    Some(MavenArtifact {
        fully_qualified_name: ArcStr::from(format!(
            "{}:{artifact_id}",
            group_id_segments.join(".")
        )),
        version: parsed_version,
    })
}

fn parse_artifact_from_path_for_domain(path: &str, domain: &str) -> Option<MavenArtifact> {
    let path = path.trim_start_matches('/');
    prefix_candidates_for_domain(domain)
        .iter()
        .find_map(|prefix| strip_path_prefix(path, prefix).and_then(parse_artifact_from_path))
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

use std::str::FromStr;
