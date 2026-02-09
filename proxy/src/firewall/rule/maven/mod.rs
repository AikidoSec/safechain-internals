use std::fmt;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
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
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
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

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Maven rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let path = req.uri().path().trim_start_matches('/');
        let artifact = parse_artifact_from_path(path);

        if let Some(artifact) = artifact {
            if let Some(entries) = self
                .remote_malware_list
                .find_entries(artifact.fully_qualified_name.as_str())
                .entries()
                && entries.iter().any(|entry| artifact.matches(entry))
            {
                let artifact_name = artifact.fully_qualified_name.clone();
                let artifact_version = artifact.version.clone();
                tracing::warn!("Blocked malware from {artifact_name}");
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

/// Parse Maven artifact information from a repository path.
///
/// Maven repository layout:
/// `/{groupId as directory}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{extension}`
///
/// Example paths:
/// - `/org/apache/maven/maven/2.0/maven-2.0.jar`
/// - `/org/mvnpm/carbon-components/11.66.1/carbon-components-11.66.1.jar`
/// - `/com/example/lib/1.0/lib-1.0-sources.jar` (with classifier)
fn parse_artifact_from_path(path: &str) -> Option<MavenArtifact> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Maven paths must have at least: group/artifact/version/file
    // Minimum structure: a/b/c/b-c.jar (4+ segments where last is filename)
    if segments.len() < 4 {
        return None;
    }

    let filename = segments[segments.len() - 1];
    if !filename.contains('.') {
        return None;
    }

    // Only process executable archive files (JAR, WAR, AAR)
    if !filename.ends_with(".jar") && !filename.ends_with(".war") && !filename.ends_with(".aar") {
        return None;
    }

    let version_str = segments[segments.len() - 2];
    let artifact_id = segments[segments.len() - 3];
    let group_id_segments = &segments[..segments.len() - 3];
    if group_id_segments.is_empty() {
        return None;
    }
    let group_id = group_id_segments.join(".");

    // The filename must start with "{artifactId}-{version}"
    let expected_prefix = format!("{}-{}", artifact_id, version_str);
    if !filename.starts_with(&expected_prefix) {
        return None;
    }

    // After the expected prefix, we should have either:
    // - A dot (e.g., "lib-1.0.0.jar")
    // - A hyphen followed by classifier (e.g., "lib-1.0.0-sources.jar")
    let remainder = &filename[expected_prefix.len()..];
    if !remainder.starts_with('.') && !remainder.starts_with('-') {
        return None;
    }

    let fully_qualified_name = ArcStr::from(format!("{}:{}", group_id, artifact_id));

    let version = PragmaticSemver::from_str(version_str).ok()?;

    Some(MavenArtifact {
        fully_qualified_name,
        version,
    })
}

use std::str::FromStr;
