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
    endpoint_protection::{EcosystemKey, RemoteEndpointConfig},
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
        rule::{BlockedRequest, RequestAction, Rule},
    },
    package::{
        malware_list::RemoteMalwareList, released_packages_list::RemoteReleasedPackagesList,
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

mod package_name;
use self::package_name::SkillsShPackageName;

type SkillsShRemoteMalwareList = RemoteMalwareList<SkillsShPackageName>;
type SkillsShRemoteReleasedPackageList = RemoteReleasedPackagesList<SkillsShPackageName>;

const SKILLS_SH_PRODUCT_KEY: ArcStr = arcstr!("skills_sh");
const SKILLS_SH_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("skills_sh");

pub(in crate::http::firewall) struct RuleSkillsSh {
    target_domains: DomainMatcher,
    remote_malware_list: SkillsShRemoteMalwareList,
    remote_released_packages_list: SkillsShRemoteReleasedPackageList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
}

impl RuleSkillsSh {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_skills_sh.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
        )
        .await
        .context("create remote malware list for skills.sh block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/releases/skills_sh.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for skills.sh block rule")?;

        Ok(Self {
            target_domains: ["github.com"].into_iter().collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
        })
    }
}

impl fmt::Debug for RuleSkillsSh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSkillsSh").finish()
    }
}

impl Rule for RuleSkillsSh {
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

        let Some(repo_name) = Self::parse_repo_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "Skills.sh: url is not a git repository operation"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            repo.name = %repo_name,
            "Skills.sh git repository operation request"
        );

        // policy evaluator is not used for skills_sh at the moment (git repos could be blocked)

        if self.is_repo_listed_as_malware(&repo_name) {
            tracing::warn!(
                http.url.path = %path,
                repo.name = %repo_name,
                "blocked Skills.sh repository git operation"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(repo_name),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self
            .remote_released_packages_list
            .is_recently_released(&repo_name, None, cutoff_ts)
        {
            tracing::debug!(
                http.url.path = %path,
                repo.name = %repo_name,
                "blocked Skills.sh repository git operation: repo released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(repo_name),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!(
            http.url.path = %path,
            "Skills.sh repository is not listed as malware: passthrough"
        );
        Ok(RequestAction::Allow(req))
    }
}

impl RuleSkillsSh {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(2);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.remote_endpoint_config
            .as_ref()
            .map(|c| {
                c.get_package_age_cutoff_ts(&SKILLS_SH_ECOSYSTEM_KEY, Self::DEFAULT_MIN_PACKAGE_AGE)
            })
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn blocked_artifact(repo_name: SkillsShPackageName) -> Artifact {
        Artifact {
            product: SKILLS_SH_PRODUCT_KEY,
            identifier: repo_name.into_arcstr(),
            display_name: None,
            version: None,
        }
    }

    fn is_repo_listed_as_malware(&self, repo_name: &SkillsShPackageName) -> bool {
        self.remote_malware_list
            .find_entries(repo_name)
            .entries()
            .is_some()
    }

    fn parse_repo_from_path(path: &str) -> Option<SkillsShPackageName> {
        // Git smart-HTTP protocol endpoints (gitprotocol-http):
        //   GET  /{repo}/info/refs?service=git-upload-pack  (fetch/clone discovery)
        //   POST /{repo}/git-upload-pack                    (fetch/clone pack transfer)
        //   GET  /{repo}/info/refs?service=git-receive-pack (push discovery)
        //   POST /{repo}/git-receive-pack                   (push pack transfer)
        //
        // {repo} may or may not carry a ".git" suffix, e.g.:
        //   /owner/repo.git/git-upload-pack
        //   /owner/repo/git-upload-pack
        //
        // uri().path() already strips the query string, so "/info/refs" is the
        // literal path suffix regardless of the "?service=..." parameter.

        const GIT_ENDPOINTS: &[&str] = &["/info/refs", "/git-upload-pack", "/git-receive-pack"];

        // Strip one of the known git endpoint suffixes
        let repo_path = GIT_ENDPOINTS
            .iter()
            .find_map(|endpoint| path.strip_suffix(endpoint))?;

        // Strip optional ".git" suffix from the repo path, then trim slashes
        let repo_path = repo_path
            .strip_suffix(".git")
            .unwrap_or(repo_path)
            .trim_matches('/');

        // Must look like owner/repo (at least one slash present)
        if repo_path.is_empty() || !repo_path.contains('/') {
            return None;
        }

        Some(SkillsShPackageName::from(repo_path))
    }
}

#[cfg(test)]
mod tests;
