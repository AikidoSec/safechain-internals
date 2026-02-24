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
    http::{
        firewall::{
            domain_matcher::DomainMatcher,
            events::{BlockedArtifact, BlockedEventInfo},
            rule::{BlockedRequest, RequestAction, Rule},
        },
        response::generate_malware_blocked_response_for_req,
    },
    package::malware_list::{ListDataEntry, MalwareListEntryFormatter, RemoteMalwareList},
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

/// Formats a skills.sh malware-list entry as `owner/repo` (lowercase).
///
/// The malware list uses three-part names (`owner/repo/skill-name`) because a
/// single repository may contain multiple skills.  A git pull URL, however,
/// only ever identifies the repository (`owner/repo`), so we index the trie by
/// that prefix so that any listed skill in a repository triggers a block.
#[derive(Debug, Default, Clone)]
struct SkillsShEntryFormatter;

impl MalwareListEntryFormatter for SkillsShEntryFormatter {
    fn format(&self, entry: &ListDataEntry) -> String {
        let name = entry.package_name.trim().to_ascii_lowercase();
        // Take only the first two slash-delimited segments (owner/repo),
        // discarding the skill-name suffix.
        match name.splitn(3, '/').collect::<Vec<_>>().as_slice() {
            [owner, repo, ..] if !owner.is_empty() && !repo.is_empty() => {
                format!("{owner}/{repo}")
            }
            _ => name,
        }
    }
}

pub(in crate::http::firewall) struct RuleSkillsSh {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleSkillsSh {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_skills_sh.json"),
            sync_storage,
            remote_malware_list_https_client,
            SkillsShEntryFormatter,
        )
        .await
        .context("create remote malware list for skills_sh block rule")?;

        Ok(Self {
            target_domains: ["github.com"].into_iter().collect(),
            remote_malware_list,
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
    fn product_name(&self) -> &'static str {
        "Skills.sh"
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
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            return Ok(RequestAction::Allow(req));
        }

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

        if self.is_repo_listed_as_malware(&repo_name) {
            Ok(RequestAction::Block(BlockedRequest {
                response: generate_malware_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("skills_sh"),
                        identifier: ArcStr::from(repo_name),
                        version: None,
                    },
                },
            }))
        } else {
            tracing::debug!(
                http.url.path = %path,
                "Skills.sh repository is not listed as malware: passthrough"
            );
            Ok(RequestAction::Allow(req))
        }
    }
}

impl RuleSkillsSh {
    fn is_repo_listed_as_malware(&self, repo_name: &str) -> bool {
        self.remote_malware_list
            .find_entries(repo_name)
            .entries()
            .is_some()
    }

    fn parse_repo_from_path(path: &str) -> Option<String> {
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

        const GIT_ENDPOINTS: &[&str] =
            &["/info/refs", "/git-upload-pack", "/git-receive-pack"];

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

        Some(repo_path.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests;
