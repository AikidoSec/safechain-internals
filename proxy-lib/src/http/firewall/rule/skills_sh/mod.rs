use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{
        Request, Response, Uri,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayOutput},
    },
    net::address::Domain,
    telemetry::tracing,
    utils::str::arcstr::{ArcStr, arcstr},
};

use crate::{
    endpoint_protection::PolicyEvaluator,
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
        rule::{BlockedRequest, RequestAction, Rule},
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
    #[allow(dead_code)]
    policy_evaluator: Option<PolicyEvaluator>,
}

impl RuleSkillsSh {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_skills_sh.json"),
            sync_storage,
            remote_malware_list_https_client,
            SkillsShEntryFormatter,
        )
        .await
        .context("create remote malware list for skills.sh block rule")?;

        Ok(Self {
            target_domains: ["github.com"].into_iter().collect(),
            remote_malware_list,
            policy_evaluator,
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
            Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&repo_name),
                BlockReason::Malware,
            )))
        } else {
            tracing::debug!(
                http.url.path = %path,
                "Skills.sh repository is not listed as malware: passthrough"
            );
            Ok(RequestAction::Allow(req))
        }
    }

    #[inline(always)]
    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        Ok(resp)
    }

    #[inline(always)]
    async fn evaluate_ws_relay_msg(
        &self,
        _: WebSocketRelayDirection,
        data: WebSocketRelayOutput,
    ) -> Result<WebSocketRelayOutput, BoxError> {
        Ok(data)
    }
}

impl RuleSkillsSh {
    fn blocked_artifact(repo_name: &str) -> Artifact {
        Artifact {
            product: arcstr!("skills_sh"),
            identifier: ArcStr::from(repo_name),
            display_name: None,
            version: None,
        }
    }

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

        Some(repo_path.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests;
