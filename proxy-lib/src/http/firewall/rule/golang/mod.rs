use std::{fmt, str::FromStr};

use rama::utils::time::now_unix_ms;
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
    endpoint_protection::{PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig},
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        released_packages_list::{LowerCaseReleasedPackageFormatter, RemoteReleasedPackagesList},
        version::{PackageVersion, PragmaticSemver},
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

#[cfg(test)]
mod tests;

pub(in crate::http::firewall) struct RuleGolang {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    remote_released_packages_list: RemoteReleasedPackagesList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
    policy_evaluator: Option<PolicyEvaluator>,
}

impl RuleGolang {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_golang.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for golang block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/releases/golang.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseReleasedPackageFormatter,
        )
        .await
        .context("create remote released packages list for golang block rule")?;

        Ok(Self {
            target_domains: ["proxy.golang.org"].into_iter().collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            policy_evaluator,
        })
    }
}

impl fmt::Debug for RuleGolang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleGolang").finish()
    }
}

impl Rule for RuleGolang {
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
        if !is_zip_download(path) {
            return Ok(RequestAction::Allow(req));
        }
        self.evaluate_zip_request(req).await
    }
}

impl RuleGolang {
    const DEFAULT_MIN_PACKAGE_AGE_SECS: i64 = 48 * 3600;

    fn get_package_age_cutoff_secs(&self) -> i64 {
        let maybe_ts = self.remote_endpoint_config.as_ref().and_then(|c| {
            c.get_ecosystem_config("golang")
                .config()
                .and_then(|cfg| cfg.minimum_allowed_age_timestamp)
        });
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        (now_unix_ms() / 1000) - Self::DEFAULT_MIN_PACKAGE_AGE_SECS
    }

    fn blocked_artifact(package: &GoPackage) -> Artifact {
        Artifact {
            product: arcstr!("golang"),
            identifier: ArcStr::from(package.fully_qualified_name.as_str()),
            display_name: None,
            version: Some(PackageVersion::Semver(package.version.clone())),
        }
    }

    fn is_package_listed_as_malware(&self, package: &GoPackage) -> bool {
        self.remote_malware_list.has_entries_with_version(
            &package.fully_qualified_name,
            PackageVersion::Semver(package.version.clone()),
        )
    }

    async fn evaluate_zip_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        let path = req.uri().path().trim_start_matches('/');

        let Some(package) = parse_package_from_path(path) else {
            tracing::debug!("Golang url: {path} is not a module zip download: passthrough");
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package.name = %package.fully_qualified_name,
            package.version = %package.version,
            "Go module zip download request"
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision =
                policy_evaluator.evaluate_package_install("golang", &package.fully_qualified_name);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                decision => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(&package),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&package) {
            tracing::warn!("Blocked malware from {}", package.fully_qualified_name);
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&package),
                BlockReason::Malware,
            )));
        }

        let cutoff_secs = self.get_package_age_cutoff_secs();
        if self.remote_released_packages_list.is_recently_released(
            &package.fully_qualified_name,
            Some(&PackageVersion::Semver(package.version.clone())),
            cutoff_secs,
        ) {
            tracing::info!(
                http.url.path = %path,
                package = %package.fully_qualified_name,
                "blocked golang zip download: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&package),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!("Golang url: {path} does not contain malware: passthrough");
        Ok(RequestAction::Allow(req))
    }
}

pub(super) struct GoPackage {
    pub(super) fully_qualified_name: String,
    pub(super) version: PragmaticSemver,
}

fn is_zip_download(path: &str) -> bool {
    path.ends_with(".zip") && path.contains("/@v/")
}

/// Parses a Go module proxy zip URL path into a normalized module name and version.
///
/// Expected path shape: `/{module_path}/@v/{version}.zip`
///
/// Go's module proxy encodes uppercase letters as `!` + lowercase (e.g., `AikidoSec` →
/// `!aikido!sec`, percent-encoded as `%21aikido%21sec`). We lowercase the whole path
/// to normalise for malware-list lookup (which uses `LowerCaseEntryFormatter`).
pub(super) fn parse_package_from_path(path: &str) -> Option<GoPackage> {
    let path = path.trim_matches('/');

    let (module_path_raw, rest) = path.split_once("/@v/")?;
    let version_raw = rest.strip_suffix(".zip")?;

    if module_path_raw.is_empty() || version_raw.is_empty() {
        return None;
    }

    // Percent-decode the module path (handles %21 → !)
    let module_path_decoded = percent_decode(module_path_raw);
    // Lowercase for consistent malware-list lookup
    let module_name = module_path_decoded.to_ascii_lowercase();

    // Go versions always carry a 'v' prefix in the proxy URL; strip it for semver parsing
    let version_str = version_raw.strip_prefix('v').unwrap_or(version_raw);
    let version = PragmaticSemver::from_str(version_str)
        .inspect_err(|err| {
            tracing::debug!(
                "failed to parse golang module ({module_name}) version (raw = {version_raw}): err = {err}"
            );
        })
        .ok()?;

    Some(GoPackage {
        fully_qualified_name: module_name,
        version,
    })
}

/// Decodes percent-encoded characters in a URL path segment.
/// Only handles the ASCII subset relevant to Go module paths (`%21` → `!`, etc.).
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
