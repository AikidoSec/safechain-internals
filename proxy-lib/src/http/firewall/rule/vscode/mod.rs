use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::{
        str::{
            self as str_utils,
            arcstr::{ArcStr, arcstr},
        },
        time::now_unix_ms,
    },
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
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, HttpRequestMatcherView, RequestAction, Rule};

pub mod min_package_age;
use min_package_age::MinPackageAgeVSCode;

pub(in crate::http::firewall) struct RuleVSCode {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
    remote_released_packages_list: RemoteReleasedPackagesList,
    remote_endpoint_config: Option<RemoteEndpointConfig>,
    policy_evaluator: Option<PolicyEvaluator>,
    min_package_age: Option<MinPackageAgeVSCode>,
}

impl RuleVSCode {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        policy_evaluator: Option<PolicyEvaluator>,
        min_package_age: Option<MinPackageAgeVSCode>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_vscode.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for vscode block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/vscode.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseReleasedPackageFormatter,
        )
        .await
        .context("create remote released packages list for vscode block rule")?;

        Ok(Self {
            target_domains: [
                "gallery.vsassets.io",
                "gallerycdn.vsassets.io",
                "marketplace.visualstudio.com",
                "*.gallery.vsassets.io",
                "*.gallerycdn.vsassets.io",
            ]
            .into_iter()
            .collect(),
            remote_malware_list,
            remote_released_packages_list,
            remote_endpoint_config,
            policy_evaluator,
            min_package_age,
        })
    }
}

impl fmt::Debug for RuleVSCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleVSCode").finish()
    }
}

impl Rule for RuleVSCode {
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

        // Check for direct .vsix file downloads from the CDN
        if !Self::is_extension_install_asset_path(path) {
            tracing::trace!(
                http.url.path = %path,
                "VSCode path is not an install asset (e.g., manifest/signature): passthrough"
            );
            return Ok(RequestAction::Allow(req));
        }

        let Some(vscode_extension) = Self::parse_extension_id_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "VSCode extension install asset path could not be parsed for extension ID: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package = %vscode_extension,
            "VSCode install asset request"
        );

        // Apply endpoint policy (rejected packages, allow exceptions, block_all_installs).
        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision = policy_evaluator
                .evaluate_package_install("vscode", vscode_extension.extension_id.as_str());

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                decision => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        Self::blocked_artifact(&vscode_extension),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&vscode_extension) {
            tracing::info!(
                http.url.path = %path,
                package = %vscode_extension,
                "blocked VSCode extension install asset download"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&vscode_extension),
                BlockReason::Malware,
            )));
        }

        let cutoff_secs = self.get_package_age_cutoff_secs();
        let version: Option<PackageVersion> = vscode_extension
            .version
            .as_deref()
            .map(|v| v.parse().unwrap());
        if self.remote_released_packages_list.is_recently_released(
            &vscode_extension.extension_id,
            version.as_ref(),
            cutoff_secs,
        ) {
            tracing::debug!(
                http.url.path = %path,
                package = %vscode_extension,
                "blocked VSCode extension install: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                Self::blocked_artifact(&vscode_extension),
                BlockReason::NewPackage,
            )));
        }

        tracing::trace!(
            http.url.path = %path,
            package = %vscode_extension,
            "VSCode install asset does not contain malware: passthrough"
        );

        Ok(RequestAction::Allow(req))
    }

    fn match_http_response_payload_inspection_request(
        &self,
        req: HttpRequestMatcherView<'_>,
    ) -> bool {
        if self.min_package_age.is_none() {
            return false;
        }

        let path = req.uri.path();
        if Self::is_extension_install_asset_path(path) {
            return false;
        }
        let matched = Self::is_metadata_request_path(path);
        if matched {
            tracing::debug!(
                http.url.path = %path,
                http.method = %req.method,
                "VSCode gallery metadata request — will inspect response"
            );
        }
        matched
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        let Some(min_package_age) = self.min_package_age.as_ref() else {
            return Ok(resp);
        };

        min_package_age
            .remove_new_versions(resp, self.get_package_age_cutoff_secs())
            .await
    }
}

impl RuleVSCode {
    const DEFAULT_MIN_PACKAGE_AGE_SECS: i64 = 24 * 3600;

    fn get_package_age_cutoff_secs(&self) -> i64 {
        let maybe_ts = self.remote_endpoint_config.as_ref().and_then(|c| {
            c.get_ecosystem_config("vscode")
                .config()
                .and_then(|cfg| cfg.minimum_allowed_age_timestamp)
        });
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        (now_unix_ms()) / 1000 - Self::DEFAULT_MIN_PACKAGE_AGE_SECS
    }

    fn blocked_artifact(vscode_extension: &VsCodeExtensionId) -> Artifact {
        Artifact {
            product: arcstr!("vscode"),
            identifier: ArcStr::from(vscode_extension.extension_id.as_str()),
            display_name: None,
            version: None,
        }
    }

    fn is_package_listed_as_malware(&self, vscode_extension: &VsCodeExtensionId) -> bool {
        self.remote_malware_list
            .find_entries(&vscode_extension.extension_id)
            .entries()
            .is_some()
    }

    /// Returns true for Marketplace metadata requests that can carry version lists.
    fn is_metadata_request_path(path: &str) -> bool {
        path.trim_start_matches('/')
            .eq_ignore_ascii_case("_apis/public/gallery/extensionquery")
    }

    fn is_extension_install_asset_path(path: &str) -> bool {
        let path = path.trim_end_matches('/');

        str_utils::any_ends_with_ignore_ascii_case(
            path,
            [
                ".vsix",
                "/Microsoft.VisualStudio.Services.VSIXPackage",
                "/vspackage",
            ],
        )
    }

    /// Parse extension ID (publisher.name) from .vsix download URL path.
    fn parse_extension_id_from_path(path: &str) -> Option<VsCodeExtensionId> {
        let mut it = path.trim_start_matches('/').split('/');

        let first = it.next()?;

        // Pattern: files/<publisher>/<extension>/<version>/...
        if first.eq_ignore_ascii_case("files") {
            let publisher = it.next()?;
            let extension = it.next()?;
            let version = it.next()?; // we require at least a fourth path segment
            return Some(VsCodeExtensionId::new(publisher, extension, Some(version)));
        }

        // Pattern: extensions/<publisher>/<extension>[/<version>/...]
        if first.eq_ignore_ascii_case("extensions") {
            let publisher = it.next()?;
            let extension = it.next()?;
            let version = it.next();
            return Some(VsCodeExtensionId::new(publisher, extension, version));
        }

        // Pattern: _apis/public/gallery/publishers/<publisher>/vsextensions/<extension>/...
        if first.eq_ignore_ascii_case("_apis") {
            let second = it.next()?;
            let third = it.next()?;
            let fourth = it.next()?;

            if second.eq_ignore_ascii_case("public")
                && third.eq_ignore_ascii_case("gallery")
                && fourth.eq_ignore_ascii_case("publishers")
            {
                let publisher = it.next()?;
                let fifth = it.next()?;
                if fifth.eq_ignore_ascii_case("vsextensions")
                    || fifth.eq_ignore_ascii_case("extensions")
                {
                    let extension = it.next()?;
                    let version = it.next();
                    return Some(VsCodeExtensionId::new(publisher, extension, version));
                }
            }

            // Pattern: _apis/public/gallery/publisher/<publisher>/<extension>/<version>/...
            // Pattern: _apis/public/gallery/publisher/<publisher>/extension/<extension>/<version>/...
            if second.eq_ignore_ascii_case("public")
                && third.eq_ignore_ascii_case("gallery")
                && fourth.eq_ignore_ascii_case("publisher")
            {
                let publisher = it.next()?;
                let next = it.next()?;

                if next.eq_ignore_ascii_case("extension") {
                    let extension = it.next()?;
                    let version = it.next();
                    return Some(VsCodeExtensionId::new(publisher, extension, version));
                }

                // next is the extension name; the following segment (if any) is the version
                let version = it.next();
                return Some(VsCodeExtensionId::new(publisher, next, version));
            }
        }

        None
    }
}

struct VsCodeExtensionId {
    extension_id: String,
    version: Option<String>,
}

impl VsCodeExtensionId {
    fn new(publisher: &str, extension: &str, version: Option<&str>) -> VsCodeExtensionId {
        Self {
            extension_id: format!("{publisher}.{extension}").to_lowercase(),
            version: version.map(|v| v.to_lowercase()),
        }
    }
}

impl fmt::Display for VsCodeExtensionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.extension_id)
    }
}

#[cfg(test)]
mod tests;
