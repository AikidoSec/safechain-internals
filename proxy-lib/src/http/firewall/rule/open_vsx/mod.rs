use std::{fmt, str::FromStr as _};

use rama::{
    Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::{
        self as str_utils,
        arcstr::{ArcStr, arcstr},
        smol_str::format_smolstr,
    },
};

use crate::{
    endpoint_protection::{
        EcosystemKey, PackagePolicyDecision, PolicyEvaluator, RemoteEndpointConfig,
    },
    http::firewall::{
        domain_matcher::DomainMatcher,
        events::{Artifact, BlockReason},
    },
    package::{
        malware_list::RemoteMalwareList, name_formatter::LowerCasePackageName,
        released_packages_list::RemoteReleasedPackagesList, version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, HttpRequestMatcherView, RequestAction, Rule};

pub mod min_package_age;
use min_package_age::MinPackageAgeOpenVsx;

type OpenVsxPackageName = LowerCasePackageName;
type OpenVsxRemoteMalwareList = RemoteMalwareList<OpenVsxPackageName>;
type OpenVsxRemoteReleasedPackagesList = RemoteReleasedPackagesList<OpenVsxPackageName>;

const OPEN_VSX_PRODUCT_KEY: ArcStr = arcstr!("open_vsx");
const OPEN_VSX_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("open_vsx");

#[inline(always)]
fn new_open_vsx_package_name(raw: &str) -> OpenVsxPackageName {
    OpenVsxPackageName::from(raw)
}

pub(in crate::http::firewall) struct RuleOpenVsx {
    target_domains: DomainMatcher,
    remote_malware_list: OpenVsxRemoteMalwareList,
    remote_released_packages_list: OpenVsxRemoteReleasedPackagesList,
    policy_evaluator: Option<PolicyEvaluator<OpenVsxPackageName>>,
    min_package_age: Option<MinPackageAgeOpenVsx>,
}

impl RuleOpenVsx {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
        min_package_age: Option<MinPackageAgeOpenVsx>,
        remote_endpoint_config: Option<RemoteEndpointConfig>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/malware_open_vsx.json"),
            sync_storage.clone(),
            remote_malware_list_https_client.clone(),
        )
        .await
        .context("create remote malware list for open vsx block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/open_vsx.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for open vsx block rule")?;

        let policy_evaluator = remote_endpoint_config.map(|config| {
            PolicyEvaluator::new(guard.clone(), OPEN_VSX_ECOSYSTEM_KEY.clone(), config)
        });

        Ok(Self {
            target_domains: ["open-vsx.org", "marketplace.cursorapi.com"]
                .into_iter()
                .collect(),
            remote_malware_list,
            remote_released_packages_list,
            policy_evaluator,
            min_package_age,
        })
    }
}

impl fmt::Debug for RuleOpenVsx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleOpenVsx").finish()
    }
}

impl Rule for RuleOpenVsx {
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

        if !Self::is_extension_install_asset_path(path) {
            tracing::trace!(
                http.url.path = %path,
                "Open VSX path is not an install asset: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        }

        let Some(extension) = Self::parse_extension_id_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "Open VSX install asset path could not be parsed for extension ID: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package = %extension,
            "Open VSX install asset request"
        );

        if let Some(policy_evaluator) = self.policy_evaluator.as_ref() {
            let decision = policy_evaluator.evaluate_package_install(&extension.extension_id);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => (),
                PackagePolicyDecision::BlockAll
                | PackagePolicyDecision::Rejected
                | PackagePolicyDecision::RequestInstall => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        extension.into_blocked_artifact(),
                        super::block_reason_for(decision),
                    )));
                }
            }
        }

        if self.is_package_listed_as_malware(&extension) {
            tracing::warn!(
                http.url.path = %path,
                package = %extension,
                "blocked Open VSX extension install asset download"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                extension.into_blocked_artifact(),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &extension.extension_id,
            extension.version.as_ref(),
            cutoff_ts,
        ) {
            tracing::debug!(
                http.url.path = %path,
                package = %extension,
                "blocked Open VSX extension install: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                extension.into_blocked_artifact(),
                BlockReason::NewPackage,
            )));
        }

        tracing::debug!(
            http.url.path = %path,
            package = %extension,
            "Open VSX install asset does not contain malware: passthrough"
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
                "Open VSX gallery metadata request — will inspect response"
            );
        }
        matched
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        let Some(min_package_age) = self.min_package_age.as_ref() else {
            return Ok(resp);
        };

        min_package_age
            .remove_new_versions(
                resp,
                &self.remote_released_packages_list,
                self.get_package_age_cutoff_ts(),
                |extension_id| {
                    self.is_extension_allowlisted(&new_open_vsx_package_name(extension_id))
                },
            )
            .await
    }
}

impl RuleOpenVsx {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(1);

    /// Returns `true` if the endpoint-protection policy explicitly allowlists
    /// the given extension ID (`publisher/extension`), i.e. evaluates to
    /// [`PackagePolicyDecision::Allow`]. Used by the metadata-rewrite path
    /// to skip the min-age strip for trusted extensions.
    fn is_extension_allowlisted(&self, extension_id: &OpenVsxPackageName) -> bool {
        self.policy_evaluator.as_ref().is_some_and(|policy| {
            policy.evaluate_package_install(extension_id) == PackagePolicyDecision::Allow
        })
    }

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.policy_evaluator
            .as_ref()
            .map(|c| c.package_age_cutoff_ts(Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn is_package_listed_as_malware(&self, extension: &OpenVsxExtensionId) -> bool {
        self.remote_malware_list
            .find_entries(&extension.extension_id)
            .entries()
            .is_some()
    }

    fn is_extension_install_asset_path(path: &str) -> bool {
        let path = path.trim_end_matches('/');

        str_utils::any_ends_with_ignore_ascii_case(
            path,
            ["/Microsoft.VisualStudio.Services.VSIXPackage", ".vsix"],
        )
    }

    /// Returns true for OpenVSX / Cursor marketplace metadata paths that can carry version lists.
    fn is_metadata_request_path(path: &str) -> bool {
        let trimmed = path.trim_start_matches('/').trim_end_matches('/');

        // OpenVSX batch query / search endpoints
        if trimmed.eq_ignore_ascii_case("api/-/query")
            || trimmed.eq_ignore_ascii_case("api/v2/-/query")
            || trimmed.eq_ignore_ascii_case("api/-/search")
        {
            return true;
        }

        // OpenVSX single-extension: /api/{namespace}/{name} — exactly 3 segments.
        let segs: Vec<&str> = trimmed.split('/').collect();
        if segs.len() == 3
            && segs[0].eq_ignore_ascii_case("api")
            && !segs[1].is_empty()
            && !segs[2].is_empty()
            && segs[1] != "-"
        {
            return true;
        }

        // VS-Marketplace-shaped mirrors — both endpoint variants observed in the wild:
        // - `_apis/public/gallery/extensionquery` (Cursor's `marketplace.cursorapi.com`)
        // - `vscode/gallery/extensionquery` (OpenVSX's own mirror at `open-vsx.org`,
        //   used by VSCodium's auto-update poll and its extension search panel)
        let lower = trimmed.to_ascii_lowercase();
        if lower.ends_with("_apis/public/gallery/extensionquery")
            || lower.ends_with("vscode/gallery/extensionquery")
        {
            return true;
        }

        false
    }

    /// Parse extension ID (`publisher.extension`) from an Open VSX download URL path.
    ///
    /// Handles three URL patterns:
    /// - `open-vsx.org`: `/vscode/asset/{publisher}/{extension}/{version}/...`
    /// - `open-vsx.org` API: `/api/{publisher}/{extension}/{version}/file/{filename}`
    /// - `marketplace.cursorapi.com`: `/open-vsx-mirror/vscode/asset/{publisher}/{extension}/{version}/...`
    fn parse_extension_id_from_path(path: &str) -> Option<OpenVsxExtensionId> {
        let mut it = path.trim_start_matches('/').split('/');

        let first = it.next()?;

        // Pattern: vscode/asset/{publisher}/{extension}/{version}/...
        if first.eq_ignore_ascii_case("vscode") {
            let second = it.next()?;
            if second.eq_ignore_ascii_case("asset") {
                let publisher = it.next()?;
                let extension = it.next()?;
                let version = it.next();
                return Some(OpenVsxExtensionId::new(publisher, extension, version));
            }
        }

        // Pattern: api/{publisher}/{extension}/{version}/file/{filename}
        if first.eq_ignore_ascii_case("api") {
            let publisher = it.next()?;
            let extension = it.next()?;
            let version = it.next();
            return Some(OpenVsxExtensionId::new(publisher, extension, version));
        }

        // Pattern: open-vsx-mirror/vscode/asset/{publisher}/{extension}/{version}/...
        if first.eq_ignore_ascii_case("open-vsx-mirror") {
            let second = it.next()?;
            if second.eq_ignore_ascii_case("vscode") {
                let third = it.next()?;
                if third.eq_ignore_ascii_case("asset") {
                    let publisher = it.next()?;
                    let extension = it.next()?;
                    let version = it.next();
                    return Some(OpenVsxExtensionId::new(publisher, extension, version));
                }
            }
        }

        None
    }
}

struct OpenVsxExtensionId {
    extension_id: OpenVsxPackageName,
    version: Option<PackageVersion>,
}

impl OpenVsxExtensionId {
    fn new(publisher: &str, extension: &str, version_str: Option<&str>) -> OpenVsxExtensionId {
        Self {
            extension_id: OpenVsxPackageName::from(format_smolstr!("{publisher}/{extension}")),
            version: version_str.map(|s| {
                let Ok(version) = PackageVersion::from_str(s);
                version
            }),
        }
    }

    fn into_blocked_artifact(self) -> Artifact {
        let Self {
            extension_id,
            version,
        } = self;
        Artifact {
            product: OPEN_VSX_PRODUCT_KEY,
            identifier: extension_id.into_arcstr(),
            display_name: None,
            version,
        }
    }
}

impl fmt::Display for OpenVsxExtensionId {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.extension_id.fmt(f)
    }
}

#[cfg(test)]
mod tests;
