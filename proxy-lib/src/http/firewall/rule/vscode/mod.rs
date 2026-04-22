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

use super::{BlockedRequest, RequestAction, Rule};

type VSCodePackageName = LowerCasePackageName;
type VSCodeRemoteMalwareList = RemoteMalwareList<VSCodePackageName>;
type VSCodeRemoteReleasedPackageList = RemoteReleasedPackagesList<VSCodePackageName>;

const VSCODE_PRODUCT_KEY: ArcStr = arcstr!("vscode");
const VSCODE_ECOSYSTEM_KEY: EcosystemKey = EcosystemKey::from_static("vscode");

#[inline(always)]
fn new_vscode_package_name(raw: &str) -> VSCodePackageName {
    VSCodePackageName::from(raw)
}

pub(in crate::http::firewall) struct RuleVSCode {
    target_domains: DomainMatcher,
    remote_malware_list: VSCodeRemoteMalwareList,
    remote_released_packages_list: VSCodeRemoteReleasedPackageList,
    policy_evaluator: Option<PolicyEvaluator<VSCodePackageName>>,
}

impl RuleVSCode {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
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
        )
        .await
        .context("create remote malware list for vscode block rule")?;

        let remote_released_packages_list = RemoteReleasedPackagesList::try_new(
            guard.clone(),
            Uri::from_static("https://malware-list.aikido.dev/releases/vscode.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote released packages list for vscode block rule")?;

        let policy_evaluator = remote_endpoint_config.map(|config| {
            PolicyEvaluator::new(guard.clone(), VSCODE_ECOSYSTEM_KEY.clone(), config)
        });

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
            policy_evaluator,
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
            let decision =
                policy_evaluator.evaluate_package_install(&vscode_extension.extension_id);

            match decision {
                PackagePolicyDecision::Allow => {
                    return Ok(RequestAction::Allow(req));
                }
                PackagePolicyDecision::Defer => {}
                PackagePolicyDecision::BlockAll
                | PackagePolicyDecision::Rejected
                | PackagePolicyDecision::RequestInstall => {
                    return Ok(RequestAction::Block(BlockedRequest::blocked(
                        req,
                        vscode_extension.into_blocked_artifact(),
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
                vscode_extension.into_blocked_artifact(),
                BlockReason::Malware,
            )));
        }

        let cutoff_ts = self.get_package_age_cutoff_ts();
        if self.remote_released_packages_list.is_recently_released(
            &vscode_extension.extension_id,
            vscode_extension.version.as_ref(),
            cutoff_ts,
        ) {
            tracing::debug!(
                http.url.path = %path,
                package = %vscode_extension,
                "blocked VSCode extension install: package released too recently"
            );
            return Ok(RequestAction::Block(BlockedRequest::blocked(
                req,
                vscode_extension.into_blocked_artifact(),
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
}

impl RuleVSCode {
    const DEFAULT_MIN_PACKAGE_AGE: SystemDuration = SystemDuration::days(1);

    fn get_package_age_cutoff_ts(&self) -> SystemTimestampMilliseconds {
        self.policy_evaluator
            .as_ref()
            .map(|c| c.package_age_cutoff_ts(Self::DEFAULT_MIN_PACKAGE_AGE))
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - Self::DEFAULT_MIN_PACKAGE_AGE)
    }

    fn is_package_listed_as_malware(&self, vscode_extension: &VsCodeExtensionId) -> bool {
        self.remote_malware_list
            .find_entries(&vscode_extension.extension_id)
            .entries()
            .is_some()
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
    extension_id: VSCodePackageName,
    version: Option<PackageVersion>,
}

impl VsCodeExtensionId {
    fn new(publisher: &str, extension: &str, maybe_version_str: Option<&str>) -> VsCodeExtensionId {
        let maybe_version = maybe_version_str.map(|version_str| {
            let Ok(version) = PackageVersion::from_str(version_str);
            version
        });
        Self {
            extension_id: new_vscode_package_name(&format_smolstr!("{publisher}.{extension}")),
            version: maybe_version,
        }
    }

    fn into_blocked_artifact(self) -> Artifact {
        let Self {
            extension_id,
            version,
        } = self;
        Artifact {
            product: VSCODE_PRODUCT_KEY,
            identifier: extension_id.into_arcstr(),
            display_name: None,
            version,
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
