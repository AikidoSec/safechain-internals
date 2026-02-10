use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
};

use rama::utils::str::arcstr::{ArcStr, arcstr};

use crate::{
    firewall::{
        domain_matcher::DomainMatcher,
        events::{BlockedArtifact, BlockedEventInfo},
        malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
        pac::PacScriptGenerator,
    },
    http::response::generate_malware_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

pub(in crate::firewall) struct RuleVSCode {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleVSCode {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_vscode.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for vscode block rule")?;

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
    fn product_name(&self) -> &'static str {
        "VSCode Extensions"
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

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("VSCode rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

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

        if self.is_package_listed_as_malware(&vscode_extension) {
            tracing::info!(
                http.url.path = %path,
                package = %vscode_extension,
                "blocked VSCode extension install asset download"
            );
            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_malware_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("vscode"),
                        identifier: ArcStr::from(vscode_extension.extension_id.as_str()),
                        version: None,
                    },
                },
            }));
        }

        tracing::trace!(
            http.url.path = %path,
            package = %vscode_extension,
            "VSCode install asset does not contain malware: passthrough"
        );

        Ok(RequestAction::Allow(req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        Ok(resp)
    }
}

impl RuleVSCode {
    fn is_package_listed_as_malware(&self, vscode_extension: &VsCodeExtensionId) -> bool {
        self.remote_malware_list
            .find_entries(&vscode_extension.extension_id)
            .entries()
            .is_some()
    }

    fn ends_with_ignore_ascii_case(path: &str, suffix: &str) -> bool {
        if path.len() < suffix.len() {
            return false;
        }

        let start = path.len() - suffix.len();
        path.get(start..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
    }

    fn is_extension_install_asset_path(path: &str) -> bool {
        let path = path.trim_end_matches('/');

        Self::ends_with_ignore_ascii_case(path, ".vsix")
            || Self::ends_with_ignore_ascii_case(
                path,
                "/Microsoft.VisualStudio.Services.VSIXPackage",
            )
            || Self::ends_with_ignore_ascii_case(path, "/vspackage")
    }

    /// Parse extension ID (publisher.name) from .vsix download URL path.
    fn parse_extension_id_from_path(path: &str) -> Option<VsCodeExtensionId> {
        let mut it = path.trim_start_matches('/').split('/');

        let first = it.next()?;

        // Pattern: files/<publisher>/<extension>/<version>/...
        if first.eq_ignore_ascii_case("files") {
            let publisher = it.next()?;
            let extension = it.next()?;
            let _ = it.next()?; // we require at least a fourth path
            return Some(VsCodeExtensionId::new(publisher, extension));
        }

        // Pattern: extensions/<publisher>/<extension>/...
        if first.eq_ignore_ascii_case("extensions") {
            let publisher = it.next()?;
            let extension = it.next()?;
            return Some(VsCodeExtensionId::new(publisher, extension));
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
                    return Some(VsCodeExtensionId::new(publisher, extension));
                }
            }

            // Pattern: _apis/public/gallery/publisher/<publisher>/<extension>/...
            // Pattern: _apis/public/gallery/publisher/<publisher>/extension/<extension>/...
            if second.eq_ignore_ascii_case("public")
                && third.eq_ignore_ascii_case("gallery")
                && fourth.eq_ignore_ascii_case("publisher")
            {
                let publisher = it.next()?;
                let next = it.next()?;

                if next.eq_ignore_ascii_case("extension") {
                    let extension = it.next()?;
                    return Some(VsCodeExtensionId::new(publisher, extension));
                }

                return Some(VsCodeExtensionId::new(publisher, next));
            }
        }

        None
    }
}

struct VsCodeExtensionId {
    extension_id: String,
}

impl VsCodeExtensionId {
    fn new(publisher: &str, extension: &str) -> VsCodeExtensionId {
        Self {
            extension_id: format!("{publisher}.{extension}"),
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
