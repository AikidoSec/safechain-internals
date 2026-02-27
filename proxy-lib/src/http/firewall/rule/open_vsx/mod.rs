use std::fmt;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::Domain,
    telemetry::tracing,
    utils::str::{
        self as str_utils,
        arcstr::{ArcStr, arcstr},
    },
};

use crate::{
    http::{
        firewall::{
            domain_matcher::DomainMatcher,
            events::{BlockedArtifact, BlockedEventInfo},
        },
        response::generate_malware_blocked_response_for_req,
    },
    package::malware_list::{LowerCaseEntryFormatter, RemoteMalwareList},
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

pub(in crate::http::firewall) struct RuleOpenVsx {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RuleOpenVsx {
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
            Uri::from_static("https://malware-list.aikido.dev/malware_open_vsx.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for open vsx block rule")?;

        Ok(Self {
            target_domains: ["open-vsx.org", "marketplace.cursorapi.com"]
                .into_iter()
                .collect(),
            remote_malware_list,
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
    fn product_name(&self) -> &'static str {
        "Open VSX Extensions"
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

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("Open VSX rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

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

        if self.is_package_listed_as_malware(&extension) {
            tracing::warn!(
                http.url.path = %path,
                package = %extension,
                "blocked Open VSX extension install asset download"
            );
            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_malware_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("open_vsx"),
                        identifier: ArcStr::from(extension.extension_id.as_str()),
                        version: None,
                    },
                },
            }));
        }

        tracing::debug!(
            http.url.path = %path,
            package = %extension,
            "Open VSX install asset does not contain malware: passthrough"
        );

        Ok(RequestAction::Allow(req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        Ok(resp)
    }
}

impl RuleOpenVsx {
    fn is_package_listed_as_malware(&self, extension: &OpenVsxExtensionId) -> bool {
        self.remote_malware_list
            .find_entries(&extension.extension_id.to_ascii_lowercase())
            .entries()
            .is_some()
    }

    fn is_extension_install_asset_path(path: &str) -> bool {
        let path = path.trim_end_matches('/');

        str_utils::any_ends_with_ignore_ascii_case(
            path,
            ["/Microsoft.VisualStudio.Services.VSIXPackage"],
        )
    }

    /// Parse extension ID (`publisher.extension`) from an Open VSX download URL path.
    ///
    /// Handles two URL patterns:
    /// - `open-vsx.org`: `/vscode/asset/{publisher}/{extension}/{version}/...`
    /// - `marketplace.cursorapi.com`: `/open-vsx-mirror/vscode/asset/{publisher}/{extension}/{version}/...`
    fn parse_extension_id_from_path(path: &str) -> Option<OpenVsxExtensionId> {
        let mut it = path.trim_start_matches('/').split('/');

        let first = it.next()?;

        // Pattern: vscode/asset/{publisher}/{extension}/...
        if first.eq_ignore_ascii_case("vscode") {
            let second = it.next()?;
            if second.eq_ignore_ascii_case("asset") {
                let publisher = it.next()?;
                let extension = it.next()?;
                return Some(OpenVsxExtensionId::new(publisher, extension));
            }
        }

        // Pattern: open-vsx-mirror/vscode/asset/{publisher}/{extension}/...
        if first.eq_ignore_ascii_case("open-vsx-mirror") {
            let second = it.next()?;
            if second.eq_ignore_ascii_case("vscode") {
                let third = it.next()?;
                if third.eq_ignore_ascii_case("asset") {
                    let publisher = it.next()?;
                    let extension = it.next()?;
                    return Some(OpenVsxExtensionId::new(publisher, extension));
                }
            }
        }

        None
    }
}

struct OpenVsxExtensionId {
    extension_id: String,
}

impl OpenVsxExtensionId {
    fn new(publisher: &str, extension: &str) -> OpenVsxExtensionId {
        Self {
            extension_id: format!("{publisher}/{extension}"),
        }
    }
}

impl fmt::Display for OpenVsxExtensionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.extension_id)
    }
}

#[cfg(test)]
mod tests;
