use std::fmt;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, StatusCode, Uri,
        headers::{ContentLength, HeaderMapExt as _},
    },
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::smol_str::{SmolStr, format_smolstr},
};

use rama::http::body::util::BodyExt;

use crate::{
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::response::generate_malware_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{RequestAction, Rule};

mod marketplace_json;

pub(in crate::firewall) struct RuleVSCode {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RuleVSCode {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        // NOTE: should you ever need to share a remote malware list between different rules,
        // you would simply create it outside of the rule, clone and pass it in.
        // These remoter malware list resources are cloneable and will share the list,
        // so it only gets updated once
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_vscode.json"),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote malware list for vscode block rule")?;

        Ok(Self {
            target_domains: [
                "gallery.vsassets.io",
                "gallerycdn.vsassets.io",
                "marketplace.visualstudio.com",
            ]
            .into_iter()
            .map(|domain| (Domain::from_static(domain), ()))
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
        "VSCode"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("VSCode rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let path = req.uri().path();

        // Check for direct .vsix file downloads from the CDN
        // VS Code can install extensions via:
        // 1. Gallery API (handled in evaluate_response) - queries extension metadata
        // 2. Direct .vsix downloads - can skip the API query entirely
        // Safe-chain handles both paths
        if !Self::is_extension_install_asset_path(path) {
            return Ok(RequestAction::Allow(req));
        }

        let Some(extension_id) = Self::parse_extension_id_from_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "VSCode extension install asset path could not be parsed for extension ID: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package = %extension_id,
            "VSCode install asset request"
        );

        if self.is_extension_id_malware(extension_id.as_str()) {
            tracing::info!(
                http.url.path = %path,
                package = %extension_id,
                "blocked VSCode extension install asset download"
            );
            return Ok(RequestAction::Block(
                generate_malware_blocked_response_for_req(req),
            ));
        }

        tracing::trace!(
            http.url.path = %path,
            package = %extension_id,
            "VSCode install asset does not contain malware: passthrough"
        );

        Ok(RequestAction::Allow(req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        // Check content type; JSON responses from gallery API will be inspected for blocked extensions.
        let is_json = resp
            .headers()
            .typed_get::<rama::http::headers::ContentType>()
            .map(|ct| ct == rama::http::headers::ContentType::json())
            .unwrap_or_default();

        if !is_json {
            tracing::trace!("VSCode response is not JSON: passthrough");
            return Ok(resp);
        }

        let (mut parts, body) = resp.into_parts();

        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "VSCode response: failed to collect body bytes; returning 502"
                );

                parts.status = StatusCode::BAD_GATEWAY;
                parts.headers.remove(rama::http::header::CONTENT_LENGTH);

                return Ok(Response::from_parts(parts, Body::empty()));
            }
        };

        // Attempt to rewrite Marketplace JSON to mark malware extensions.
        if let Some(modified_body) =
            self.rewrite_marketplace_json_response_body(body_bytes.as_ref())
        {
            tracing::debug!("VSCode response modified to mark blocked extensions");

            // Remove stale cache headers that no longer match the modified content
            parts.headers.remove(rama::http::header::ETAG);
            parts.headers.remove(rama::http::header::LAST_MODIFIED);
            parts.headers.remove(rama::http::header::CACHE_CONTROL);

            parts
                .headers
                .typed_insert(ContentLength(modified_body.len() as u64));

            return Ok(Response::from_parts(parts, Body::from(modified_body)));
        }

        tracing::trace!("VSCode response does not contain blocked extensions: passthrough");

        parts
            .headers
            .typed_insert(ContentLength(body_bytes.len() as u64));

        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    }
}

impl RuleVSCode {
    fn is_extension_id_malware(&self, extension_id: &str) -> bool {
        self.remote_malware_list
            .find_entries(extension_id)
            .entries()
            .is_some()
    }

    fn is_extension_install_asset_path(path: &str) -> bool {
        // VS Code install flow fetches multiple assets (manifest, signature, and eventually the VSIX).
        // If we only block the VSIX file itself, installs can still succeed depending on how the client
        // stages downloads. So treat these as install-related downloads as well.
        path.ends_with(".vsix")
            || path.ends_with("/Microsoft.VisualStudio.Services.VSIXPackage")
            || path.contains("/Microsoft.VisualStudio.Code.Manifest")
            || path.contains("/Microsoft.VisualStudio.Services.VsixSignature")
    }

    /// Parse extension ID (publisher.name) from .vsix download URL path.
    ///
    /// CDN paths typically follow patterns like:
    /// - /files/publisher/extensionname/version/extension.vsix
    /// - /_apis/public/gallery/publisher/publisher/extension/version/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage
    ///
    /// Returns `publisher.extensionname` format.
    fn parse_extension_id_from_path(path: &str) -> Option<SmolStr> {
        let path = path.trim_start_matches('/');

        // Pattern: /files/<publisher>/<extension>/<version>/...
        // The `files/` form is used for versioned artifacts, so require a version segment.
        if let Some(rest) = path.strip_prefix("files/") {
            let mut parts = rest.split('/');
            let publisher = parts.next()?;
            let extension = parts.next()?;
            let _version = parts.next()?;
            return Some(format_smolstr!("{}.{}", publisher, extension));
        }

        // Pattern: /_apis/public/gallery/publisher/<publisher>/<extension>/<version>/...
        // Pattern: /extensions/<publisher>/<extension>/<version>/<...>/Microsoft.VisualStudio.Services.VSIXPackage
        for prefix in ["_apis/public/gallery/publisher/", "extensions/"] {
            if let Some(rest) = path.strip_prefix(prefix) {
                let (publisher, extension) = parse_first_two_path_segments(rest)?;
                return Some(format_smolstr!("{}.{}", publisher, extension));
            }
        }

        // Pattern: /_apis/public/gallery/publishers/<publisher>/vsextensions/<extension>/<version>/...
        if let Some(rest) = path.strip_prefix("_apis/public/gallery/publishers/") {
            let mut parts = rest.split('/');
            let publisher = parts.next()?;
            let segment = parts.next()?;
            let extension = parts.next()?;
            let _version = parts.next()?;

            if segment.eq_ignore_ascii_case("vsextensions") {
                return Some(format_smolstr!("{}.{}", publisher, extension));
            }
        }

        None
    }
}

/// Extract first two path segments from a slash-separated path.
fn parse_first_two_path_segments(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    Some((parts.next()?, parts.next()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_extension_install_asset_path() {
        assert!(RuleVSCode::is_extension_install_asset_path(
            "/files/ms-python/python/1.0.0/whatever.vsix"
        ));
        assert!(RuleVSCode::is_extension_install_asset_path(
            "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
        ));
        assert!(RuleVSCode::is_extension_install_asset_path(
            "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest"
        ));
        assert!(RuleVSCode::is_extension_install_asset_path(
            "/extensions/ms-python/python/1.0.0/Microsoft.VisualStudio.Services.VsixSignature"
        ));

        assert!(!RuleVSCode::is_extension_install_asset_path(
            "/extensions/ms-python/python/whatever"
        ));
    }

    #[test]
    fn test_parse_extension_id_from_path() {
        let test_cases = vec![
            (
                "/files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
                Some("ms-python.python"),
            ),
            (
                "files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
                Some("ms-python.python"),
            ),
            (
                "/_apis/public/gallery/publisher/ms-python/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
                Some("ms-python.python"),
            ),
            (
                "/_apis/public/gallery/publishers/ms-python/vsextensions/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
                Some("ms-python.python"),
            ),
            (
                "/extensions/ms-python/python/2024.22.0/Microsoft.VisualStudio.Services.VsixSignature",
                Some("ms-python.python"),
            ),
            ("/extensions/ms-python/python", Some("ms-python.python")),
            ("/files/ms-python/python", None),
            (
                "/_apis/public/gallery/publishers/ms-python/notvsextensions/python/1.0.0",
                None,
            ),
            ("/something/else", None),
        ];

        for (input, expected) in test_cases {
            let parsed = RuleVSCode::parse_extension_id_from_path(input);
            assert_eq!(parsed.as_deref(), expected);
        }
    }
}
