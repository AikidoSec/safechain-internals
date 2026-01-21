use std::fmt;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsRef as _,
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, StatusCode, Uri,
        headers::{ContentLength, HeaderMapExt as _},
        service::web::response::IntoResponse,
    },
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::smol_str::{SmolStr, format_smolstr},
};

use rama::http::body::util::BodyExt;

use rama::utils::str::arcstr::{ArcStr, arcstr};

use crate::{
    firewall::events::{BlockedArtifact, BlockedEventInfo},
    firewall::layer::evaluate_resp::ResponseRequestDomain,
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::{
        KnownContentType, remove_cache_headers, response::generate_malware_blocked_response_for_req,
    },
    storage::SyncCompactDataStorage,
};

use super::{BlockedRequest, RequestAction, Rule};

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
                "*.gallery.vsassets.io",
                "*.gallerycdn.vsassets.io",
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
        "VSCode Extensions"
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
            tracing::trace!(
                http.url.path = %path,
                "VSCode path is not an install asset (e.g., manifest/signature): passthrough"
            );
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
            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_malware_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("vscode"),
                        identifier: ArcStr::from(extension_id.as_str()),
                        version: None,
                    },
                },
            }));
        }

        tracing::trace!(
            http.url.path = %path,
            package = %extension_id,
            "VSCode install asset does not contain malware: passthrough"
        );

        Ok(RequestAction::Allow(req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        if !resp
            .extensions()
            .get::<ResponseRequestDomain>()
            .map(|domain| self.match_domain(&domain.0))
            .unwrap_or_default()
        {
            tracing::trace!("VSCode rule did not match response domain: passthrough");
            return Ok(resp);
        }

        // Check content type; JSON responses from gallery API will be inspected for blocked extensions.
        let is_json = resp
            .headers()
            .typed_get()
            .and_then(KnownContentType::detect_from_content_type_header)
            == Some(KnownContentType::Json);

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
                return Ok(StatusCode::BAD_GATEWAY.into_response());
            }
        };

        // Attempt to rewrite Marketplace JSON to mark malware extensions.
        if let Some(modified_body) =
            self.rewrite_marketplace_json_response_body(body_bytes.as_ref())
        {
            tracing::debug!("VSCode response modified to mark blocked extensions");

            remove_cache_headers(&mut parts.headers);

            parts
                .headers
                .typed_insert(ContentLength(modified_body.len() as u64));

            return Ok(Response::from_parts(parts, Body::from(modified_body)));
        }

        tracing::trace!("VSCode response does not contain blocked extensions: passthrough");

        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    }
}

impl RuleVSCode {
    fn is_extension_id_malware(&self, extension_id: &str) -> bool {
        // Try exact match first (in case malware list has mixed case)
        if self
            .remote_malware_list
            .find_entries(extension_id)
            .entries()
            .is_some()
        {
            return true;
        }

        // If the id is already ASCII-lowercase, a second lookup would be identical.
        if !extension_id.as_bytes().iter().any(u8::is_ascii_uppercase) {
            return false;
        }

        let normalized_id = extension_id.to_ascii_lowercase();
        self.remote_malware_list
            .find_entries(&normalized_id)
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
    fn parse_extension_id_from_path(path: &str) -> Option<SmolStr> {
        let mut it = path.trim_start_matches('/').split('/');

        let first = it.next()?;

        // Pattern: files/<publisher>/<extension>/<version>/...
        if first.eq_ignore_ascii_case("files") {
            let publisher = it.next()?;
            let extension = it.next()?;
            let _ = it.next()?; // we require at least a fourth path
            return Some(format_smolstr!("{publisher}.{extension}"));
        }

        // Pattern: extensions/<publisher>/<extension>/...
        if first.eq_ignore_ascii_case("extensions") {
            let publisher = it.next()?;
            let extension = it.next()?;
            return Some(format_smolstr!("{publisher}.{extension}"));
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
                    return Some(format_smolstr!("{publisher}.{extension}"));
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
                    return Some(format_smolstr!("{publisher}.{extension}"));
                }

                return Some(format_smolstr!("{publisher}.{next}"));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests;
