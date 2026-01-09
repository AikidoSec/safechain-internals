use std::fmt;

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsRef,
    graceful::ShutdownGuard,
    http::{
        Body, Request, Response, StatusCode, Uri,
        headers::{ContentLength, HeaderMapExt as _},
        service::web::response::IntoResponse,
    },
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::{
        collections::smallvec::SmallVec,
        str::smol_str::{SmolStr, format_smolstr},
    },
};

use rama::http::body::util::BodyExt;

use crate::{
    firewall::layer::evaluate_resp::ResponseRequestDomain,
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::{
        KnownContentType, remove_cache_headers, response::generate_malware_blocked_response_for_req,
    },
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
        if !resp
            .extensions()
            .get::<ResponseRequestDomain>()
            .map(|domain| self.match_domain(&domain.0))
            .unwrap_or_default()
        {
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
        let path_without_query = path.split('?').next().unwrap_or(path);
        let path_without_query = path_without_query.trim_end_matches('/');

        Self::ends_with_ignore_ascii_case(path_without_query, ".vsix")
            || Self::ends_with_ignore_ascii_case(
                path_without_query,
                "/Microsoft.VisualStudio.Services.VSIXPackage",
            )
            || Self::ends_with_ignore_ascii_case(path_without_query, "/vspackage")
    }

    /// Parse extension ID (publisher.name) from .vsix download URL path.
    fn parse_extension_id_from_path(path: &str) -> Option<SmolStr> {
        let path = path.trim_start_matches('/');
        let parts: SmallVec<[&str; 8]> = path.splitn(8, '/').collect();

        // Pattern: files/<publisher>/<extension>/<version>/...
        if parts.len() >= 4 && parts[0].eq_ignore_ascii_case("files") {
            return Some(format_smolstr!("{}.{}", parts[1], parts[2]));
        }

        // Pattern: extensions/<publisher>/<extension>/...
        if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("extensions") {
            return Some(format_smolstr!("{}.{}", parts[1], parts[2]));
        }

        // Pattern: _apis/public/gallery/publishers/<publisher>/vsextensions/<extension>/...
        if parts.len() >= 7
            && parts[0].eq_ignore_ascii_case("_apis")
            && parts[1].eq_ignore_ascii_case("public")
            && parts[2].eq_ignore_ascii_case("gallery")
            && parts[3].eq_ignore_ascii_case("publishers")
            && (parts[5].eq_ignore_ascii_case("vsextensions")
                || parts[5].eq_ignore_ascii_case("extensions"))
        {
            return Some(format_smolstr!("{}.{}", parts[4], parts[6]));
        }

        // Pattern: _apis/public/gallery/publisher/<publisher>/<extension>/...
        // Pattern: _apis/public/gallery/publisher/<publisher>/extension/<extension>/...
        if parts.len() >= 6
            && parts[0].eq_ignore_ascii_case("_apis")
            && parts[1].eq_ignore_ascii_case("public")
            && parts[2].eq_ignore_ascii_case("gallery")
            && parts[3].eq_ignore_ascii_case("publisher")
        {
            let publisher = parts[4];

            // Check if there's a literal "extension" segment
            if parts[5].eq_ignore_ascii_case("extension") && parts.len() >= 7 {
                return Some(format_smolstr!("{}.{}", publisher, parts[6]));
            } else {
                return Some(format_smolstr!("{}.{}", publisher, parts[5]));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests;
