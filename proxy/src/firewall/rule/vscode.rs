use std::{env, fmt};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::{smol_str::format_smolstr, starts_with_ignore_ascii_case},
};

use serde_json::Value;
use smol_str::format_smolstr;

use crate::{
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::{response::generate_generic_blocked_response_for_req, try_get_domain_for_req},
    storage::SyncCompactDataStorage,
};

use super::{RequestAction, Rule};

const FORCE_TEST_MALWARE_ENV: &str = "SAFECHAIN_FORCE_MALWARE_VSCODE";
// Well-known extension ID for local/manual testing.
// When `SAFECHAIN_FORCE_MALWARE_VSCODE` is enabled, this extension will be treated as malware
// (all versions) to exercise the Safe-chain block UX.
const FORCED_TEST_EXTENSION_ID: &str = "ms-python.python";

fn env_var_truthy(name: &str) -> bool {
    env::var(name).ok().is_some_and(|v| {
        let v = v.as_str();
        v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
    })
}

fn is_forced_test_malware(extension_id: &str) -> bool {
    env_var_truthy(FORCE_TEST_MALWARE_ENV)
        && extension_id.eq_ignore_ascii_case(FORCED_TEST_EXTENSION_ID)
}

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
            // NOTE: should you ever make this list dynamic we would stop hardcoding these target domains here...
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
        if !try_get_domain_for_req(&req)
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
        // We need to block both paths for comprehensive protection.
        // VS Code install flow fetches multiple assets (manifest, signature, and eventually the VSIX).
        // If we only block the VSIX file itself, installs can still succeed depending on how the client
        // stages downloads. So treat these as install-related downloads as well.
        if !is_vscode_extension_install_asset_path(path) {
            // For non-install-asset requests (like gallery API queries), pass through to
            // evaluate_response where we'll inspect the JSON response for malware.
            return Ok(RequestAction::Allow(req));
        }

        let Some(extension_id) = parse_extension_id_from_vsix_path(path) else {
            tracing::debug!(
                http.url.path = %path,
                "VSCode extension install asset path could not be parsed for extension ID: passthrough"
            );
            return Ok(RequestAction::Allow(req));
        };

        tracing::debug!(
            http.url.path = %path,
            package = %extension_id,
            forced_test = %is_forced_test_malware(extension_id.as_str()),
            "VSCode install asset request"
        );

        if self.is_extension_id_malware(extension_id.as_str()) {
            tracing::warn!(
                http.url.path = %path,
                package = %extension_id,
                "blocked VSCode extension install asset download"
            );
            return Ok(RequestAction::Block(
                generate_generic_blocked_response_for_req(req),
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
        let content_type = resp
            .headers()
            .get(rama::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let is_json = content_type
            .map(|ct| ct.contains("application/json"))
            .unwrap_or_default();

        if !is_json {
            tracing::trace!("VSCode response is not JSON: passthrough");
            return Ok(resp);
        }

        // Collect the response body to inspect for blocked extensions.
        let (mut parts, body) = resp.into_parts();

        // Try to collect body bytes; if it fails, allow response through
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::debug!(error = %err, "VSCode response: failed to collect body bytes; returning empty body");

                // Ensure no stale Content-Length is sent for an empty body.
                parts.headers.remove(rama::http::header::CONTENT_LENGTH);

                return Ok(Response::from_parts(
                    parts,
                    Body::new(Full::new(Bytes::new())),
                ));
            }
        };

        // Attempt to modify the body if malware is found
        if let Some(modified_body) = self.modify_response_body_if_malware_found(&body_bytes) {
            tracing::debug!("VSCode response modified to mark blocked extensions");

            // The response body has been rewritten, so any upstream Content-Length is invalid.
            // If we keep it, HTTP/2 clients can fail with PROTOCOL_ERROR.
            parts.headers.remove(rama::http::header::CONTENT_LENGTH);

            return Ok(Response::from_parts(
                parts,
                Body::new(Full::new(modified_body)),
            ));
        }

        tracing::trace!("VSCode response does not contain blocked extensions: passthrough");
        Ok(Response::from_parts(
            parts,
            Body::new(Full::new(body_bytes)),
        ))
    }
}

impl RuleVSCode {
    fn is_extension_id_malware(&self, extension_id: &str) -> bool {
        is_forced_test_malware(extension_id)
            || self
                .remote_malware_list
                .find_entries(extension_id)
                .entries()
                .is_some()
    }

    /// Parses a JSON response body, and if it contains malware extensions,
    /// modifies the JSON to mark them as blocked.
    ///
    /// Returns `Some(Bytes)` with the modified body if changes were made,
    /// otherwise returns `None`.
    fn modify_response_body_if_malware_found(&self, body_bytes: &Bytes) -> Option<Bytes> {
        let mut val: Value = match serde_json::from_slice(body_bytes) {
            Ok(val) => val,
            Err(err) => {
                tracing::trace!(error = %err, "VSCode response: failed to parse JSON; passing through");
                return None;
            }
        };

        // Marketplace responses can be nested (e.g. results -> [ { extensions: [ ... ] } ]).
        // Instead of coupling to a specific schema, scan the JSON tree and mark any extension
        // objects that contain the fields we need.
        let modified = self.mark_any_extensions_if_malware(&mut val);

        if modified {
            match serde_json::to_vec(&val) {
                Ok(modified_bytes) => Some(Bytes::from(modified_bytes)),
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to serialize modified VSCode response; passing original through");
                    None
                }
            }
        } else {
            None
        }
    }

    /// Recursively walks a JSON tree and marks any VSCode extension objects as blocked
    /// when they match the malware list (or the forced-test extension id).
    fn mark_any_extensions_if_malware(&self, value: &mut Value) -> bool {
        match value {
            Value::Array(values) => values.iter_mut().fold(false, |acc, v| {
                self.mark_any_extensions_if_malware(v) || acc
            }),
            Value::Object(_) => {
                let mut modified = self.mark_extension_object_if_malware(value);

                // Recurse into children
                if let Some(obj) = value.as_object_mut() {
                    for (_, child) in obj.iter_mut() {
                        if self.mark_any_extensions_if_malware(child) {
                            modified = true;
                        }
                    }
                }

                modified
            }
            _ => false,
        }
    }

    /// Checks whether the provided JSON value looks like a VSCode extension object
    /// (has the fields we need: publisher + extension name) and if so, marks it as blocked.
    fn mark_extension_object_if_malware(&self, value: &mut Value) -> bool {
        let publisher = extract_publisher_name(value);
        let extension_name = extract_extension_name(value);

        let (publisher, extension_name) = match (publisher, extension_name) {
            (Some(p), Some(n)) => (p, n),
            _ => return false,
        };

        let extension_name_fallback = extension_name.to_string();
        let fq_package_name = format_smolstr!("{}.{}", publisher.trim(), extension_name.trim());

        if !self.is_extension_id_malware(fq_package_name.as_str()) {
            return false;
        }

        tracing::warn!(
            package = %fq_package_name,
            forced_test = %is_forced_test_malware(fq_package_name.as_str()),
            "marked malware VSCode extension as blocked in API response"
        );

        let Some(obj) = value.as_object_mut() else {
            return false;
        };

        let original_name = obj
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or(&extension_name_fallback);

        obj.insert(
            "displayName".to_string(),
            Value::String(format!("⛔ MALWARE: {}", original_name)),
        );

        obj.insert(
            "shortDescription".to_string(),
            Value::String(
                "This extension has been marked as malware by Safe-chain.\nInstallation will be blocked."
                    .to_string(),
            ),
        );
        obj.insert(
            "description".to_string(),
            Value::String(
                "This extension cannot be installed as it has been identified as malware by Safe-chain."
                    .to_string(),
            ),
        );

        if let Some(flags) = obj.get_mut("flags") {
            if let Some(flags_str) = flags.as_str() {
                *flags = Value::String(format!("{} malicious", flags_str));
            }
        } else {
            obj.insert("flags".to_string(), Value::String("malicious".to_string()));
        }

        true
    }
}

// Helper to extract publisher.name field using serde_json Value
fn extract_publisher_name(value: &Value) -> Option<&str> {
    // Marketplace responses vary; support a couple common shapes.
    // - { publisher: { name: "ms-python" }, name: "python" }
    // - { publisher: { publisherName: "ms-python" }, extensionName: "python" }
    // - { publisherName: "ms-python", extensionName: "python" }
    value
        .get("publisher")
        .and_then(|pub_obj| pub_obj.get("publisherName").or_else(|| pub_obj.get("name")))
        .or_else(|| value.get("publisherName"))
        .and_then(|name_val| name_val.as_str())
}

// Helper to extract extension name field using serde_json Value
fn extract_extension_name(value: &Value) -> Option<&str> {
    value
        .get("extensionName")
        .or_else(|| value.get("name"))
        .and_then(|name_val| name_val.as_str())
}

fn is_vscode_extension_install_asset_path(path: &str) -> bool {
    // VS Code install flow fetches multiple assets (manifest, signature, and eventually the VSIX).
    // If we only block the VSIX file itself, installs can still succeed depending on how the client
    // stages downloads. So treat these as install-related downloads as well.
    path.ends_with(".vsix")
        || path.ends_with("/Microsoft.VisualStudio.Services.VSIXPackage")
        || path.contains("/Microsoft.VisualStudio.Code.Manifest")
        || path.contains("/Microsoft.VisualStudio.Services.VsixSignature")
}

/// Parse extension ID (publisher.name) from .vsix download URL path
/// CDN paths typically follow patterns like:
/// - /files/publisher/extensionname/version/extension.vsix
/// - /_apis/public/gallery/publisher/publisher/extension/version/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage
///   Returns publisher.extensionname format
fn parse_extension_id_from_vsix_path(path: &str) -> Option<smol_str::SmolStr> {
    let path = path.trim_start_matches('/');

    // Pattern: /files/<publisher>/<extension>/<version>/...
    if let Some(rest) = path.strip_prefix("files/") {
        let mut parts = rest.split('/');
        let publisher = parts.next()?;
        let extension = parts.next()?;
        let _version = parts.next()?;
        return Some(format_smolstr!("{}.{}", publisher, extension));
    }

    // Pattern: /_apis/public/gallery/publisher/<publisher>/<extension>/<version>/...
    if let Some(rest) = path.strip_prefix("_apis/public/gallery/publisher/") {
        let mut parts = rest.split('/');
        let publisher = parts.next()?;
        let extension = parts.next()?;
        return Some(format_smolstr!("{}.{}", publisher, extension));
    }

    // Pattern (common in marketplace downloads):
    // /_apis/public/gallery/publishers/<publisher>/vsextensions/<extension>/<version>/...
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

    // Pattern (seen in your logs for marketplace CDN assets):
    // /extensions/<publisher>/<extension>/<version>/<...>/Microsoft.VisualStudio.Services.VSIXPackage
    if let Some(rest) = path.strip_prefix("extensions/") {
        let mut parts = rest.split('/');
        let publisher = parts.next()?;
        let extension = parts.next()?;
        return Some(format_smolstr!("{}.{}", publisher, extension));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_vscode_extension_install_asset_path() {
        assert!(is_vscode_extension_install_asset_path(
            "/files/ms-python/python/1.0.0/whatever.vsix"
        ));
        assert!(is_vscode_extension_install_asset_path(
            "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
        ));
        assert!(is_vscode_extension_install_asset_path(
            "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest"
        ));
        assert!(is_vscode_extension_install_asset_path(
            "/extensions/ms-python/python/1.0.0/Microsoft.VisualStudio.Services.VsixSignature"
        ));

        assert!(!is_vscode_extension_install_asset_path(
            "/extensions/ms-python/python/whatever"
        ));
    }

    #[test]
    fn test_parse_extension_id_from_vsix_path() {
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
            let parsed = parse_extension_id_from_vsix_path(input);
            assert_eq!(parsed.as_deref(), expected);
        }
    }
}
