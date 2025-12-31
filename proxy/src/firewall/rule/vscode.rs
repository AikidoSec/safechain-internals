use std::{env, fmt};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri, service::web::response::IntoResponse},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::smol_str::{SmolStr, format_smolstr},
};

use crate::{
    firewall::{malware_list::RemoteMalwareList, pac::PacScriptGenerator},
    http::response::generate_malware_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{RequestAction, Rule};

#[path = "vscode/marketplace_json.rs"]
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
            // For non-install-asset requests (like gallery API queries), pass through to
            // evaluate_response where we'll inspect the JSON response for malware.
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
            forced_test = %Self::is_forced_test_malware(extension_id.as_str()),
            "VSCode install asset request"
        );

        if self.is_extension_id_malware(extension_id.as_str()) {
            tracing::warn!(
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

        let (mut parts, body) = resp.into_parts();

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

        // Attempt to rewrite Marketplace JSON to mark malware extensions.
        if let Some(modified_body) =
            marketplace_json::rewrite_marketplace_json_response_body(&body_bytes, |extension_id| {
                self.is_extension_id_malware(extension_id)
            })
        {
            tracing::debug!("VSCode response modified to mark blocked extensions");

            // The response body has been rewritten, so any upstream Content-Length is invalid.
            // If we keep it, HTTP/2 clients can fail with PROTOCOL_ERROR.
            parts.headers.remove(rama::http::header::CONTENT_LENGTH);

            let mut rebuilt_resp = modified_body.into_response();
            *rebuilt_resp.status_mut() = parts.status;
            *rebuilt_resp.headers_mut() = parts.headers;
            *rebuilt_resp.extensions_mut() = parts.extensions;
            return Ok(rebuilt_resp);
        }

        tracing::trace!("VSCode response does not contain blocked extensions: passthrough");
        let mut rebuilt_resp = body_bytes.into_response();
        *rebuilt_resp.status_mut() = parts.status;
        *rebuilt_resp.headers_mut() = parts.headers;
        *rebuilt_resp.extensions_mut() = parts.extensions;
        Ok(rebuilt_resp)
    }
}

impl RuleVSCode {
    const FORCE_TEST_MALWARE_ENV: &str = "SAFECHAIN_FORCE_MALWARE_VSCODE";

    /// Get the extension ID(s) to force-treat as malware for testing.
    ///
    /// This allows local testing of the block UX without needing to publish
    ///  actual malicious extensions to the VS Code marketplace
    ///
    /// Usage:
    /// ```sh
    /// # Force-treat a single extension as malware:
    /// export SAFECHAIN_FORCE_MALWARE_VSCODE=ms-python.python
    ///
    /// # Force-treat multiple extensions:
    /// export SAFECHAIN_FORCE_MALWARE_VSCODE=ms-python.python,github.copilot
    /// ```
    fn get_forced_test_malware_ids() -> Option<Vec<String>> {
        env::var(Self::FORCE_TEST_MALWARE_ENV).ok().map(|val| {
            val.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
    }

    fn is_forced_test_malware(extension_id: &str) -> bool {
        Self::get_forced_test_malware_ids()
            .map(|ids| ids.iter().any(|id| id.eq_ignore_ascii_case(extension_id)))
            .unwrap_or(false)
    }

    fn is_extension_id_malware(&self, extension_id: &str) -> bool {
        Self::is_forced_test_malware(extension_id)
            || self
                .remote_malware_list
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

    use serde_json::Value;

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

    #[test]
    fn test_rewrite_marketplace_json_marks_matching_extension() {
        let body = Bytes::from(
            r#"{
                            "results": [
                                {
                                    "extensions": [
                                        {
                                            "publisher": { "publisherName": "pythoner" },
                                            "extensionName": "pythontheme",
                                            "displayName": "Python Theme"
                                        }
                                    ]
                                }
                            ]
                        }"#,
        );

        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |id| {
            id == "pythoner.pythontheme"
        })
        .expect("should rewrite");

        let val: Value = serde_json::from_slice(&modified).unwrap();
        let ext = &val["results"][0]["extensions"][0];
        assert!(
            ext["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
        );
        assert!(ext.get("shortDescription").is_some());
        assert!(ext.get("description").is_some());
    }

    #[test]
    fn test_rewrite_marketplace_json_noop_when_no_match() {
        let body = Bytes::from(
            r#"{\"results\":[{\"extensions\":[{\"publisher\":{\"publisherName\":\"python\"},\"extensionName\":\"python\",\"displayName\":\"Python\"}]}]}"#,
        );

        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |_id| false);
        assert!(modified.is_none());
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_invalid_responses() {
        // Invalid JSON
        let body = Bytes::from("not valid json");
        assert!(
            marketplace_json::rewrite_marketplace_json_response_body(&body, |_| true).is_none()
        );

        // Empty body
        let body = Bytes::from("");
        assert!(
            marketplace_json::rewrite_marketplace_json_response_body(&body, |_| true).is_none()
        );

        // Missing expected structure
        let body = Bytes::from(r#"{\"results\": []}"#);
        assert!(
            marketplace_json::rewrite_marketplace_json_response_body(&body, |_| true).is_none()
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_marks_multiple_malware_extensions() {
        let body = Bytes::from(
            r#"{
                "results": [{
                    "extensions": [
                        {
                            "publisher": { "publisherName": "malware1" },
                            "extensionName": "bad1",
                            "displayName": "Bad Extension 1"
                        },
                        {
                            "publisher": { "publisherName": "safe" },
                            "extensionName": "good",
                            "displayName": "Good Extension"
                        },
                        {
                            "publisher": { "publisherName": "malware2" },
                            "extensionName": "bad2",
                            "displayName": "Bad Extension 2"
                        }
                    ]
                }]
            }"#,
        );

        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |id| {
            id == "malware1.bad1" || id == "malware2.bad2"
        })
        .expect("should rewrite");

        let val: Value = serde_json::from_slice(&modified).unwrap();
        let extensions = val["results"][0]["extensions"].as_array().unwrap();

        assert_eq!(extensions.len(), 3);

        let malware1 = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("bad1"))
            .expect("malware1.bad1 should exist");
        assert!(
            malware1["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
            "malware1 displayName should start with malware marker, got: {}",
            malware1["displayName"].as_str().unwrap(),
        );

        let safe = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("good"))
            .expect("safe.good should exist");
        assert_eq!(safe["displayName"].as_str().unwrap(), "Good Extension");

        let malware2 = extensions
            .iter()
            .find(|e| e["extensionName"].as_str() == Some("bad2"))
            .expect("malware2.bad2 should exist");
        assert!(
            malware2["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:"),
            "malware2 displayName should start with malware marker, got: {}",
            malware2["displayName"].as_str().unwrap(),
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_nested_results() {
        let body = Bytes::from(
            r#"{
                "results": [
                    {
                        "extensions": [
                            {
                                "publisher": { "publisherName": "test1" },
                                "extensionName": "ext1",
                                "displayName": "Extension 1"
                            }
                        ]
                    },
                    {
                        "extensions": [
                            {
                                "publisher": { "publisherName": "malware" },
                                "extensionName": "bad",
                                "displayName": "Bad Extension"
                            }
                        ]
                    }
                ]
            }"#,
        );

        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |id| {
            id == "malware.bad"
        })
        .expect("should rewrite");

        let val: Value = serde_json::from_slice(&modified).unwrap();
        let results = val["results"].as_array().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0]["extensions"][0]["displayName"].as_str().unwrap(),
            "Extension 1"
        );
        assert!(
            results[1]["extensions"][0]["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_preserves_other_fields() {
        let body = Bytes::from(
            r#"{
                "results": [{
                    "extensions": [{
                        "publisher": { "publisherName": "test", "url": "https://example.com" },
                        "extensionName": "test",
                        "displayName": "Test",
                        "version": "1.0.0",
                        "lastUpdated": "2024-01-01",
                        "downloadCount": 1000
                    }]
                }]
            }"#,
        );

        let modified =
            marketplace_json::rewrite_marketplace_json_response_body(&body, |id| id == "test.test")
                .expect("should rewrite");

        let val: Value = serde_json::from_slice(&modified).unwrap();
        let ext = &val["results"][0]["extensions"][0];

        // Modified fields
        assert!(
            ext["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
        assert!(ext.get("shortDescription").is_some());
        assert!(ext.get("description").is_some());

        // Preserved fields
        assert_eq!(ext["version"].as_str().unwrap(), "1.0.0");
        assert_eq!(ext["lastUpdated"].as_str().unwrap(), "2024-01-01");
        assert_eq!(ext["downloadCount"].as_i64().unwrap(), 1000);
        assert_eq!(
            ext["publisher"]["url"].as_str().unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_handles_large_response() {
        // Create a response with many extensions
        let mut extensions = Vec::new();
        for i in 0..100 {
            extensions.push(serde_json::json!({
                "publisher": { "publisherName": format!("publisher{}", i) },
                "extensionName": format!("ext{}", i),
                "displayName": format!("Extension {}", i)
            }));
        }

        let body_json = serde_json::json!({
            "results": [{
                "extensions": extensions
            }]
        });

        let body = Bytes::from(serde_json::to_string(&body_json).unwrap());

        // Mark the 50th extension as malware
        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |id| {
            id == "publisher50.ext50"
        })
        .expect("should rewrite");

        let val: Value = serde_json::from_slice(&modified).unwrap();
        let result_extensions = val["results"][0]["extensions"].as_array().unwrap();

        assert_eq!(result_extensions.len(), 100);
        assert!(
            result_extensions[50]["displayName"]
                .as_str()
                .unwrap()
                .starts_with("⛔ MALWARE:")
        );
        assert_eq!(
            result_extensions[0]["displayName"].as_str().unwrap(),
            "Extension 0"
        );
        assert_eq!(
            result_extensions[99]["displayName"].as_str().unwrap(),
            "Extension 99"
        );
    }

    #[test]
    fn test_rewrite_marketplace_json_depth_limit_stops_traversal() {
        // Build a deeply nested JSON object, deeper than the traversal limit.
        // This ensures we do not recurse unboundedly and that we intentionally
        // stop searching past a reasonable depth.
        let mut root = serde_json::json!({});

        let mut current = &mut root;
        for _ in 0..(marketplace_json::MAX_MARKETPLACE_JSON_TRAVERSAL_DEPTH + 10) {
            current
                .as_object_mut()
                .unwrap()
                .insert("n".to_string(), serde_json::json!({}));
            current = current.get_mut("n").unwrap();
        }

        // Place an extension-like object beyond the depth limit.
        current.as_object_mut().unwrap().insert(
            "extension".to_string(),
            serde_json::json!({
                "publisher": { "publisherName": "ms-python" },
                "extensionName": "python",
                "displayName": "Python"
            }),
        );

        let body = Bytes::from(serde_json::to_vec(&root).unwrap());

        // Even if we treat every ID as malware, we should not rewrite because the traversal
        // never reaches the nested extension object.
        let modified = marketplace_json::rewrite_marketplace_json_response_body(&body, |_id| true);
        assert!(modified.is_none());
    }
}
