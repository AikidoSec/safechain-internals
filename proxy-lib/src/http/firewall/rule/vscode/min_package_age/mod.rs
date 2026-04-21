use std::time::SystemTime;

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response,
        body::util::BodyExt as _,
        header,
        headers::{CacheControl, ContentType, HeaderMapExt as _},
        layer::remove_header::{
            remove_cache_policy_headers, remove_cache_validation_response_headers,
        },
    },
    telemetry::tracing,
    utils::{str::arcstr::ArcStr, time::now_unix_ms},
};

use crate::{
    http::{
        KnownContentType,
        firewall::{
            events::{Artifact, MinPackageAgeEvent},
            notifier::EventNotifier,
        },
    },
    package::version::PackageVersion,
};

#[derive(Debug, Clone)]
pub(in crate::http::firewall) struct MinPackageAgeVSCode {
    notifier: Option<EventNotifier>,
}

impl MinPackageAgeVSCode {
    pub fn new(notifier: Option<EventNotifier>) -> Self {
        Self { notifier }
    }

    pub async fn remove_new_versions(
        &self,
        resp: Response,
        cutoff_secs: i64,
    ) -> Result<Response, BoxError> {
        if resp
            .headers()
            .typed_get::<ContentType>()
            .clone()
            .and_then(KnownContentType::detect_from_content_type_header)
            != Some(KnownContentType::Json)
        {
            return Ok(resp);
        }

        let (mut parts, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .context("collect VSCode marketplace metadata response body")?
            .to_bytes();

        if bytes.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        let Some(rewrite) = rewrite_json(&bytes, cutoff_secs) else {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        };

        tracing::info!(
            suppressed_versions = ?rewrite.suppressed_versions,
            "VSCode marketplace metadata rewritten: suppressed too-young versions"
        );

        self.notify_rewrites(&rewrite.suppressed_versions).await;

        remove_cache_policy_headers(&mut parts.headers);
        remove_cache_validation_response_headers(&mut parts.headers);
        parts.headers.remove(header::CONTENT_LENGTH);
        parts
            .headers
            .typed_insert(CacheControl::new().with_no_cache());

        Ok(Response::from_parts(parts, Body::from(rewrite.bytes)))
    }

    async fn notify_rewrites(&self, suppressed: &[(ArcStr, PackageVersion)]) {
        let Some(notifier) = &self.notifier else {
            return;
        };

        // Group suppressed versions by extension ID before notifying.
        let mut by_extension: std::collections::HashMap<ArcStr, Vec<PackageVersion>> =
            std::collections::HashMap::new();
        for (ext_id, version) in suppressed {
            by_extension
                .entry(ext_id.clone())
                .or_default()
                .push(version.clone());
        }
        for (ext_id, versions) in by_extension {
            let event = MinPackageAgeEvent {
                ts_ms: now_unix_ms(),
                artifact: Artifact {
                    product: "vscode".into(),
                    identifier: ext_id.clone(),
                    display_name: Some(ext_id),
                    version: None,
                },
                suppressed_versions: versions,
            };
            notifier.notify_min_package_age(event).await;
        }
    }
}

#[derive(Debug)]
struct RewriteResult {
    bytes: Vec<u8>,
    suppressed_versions: Vec<(ArcStr, PackageVersion)>,
}

/// Filters out too-recent versions from a VSCode Marketplace JSON response.
/// # Example input (batch)
/// ```json
/// {
///   "results": [{
///     "extensions": [{
///       "publisher": { "publisherName": "rust-lang" },
///       "extensionName": "rust-analyzer",
///       "versions": [
///         { "version": "0.4.0", "lastUpdated": "9999-01-01T00:00:00Z" },
///         { "version": "0.3.0", "lastUpdated": "2020-01-01T00:00:00Z" }
///       ]
///     }]
///   }]
/// }
/// ```
/// Given a `cutoff_secs` in the past, `0.4.0` is stripped and `0.3.0` is kept.
fn rewrite_json(bytes: &[u8], cutoff_secs: i64) -> Option<RewriteResult> {
    let mut json: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(
                "VSCode marketplace response is not valid JSON, passing through: {err}"
            );
            return None;
        }
    };

    let mut suppressed: Vec<(ArcStr, PackageVersion)> = Vec::new();

    // Handle extensionquery batch response: {"results": [{"extensions": [...]}]}
    // Fall back to single-extension response: {"publisher": {...}, "extensionName": "...", "versions": [...]}
    let batch_extensions: Option<Vec<&mut serde_json::Value>> = json
        .get_mut("results")
        .and_then(|r| r.as_array_mut())
        .map(|results| {
            results
                .iter_mut()
                .filter_map(|r| r.get_mut("extensions").and_then(|e| e.as_array_mut()))
                .flatten()
                .collect()
        });

    if let Some(extensions) = batch_extensions {
        for extension in extensions {
            filter_extension_versions(extension, cutoff_secs, &mut suppressed);
        }
    } else {
        filter_extension_versions(&mut json, cutoff_secs, &mut suppressed);
    }

    if suppressed.is_empty() {
        return None;
    }

    let new_bytes = match serde_json::to_vec(&json) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!("failed to serialize modified VSCode marketplace response: {err}");
            return None;
        }
    };

    Some(RewriteResult {
        bytes: new_bytes,
        suppressed_versions: suppressed,
    })
}

fn filter_extension_versions(
    extension: &mut serde_json::Value,
    cutoff_secs: i64,
    suppressed: &mut Vec<(ArcStr, PackageVersion)>,
) {
    let publisher_name = extension
        .get("publisher")
        .and_then(|p| p.get("publisherName"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let extension_name = extension
        .get("extensionName")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if publisher_name.is_empty() || extension_name.is_empty() {
        return;
    }

    let extension_id: ArcStr = format!("{publisher_name}.{extension_name}").into();

    let Some(versions) = extension.get_mut("versions").and_then(|v| v.as_array_mut()) else {
        return;
    };

    // Track which version numbers have already been recorded to avoid duplicates
    // from platform-specific entries (e.g. darwin-arm64, darwin-x64, win32-x64).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    versions.retain(|v| {
        let Some(last_updated) = v.get("lastUpdated").and_then(|t| t.as_str()) else {
            return true;
        };
        let Some(published_secs) = parse_rfc3339_to_epoch_secs(last_updated) else {
            return true;
        };
        let too_new = published_secs > cutoff_secs;
        let version_str_opt = v.get("version").and_then(|s| s.as_str());
        if too_new
            && let Some(version_str) = version_str_opt
            && seen.insert(version_str.to_owned())
        {
            let version: PackageVersion = version_str.parse().unwrap();
            suppressed.push((extension_id.clone(), version));
        }
        !too_new
    });
}

/// Parse an RFC 3339 timestamp string into Unix epoch seconds, returning `None` on failure.
fn parse_rfc3339_to_epoch_secs(timestamp: &str) -> Option<i64> {
    match humantime::parse_rfc3339(timestamp) {
        Ok(t) => t
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .ok(),
        Err(err) => {
            tracing::debug!("failed to parse VSCode version timestamp '{timestamp}': {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests;
