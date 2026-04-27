use std::str::FromStr as _;

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response,
        body::util::BodyExt as _,
        header::CONTENT_LENGTH,
        headers::{ContentType, HeaderMapExt as _},
    },
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use crate::{
    http::{
        KnownContentType,
        firewall::{
            events::{Artifact, MinPackageAgeEvent},
            notifier::EventNotifier,
        },
        headers::make_response_uncacheable,
    },
    package::{
        name_formatter::LowerCasePackageName, released_packages_list::RemoteReleasedPackagesList,
        version::PackageVersion,
    },
    utils::time::SystemTimestampMilliseconds,
};

type OpenVsxPackageName = LowerCasePackageName;
type OpenVsxRemoteReleasedPackagesList = RemoteReleasedPackagesList<OpenVsxPackageName>;

/// Max response body size we will buffer for JSON rewriting.
/// Observed normal range: 163 KB – 373 KB; occasional 10 MB; one 57 MB outlier.
/// 8 MB comfortably covers typical traffic and stops pathological bodies from
/// pulling hundreds of MB through `serde_json::Value`.
const MAX_METADATA_BODY_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(in crate::http::firewall) struct MinPackageAgeOpenVsx {
    notifier: Option<EventNotifier>,
}

impl MinPackageAgeOpenVsx {
    pub fn new(notifier: Option<EventNotifier>) -> Self {
        Self { notifier }
    }

    pub async fn remove_new_versions(
        &self,
        resp: Response,
        released_packages_list: &OpenVsxRemoteReleasedPackagesList,
        cutoff_ts: SystemTimestampMilliseconds,
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

        // Size guard: if the server advertised a Content-Length larger than the cap,
        // passthrough untouched rather than buffer the entire body for JSON rewriting.
        // A missing Content-Length (chunked) falls through to collect(); we have not
        // observed chunked metadata responses in practice.
        if let Some(declared_len) = resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            && declared_len > MAX_METADATA_BODY_BYTES
        {
            tracing::warn!(
                declared_len,
                limit = MAX_METADATA_BODY_BYTES,
                "OpenVSX metadata response exceeds size cap, skipping rewrite"
            );
            return Ok(resp);
        }

        let (mut parts, body) = resp.into_parts();
        // If `collect` fails the upstream stream was already broken — the original
        // body cannot be reconstructed for passthrough, and the client was going to
        // see a transport error either way. Propagate so rama can surface it.
        let bytes = body
            .collect()
            .await
            .context("collect OpenVSX metadata response body")?
            .to_bytes();

        if bytes.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        let Some(rewrite) = rewrite_json(&bytes, released_packages_list, cutoff_ts) else {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        };

        tracing::info!(
            suppressed_versions = ?rewrite.suppressed_versions,
            "OpenVSX metadata rewritten: suppressed too-young versions"
        );

        self.notify_rewrites(&rewrite.suppressed_versions).await;

        make_response_uncacheable(&mut parts.headers);

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
                ts_ms: SystemTimestampMilliseconds::now(),
                artifact: Artifact {
                    product: "open_vsx".into(),
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

/// Filters too-recent versions out of an OpenVSX-style JSON metadata response.
///
/// Handles three shapes:
///
/// 1. Native OpenVSX single-extension (`/api/{namespace}/{name}`):
///    ```json
///    { "namespace": "...", "name": "...", "version": "...",
///      "allVersions": { "1.2.3": "url", "1.2.2": "url", ... } }
///    ```
/// 2. Native OpenVSX query (`/api/-/query` or `/api/v2/-/query`):
///    ```json
///    { "extensions": [ { "namespace": "...", "name": "...", "allVersions": {...}, ... } ] }
///    ```
/// 3. VS-Marketplace-shaped mirror (Cursor's `marketplace.cursorapi.com`,
///    OpenVSX's own `/vscode/gallery/extensionquery`):
///    ```json
///    { "results": [ { "extensions": [ { "publisher": {"publisherName": "..."},
///                                       "extensionName": "...",
///                                       "versions": [ {"version": "..."} , ... ] } ] } ] }
///    ```
fn rewrite_json(
    bytes: &[u8],
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
) -> Option<RewriteResult> {
    let mut json: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!("OpenVSX response is not valid JSON, passing through: {err}");
            return None;
        }
    };

    let mut suppressed: Vec<(ArcStr, PackageVersion)> = Vec::new();

    // Shape 3: VS-Marketplace-shaped mirror — detect by top-level `results` array.
    if let Some(results) = json.get_mut("results").and_then(|r| r.as_array_mut()) {
        for result in results.iter_mut() {
            let Some(extensions) = result.get_mut("extensions").and_then(|e| e.as_array_mut())
            else {
                continue;
            };
            for extension in extensions {
                filter_vsmarketplace_extension(
                    extension,
                    released_packages_list,
                    cutoff_ts,
                    &mut suppressed,
                );
            }
        }
    }
    // Shape 2: OpenVSX query — detect by top-level `extensions` array.
    else if let Some(extensions) = json.get_mut("extensions").and_then(|e| e.as_array_mut()) {
        for extension in extensions {
            filter_openvsx_extension(
                extension,
                released_packages_list,
                cutoff_ts,
                &mut suppressed,
            );
        }
    }
    // Shape 1: OpenVSX single-extension — top-level object with `namespace`/`name`.
    else if json.get("namespace").is_some() && json.get("name").is_some() {
        filter_openvsx_extension(
            &mut json,
            released_packages_list,
            cutoff_ts,
            &mut suppressed,
        );
    } else {
        return None;
    }

    if suppressed.is_empty() {
        return None;
    }

    let new_bytes = match serde_json::to_vec(&json) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!("failed to serialize modified OpenVSX metadata response: {err}");
            return None;
        }
    };

    Some(RewriteResult {
        bytes: new_bytes,
        suppressed_versions: suppressed,
    })
}

/// Native OpenVSX per-extension filter. Expects an object shaped like:
/// `{ "namespace": "...", "name": "...", "version": "...", "allVersions": {...} }`.
fn filter_openvsx_extension(
    extension: &mut serde_json::Value,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
    suppressed: &mut Vec<(ArcStr, PackageVersion)>,
) {
    let namespace = extension
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = extension
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if namespace.is_empty() || name.is_empty() {
        return;
    }

    let raw_id = format!("{namespace}/{name}");
    let lookup_key = OpenVsxPackageName::from(raw_id.as_str());
    let extension_id: ArcStr = raw_id.into();

    let Some(all_versions) = extension
        .get_mut("allVersions")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    let keys: Vec<String> = all_versions.keys().cloned().collect();
    for key in keys {
        let Ok(version) = PackageVersion::from_str(&key);
        if released_packages_list.is_recently_released(&lookup_key, Some(&version), cutoff_ts) {
            all_versions.remove(&key);
            suppressed.push((extension_id.clone(), version));
        }
    }
}

/// VS-Marketplace-shaped per-extension filter. Expects an object shaped like:
/// `{ "publisher": {"publisherName": "..."}, "extensionName": "...", "versions": [ {"version": "..."} ] }`.
fn filter_vsmarketplace_extension(
    extension: &mut serde_json::Value,
    released_packages_list: &OpenVsxRemoteReleasedPackagesList,
    cutoff_ts: SystemTimestampMilliseconds,
    suppressed: &mut Vec<(ArcStr, PackageVersion)>,
) {
    let publisher = extension
        .get("publisher")
        .and_then(|p| p.get("publisherName"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = extension
        .get("extensionName")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if publisher.is_empty() || name.is_empty() {
        return;
    }

    let raw_id = format!("{publisher}/{name}");
    let lookup_key = OpenVsxPackageName::from(raw_id.as_str());
    let extension_id: ArcStr = raw_id.into();

    let Some(versions) = extension.get_mut("versions").and_then(|v| v.as_array_mut()) else {
        return;
    };

    // Track which version numbers have already been recorded to avoid duplicates
    // from platform-specific entries (e.g. darwin-arm64, darwin-x64, win32-x64).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    versions.retain(|v| {
        let Some(version_str) = v.get("version").and_then(|s| s.as_str()) else {
            return true;
        };
        let Ok(version) = PackageVersion::from_str(version_str);
        let too_new =
            released_packages_list.is_recently_released(&lookup_key, Some(&version), cutoff_ts);
        if too_new && seen.insert(version_str.to_owned()) {
            suppressed.push((extension_id.clone(), version));
        }
        !too_new
    });
}

#[cfg(test)]
mod tests;
