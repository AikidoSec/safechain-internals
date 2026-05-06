use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response,
        body::util::BodyExt as _,
        headers::{ContentLength, ContentType, HeaderMapExt as _},
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

mod json;
use json::rewrite_json;

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
        is_allowed: impl Fn(&str) -> bool,
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
        let oversized_content_length = resp
            .headers()
            .typed_get::<ContentLength>()
            .map(|cl| cl.0)
            .filter(|&n| n > MAX_METADATA_BODY_BYTES);

        if let Some(declared_len) = oversized_content_length {
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

        let Some(rewrite) = rewrite_json(&bytes, released_packages_list, cutoff_ts, &is_allowed)
        else {
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

#[cfg(test)]
mod tests;
