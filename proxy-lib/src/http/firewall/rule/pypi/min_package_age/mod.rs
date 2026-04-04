use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, HeaderName, Response,
        body::util::BodyExt as _,
        headers::{CacheControl, ContentType, HeaderMapExt as _},
        layer::remove_header::{
            remove_cache_policy_headers, remove_cache_validation_response_headers,
        },
    },
    telemetry::tracing,
    utils::time::now_unix_ms,
};

use crate::{
    http::firewall::{
        events::{Artifact, MinPackageAgeEvent},
        notifier::EventNotifier,
    },
    package::released_packages_list::RemoteReleasedPackagesList,
};

mod html;
mod json;

/// PyPI serves its simple index with vendor MIME types per PEP 629/691,
/// using RFC 6839 structured syntax suffixes (`+json`, `+html`).
/// This enum captures the two response formats we care about for rewriting.
enum PyPIResponseFormat {
    Json,
    Html,
}

impl PyPIResponseFormat {
    fn detect(ct: &rama::http::headers::ContentType) -> Option<Self> {
        use rama::http::mime;
        let mime = ct.mime();
        // Check subtype first (e.g. `application/json`, `text/html`),
        // then fall back to the structured syntax suffix
        // (e.g. `application/vnd.pypi.simple.v1+json`).
        let is_json = mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON);
        let is_html = mime.subtype() == mime::HTML || mime.suffix() == Some(mime::HTML);
        if is_json {
            Some(Self::Json)
        } else if is_html {
            Some(Self::Html)
        } else {
            None
        }
    }
}

pub(in crate::http::firewall) struct MinPackageAgePyPI {
    notifier: Option<EventNotifier>,
}

pub(super) struct RewriteResult {
    bytes: Vec<u8>,
    package_name: rama::utils::str::arcstr::ArcStr,
    suppressed_versions: Vec<String>,
}

impl MinPackageAgePyPI {
    pub fn new(notifier: Option<EventNotifier>) -> Self {
        Self { notifier }
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        released_packages: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) -> Result<Response, BoxError> {
        let Some(format) = resp
            .headers()
            .typed_get::<ContentType>()
            .as_ref()
            .and_then(PyPIResponseFormat::detect)
        else {
            return Ok(resp);
        };

        let (mut parts, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .context("collect pypi info response body")?
            .to_bytes();

        let rewrite = match format {
            PyPIResponseFormat::Json => {
                json::rewrite_response(&bytes, cutoff_secs, released_packages)
            }
            PyPIResponseFormat::Html => {
                html::rewrite_response(&bytes, cutoff_secs, released_packages)
            }
        };

        let Some(rewrite) = rewrite else {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        };

        tracing::info!(
            package = %rewrite.package_name,
            suppressed_versions = ?rewrite.suppressed_versions,
            "PyPI metadata rewritten: suppressed too-young versions"
        );

        Self::make_uncacheable(&mut parts.headers);
        self.notify_rewrite(&rewrite).await;

        Ok(Response::from_parts(parts, Body::from(rewrite.bytes)))
    }

    fn make_uncacheable(headers: &mut rama::http::HeaderMap) {
        remove_cache_policy_headers(headers);
        remove_cache_validation_response_headers(headers);
        headers.remove(HeaderName::from_static("content-length"));
        headers.typed_insert(CacheControl::new().with_no_cache());
    }

    async fn notify_rewrite(&self, rewrite: &RewriteResult) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        let event = MinPackageAgeEvent {
            ts_ms: now_unix_ms(),
            artifact: Artifact {
                product: "pypi".into(),
                identifier: rewrite.package_name.clone(),
                display_name: Some(rewrite.package_name.clone()),
                version: None,
            },
            suppressed_versions: rewrite
                .suppressed_versions
                .iter()
                .filter_map(|version| version.parse().ok())
                .collect(),
        };
        notifier.notify_min_package_age(event).await;
    }
}

#[cfg(test)]
mod tests;
