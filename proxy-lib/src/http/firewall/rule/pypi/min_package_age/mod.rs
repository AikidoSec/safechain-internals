use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response,
        body::util::BodyExt as _,
        headers::{CacheControl, ContentType, HeaderMapExt as _},
        layer::remove_header::{
            remove_cache_policy_headers, remove_cache_validation_response_headers,
            remove_payload_metadata_headers,
        },
    },
    telemetry::tracing,
    utils::{str::arcstr::ArcStr, time::now_unix_ms},
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

pub(super) struct JsonRewriteResult {
    bytes: Vec<u8>,
    package_name: ArcStr,
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

        match format {
            PyPIResponseFormat::Json => {
                let bytes = body
                    .collect()
                    .await
                    .context("collect pypi info response body")?
                    .to_bytes();

                let Some((rewrite_kind, rewrite)) =
                    json::rewrite_response(&bytes, cutoff_secs, released_packages)
                else {
                    return Ok(Response::from_parts(parts, Body::from(bytes)));
                };

                tracing::info!(
                    format = rewrite_kind.as_str(),
                    package = %rewrite.package_name,
                    suppressed_versions = ?rewrite.suppressed_versions,
                    "PyPI metadata rewritten: suppressed too-young versions"
                );

                Self::make_uncacheable(&mut parts.headers);
                self.notify_rewrite(&rewrite).await;

                Ok(Response::from_parts(parts, Body::from(rewrite.bytes)))
            }

            PyPIResponseFormat::Html => {
                // HTML is streamed through lol_html without buffering the full body.
                // Cache headers are stripped upfront because we cannot defer
                // header writes until the body is fully consumed.
                Self::make_uncacheable(&mut parts.headers);

                let notifier = self.notifier.clone();
                let streaming_body = html::rewrite_body(
                    body,
                    cutoff_secs,
                    released_packages.clone(),
                    move |rewrite| on_html_rewrite_end(rewrite, notifier),
                );

                Ok(Response::from_parts(parts, Body::new(streaming_body)))
            }
        }
    }

    fn make_uncacheable(headers: &mut rama::http::HeaderMap) {
        remove_cache_policy_headers(headers);
        remove_cache_validation_response_headers(headers);
        remove_payload_metadata_headers(headers);
        headers.typed_insert(CacheControl::new().with_no_cache());
    }

    async fn notify_rewrite(&self, rewrite: &JsonRewriteResult) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        let event = build_min_package_age_event(
            rewrite.package_name.clone(),
            rewrite.suppressed_versions.clone(),
        );
        notifier.notify_min_package_age(event).await;
    }
}

fn on_html_rewrite_end(rewrite: Option<html::HtmlRewriteOutcome>, notifier: Option<EventNotifier>) {
    let Some(rewrite) = rewrite else {
        return;
    };

    tracing::info!(
        format = "simple-html",
        package = %rewrite.package_name,
        suppressed_versions = ?rewrite.suppressed_versions,
        "PyPI metadata rewritten: suppressed too-young versions"
    );

    if let Some(notifier) = notifier {
        let event = build_min_package_age_event(rewrite.package_name, rewrite.suppressed_versions);
        tokio::spawn(async move {
            notifier.notify_min_package_age(event).await;
        });
    }
}

fn build_min_package_age_event(
    package_name: ArcStr,
    suppressed_versions: Vec<String>,
) -> MinPackageAgeEvent {
    MinPackageAgeEvent {
        ts_ms: now_unix_ms(),
        artifact: Artifact {
            product: "pypi".into(),
            identifier: package_name.clone(),
            display_name: Some(package_name),
            version: None,
        },
        suppressed_versions: suppressed_versions
            .iter()
            .map(|v| {
                let Ok(v) = v.parse();
                v
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
