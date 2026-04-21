use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response,
        body::util::BodyExt as _,
        headers::{ContentType, HeaderMapExt as _},
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
    package::{released_packages_list::RemoteReleasedPackagesList, version::PackageVersion},
};

mod html;
mod json;

#[derive(Debug, Clone)]
pub(in crate::http::firewall) struct MinPackageAgePyPI {
    notifier: Option<EventNotifier>,
}

#[derive(Debug)]
pub(super) struct JsonRewriteResult {
    bytes: Vec<u8>,
    package_name: ArcStr,
    suppressed_versions: Vec<PackageVersion>,
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
            .and_then(KnownContentType::detect_from_content_type_header)
        else {
            return Ok(resp);
        };

        let (mut parts, body) = resp.into_parts();

        match format {
            KnownContentType::Json => {
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
                    rewrite_kind = ?rewrite_kind,
                    package = %rewrite.package_name,
                    suppressed_versions = ?rewrite.suppressed_versions,
                    "PyPI metadata rewritten: suppressed too-young versions"
                );

                super::super::make_response_uncacheable(&mut parts.headers);
                self.notify_rewrite(&rewrite).await;

                Ok(Response::from_parts(parts, Body::from(rewrite.bytes)))
            }

            KnownContentType::Txt | KnownContentType::Xml => Ok(Response::from_parts(parts, body)),

            KnownContentType::Html => {
                // HTML is streamed through lol_html without buffering the full body.
                // Cache headers are stripped upfront because we cannot defer
                // header writes until the body is fully consumed.
                super::super::make_response_uncacheable(&mut parts.headers);

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
    suppressed_versions: Vec<PackageVersion>,
) -> MinPackageAgeEvent {
    MinPackageAgeEvent {
        ts_ms: now_unix_ms(),
        artifact: Artifact {
            product: "pypi".into(),
            identifier: package_name.clone(),
            display_name: Some(package_name),
            version: None,
        },
        suppressed_versions,
    }
}

#[cfg(test)]
mod tests;
