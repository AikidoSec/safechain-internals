use std::str::FromStr;

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{Body, Response, body::util::BodyExt as _},
    telemetry::tracing,
    utils::{str::arcstr::ArcStr, time::now_unix_ms},
};

use crate::{
    http::firewall::{
        events::{Artifact, MinPackageAgeEvent},
        notifier::EventNotifier,
    },
    package::{
        released_packages_list::RemoteReleasedPackagesList,
        version::{PackageVersion, PragmaticSemver},
    },
};

#[derive(Debug, Clone)]
pub(in crate::http::firewall) struct MinPackageAgeGolang {
    notifier: Option<EventNotifier>,
}

impl MinPackageAgeGolang {
    pub fn new(notifier: Option<EventNotifier>) -> Self {
        Self { notifier }
    }

    pub async fn rewrite_list_response(
        &self,
        resp: Response,
        module_name: &str,
        released_packages: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) -> Result<Response, BoxError> {
        let (mut parts, body) = resp.into_parts();

        let bytes = body
            .collect()
            .await
            .context("collect golang list response body")?
            .to_bytes();

        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(_) => {
                tracing::debug!("golang list response body is not valid UTF-8, passing through");
                return Ok(Response::from_parts(parts, Body::from(bytes)));
            }
        };

        let mut suppressed: Vec<PackageVersion> = Vec::new();
        let mut kept: Vec<&str> = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let version_str = line.strip_prefix('v').unwrap_or(line);
            match PragmaticSemver::from_str(version_str) {
                Ok(parsed) => {
                    let version = PackageVersion::Semver(parsed);
                    if released_packages.is_recently_released(
                        module_name,
                        Some(&version),
                        cutoff_secs,
                    ) {
                        suppressed.push(version);
                    } else {
                        kept.push(line);
                    }
                }
                Err(_) => {
                    kept.push(line);
                }
            }
        }

        if suppressed.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        tracing::info!(
            module = %module_name,
            suppressed_versions = ?suppressed,
            "Go module list rewritten: suppressed too-young versions"
        );

        super::super::make_response_uncacheable(&mut parts.headers);

        let new_body = kept.join("\n") + "\n";

        self.notify_rewrite(module_name, suppressed).await;

        Ok(Response::from_parts(parts, Body::from(new_body)))
    }

    async fn notify_rewrite(&self, module_name: &str, suppressed: Vec<PackageVersion>) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        let identifier: ArcStr = module_name.into();
        let event = MinPackageAgeEvent {
            ts_ms: now_unix_ms(),
            artifact: Artifact {
                product: "golang".into(),
                identifier: identifier.clone(),
                display_name: None,
                version: None,
            },
            suppressed_versions: suppressed,
        };
        notifier.notify_min_package_age(event).await;
    }
}

#[cfg(test)]
mod tests;
