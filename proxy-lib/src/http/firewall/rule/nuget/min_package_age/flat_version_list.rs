use rama::{
    error::{BoxError, ErrorContext},
    http::{Body, Response, Uri, body::util::BodyExt},
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use crate::{
    http::{
        firewall::{
            events::{Artifact, MinPackageAgeEvent},
            notifier::EventNotifier,
            rule::nuget::{NUGET_PRODUCT_KEY, NugetRemoteReleasedPackageList},
        },
        headers::make_response_uncacheable,
    },
    package::{
        name_formatter::LowerCasePackageName,
        version::{PackageVersion, PragmaticSemver},
    },
    utils::time::SystemTimestampMilliseconds,
};

const BASE_PATH: &str = "/v3-flatcontainer";

pub struct FlatVersionList {
    pub notifier: Option<EventNotifier>,
}

impl FlatVersionList {
    pub fn match_uri(&self, uri: &Uri) -> Option<ArcStr> {
        let (package_name, index_json) = uri
            .path()
            .strip_prefix(BASE_PATH)?
            .trim_start_matches('/')
            .split_once('/')?;

        if index_json.eq_ignore_ascii_case("index.json") {
            Some(package_name.into())
        } else {
            None
        }
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        package_name: ArcStr,
        released_package_list: &NugetRemoteReleasedPackageList,
        cutoff_secs: SystemTimestampMilliseconds,
    ) -> Result<Response, BoxError> {
        let (mut parts, body) = resp.into_parts();

        let bytes = body
            .collect()
            .await
            .context("collect nuget index response body")?
            .to_bytes();

        let mut json: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    "nuget index response body is not valid JSON, passing through: {err}"
                );
                return Ok(Response::from_parts(parts, Body::from(bytes)));
            }
        };

        let mut removed_versions: Vec<String> = vec![];

        if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_array_mut()) {
            versions.retain(|v| {
                let Some(version_str) = v.as_str() else {
                    return true;
                };
                let Ok(version) = PragmaticSemver::parse(version_str) else {
                    return true;
                };

                if released_package_list.is_recently_released(
                    &LowerCasePackageName::from(package_name.clone()),
                    Some(&PackageVersion::Semver(version)),
                    cutoff_secs,
                ) {
                    removed_versions.push(version_str.to_string());
                    tracing::info!("{package_name}@{version_str} was removed from the nuget meta response because it was recently released.");
                    false
                } else {
                    true
                }
            });
        }

        if removed_versions.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        } else {
            if let Some(notifier) = &self.notifier {
                let event = MinPackageAgeEvent {
                    ts_ms: SystemTimestampMilliseconds::now(),
                    artifact: Artifact {
                        product: NUGET_PRODUCT_KEY,
                        identifier: package_name.clone(),
                        display_name: Some(package_name),
                        version: None,
                    },
                    suppressed_versions: removed_versions
                        .iter()
                        .filter_map(|v| v.parse().ok())
                        .collect(),
                };
                notifier.notify_min_package_age(event).await;
            }
        }

        let new_bytes =
            serde_json::to_vec(&json).context("serialize modified nuget index response")?;

        make_response_uncacheable(&mut parts.headers);

        Ok(Response::from_parts(parts, Body::from(new_bytes)))
    }
}
