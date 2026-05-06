use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Request, Response,
        body::util::BodyExt as _,
        headers::{Accept, ContentType, HeaderMapExt as _},
    },
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};
use serde_json::json;

use crate::{
    http::{
        KnownContentType,
        firewall::{
            events::{Artifact, MinPackageAgeEvent},
            notifier::EventNotifier,
        },
        headers::make_response_uncacheable,
    },
    utils::time::SystemTimestampMilliseconds,
};

pub(in crate::http::firewall) struct MinPackageAge {
    notifier: Option<EventNotifier>,
}

impl MinPackageAge {
    pub(in crate::http::firewall) fn new(notifier: Option<EventNotifier>) -> Self {
        Self { notifier }
    }

    pub(super) fn modify_request_headers(&self, req: &mut Request) {
        if !req
            .headers()
            .typed_get()
            .map(|Accept(qvs)| {
                qvs.iter()
                    .any(|mime| mime.value.subtype() == "vnd.npm.install-v1")
            })
            .unwrap_or_default()
        {
            return;
        }

        req.headers_mut().typed_insert(Accept::json());
    }

    pub(super) async fn remove_new_packages(
        &self,
        resp: Response,
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

        let (mut parts, body) = resp.into_parts();

        let collected = body
            .collect()
            .await
            .context("collect npm info response body")?;
        let bytes = collected.to_bytes();

        let mut json: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!("npm info response body is not valid JSON, passing through: {err}");
                return Ok(Response::from_parts(parts, Body::from(bytes)));
            }
        };

        let versions_to_remove = Self::get_versions_to_remove(&json, cutoff_ts);

        if versions_to_remove.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        let package_name: ArcStr = json
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown package")
            .into();

        for key in versions_to_remove.iter() {
            json = Self::remove_version_from_json(json, key);
        }
        json = Self::set_latest_dist_tag(json, &versions_to_remove);

        let new_bytes =
            serde_json::to_vec(&json).context("serialize modified npm info response")?;

        make_response_uncacheable(&mut parts.headers);

        if let Some(notifier) = &self.notifier {
            let event = MinPackageAgeEvent {
                ts_ms: SystemTimestampMilliseconds::now(),
                artifact: Artifact {
                    product: "npm".into(),
                    identifier: package_name.clone(),
                    display_name: Some(package_name),
                    version: None,
                },
                suppressed_versions: versions_to_remove
                    .iter()
                    .filter_map(|v| v.parse().ok())
                    .collect(),
            };
            notifier.notify_min_package_age(event).await;
        }

        Ok(Response::from_parts(parts, Body::from(new_bytes)))
    }

    fn remove_version_from_json(mut json: serde_json::Value, version: &str) -> serde_json::Value {
        if let Some(time_obj) = json.get_mut("time").and_then(|t| t.as_object_mut()) {
            time_obj.remove(version);
        }

        if let Some(version_obj) = json.get_mut("versions").and_then(|t| t.as_object_mut()) {
            version_obj.remove(version);
        }

        json
    }

    fn set_latest_dist_tag(
        mut json: serde_json::Value,
        removed_versions: &[String],
    ) -> serde_json::Value {
        let Some(dist_tags) = json.get_mut("dist-tags").and_then(|t| t.as_object_mut()) else {
            return json;
        };

        let Some(latest_value) = dist_tags
            .get("latest")
            .and_then(|latest_tag| latest_tag.as_str())
        else {
            return json;
        };

        if !removed_versions.iter().any(|v| v == latest_value) {
            return json;
        }

        // Find the new latest version using an immutable borrow before mutating dist_tags.
        let new_latest = json
            .get("time")
            .and_then(|t| t.as_object())
            .and_then(|time_tag| {
                time_tag
                    .iter()
                    .filter(|(version, _)| {
                        version.starts_with(|c: char| c.is_ascii_digit()) && !version.contains('-')
                    })
                    .filter_map(|(version, value)| {
                        let ts = humantime::parse_rfc3339(value.as_str()?).ok()?;
                        Some((ts, version.as_str()))
                    })
                    .max_by_key(|(ts, _)| *ts)
                    .map(|(_, v)| v.to_owned())
            });

        let Some(dist_tags) = json.get_mut("dist-tags").and_then(|t| t.as_object_mut()) else {
            return json;
        };

        dist_tags.remove("latest");
        if let Some(version) = new_latest {
            dist_tags.insert("latest".to_owned(), json!(version));
        }

        json
    }

    fn get_versions_to_remove(
        json: &serde_json::Value,
        cutoff_ts: SystemTimestampMilliseconds,
    ) -> Vec<String> {
        if let Some(time_obj) = json.get("time").and_then(|t| t.as_object()) {
            let keys_to_remove: Vec<String> = time_obj
                .iter()
                .filter(|(key, value)| {
                    if *key == "created" || *key == "modified" {
                        return false;
                    }
                    let Some(timestamp_str) = value.as_str() else {
                        return false;
                    };
                    match humantime::parse_rfc3339(timestamp_str) {
                        Ok(published_at) => {
                            let published_ts = SystemTimestampMilliseconds::from(published_at);
                            published_ts > cutoff_ts
                        }
                        Err(err) => {
                            tracing::debug!(
                                "failed to parse npm package timestamp '{timestamp_str}': {err}"
                            );
                            false
                        }
                    }
                })
                .map(|(key, _)| key.clone())
                .collect();
            keys_to_remove
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests;
