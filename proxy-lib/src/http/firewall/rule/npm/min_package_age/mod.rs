use std::time::{Duration, SystemTime};

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, HeaderValue, Request, Response,
        body::util::BodyExt as _,
        headers::{Accept, ContentType, HeaderMapExt as _},
    },
    telemetry::tracing,
};
use serde_json::json;

use crate::http::KnownContentType;

pub(in crate::http::firewall) struct MinPackageAge {}

impl MinPackageAge {
    pub fn modify_request_headers(req: &mut Request) {
        let Some(accept_is_npm_info) = req.headers().typed_get().map(|accept: Accept| {
            accept
                .0
                .iter()
                .any(|mime| mime.value.subtype() == "vnd.npm.install-v1")
        }) else {
            return;
        };

        if !accept_is_npm_info {
            return;
        }

        if let Ok(replacement_accept_header) = HeaderValue::from_str("application/json") {
            tracing::debug!(
                "modified accept: application/vnd.npm.install-v1+json header to application/json",
            );
            let _ = &req
                .headers_mut()
                .insert("accept", replacement_accept_header);
        }
    }

    pub async fn remove_new_packages(
        resp: Response,
        cut_off_duration: Duration,
    ) -> Result<Response, BoxError> {
        let Some(content_type) = resp.headers().typed_get::<ContentType>() else {
            return Ok(resp);
        };
        let is_json = KnownContentType::detect_from_content_type_header(content_type.clone())
            .map(|ct| ct == KnownContentType::Json)
            .unwrap_or(false);

        if !is_json {
            return Ok(resp);
        }

        let cutoff = SystemTime::now() - cut_off_duration;

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

        let versions_to_remove = Self::get_versions_to_remove(&json, cutoff);

        if versions_to_remove.is_empty() {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }

        for key in versions_to_remove.iter() {
            json = Self::remove_version_from_json(json, key);
        }
        json = Self::set_latest_dist_tag(json, &versions_to_remove);

        let new_bytes =
            serde_json::to_vec(&json).context("serialize modified npm info response")?;

        parts.headers.remove("content-length");
        parts.headers.remove("etag");
        parts.headers.remove("last-modified");
        if let Ok(no_cache) = HeaderValue::from_str("no-cache") {
            parts.headers.insert("cache-control", no_cache);
        } else {
            parts.headers.remove("cache-control");
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
            .map(str::to_owned)
        else {
            return json;
        };

        if !removed_versions.contains(&latest_value) {
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

    fn get_versions_to_remove(json: &serde_json::Value, cutoff: SystemTime) -> Vec<String> {
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
                        Ok(published_at) => published_at > cutoff,
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
