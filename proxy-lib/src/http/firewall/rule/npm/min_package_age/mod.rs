use std::time::{Duration, SystemTime};

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Request, Response,
        body::util::BodyExt as _,
        headers::{Accept, CacheControl, ContentType, HeaderMapExt as _},
        layer::remove_header::{
            remove_cache_policy_headers, remove_cache_validation_response_headers,
        },
    },
    telemetry::tracing,
    utils::time::now_unix_ms,
};
use serde_json::json;

use crate::http::KnownContentType;

pub(in crate::http::firewall) struct MinPackageAge {
    duration: Duration,
}

impl MinPackageAge {
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }

    pub fn modify_request_headers(&self, req: &mut Request) {
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

        req.headers_mut().typed_insert(Accept::json());
    }

    pub async fn remove_new_packages(&self, resp: Response) -> Result<Response, BoxError> {
        let Some(content_type) = resp.headers().typed_get::<ContentType>() else {
            return Ok(resp);
        };

        if KnownContentType::detect_from_content_type_header(content_type.clone())
            != Some(KnownContentType::Json)
        {
            return Ok(resp);
        }

        let cutoff = now_unix_ms() - self.duration.as_millis() as i64;

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

        remove_cache_policy_headers(&mut parts.headers);
        remove_cache_validation_response_headers(&mut parts.headers);
        parts
            .headers
            .typed_insert(CacheControl::new().with_no_cache());

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

    fn get_versions_to_remove(json: &serde_json::Value, cutoff_unix_ms: i64) -> Vec<String> {
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
                            let published_unix_ms = published_at
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or(0);
                            published_unix_ms > cutoff_unix_ms
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
