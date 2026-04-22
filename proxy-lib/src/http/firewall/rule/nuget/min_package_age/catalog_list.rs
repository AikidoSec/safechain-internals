use rama::{
    error::{BoxError, ErrorContext},
    http::{Body, Response, Uri, body::util::BodyExt},
    telemetry::tracing,
};

use crate::package::{
    released_packages_list::RemoteReleasedPackagesList,
    version::{PackageVersion, PragmaticSemver},
};

pub struct CatalogList {}

impl CatalogList {
    pub fn match_uri<'a>(&self, uri: &'a Uri) -> Option<&'a str> {
        let path = uri.path();

        let (segment, path) = path.trim_start_matches("/").split_once("/")?; 
        if !segment.eq_ignore_ascii_case("v3") {
            return None;
        }

        let (segment, path) = path.trim_start_matches("/").split_once("/")?;
        if !segment.eq_ignore_ascii_case("registration5-gz-semver2") {
            return None;
        }

        path.split_once("/").map(|(package_name, _)| package_name)
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        _: &str,
        remote_released_packages_list: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) -> Result<Response, BoxError> {
        let (parts, body) = resp.into_parts();

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

        Self::handle_items_collection(&mut json, remote_released_packages_list, cutoff_secs);

        let new_bytes =
            serde_json::to_vec(&json).context("serialize modified nuget index response")?;

        Ok(Response::from_parts(parts, Body::from(new_bytes)))
    }

    fn handle_items_collection(
        json: &mut serde_json::Value,
        remote_released_packages_list: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) {

        let Some(serde_json::Value::Array(items)) = json.get_mut("items") else {
            return;
        };

        items.retain_mut(|item| {
            if Self::has_type(item, "Package") {
                return !Self::should_remove_package(
                    item,
                    remote_released_packages_list,
                    cutoff_secs,
                );
            }

            // Recursively loop over child items arrays
            Self::handle_items_collection(item, remote_released_packages_list, cutoff_secs);
            true
        });
        
        let new_count = items.len();
        if let Some(count) = json.get_mut("count") {
            if count.as_u64() != Some(new_count as u64) {
                *count = serde_json::Value::Number(new_count.into());
            }
        }
    }

    fn has_type(json: &serde_json::Value, type_name: &str) -> bool {
        match json.get("@type") {
            Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case(type_name),
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(type_name))
            }),
            _ => false,
        }
    }

    fn should_remove_package(
        package_json: &serde_json::Value,
        remote_released_packages_list: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) -> bool {
        let serde_json::Value::Object(package) = package_json else {
            return false;
        };
        let Some(serde_json::Value::Object(catalog_entry)) = package.get("catalogEntry") else {
            return false;
        };
        let Some(serde_json::Value::String(package_name)) = catalog_entry.get("id") else {
            return false;
        };
        let Some(serde_json::Value::String(package_version)) = catalog_entry.get("version") else {
            return false;
        };
        
        let version = match PragmaticSemver::parse(package_version) {
            Ok(version_semver) => PackageVersion::Semver(version_semver),
            Err(_) => PackageVersion::Unknown(package_version.into()),
        };

        remote_released_packages_list.is_recently_released(
            package_name,
            Some(&version),
            cutoff_secs,
        )
    }
}
