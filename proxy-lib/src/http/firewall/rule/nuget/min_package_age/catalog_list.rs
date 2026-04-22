use rama::{
    error::{BoxError, ErrorContext},
    http::{Body, Response, Uri, body::util::BodyExt},
    telemetry::tracing,
};

use crate::{
    http::firewall::rule::nuget::NugetRemoteReleasedPackageList,
    package::{
        name_formatter::LowerCasePackageName,
        version::{PackageVersion, PragmaticSemver},
    },
    utils::time::SystemTimestampMilliseconds,
};

const BASE_PATH: &str = "/v3/registration5-gz-semver2";

pub struct CatalogList {}

impl CatalogList {
    pub fn match_uri<'u>(&self, uri: &'u Uri) -> Option<&'u str> {
        uri.path()
            .strip_prefix(BASE_PATH)?
            .trim_start_matches('/')
            .split_once('/')
            .map(|(package_name, _)| package_name)
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        _: &str,
        remote_released_packages_list: &NugetRemoteReleasedPackageList,
        cutoff_secs: SystemTimestampMilliseconds,
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
        remote_released_packages_list: &NugetRemoteReleasedPackageList,
        cutoff_secs: SystemTimestampMilliseconds,
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
        if let Some(count) = json.get_mut("count")
            && count.as_u64() != Some(new_count as u64)
        {
            *count = serde_json::Value::Number(new_count.into());
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
        remote_released_packages_list: &NugetRemoteReleasedPackageList,
        cutoff_secs: SystemTimestampMilliseconds,
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

        let normalized_package_name = LowerCasePackageName::from(package_name);

        remote_released_packages_list.is_recently_released(
            &normalized_package_name,
            Some(&version),
            cutoff_secs,
        )
    }
}
