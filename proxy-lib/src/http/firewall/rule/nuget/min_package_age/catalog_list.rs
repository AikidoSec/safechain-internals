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

        path.split_once("/")
            .map(|(package_name, _)| package_name)
    }

    #[allow(unused)]
    pub async fn remove_new_packages(
        &self,
        resp: Response,
        package_name: &str,
        released_package_list: &RemoteReleasedPackagesList,
        cutoff_secs: i64,
    ) -> Result<Response, BoxError> {
        let (parts, body) = resp.into_parts();
        tracing::debug!("DEBUGGING: detected catalog list");

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

        if Self::is_catalog_page(&json) {
            tracing::debug!("DEBUGGING: detected catalog page");
        }

        // if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_array_mut()) {
        //     versions.retain(|v| {
        //         let Some(version_str) = v.as_str() else {
        //             return true;
        //         };
        //         let Ok(version) = PragmaticSemver::parse(version_str) else {
        //             return true;
        //         };

        //         if released_package_list.is_recently_released(
        //             package_name,
        //             Some(&PackageVersion::Semver(version)),
        //             cutoff_secs,
        //         ) {
        //             tracing::info!("Version {version_str} was recently released.");
        //             false
        //         } else {
        //             tracing::info!("Version {version_str} was not recently released.");
        //             true
        //         }
        //     });
        // }

        let new_bytes =
            serde_json::to_vec(&json).context("serialize modified nuget index response")?;

        Ok(Response::from_parts(parts, Body::from(new_bytes)))
    }

    fn is_catalog_page(json: &serde_json::Value) -> bool {
        let Some(object_type) = json.get("@type").and_then(|t| t.as_str()) else {
            return false;
        };

        object_type.eq_ignore_ascii_case("catalog:CatalogPage")
    }
}
