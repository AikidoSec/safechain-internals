use rama::{
    error::BoxError,
    http::{
        Response, Uri,
        headers::{ContentType, HeaderMapExt as _},
    },
};

use crate::{
    http::{
        KnownContentType,
        firewall::{
            notifier::EventNotifier,
            rule::nuget::{
                NugetRemoteReleasedPackageList,
                min_package_age::{catalog_list::CatalogList, flat_version_list::FlatVersionList},
            },
        },
    },
    utils::time::SystemTimestampMilliseconds,
};

mod catalog_list;
mod flat_version_list;
#[cfg(test)]
mod tests;

pub(in crate::http::firewall) struct MinPackageAgeNuget {
    remote_released_packages_list: NugetRemoteReleasedPackageList,
    flat_version_list: FlatVersionList,
    catalog_list: CatalogList,
}

impl MinPackageAgeNuget {
    pub fn new(
        remote_released_packages_list: NugetRemoteReleasedPackageList,
        notifier: Option<EventNotifier>,
    ) -> MinPackageAgeNuget {
        Self {
            remote_released_packages_list,
            flat_version_list: FlatVersionList {
                notifier: notifier.clone(),
            },
            catalog_list: CatalogList { notifier },
        }
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        req_uri: &Uri,
        cut_off_secs: SystemTimestampMilliseconds,
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

        if let Some(package_name) = self.flat_version_list.match_uri(req_uri) {
            return self
                .flat_version_list
                .remove_new_packages(
                    resp,
                    package_name,
                    &self.remote_released_packages_list,
                    cut_off_secs,
                )
                .await;
        }

        if let Some(package_name) = self.catalog_list.match_uri(req_uri) {
            return self
                .catalog_list
                .remove_new_packages(
                    resp,
                    package_name,
                    &self.remote_released_packages_list,
                    cut_off_secs,
                )
                .await;
        }

        Ok(resp)
    }
}
