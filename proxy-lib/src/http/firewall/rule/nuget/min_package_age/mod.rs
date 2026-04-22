/*

TODO list:
 - make urls dynamic
 - add notifier
 - check last modified response header
*/

use rama::{
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Response, Uri,
        headers::{ContentType, HeaderMapExt as _},
    },
};

use crate::{
    http::{KnownContentType, firewall::rule::nuget::min_package_age::{catalog_list::CatalogList, flat_version_list::FlatVersionList}},
    package::
        released_packages_list::RemoteReleasedPackagesList
    ,
};

mod flat_version_list;
mod catalog_list;

pub(in crate::http::firewall) struct MinPackageAgeNuget {
    remote_released_packages_list: RemoteReleasedPackagesList,
    flat_version_list: FlatVersionList,
    catalog_list: CatalogList,
}

impl MinPackageAgeNuget {

    pub fn new(
        remote_released_packages_list: RemoteReleasedPackagesList
    ) -> MinPackageAgeNuget {
        Self { 
            remote_released_packages_list,
            flat_version_list: FlatVersionList {  },
            catalog_list: CatalogList {  },
        }
    }

    pub async fn remove_new_packages(
        &self,
        resp: Response,
        cut_off_secs: i64,
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

        let Some(req_uri) = resp.extensions().get::<Uri>().cloned() else {
            return Ok(resp);
        };

        if let Some(package_name) = self.flat_version_list.match_uri(&req_uri) {
            return self.flat_version_list.remove_new_packages(
                resp,
                package_name,
                &self.remote_released_packages_list,
                cut_off_secs,
            )
            .await;
        }

        if let Some(package_name) = self.catalog_list.match_uri(&req_uri) {
            return self.catalog_list.remove_new_packages(
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
