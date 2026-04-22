use rama::http::Uri;

use super::catalog_list::CatalogList;
use super::flat_version_list::FlatVersionList;

// FlatVersionList matches GET /v3-flatcontainer/{package}/index.json (step 4 in nuget restore)

#[test]
fn test_flat_version_list_match_uri_returns_package_name() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/index.json",
    );
    assert_eq!(
        FlatVersionList {}.match_uri(&uri),
        Some("microsoft.extensions.logging")
    );
}

#[test]
fn test_flat_version_list_match_uri_no_match_for_package_download() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/9.0.1/microsoft.extensions.logging.9.0.1.nupkg",
    );
    assert_eq!(FlatVersionList {}.match_uri(&uri), None);
}

#[test]
fn test_flat_version_list_match_uri_no_match_for_wrong_base_path() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/index.json",
    );
    assert_eq!(FlatVersionList {}.match_uri(&uri), None);
}

// CatalogList matches GET /v3/registration5-gz-semver2/{package}/... (steps 2 and 3 in nuget restore)

#[test]
fn test_catalog_list_match_uri_returns_package_name_for_index() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/index.json",
    );
    assert_eq!(
        CatalogList {}.match_uri(&uri),
        Some("microsoft.extensions.logging")
    );
}

#[test]
fn test_catalog_list_match_uri_returns_package_name_for_page_request() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3/registration5-gz-semver2/microsoft.extensions.logging/page/9.0.1/11.0.0-preview.3.26207.106.json",
    );
    assert_eq!(
        CatalogList {}.match_uri(&uri),
        Some("microsoft.extensions.logging")
    );
}

#[test]
fn test_catalog_list_match_uri_no_match_for_wrong_base_path() {
    let uri = Uri::from_static(
        "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.logging/index.json",
    );
    assert_eq!(CatalogList {}.match_uri(&uri), None);
}
