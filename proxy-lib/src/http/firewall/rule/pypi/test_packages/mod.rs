//! Synthetic-metadata path for the agent's PyPI test command.

use rama::http::{
    Response, Uri,
    service::web::response::{Html, IntoResponse, Json},
};

use crate::http::headers::make_response_uncacheable;

use super::PyPIPackageName;
use super::parser::parse_package_info_from_path;

pub(super) const TEST_PACKAGES: &[&str] = &["safe-chain-pi-test", "aikido-endpoint-test"];

const TEST_PACKAGE_VERSION: &str = "0.1.0";

pub(super) fn is_test_package(name: &PyPIPackageName) -> bool {
    TEST_PACKAGES
        .iter()
        .any(|candidate| PyPIPackageName::from(*candidate) == *name)
}

/// If `uri` targets a metadata endpoint for one of the test packages, build a
/// synthetic metadata response that advertises a single wheel.
/// Returns `None` for any URL that does not match a test package, so callers fall
/// through to the normal upstream/min-package-age path.
pub(super) fn synthesize_metadata_response(uri: &Uri) -> Option<Response> {
    let path = uri.path();
    let package_info = parse_package_info_from_path(path)?;
    if !package_info.is_metadata_request() {
        return None;
    }

    let canonical_name = TEST_PACKAGES
        .iter()
        .copied()
        .find(|candidate| PyPIPackageName::from(*candidate) == package_info.name)?;

    let response = if path.starts_with("/pypi/") && path.ends_with("/json") {
        synthesize_json(canonical_name)
    } else {
        synthesize_simple_html(canonical_name)
    };

    Some(response)
}

fn wheel_filename(canonical_name: &str) -> String {
    let dist = canonical_name.replace('-', "_");
    format!("{dist}-{TEST_PACKAGE_VERSION}-py3-none-any.whl")
}

fn wheel_url(canonical_name: &str) -> String {
    format!(
        "https://files.pythonhosted.org/packages/00/00/{}",
        wheel_filename(canonical_name)
    )
}

fn synthesize_simple_html(canonical_name: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>Links for {canonical_name}</title>
  </head>
  <body>
    <h1>Links for {canonical_name}</h1>
    <a href="{wheel}">{filename}</a><br/>
  </body>
</html>
"#,
        wheel = wheel_url(canonical_name),
        filename = wheel_filename(canonical_name),
    );

    let mut response = Html(body).into_response();
    make_response_uncacheable(response.headers_mut());
    response
}

fn synthesize_json(canonical_name: &str) -> Response {
    let filename = wheel_filename(canonical_name);
    let url = wheel_url(canonical_name);
    let file_entry = serde_json::json!({
        "filename": filename,
        "url": url,
        "packagetype": "bdist_wheel",
        "python_version": "py3",
    });
    let body = serde_json::json!({
        "info": { "name": canonical_name, "version": TEST_PACKAGE_VERSION },
        "urls": [file_entry.clone()],
        "releases": { TEST_PACKAGE_VERSION: [file_entry] },
    });

    let mut response = Json(body).into_response();
    make_response_uncacheable(response.headers_mut());
    response
}

#[cfg(test)]
mod tests;
