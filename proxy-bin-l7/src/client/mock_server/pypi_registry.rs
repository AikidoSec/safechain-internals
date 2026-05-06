use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response, StatusCode,
        service::web::response::{Html, IntoResponse, Json},
    },
    service::service_fn,
};
use serde_json::json;

use super::malware_list::{FRESH_PYPI_PACKAGE_NAME, FRESH_PYPI_PACKAGE_VERSION};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(handle)
}

/// Handles PyPI registry requests for the mock server.
///
/// Serves the legacy JSON metadata for [`FRESH_PYPI_PACKAGE_NAME`] at
/// `/pypi/<name>/json` and the PEP 503 Simple HTML index at `/simple/<name>/`,
/// each including both a stable older release (`0.9.0`) and the current fresh
/// version. All other paths return `200 OK` with an empty body.
async fn handle(req: Request) -> Result<Response, Infallible> {
    let path = req.uri().path();

    if path == format!("/simple/{FRESH_PYPI_PACKAGE_NAME}/") {
        let body = format!(
            r#"<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.0">
    <title>Links for {name}</title>
  </head>
  <body>
    <h1>Links for {name}</h1>
    <a href="https://files.pythonhosted.org/packages/source/b/{name}/{name}-0.9.0.tar.gz">{name}-0.9.0.tar.gz</a><br/>
    <a href="https://files.pythonhosted.org/packages/source/b/{name}/{name}-{version}.tar.gz">{name}-{version}.tar.gz</a><br/>
  </body>
</html>
"#,
            name = FRESH_PYPI_PACKAGE_NAME,
            version = FRESH_PYPI_PACKAGE_VERSION,
        );
        return Ok(Html(body).into_response());
    }

    if path == format!("/pypi/{FRESH_PYPI_PACKAGE_NAME}/json") {
        let body = json!({
            "info": {
                "name": FRESH_PYPI_PACKAGE_NAME,
                "version": FRESH_PYPI_PACKAGE_VERSION
            },
            "releases": {
                "0.9.0": [{
                    "filename": format!("{FRESH_PYPI_PACKAGE_NAME}-0.9.0.tar.gz"),
                    "url": format!(
                        "https://files.pythonhosted.org/packages/source/b/{name}/{name}-0.9.0.tar.gz",
                        name = FRESH_PYPI_PACKAGE_NAME,
                    )
                }],
                FRESH_PYPI_PACKAGE_VERSION: [{
                    "filename": format!("{FRESH_PYPI_PACKAGE_NAME}-{FRESH_PYPI_PACKAGE_VERSION}.tar.gz"),
                    "url": format!(
                        "https://files.pythonhosted.org/packages/source/b/{name}/{name}-{version}.tar.gz",
                        name = FRESH_PYPI_PACKAGE_NAME,
                        version = FRESH_PYPI_PACKAGE_VERSION,
                    )
                }]
            },
            "urls": [{
                "filename": format!("{FRESH_PYPI_PACKAGE_NAME}-{FRESH_PYPI_PACKAGE_VERSION}.tar.gz"),
                "url": format!(
                    "https://files.pythonhosted.org/packages/source/b/{name}/{name}-{version}.tar.gz",
                    name = FRESH_PYPI_PACKAGE_NAME,
                    version = FRESH_PYPI_PACKAGE_VERSION,
                )
            }]
        });

        return Ok(Json(body).into_response());
    }

    Ok(StatusCode::OK.into_response())
}
