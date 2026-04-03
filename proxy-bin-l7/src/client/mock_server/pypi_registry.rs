use std::convert::Infallible;

use rama::{
    Service,
    http::{Request, Response, StatusCode, service::web::response::IntoResponse},
    service::service_fn,
};
use serde_json::json;

use super::malware_list::{FRESH_PYPI_PACKAGE_NAME, FRESH_PYPI_PACKAGE_VERSION};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(|req: Request| async move {
        let path = req.uri().path();

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

            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(rama::http::Body::from(body.to_string()))
                .unwrap());
        }

        Ok(StatusCode::OK.into_response())
    })
}
