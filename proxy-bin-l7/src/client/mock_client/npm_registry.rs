use std::convert::Infallible;

use rama::{
    Service,
    http::{Request, Response, StatusCode, service::web::response::IntoResponse},
    service::service_fn,
};
use serde_json::json;

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(|req: Request| async move {
        let path = req.uri().path();
        if path == "/min-age-test-package" {
            let body = json!({
                "name": "min-age-test-package",
                "dist-tags": { "latest": "2.0.0" },
                "time": {
                    "created": "2020-01-01T00:00:00.000Z",
                    "modified": "9999-01-01T00:00:00.000Z",
                    "1.0.0": "2020-01-01T00:00:00.000Z",
                    "2.0.0": "9999-01-01T00:00:00.000Z"
                },
                "versions": {
                    "1.0.0": {},
                    "2.0.0": {}
                }
            });
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(rama::http::Body::from(body.to_string()))
                .unwrap())
        } else {
            Ok(StatusCode::OK.into_response())
        }
    })
}
