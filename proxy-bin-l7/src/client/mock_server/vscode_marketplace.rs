use std::convert::Infallible;

use rama::{
    Service,
    http::{Request, Response, StatusCode, service::web::response::IntoResponse},
    service::service_fn,
};
use serde_json::json;

use super::malware_list::{
    FRESH_VSCODE_EXTENSION_NAME, FRESH_VSCODE_EXTENSION_PUBLISHER, FRESH_VSCODE_EXTENSION_VERSION,
};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(|req: Request| async move {
        let path = req.uri().path().trim_start_matches('/');
        if path.eq_ignore_ascii_case("_apis/public/gallery/extensionquery") {
            Ok(extension_query_response())
        } else {
            Ok(StatusCode::NOT_FOUND.into_response())
        }
    })
}

fn extension_query_response() -> Response {
    let body = json!({
        "results": [{
            "extensions": [{
                "publisher": { "publisherName": FRESH_VSCODE_EXTENSION_PUBLISHER },
                "extensionName": FRESH_VSCODE_EXTENSION_NAME,
                "versions": [
                    // Far-future timestamp: always "too new" relative to any realistic cutoff.
                    { "version": FRESH_VSCODE_EXTENSION_VERSION, "lastUpdated": "9999-01-01T00:00:00.000Z" },
                    // Old stable version that should always be kept.
                    { "version": "0.9.0", "lastUpdated": "2020-01-01T00:00:00.000Z" }
                ]
            }]
        }]
    });
    Response::builder()
        .header("content-type", "application/json")
        .body(rama::http::Body::from(body.to_string()))
        .unwrap()
}
