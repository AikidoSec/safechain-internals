use std::convert::Infallible;

use rama::{
    Service,
    http::{Request, Response, StatusCode, service::web::response::IntoResponse},
    service::service_fn,
};
use serde_json::json;

use super::malware_list::{
    FRESH_OPEN_VSX_EXTENSION_NAME, FRESH_OPEN_VSX_EXTENSION_PUBLISHER,
    FRESH_OPEN_VSX_EXTENSION_VERSION,
};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(handle)
}

async fn handle(req: Request) -> Result<Response, Infallible> {
    let path = req
        .uri()
        .path()
        .trim_start_matches('/')
        .trim_end_matches('/');
    let path_lower = path.to_ascii_lowercase();

    // Both endpoint variants observed in the wild:
    //  - `vscode/gallery/extensionquery` on `open-vsx.org`
    //  - `_apis/public/gallery/extensionquery` on `marketplace.cursorapi.com`
    if path_lower == "vscode/gallery/extensionquery"
        || path_lower == "_apis/public/gallery/extensionquery"
    {
        Ok(extension_query_response())
    } else {
        // Asset downloads, manifests, signatures, etc. — keep behaving like the
        // pre-existing not-found echo so the asset-block / asset-allow e2e tests
        // remain green. Empty 200 is sufficient: the firewall decides those paths
        // before they ever reach upstream.
        Ok(StatusCode::OK.into_response())
    }
}

fn extension_query_response() -> Response {
    let body = json!({
        "results": [{
            "extensions": [{
                "publisher": { "publisherName": FRESH_OPEN_VSX_EXTENSION_PUBLISHER },
                "extensionName": FRESH_OPEN_VSX_EXTENSION_NAME,
                // OpenVSX rule consults the released-packages list (no body
                // timestamps), so version objects only need `version` strings.
                "versions": [
                    { "version": FRESH_OPEN_VSX_EXTENSION_VERSION },
                    { "version": "0.9.0" }
                ]
            }]
        }]
    });
    Response::builder()
        .header("content-type", "application/json")
        .body(rama::http::Body::from(body.to_string()))
        .unwrap()
}
