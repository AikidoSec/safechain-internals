use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
};
use serde_json::json;

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        // Minimal Marketplace-style JSON payload with nested extension objects.
        // The VSCode firewall rule scans the JSON tree for objects with publisher + name fields.
        .with_get("_apis/public/gallery/extensionquery", extension_query)
        // Variant used to test forced-malware behavior for `ms-python.python`.
        .with_get(
            "_apis/public/gallery/extensionquery_force_malware",
            extension_query_force_malware,
        )
}

async fn extension_query() -> impl IntoResponse {
    Json(json!({
        "results": [
            {
                "extensions": [
                    {
                        "publisher": { "publisherName": "pythoner" },
                        "extensionName": "pythontheme",
                        "displayName": "Python Theme",
                        "flags": "validated"
                    },
                    {
                        "publisher": { "publisherName": "python" },
                        "extensionName": "python",
                        "displayName": "Python",
                        "flags": "validated"
                    }
                ]
            }
        ]
    }))
}

async fn extension_query_force_malware() -> impl IntoResponse {
    Json(json!({
        "results": [
            {
                "extensions": [
                    {
                        "publisher": { "publisherName": "ms-python" },
                        "extensionName": "python",
                        "displayName": "Python",
                        "flags": "validated"
                    },
                    {
                        "publisher": { "publisherName": "python" },
                        "extensionName": "python",
                        "displayName": "Python (Safe)",
                        "flags": "validated"
                    }
                ]
            }
        ]
    }))
}
