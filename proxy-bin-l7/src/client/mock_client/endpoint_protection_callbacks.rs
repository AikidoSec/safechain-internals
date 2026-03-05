use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response, StatusCode,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
};
use serde_json::json;

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new().with_get(
        "/api/endpoint_protection/callbacks/fetchPermissions",
        fetch_permissions,
    )
}

async fn fetch_permissions(req: Request) -> impl IntoResponse {
    let Some(auth_header) = req.headers().get("authorization") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // We use token to determine which mock policy to return.
    let token = auth_header.to_str().unwrap_or_default();

    let default_ecosystem_policy = json!({
        "block_all_installs": false,
        "request_installs": false,
        "minimum_allowed_age_timestamp": null,
        "exceptions": {
            "allowed_packages": [],
            "rejected_packages": []
        }
    });

    let pypi_policy = match token {
        "policy-block-pypi" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-requests-pypi" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["requests"],
                "rejected_packages": []
            }
        }),
        "policy-reject-requests-pypi" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["requests"]
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let vscode_policy = match token {
        "policy-block-vscode" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-python-python-vscode" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["python.python"],
                "rejected_packages": []
            }
        }),
        "policy-reject-python-python-vscode" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["python.python"]
            }
        }),
        _ => default_ecosystem_policy,
    };

    Json(json!({
        "permission_group": {
            "id": 42,
            "name": "Mock Group"
        },
        "ecosystems": {
            "pypi": pypi_policy,
            "vscode": vscode_policy
        }
    }))
    .into_response()
}
