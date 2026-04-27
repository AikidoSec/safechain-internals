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
        "policy-allow-safe-chain-pi-test-pypi" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["safe-chain-pi-test"], // listed as malware in mock list
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
        "policy-request-installs-pypi" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-pypi" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future: released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
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
        "policy-allow-pythoner-pythontheme-vscode" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["pythoner.pythontheme"], // listed as malware in mock list
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
        "policy-request-installs-vscode" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-vscode" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let npm_policy = match token {
        "policy-block-npm" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-safe-chain-test-npm" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["safe-chain-test"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-lodash-npm" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["lodash"]
            }
        }),
        "policy-request-installs-npm" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-npm" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future : released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let maven_policy = match token {
        "policy-block-maven" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-malicious-lib-maven" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["org.example:malicious-lib"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-junit-maven" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["org.junit:junit"]
            }
        }),
        "policy-request-installs-maven" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-maven" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // way too far in future -> not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let nuget_policy = match token {
        "policy-block-nuget" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-safechaintest-nuget" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["safechaintest"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-newtonsoft-nuget" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["newtonsoft.json"]
            }
        }),
        "policy-request-installs-nuget" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-nuget" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future: released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let chrome_policy = match token {
        "policy-block-chrome" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-malicious-ext-chrome" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["lajondecmobodlejlcjllhojikagldgd"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-safeext-chrome" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["safeextension12345"]
            }
        }),
        "policy-request-installs-chrome" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-chrome" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future: released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let open_vsx_policy = match token {
        "policy-block-open-vsx" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-evil-extension-open-vsx" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["malicious-publisher/evil-extension"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-redhat-java-open-vsx" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["redhat/java"]
            }
        }),
        "policy-request-installs-open-vsx" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let ruby_policy = match token {
        "policy-block-ruby" => json!({
            "block_all_installs": true,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-allow-safe-chain-ruby-test" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": ["safe-chain-ruby-test"], // listed as malware in mock list
                "rejected_packages": []
            }
        }),
        "policy-reject-rake-ruby" => json!({
            "block_all_installs": false,
            "request_installs": false,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": ["rake"]
            }
        }),
        "policy-request-installs-ruby" => json!({
            "block_all_installs": false,
            "request_installs": true,
            "minimum_allowed_age_timestamp": null,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        "policy-bypass-new-package-ruby" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future (year ~2286): released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": 9_999_999_999_i64,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
            }
        }),
        _ => default_ecosystem_policy.clone(),
    };

    let skills_sh_policy = match token {
        "policy-bypass-new-package-skills-sh" => json!({
            "block_all_installs": false,
            "request_installs": false,
            // Cutoff set to far future): released_on (year ~2255) <= cutoff → not blocked
            "minimum_allowed_age_timestamp": i64::MAX / 1000,
            "exceptions": {
                "allowed_packages": [],
                "rejected_packages": []
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
            "vscode": vscode_policy,
            "npm": npm_policy,
            "maven": maven_policy,
            "nuget": nuget_policy,
            "chrome": chrome_policy,
            "open_vsx": open_vsx_policy,
            "skills_sh": skills_sh_policy,
            "ruby": ruby_policy
        }
    }))
    .into_response()
}
