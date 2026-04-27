use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response, StatusCode,
        service::web::response::{IntoResponse, Json},
    },
    service::service_fn,
};
use serde_json::json;

use super::malware_list::{
    FRESH_PACKAGIST_PACKAGE, FRESH_PACKAGIST_VENDOR, FRESH_PACKAGIST_VERSION,
    MALWARE_PACKAGIST_PACKAGE, MALWARE_PACKAGIST_VENDOR, MALWARE_PACKAGIST_VERSION,
};

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(handle)
}

/// Handles Packagist v2 metadata requests for the mock server.
///
/// Serves `/p2/vendor/package.json` responses in Composer 2.x minified format.
/// Known test packages carry specific version entries used by the e2e firewall tests;
/// all other paths return `200 OK` with an empty packages object.
async fn handle(req: Request) -> Result<Response, Infallible> {
    let path = req.uri().path();

    let malware_p2_path =
        format!("/p2/{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}.json");
    let fresh_p2_path = format!("/p2/{FRESH_PACKAGIST_VENDOR}/{FRESH_PACKAGIST_PACKAGE}.json");

    if path == malware_p2_path {
        // Version 1.0.0 is in the malware list; 0.9.0 is safe and old.
        let body = json!({
            "minified": "composer/2.0",
            "packages": {
                format!("{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}"): [
                    {
                        "name": format!("{MALWARE_PACKAGIST_VENDOR}/{MALWARE_PACKAGIST_PACKAGE}"),
                        "description": "Test package for SafeChain malware blocking",
                        "version": MALWARE_PACKAGIST_VERSION,
                        "version_normalized": "1.0.0.0",
                        "dist": {
                            "url": "https://api.github.com/repos/test/test/zipball/abc",
                            "type": "zip",
                            "reference": "abc",
                            "shasum": ""
                        },
                        "source": {
                            "url": "https://github.com/test/test.git",
                            "type": "git",
                            "reference": "abc"
                        },
                        "time": "2020-06-01T00:00:00+00:00",
                        "require": {"php": "^8.0"}
                    },
                    {
                        "version": "0.9.0",
                        "version_normalized": "0.9.0.0",
                        "dist": {
                            "url": "https://api.github.com/repos/test/test/zipball/def",
                            "type": "zip",
                            "reference": "def",
                            "shasum": ""
                        },
                        "source": {
                            "url": "https://github.com/test/test.git",
                            "type": "git",
                            "reference": "def"
                        },
                        "time": "2020-01-01T00:00:00+00:00"
                    }
                ]
            }
        });
        return Ok(Json(body).into_response());
    }

    if path == fresh_p2_path {
        // Version 2.0.0 has a far-future `time` (always "too new"); 1.0.0 is old and safe.
        let body = json!({
            "minified": "composer/2.0",
            "packages": {
                format!("{FRESH_PACKAGIST_VENDOR}/{FRESH_PACKAGIST_PACKAGE}"): [
                    {
                        "name": format!("{FRESH_PACKAGIST_VENDOR}/{FRESH_PACKAGIST_PACKAGE}"),
                        "description": "Test package for SafeChain min-age blocking",
                        "version": FRESH_PACKAGIST_VERSION,
                        "version_normalized": "2.0.0.0",
                        "dist": {
                            "url": "https://api.github.com/repos/test/fresh/zipball/ghi",
                            "type": "zip",
                            "reference": "ghi",
                            "shasum": ""
                        },
                        "source": {
                            "url": "https://github.com/test/fresh.git",
                            "type": "git",
                            "reference": "ghi"
                        },
                        // Far-future timestamp so this is always considered "recently released".
                        "time": "2255-01-01T00:00:00+00:00",
                        "require": {"php": "^8.1"}
                    },
                    {
                        "version": "1.0.0",
                        "version_normalized": "1.0.0.0",
                        "dist": {
                            "url": "https://api.github.com/repos/test/fresh/zipball/jkl",
                            "type": "zip",
                            "reference": "jkl",
                            "shasum": ""
                        },
                        "source": {
                            "url": "https://github.com/test/fresh.git",
                            "type": "git",
                            "reference": "jkl"
                        },
                        "time": "2020-01-01T00:00:00+00:00"
                    }
                ]
            }
        });
        return Ok(Json(body).into_response());
    }

    Ok(StatusCode::OK.into_response())
}
