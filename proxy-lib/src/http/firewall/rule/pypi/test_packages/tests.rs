use rama::http::StatusCode;

use super::*;

#[test]
fn is_test_package_recognizes_canonical_names() {
    for &name in TEST_PACKAGES {
        assert!(is_test_package(&PyPIPackageName::from(name)));
    }
}

#[test]
fn is_test_package_after_parser_normalization() {
    // The parser uses `normalize_package_name` (`_` -> `-`, then ASCII-lowercase
    // via `LowerCasePackageName`). We replicate that pipeline here so the test
    // mirrors how `is_test_package` is actually invoked from `evaluate_request`.
    for raw in ["Safe_Chain_Pi_Test", "AIKIDO_ENDPOINT_TEST"] {
        let normalized = super::super::parser::normalize_package_name(raw);
        assert!(
            is_test_package(&normalized),
            "expected {raw} to be recognized as a test package"
        );
    }
}

#[test]
fn is_test_package_rejects_non_test_names() {
    assert!(!is_test_package(&PyPIPackageName::from("requests")));
    assert!(!is_test_package(&PyPIPackageName::from("safe-chain")));
    assert!(!is_test_package(&PyPIPackageName::from(
        "safe-chain-pi-tester"
    )));
}

fn uri(path: &str) -> Uri {
    path.parse().expect("test paths must parse")
}

#[test]
fn synthesize_returns_none_for_non_test_package() {
    assert!(synthesize_metadata_response(&uri("/simple/requests/")).is_none());
    assert!(synthesize_metadata_response(&uri("/pypi/requests/json")).is_none());
}

#[test]
fn synthesize_returns_none_for_artifact_path() {
    assert!(
        synthesize_metadata_response(&uri(
            "/packages/00/00/safe_chain_pi_test-0.1.0-py3-none-any.whl"
        ))
        .is_none()
    );
}

#[tokio::test]
async fn synthesize_simple_advertises_wheel_url_for_each_test_package() {
    for &name in TEST_PACKAGES {
        let req_uri = uri(&format!("/simple/{name}/"));
        let resp = synthesize_metadata_response(&req_uri).expect("must synthesize");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp).await;
        let expected_url = wheel_url(name);
        assert!(
            body.contains(&expected_url),
            "expected synthesized HTML to advertise {expected_url}, got body: {body}"
        );
    }
}

#[tokio::test]
async fn synthesize_json_for_pypi_json_path() {
    let req_uri = uri("/pypi/safe-chain-pi-test/json");
    let resp = synthesize_metadata_response(&req_uri).expect("must synthesize");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_to_string(resp).await;
    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("synthesized body must be valid JSON");
    assert_eq!(parsed["info"]["name"], "safe-chain-pi-test");
    assert_eq!(parsed["info"]["version"], "0.1.0");
    assert_eq!(parsed["urls"][0]["url"], wheel_url("safe-chain-pi-test"));
}

async fn body_to_string(resp: Response) -> String {
    use rama::http::body::util::BodyExt as _;
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect synthetic body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("synthetic body is utf-8")
}
