use rama::{
    extensions::Extensions as RamaExtensions,
    http::{Body, BodyExtractExt as _, Response, Uri},
};

use crate::{
    endpoint_protection::{EcosystemConfig, ExceptionLists, PolicyEvaluator},
    http::RequestMetaUri,
    package::{
        malware_list::RemoteMalwareList,
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
        version::{PackageVersion, PragmaticSemver},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;
use super::parser::{
    PackageInfo, normalize_package_name, parse_package_info_from_filename,
    parse_package_info_from_path, parse_package_info_from_url, parse_source_dist_filename,
    parse_wheel_filename,
};

fn ecosystem_config_with_allowed(allowed: &[&str]) -> EcosystemConfig {
    EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: ExceptionLists {
            allowed_packages: allowed.iter().map(|v| (*v).into()).collect(),
            rejected_packages: Default::default(),
        },
    }
}

fn make_test_rule(
    ecosystem_config: Option<&EcosystemConfig>,
    recent_releases: &[(&str, &str, u64)],
) -> RulePyPI {
    let now_ts = SystemTimestampMilliseconds::now();
    let released_entries = recent_releases
        .iter()
        .map(|(name, version, hours_ago)| ReleasedPackageData {
            package_name: (*name).to_owned(),
            version: version.parse().unwrap(),
            released_on: now_ts - SystemDuration::hours(*hours_ago as u16),
        })
        .collect();

    RulePyPI {
        target_domains: ["pypi.org", "files.pythonhosted.org", "pypi.python.org"]
            .into_iter()
            .collect(),
        remote_malware_list: RemoteMalwareList::from_entries_for_tests(vec![]),
        remote_released_packages_list: RemoteReleasedPackagesList::from_entries_for_tests(
            released_entries,
            now_ts,
        ),
        maybe_min_package_age: Some(MinPackageAgePyPI::new(None)),
        policy_evaluator: ecosystem_config.map(PolicyEvaluator::for_tests),
    }
}

fn make_metadata_response(body: &str, path: &str) -> Response {
    let resp = Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let (mut parts, body) = resp.into_parts();
    let extensions = RamaExtensions::new();
    extensions.insert(RequestMetaUri(path.parse::<Uri>().unwrap()));
    parts.extensions = extensions;
    Response::from_parts(parts, body)
}

#[test]
fn test_parse_wheel_filename() {
    let test_cases = vec![
        // (input, expected_name, expected_version)
        // Basic cases
        (
            "requests-2.31.0-py3-none-any.whl",
            Some(("requests", PragmaticSemver::new_two_components(2, 31))),
        ),
        (
            "Django-4.2.0-py3-none-any.whl",
            Some(("django", PragmaticSemver::new_two_components(4, 2))),
        ),
        (
            "boto3-1.28.85-py3-none-any.whl",
            Some(("boto3", PragmaticSemver::new_semver(1, 28, 85))),
        ),
        // Package names with hyphens (wheels use underscores per PEP 427)
        (
            "safe_chain_pi_test-0.1.0-py3-none-any.whl",
            Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
        ),
        (
            "pip_tools-6.12.0-py3-none-any.whl",
            Some(("pip-tools", PragmaticSemver::new_two_components(6, 12))),
        ),
        // Package names with underscores (normalized to hyphens)
        (
            "foo_bar-1.0.0-py2.py3-none-any.whl",
            Some(("foo-bar", PragmaticSemver::new_single(1))),
        ),
        (
            "my_package_name-2.0.0-py3-none-any.whl",
            Some(("my-package-name", PragmaticSemver::new_single(2))),
        ),
        (
            "safe_chain_pi_test-0.1.0-py3-none-any.whl",
            Some((
                "safe-chain-pi-test",
                PragmaticSemver::new_two_components(0, 1),
            )),
        ),
        // Package names with dots
        (
            "zope.interface-6.0-cp311-cp311-macosx_10_9_x86_64.whl",
            Some(("zope.interface", PragmaticSemver::new_single(6))),
        ),
        (
            "backports.zoneinfo-0.2.1-cp36-cp36m-win_amd64.whl",
            Some(("backports.zoneinfo", PragmaticSemver::new_semver(0, 2, 1))),
        ),
        // WITH BUILD TAG (per PEP 427/491)
        (
            "distribution-1.0-1-py27-none-any.whl",
            Some(("distribution", PragmaticSemver::new_single(1))),
        ),
        (
            "package-2.0-123-py3-none-any.whl",
            Some(("package", PragmaticSemver::new_single(2))),
        ),
        // Platform-specific wheels
        (
            "numpy-1.24.0-cp311-cp311-macosx_10_9_x86_64.whl",
            Some(("numpy", PragmaticSemver::new_semver(1, 24, 0))),
        ),
        (
            "Pillow-10.0.0-cp311-cp311-win_amd64.whl",
            Some(("pillow", PragmaticSemver::new_single(10))),
        ),
        // With metadata suffix
        (
            "Django-4.2.0-py3-none-any.whl.metadata",
            Some(("django", PragmaticSemver::new_semver(4, 2, 0))),
        ),
        // Multiple python versions
        (
            "six-1.16.0-py2.py3-none-any.whl",
            Some(("six", PragmaticSemver::new_semver(1, 16, 0))),
        ),
        // ABI3 stable ABI
        (
            "cryptography-41.0.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            Some(("cryptography", PragmaticSemver::new_single(41))),
        ),
        // Invalid cases
        ("notawheelfile.tar.gz", None),
        ("package-latest-py3-none-any.whl", None),
        ("package--py3-none-any.whl", None),
    ];

    for (input, expected) in test_cases {
        let result = parse_wheel_filename(input);
        let Some((expected_name, expected_version)) = expected else {
            assert!(result.is_none(), "Expected None for input: {input}");
            continue;
        };
        let info = result.unwrap_or_else(|| panic!("Expected Some for: {input}"));
        assert_eq!(
            info.name.to_string(),
            expected_name,
            "Failed for input: {input}"
        );
        assert_eq!(info.version, expected_version, "Failed for input: {input}");
    }
}

#[test]
fn test_parse_sdist_filename() {
    let test_cases = vec![
        // (input, expected_name, expected_version)
        // Basic tar.gz (most common)
        (
            "requests-2.31.0.tar.gz",
            Some(("requests", PragmaticSemver::new_semver(2, 31, 0))),
        ),
        (
            "Django-4.2.0.tar.gz",
            Some(("django", PragmaticSemver::new_semver(4, 2, 0))),
        ),
        (
            "numpy-1.24.0.tar.gz",
            Some(("numpy", PragmaticSemver::new_semver(1, 24, 0))),
        ),
        // Other compression formats
        (
            "package-1.0.0.zip",
            Some(("package", PragmaticSemver::new_semver(1, 0, 0))),
        ),
        (
            "package-2.0.0.tar.bz2",
            Some(("package", PragmaticSemver::new_semver(2, 0, 0))),
        ),
        (
            "package-3.0.0.tar.xz",
            Some(("package", PragmaticSemver::new_semver(3, 0, 0))),
        ),
        // Package names with hyphens
        (
            "pip-tools-6.12.0.tar.gz",
            Some(("pip-tools", PragmaticSemver::new_semver(6, 12, 0))),
        ),
        (
            "safe-chain-pi-test-0.1.0.tar.gz",
            Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
        ),
        (
            "django-rest-framework-3.14.0.tar.gz",
            Some((
                "django-rest-framework",
                PragmaticSemver::new_semver(3, 14, 0),
            )),
        ),
        // Package names with underscores (normalized to hyphens)
        (
            "foo_bar-1.0.0.zip",
            Some(("foo-bar", PragmaticSemver::new_semver(1, 0, 0))),
        ),
        (
            "safe_chain_pi_test-0.1.0.tar.gz",
            Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
        ),
        (
            "test_package_with_underscores-3.2.1.tar.gz",
            Some((
                "test-package-with-underscores",
                PragmaticSemver::new_semver(3, 2, 1),
            )),
        ),
        // Package names with dots
        (
            "zope.interface-6.0.tar.gz",
            Some(("zope.interface", PragmaticSemver::new_two_components(6, 0))),
        ),
        (
            "backports.zoneinfo-0.2.1.tar.gz",
            Some(("backports.zoneinfo", PragmaticSemver::new_semver(0, 2, 1))),
        ),
        // Prerelease versions
        (
            "package-1.0.0a1.tar.gz",
            Some((
                "package",
                PragmaticSemver::new_semver(1, 0, 0).with_pre("a1"),
            )),
        ),
        (
            "package-2.0.0rc1.tar.gz",
            Some((
                "package",
                PragmaticSemver::new_semver(2, 0, 0).with_pre("rc1"),
            )),
        ),
        (
            "package-3.0.0.post1.tar.gz",
            Some((
                "package",
                PragmaticSemver::new_semver(3, 0, 0).with_pre("post1"),
            )),
        ),
        // With metadata suffix
        (
            "numpy-1.24.3.tar.gz.metadata",
            Some(("numpy", PragmaticSemver::new_semver(1, 24, 3))),
        ),
        // Invalid cases
        ("pkg-latest.tar.gz", None),
        ("package-latest.tar.gz", None),
        ("no-extension-1.0.0", None),
        ("-1.0.0.tar.gz", None),
        ("notasdist.whl", None),
        ("package-1.0.0.txt", None),
        // Unsupported formats (should return None)
        ("package-4.0.0.tar.zst", None),
        ("setuptools-68.0.0.egg", None),
    ];

    for (input, expected) in test_cases {
        let result = parse_source_dist_filename(input);
        let Some((expected_name, expected_version)) = expected else {
            assert!(result.is_none(), "Expected None for input: {input}");
            continue;
        };
        let info = result.unwrap_or_else(|| panic!("Expected Some for: {input}"));
        assert_eq!(
            info.name.to_string(),
            expected_name,
            "Failed for input: {input}"
        );
        assert_eq!(info.version, expected_version, "Failed for input: {input}");
    }
}

#[test]
fn test_normalize_package_name() {
    let test_cases = vec![
        ("Requests", "requests"),
        ("foo_bar", "foo-bar"),
        ("FOO_BAR_BAZ", "foo-bar-baz"),
        ("foo.bar", "foo.bar"),
        ("foo--bar", "foo--bar"),
        ("foo.__bar", "foo.--bar"),
        ("foo-._-bar", "foo-.--bar"),
    ];

    for (input, expected) in test_cases {
        assert_eq!(
            normalize_package_name(input).to_string(),
            expected,
            "Failed for input: {}",
            input
        );
    }
}

#[tokio::test]
async fn wildcard_allowlisted_metadata_skips_min_age_rewrite() {
    let cfg = ecosystem_config_with_allowed(&["my-*"]);
    let rule = make_test_rule(Some(&cfg), &[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);
    let body = serde_json::json!({
        "info": {"name": "my-package", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"filename": "my_package-1.0.0.tar.gz"}],
            "2.0.0": [{"filename": "my_package-2.0.0.tar.gz"}]
        },
        "urls": [{"filename": "my_package-2.0.0.tar.gz"}]
    })
    .to_string();

    let result = rule
        .evaluate_response(make_metadata_response(&body, "/pypi/my-package/json"))
        .await
        .unwrap();
    let json: serde_json::Value = result.try_into_json().await.unwrap();

    assert_eq!(json["info"]["version"], "2.0.0");
    assert!(json["releases"]["1.0.0"].is_array());
    assert!(json["releases"]["2.0.0"].is_array());
    assert_eq!(
        json["urls"],
        serde_json::json!([{ "filename": "my_package-2.0.0.tar.gz" }])
    );
}

#[test]
fn test_package_info_is_metadata_request() {
    let metadata_info = PackageInfo {
        name: "requests".into(),
        version: PackageVersion::None,
    };
    assert!(metadata_info.is_metadata_request());

    let file_info = PackageInfo {
        name: "requests".into(),
        version: PackageVersion::Semver(PragmaticSemver::new_semver(2, 31, 0)),
    };
    assert!(!file_info.is_metadata_request());

    let any_version_info = PackageInfo {
        name: "requests".into(),
        version: PackageVersion::Any,
    };
    assert!(!any_version_info.is_metadata_request());
}

#[test]
fn test_extract_package_info() {
    use rama::http::{Body, Request, Uri};

    let test_cases = vec![
        // (uri, expected_name, is_metadata, version_check)
        (
            "https://pypi.org/pypi/requests/json",
            Some(("requests", true, None)),
        ),
        (
            "https://pypi.org/simple/django/",
            Some(("django", true, None)),
        ),
        (
            "https://pypi.org/simple/my_package/",
            Some(("my-package", true, None)), // Normalized
        ),
        (
            "https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl",
            Some((
                "requests",
                false,
                Some(PragmaticSemver::new_semver(2, 31, 0)),
            )),
        ),
        (
            "https://files.pythonhosted.org/packages/source/d/django/Django-4.2.0.tar.gz",
            Some(("django", false, Some(PragmaticSemver::new_semver(4, 2, 0)))),
        ),
        (
            "https://pypi.org/pypi/my%20package/json",
            Some(("my package", true, None)), // Percent-encoded
        ),
        // Unrecognized URLs
        ("https://pypi.org/", None),
        ("https://pypi.org/help/", None),
    ];

    for (uri, expected) in test_cases {
        let req = Request::builder()
            .uri(Uri::from_static(uri))
            .body(Body::empty())
            .unwrap();

        let result = parse_package_info_from_path(req.uri().path());

        let Some((expected_name, is_metadata, maybe_semver)) = expected else {
            assert!(result.is_none(), "Expected None for URI: {uri}");
            continue;
        };
        let info = result.unwrap_or_else(|| panic!("Expected Some for URI: {uri}"));
        let expected_version = maybe_semver.map_or(PackageVersion::None, PackageVersion::Semver);
        assert_eq!(
            info.name.to_string(),
            expected_name,
            "Failed for URI: {uri}"
        );
        assert_eq!(info.version, expected_version, "Failed for URI: {uri}");
        assert_eq!(
            info.is_metadata_request(),
            is_metadata,
            "Failed metadata check for URI: {uri}"
        );
    }
}

#[test]
fn test_parse_package_info_from_filename() {
    let info = parse_package_info_from_filename("requests-2.31.0.tar.gz").unwrap();
    assert_eq!(info.name.to_string(), "requests");
    assert_eq!(
        info.version,
        PackageVersion::Semver(PragmaticSemver::new_semver(2, 31, 0))
    );

    assert!(parse_package_info_from_filename("README.txt").is_none());
}

#[test]
fn test_parse_package_info_from_url() {
    let info = parse_package_info_from_url(
        "https://files.pythonhosted.org/packages/source/r/requests/requests-2.31.0.tar.gz",
    )
    .unwrap();
    assert_eq!(info.name.to_string(), "requests");
    assert_eq!(
        info.version,
        PackageVersion::Semver(PragmaticSemver::new_semver(2, 31, 0))
    );

    assert!(parse_package_info_from_url("https://pypi.org/simple/requests/").is_none());
}
