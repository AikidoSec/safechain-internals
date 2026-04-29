use super::*;

use rama::http::Body;

use crate::{
    endpoint_protection::{EcosystemConfig, ExceptionLists},
    http::firewall::events::BlockReason,
    package::{
        malware_list::{ListDataEntry, Reason},
        released_packages_list::ReleasedPackageData,
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
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
    malware: Vec<ListDataEntry>,
    recent_releases: &[(&str, &str, u64)],
) -> RuleNpm {
    let now_ts = SystemTimestampMilliseconds::now();
    let released_entries = recent_releases
        .iter()
        .map(|(name, version, hours_ago)| ReleasedPackageData {
            package_name: (*name).to_owned(),
            version: version.parse().unwrap(),
            released_on: now_ts - SystemDuration::hours(*hours_ago as u16),
        })
        .collect();

    RuleNpm {
        target_domains: ["registry.npmjs.org"].into_iter().collect(),
        remote_malware_list: NpmRemoteMalwareList::from_entries_for_tests(malware),
        remote_released_packages_list: NpmRemoteReleasedPackagesList::from_entries_for_tests(
            released_entries,
            now_ts,
        ),
        maybe_min_package_age: None,
        policy_evaluator: ecosystem_config.map(PolicyEvaluator::for_tests),
    }
}

fn malware_entry(name: &str, version: &str) -> ListDataEntry {
    ListDataEntry {
        package_name: name.to_owned(),
        version: version.parse().unwrap(),
        reason: Reason::Malware,
    }
}

fn tarball_request(name: &str, version: &str) -> Request {
    let path = if let Some((_scope, bare)) = name.strip_prefix('@').and_then(|n| n.split_once('/'))
    {
        format!("/{name}/-/{bare}-{version}.tgz")
    } else {
        format!("/{name}/-/{name}-{version}.tgz")
    };
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn assert_block_reason(action: RequestAction, expected: BlockReason) {
    match action {
        RequestAction::Block(blocked) => assert_eq!(blocked.info.block_reason, expected),
        RequestAction::Allow(_) => panic!("expected Block({expected:?}), got Allow"),
    }
}

fn assert_allow(action: RequestAction) {
    if let RequestAction::Block(blocked) = action {
        panic!("expected Allow, got Block({:?})", blocked.info.block_reason);
    }
}

// 6-case truth table covering policy decision (AllowSkipAgeCheck / Allow / Defer)
// crossed against downstream signals (malware list / recent release).

#[tokio::test]
async fn wildcard_allow_bypasses_malware() {
    let cfg = ecosystem_config_with_allowed(&["@aikidosec/*"]);
    let rule = make_test_rule(
        Some(&cfg),
        vec![malware_entry("@aikidosec/ci-api-client", "1.0.15")],
        &[],
    );

    let action = rule
        .evaluate_tarball_request(tarball_request("@aikidosec/ci-api-client", "1.0.15"))
        .await
        .unwrap();
    assert_allow(action);
}

#[tokio::test]
async fn exact_allow_bypasses_malware() {
    let cfg = ecosystem_config_with_allowed(&["lodash"]);
    let rule = make_test_rule(Some(&cfg), vec![malware_entry("lodash", "4.17.21")], &[]);

    let action = rule
        .evaluate_tarball_request(tarball_request("lodash", "4.17.21"))
        .await
        .unwrap();
    assert_allow(action);
}

#[tokio::test]
async fn defer_blocks_malware() {
    let rule = make_test_rule(None, vec![malware_entry("evil-pkg", "0.0.1")], &[]);

    let action = rule
        .evaluate_tarball_request(tarball_request("evil-pkg", "0.0.1"))
        .await
        .unwrap();
    assert_block_reason(action, BlockReason::Malware);
}

#[tokio::test]
async fn wildcard_allow_bypasses_min_age() {
    let cfg = ecosystem_config_with_allowed(&["@aikidosec/*"]);
    let rule = make_test_rule(
        Some(&cfg),
        vec![],
        &[("@aikidosec/ci-api-client", "1.0.15", 1)],
    );

    let action = rule
        .evaluate_tarball_request(tarball_request("@aikidosec/ci-api-client", "1.0.15"))
        .await
        .unwrap();
    assert_allow(action);
}

#[tokio::test]
async fn exact_allow_does_not_bypass_min_age() {
    // Approval-flow approvals (exact-match entries) bypass malware but stay
    // subject to min-age — approving by name doesn't vouch for brand-new
    // versions of that name.
    let cfg = ecosystem_config_with_allowed(&["lodash"]);
    let rule = make_test_rule(Some(&cfg), vec![], &[("lodash", "4.17.21", 1)]);

    let action = rule
        .evaluate_tarball_request(tarball_request("lodash", "4.17.21"))
        .await
        .unwrap();
    assert_block_reason(action, BlockReason::NewPackage);
}

#[tokio::test]
async fn defer_blocks_recent_release() {
    let rule = make_test_rule(None, vec![], &[("brand-new-pkg", "0.1.0", 1)]);

    let action = rule
        .evaluate_tarball_request(tarball_request("brand-new-pkg", "0.1.0"))
        .await
        .unwrap();
    assert_block_reason(action, BlockReason::NewPackage);
}

#[tokio::test]
async fn test_parse_npm_package_from_path() {
    for (path, expected) in [
        (
            "lodash/-/lodash-4.17.21.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(4, 17, 21),
            )),
        ),
        (
            "/lodash/-/lodash-4.17.21.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(4, 17, 21),
            )),
        ),
        ("lodash/-/lodash-4.17.21", None),
        ("lodash", None),
        (
            "express/-/express-4.18.2.tgz",
            Some(NpmPackage::new(
                "express",
                PragmaticSemver::new_semver(4, 18, 2),
            )),
        ),
        (
            "safe-chain-test/-/safe-chain-test-1.0.0.tgz",
            Some(NpmPackage::new(
                "safe-chain-test",
                PragmaticSemver::new_semver(1, 0, 0),
            )),
        ),
        (
            "web-vitals/-/web-vitals-3.5.0.tgz",
            Some(NpmPackage::new(
                "web-vitals",
                PragmaticSemver::new_semver(3, 5, 0),
            )),
        ),
        (
            "safe-chain-test/-/safe-chain-test-0.0.1-security.tgz",
            Some(NpmPackage::new(
                "safe-chain-test",
                PragmaticSemver::new_semver(0, 0, 1).with_pre("security"),
            )),
        ),
        (
            "lodash/-/lodash-5.0.0-beta.1.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(5, 0, 0).with_pre("beta.1"),
            )),
        ),
        (
            "react/-/react-18.3.0-canary-abc123.tgz",
            Some(NpmPackage::new(
                "react",
                PragmaticSemver::new_semver(18, 3, 0).with_pre("canary-abc123"),
            )),
        ),
        (
            "@babel/core/-/core-7.21.4.tgz",
            Some(NpmPackage::new(
                "@babel/core",
                PragmaticSemver::new_semver(7, 21, 4),
            )),
        ),
        (
            "@types/node/-/node-20.10.5.tgz",
            Some(NpmPackage::new(
                "@types/node",
                PragmaticSemver::new_semver(20, 10, 5),
            )),
        ),
        (
            "@angular/common/-/common-17.0.8.tgz",
            Some(NpmPackage::new(
                "@angular/common",
                PragmaticSemver::new_semver(17, 0, 8),
            )),
        ),
        (
            "@safe-chain/test-package/-/test-package-2.1.0.tgz",
            Some(NpmPackage::new(
                "@safe-chain/test-package",
                PragmaticSemver::new_semver(2, 1, 0),
            )),
        ),
        (
            "@aws-sdk/client-s3/-/client-s3-3.465.0.tgz",
            Some(NpmPackage::new(
                "@aws-sdk/client-s3",
                PragmaticSemver::new_semver(3, 465, 0),
            )),
        ),
        (
            "@babel/core/-/core-8.0.0-alpha.1.tgz",
            Some(NpmPackage::new(
                "@babel/core",
                PragmaticSemver::new_semver(8, 0, 0).with_pre("alpha.1"),
            )),
        ),
        (
            "@safe-chain/security-test/-/security-test-1.0.0-security.tgz",
            Some(NpmPackage::new(
                "@safe-chain/security-test",
                PragmaticSemver::new_semver(1, 0, 0).with_pre("security"),
            )),
        ),
    ] {
        let result = parse_package_from_path(path);

        match (result, expected) {
            (Some(actual_package), Some(expected_package)) => {
                assert_eq!(
                    expected_package.fully_qualified_name,
                    actual_package.fully_qualified_name
                );
                assert_eq!(expected_package.version, actual_package.version);
            }
            (None, None) => {}
            (Some(actual_package), None) => {
                unreachable!(
                    "No package expected, but got '{}'",
                    actual_package.fully_qualified_name
                );
            }
            (None, Some(expected_package)) => {
                unreachable!(
                    "Expected '{}', but got None",
                    expected_package.fully_qualified_name
                );
            }
        }
    }
}
