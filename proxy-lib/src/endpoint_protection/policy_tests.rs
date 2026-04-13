use super::*;
use crate::{
    endpoint_protection::{EcosystemConfig, ExceptionLists},
    package::name_formatter::LowerCasePackageName,
};

fn exceptions(allowed_packages: &[&str], rejected_packages: &[&str]) -> ExceptionLists {
    ExceptionLists {
        allowed_packages: allowed_packages.iter().map(|v| (*v).into()).collect(),
        rejected_packages: rejected_packages.iter().map(|v| (*v).into()).collect(),
    }
}

type TestPolicyEvaluator = PolicyEvaluator<LowerCasePackageName>;

fn evaluate(cfg: &EcosystemConfig, package_name: &str) -> PackagePolicyDecision {
    TestPolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(cfg),
        &LowerCasePackageName::from(package_name),
    )
}

#[test]
fn evaluate_package_install_request_installs_blocks_unmatched_package() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: true,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &["evil-package"]),
    };

    let decision = TestPolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("numpy"),
    );
    assert_eq!(PackagePolicyDecision::RequestInstall, decision);
}

#[test]
fn evaluate_package_install_no_matching_rule_returns_defer() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &["evil-package"]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("numpy"),
    );
    assert_eq!(PackagePolicyDecision::Defer, decision);
}

#[test]
fn evaluate_package_install_allow_list_allows() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["safe-chain-pi-test"], &[]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("safe-chain-pi-test"),
    );
    assert_eq!(PackagePolicyDecision::Allow, decision);
}

#[test]
fn evaluate_package_install_block_all_blocks() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&[], &[]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("numpy"),
    );
    assert_eq!(PackagePolicyDecision::BlockAll, decision);
}

#[test]
fn evaluate_package_install_rejected_package_blocks() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&[], &["safe-chain-pi-test"]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("safe-chain-pi-test"),
    );
    assert_eq!(PackagePolicyDecision::Rejected, decision);
}

#[test]
fn evaluate_package_install_rejected_takes_priority_over_allowed() {
    // A package appearing in both lists: rejected wins (Rule 1 > Rule 2).
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &["requests"]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("requests"),
    );
    assert_eq!(PackagePolicyDecision::Rejected, decision);
}

#[test]
fn evaluate_package_install_allow_list_takes_priority_over_block_all() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &[]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(
        &super::TypedEcosystemConfig::from_raw(&cfg),
        &LowerCasePackageName::from("requests"),
    );
    assert_eq!(PackagePolicyDecision::Allow, decision);
}

#[test]
fn evaluate_package_install_allowed_packages_wildcard_prefix_scope() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["@npmcli/*"], &[]),
    };

    let decision = evaluate(&cfg, "@npmcli/arborist");
    assert_eq!(PackagePolicyDecision::Allow, decision);

    let decision = evaluate(&cfg, "@other/scope");
    assert_eq!(PackagePolicyDecision::BlockAll, decision);
}

#[test]
fn evaluate_package_install_allowed_packages_wildcard_middle() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["@types/*"], &[]),
    };

    let decision = evaluate(&cfg, "@types/node");
    assert_eq!(PackagePolicyDecision::Allow, decision);
}

#[test]
fn evaluate_package_install_rejected_packages_wildcard_blocks() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&[], &["malicious-*"]),
    };

    let decision = evaluate(&cfg, "malicious-pkg");
    assert_eq!(PackagePolicyDecision::Rejected, decision);

    let decision = evaluate(&cfg, "benign-pkg");
    assert_eq!(PackagePolicyDecision::Defer, decision);
}

#[test]
fn evaluate_package_install_rejected_wildcard_takes_priority_over_allowed_wildcard() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["pkg-*"], &["pkg-evil-*"]),
    };

    let decision = evaluate(&cfg, "pkg-evil-test");
    assert_eq!(PackagePolicyDecision::Rejected, decision);

    let decision = evaluate(&cfg, "pkg-good-test");
    assert_eq!(PackagePolicyDecision::Allow, decision);
}

#[test]
fn evaluate_package_install_star_only_allows_any_package_name() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["*"], &[]),
    };

    let decision = evaluate(&cfg, "anything-goes");
    assert_eq!(PackagePolicyDecision::Allow, decision);
}
