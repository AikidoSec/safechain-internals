use rama::utils::str::arcstr::ArcStr;

use super::*;
use crate::endpoint_protection::{EcosystemConfig, ExceptionLists};

fn exceptions(allowed_packages: &[&str], rejected_packages: &[&str]) -> ExceptionLists {
    ExceptionLists {
        allowed_packages: allowed_packages.iter().map(|v| ArcStr::from(*v)).collect(),
        rejected_packages: rejected_packages.iter().map(|v| ArcStr::from(*v)).collect(),
    }
}

#[test]
fn evaluate_package_install_no_ecosystem_returns_no_match() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: true,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &["evil-package"]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(&cfg, "numpy");
    assert_eq!(PackagePolicyDecision::NoMatch, decision);
}

#[test]
fn evaluate_package_install_allow_list_allows() {
    let cfg = EcosystemConfig {
        block_all_installs: true,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["safe-chain-pi-test"], &[]),
    };

    let decision =
        PolicyEvaluator::evaluate_package_install_for_ecosystem_config(&cfg, "safe-chain-pi-test");
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

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(&cfg, "numpy");
    assert_eq!(PackagePolicyDecision::Block, decision);
}

#[test]
fn evaluate_package_install_rejected_package_blocks() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: false,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&[], &["safe-chain-pi-test"]),
    };

    let decision =
        PolicyEvaluator::evaluate_package_install_for_ecosystem_config(&cfg, "safe-chain-pi-test");
    assert_eq!(PackagePolicyDecision::Block, decision);
}

#[test]
fn evaluate_package_install_no_matching_policy_returns_no_match() {
    let cfg = EcosystemConfig {
        block_all_installs: false,
        request_installs: true,
        minimum_allowed_age_timestamp: None,
        exceptions: exceptions(&["requests"], &["evil-package"]),
    };

    let decision = PolicyEvaluator::evaluate_package_install_for_ecosystem_config(&cfg, "numpy");
    assert_eq!(PackagePolicyDecision::NoMatch, decision);
}
