use super::*;
use crate::{
    endpoint_protection::{EcosystemConfig, ExceptionLists},
    package::name_formatter::LowerCasePackageName,
};

// --- glob_matches (policy.rs): exact match, prefix/suffix/infix `*`, empty segments, multi-star ---

#[test]
fn glob_matches_no_star_equal_strings() {
    assert!(super::glob_matches("requests", "requests"));
    assert!(!super::glob_matches("requests", "request"));
    assert!(!super::glob_matches("requests", "Requests"));
}

#[test]
fn glob_matches_no_star_empty() {
    assert!(super::glob_matches("", ""));
    assert!(!super::glob_matches("", "x"));
    assert!(!super::glob_matches("x", ""));
}

#[test]
fn glob_matches_single_star_matches_anything_including_empty() {
    assert!(super::glob_matches("*", ""));
    assert!(super::glob_matches("*", "a"));
    assert!(super::glob_matches("*", "anything"));
}

#[test]
fn glob_matches_leading_star_suffix() {
    assert!(super::glob_matches("*bar", "bar"));
    assert!(super::glob_matches("*bar", "foobar"));
    assert!(super::glob_matches("*bar", "barbar"));
    assert!(!super::glob_matches("*bar", "fooba"));
    assert!(!super::glob_matches("*bar", "barx"));
}

#[test]
fn glob_matches_trailing_star_prefix() {
    assert!(super::glob_matches("foo*", "foo"));
    assert!(super::glob_matches("foo*", "foobar"));
    assert!(!super::glob_matches("foo*", "fo"));
    assert!(!super::glob_matches("foo*", "barfoo"));
}

#[test]
fn glob_matches_both_ends_star_infix() {
    assert!(super::glob_matches("*needle*", "needle"));
    assert!(super::glob_matches("*needle*", "hayneedlestack"));
    assert!(super::glob_matches("*needle*", "needlestack"));
    assert!(super::glob_matches("*needle*", "hayneedle"));
    assert!(!super::glob_matches("*needle*", "needl"));
}

#[test]
fn glob_matches_two_internal_stars_three_segments() {
    assert!(super::glob_matches("a*b*c", "abc"));
    assert!(super::glob_matches("a*b*c", "axbyc"));
    assert!(super::glob_matches("a*b*c", "axxbxxc"));
    assert!(!super::glob_matches("a*b*c", "acb"));
    assert!(!super::glob_matches("a*b*c", "axxc"));
}

#[test]
fn glob_matches_consecutive_stars_empty_middle_segment() {
    assert!(super::glob_matches("a**b", "ab"));
    assert!(super::glob_matches("a**b", "axb"));
    assert!(super::glob_matches("a**b", "axxxb"));
    assert!(!super::glob_matches("a**b", "a"));
    assert!(!super::glob_matches("a**b", "b"));
}

#[test]
fn glob_matches_only_stars() {
    assert!(super::glob_matches("**", ""));
    assert!(super::glob_matches("**", "xyz"));
    assert!(super::glob_matches("***", "a"));
}

#[test]
fn glob_matches_scoped_npm_style() {
    assert!(super::glob_matches("@scope/*", "@scope/pkg"));
    assert!(!super::glob_matches("@scope/*", "@other/pkg"));
    assert!(!super::glob_matches("@scope/*", "scope/pkg"));
}

#[test]
fn glob_matches_star_is_literal_glob_not_regex() {
    assert!(super::glob_matches("a*b", "a*b"));
    assert!(!super::glob_matches("a.b", "axb"));
}

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
