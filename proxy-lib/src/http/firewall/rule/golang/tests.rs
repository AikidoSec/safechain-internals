use rama::http::{Body, Request};

use crate::{
    endpoint_protection::{EcosystemConfig, ExceptionLists, PolicyEvaluator},
    http::firewall::events::BlockReason,
    package::{
        malware_list::{ListDataEntry, Reason},
        released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    },
    utils::time::{SystemDuration, SystemTimestampMilliseconds},
};

use super::*;

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
) -> RuleGolang {
    let now_ts = SystemTimestampMilliseconds::now();
    let released_entries = recent_releases
        .iter()
        .map(|(name, version, hours_ago)| ReleasedPackageData {
            package_name: (*name).to_owned(),
            version: version.parse().unwrap(),
            released_on: now_ts - SystemDuration::hours(*hours_ago as u16),
        })
        .collect();

    RuleGolang {
        target_domains: ["proxy.golang.org"].into_iter().collect(),
        remote_malware_list: RemoteMalwareList::from_entries_for_tests(malware),
        remote_released_packages_list: RemoteReleasedPackagesList::from_entries_for_tests(
            released_entries,
            now_ts,
        ),
        policy_evaluator: ecosystem_config.map(PolicyEvaluator::for_tests),
        maybe_min_package_age: None,
    }
}

fn malware_entry(name: &str, version: &str) -> ListDataEntry {
    ListDataEntry {
        package_name: name.to_owned(),
        version: version.parse().unwrap(),
        reason: Reason::Malware,
    }
}

fn zip_request(name: &str, version: &str) -> Request {
    let path = format!("/{name}/@v/v{version}.zip");
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

#[tokio::test]
async fn wildcard_allow_bypasses_min_age() {
    let cfg = ecosystem_config_with_allowed(&["github.com/gorilla/*"]);
    let rule = make_test_rule(
        Some(&cfg),
        vec![],
        &[("github.com/gorilla/mux", "1.8.0", 1)],
    );

    let action = rule
        .evaluate_zip_request(zip_request("github.com/gorilla/mux", "1.8.0"))
        .await
        .unwrap();
    assert_allow(action);
}

#[tokio::test]
async fn exact_allow_does_not_bypass_min_age() {
    let cfg = ecosystem_config_with_allowed(&["github.com/gorilla/mux"]);
    let rule = make_test_rule(
        Some(&cfg),
        vec![],
        &[("github.com/gorilla/mux", "1.8.0", 1)],
    );

    let action = rule
        .evaluate_zip_request(zip_request("github.com/gorilla/mux", "1.8.0"))
        .await
        .unwrap();
    assert_block_reason(action, BlockReason::NewPackage);
}

#[tokio::test]
async fn exact_allow_bypasses_malware() {
    let cfg = ecosystem_config_with_allowed(&["github.com/gorilla/mux"]);
    let rule = make_test_rule(
        Some(&cfg),
        vec![malware_entry("github.com/gorilla/mux", "1.8.0")],
        &[],
    );

    let action = rule
        .evaluate_zip_request(zip_request("github.com/gorilla/mux", "1.8.0"))
        .await
        .unwrap();
    assert_allow(action);
}
