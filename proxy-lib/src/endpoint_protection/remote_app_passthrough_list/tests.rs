use std::net::IpAddr;

use super::*;
use crate::http::firewall::domain_matcher::DomainMatcher;
use rama::net::address::Domain;

fn make_list(apps: impl IntoIterator<Item = (String, DomainMatcher)>) -> PassthroughList {
    let mut trie = Trie::new();
    for (name, matcher) in apps {
        trie.insert(name, matcher);
    }
    PassthroughList {
        apps: trie,
        cidrs: vec![],
    }
}

fn wildcard_list(app_name: &str) -> PassthroughList {
    allowlist_list(app_name, &["*"])
}

fn allowlist_list(app_name: &str, domains: &[&'static str]) -> PassthroughList {
    let matcher: DomainMatcher = domains.iter().copied().collect();
    make_list([(app_name.to_owned(), matcher)])
}

fn flow<'a>(
    domain: Option<&'a Domain>,
    app_bundle_id: Option<&'a str>,
) -> PassthroughMatchContext<'a> {
    PassthroughMatchContext {
        domain,
        app_bundle_id,
    }
}

#[test]
fn test_matches_no_bundle_id_returns_false() {
    let list = wildcard_list("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!list.is_match(&flow(Some(&domain), None)));
}

#[test]
fn test_matches_wrong_bundle_id_returns_false() {
    let list = wildcard_list("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!list.is_match(&flow(Some(&domain), Some("com.google.Chrome"))));
}

#[test]
fn test_matches_wildcard_domain_accepts_any_domain() {
    let list = wildcard_list("com.docker.docker");

    for domain_str in &["registry.hub.docker.com", "github.com", "example.com"] {
        let domain = domain_str.parse::<Domain>().unwrap();
        assert!(
            list.is_match(&flow(Some(&domain), Some("com.docker.docker"))),
            "expected wildcard to match {domain_str}"
        );
    }
}

#[test]
fn test_matches_specific_domain_hit() {
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(list.is_match(&flow(Some(&domain), Some("com.google.Chrome"))));
}

#[test]
fn test_matches_specific_domain_miss() {
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("google.com");
    assert!(!list.is_match(&flow(Some(&domain), Some("com.google.Chrome"))));
}

#[test]
fn test_matches_bundle_id_prefix() {
    // starts_with: "com.google.Chrome.canary" starts with "com.google.Chrome"
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(list.is_match(&flow(Some(&domain), Some("com.google.Chrome.canary"))));
}

#[test]
fn test_matches_bundle_id_partial_prefix_does_not_match() {
    // "com.google.Chrom" is shorter than "com.google.Chrome" — no match
    let list = wildcard_list("com.google.Chrome");
    let domain = Domain::from_static("example.com");
    assert!(!list.is_match(&flow(Some(&domain), Some("com.google.Chrom"))));
}

#[test]
fn test_invalid_domains_are_filtered_out() {
    // "not a domain!!" is not a valid Domain and should be silently dropped.
    let list = allowlist_list("com.example.app", &["valid.example.com", "not a domain!!"]);
    let valid = Domain::from_static("valid.example.com");
    let invalid = Domain::from_static("notadomain.example.com");
    assert!(list.is_match(&flow(Some(&valid), Some("com.example.app"))));
    assert!(!list.is_match(&flow(Some(&invalid), Some("com.example.app"))));
}

#[test]
fn test_empty_domains_allowlist_matches_nothing() {
    // All domains invalid → empty allowlist → nothing matches
    let list = allowlist_list("com.example.app", &["not a domain!!"]);
    let domain = Domain::from_static("example.com");
    assert!(!list.is_match(&flow(Some(&domain), Some("com.example.app"))));
}

#[test]
fn test_app_bundle_matches_wildcard_no_domain_true() {
    let list = allowlist_list("com.fortinet", &["*"]);

    assert!(list.is_match(&flow(None, Some("com.fortinet"))));
    assert!(list.is_match(&flow(None, Some("com.fortinet.forticlient.ztagent"))));
}

// --- CIDR passthrough tests ---

fn cidr_list(cidrs: &[&str]) -> PassthroughList {
    PassthroughList {
        apps: Trie::new(),
        cidrs: cidrs.iter().filter_map(|s| s.parse().ok()).collect(),
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn test_cidr_ipv4_match_and_no_match() {
    let list = cidr_list(&["100.64.0.0/10"]);
    assert!(list.is_destination_ip_passthrough(ip("100.64.0.1")));
    assert!(!list.is_destination_ip_passthrough(ip("100.128.0.0")));
    assert!(!list.is_destination_ip_passthrough(ip("1.2.3.4")));
}

#[test]
fn test_cidr_ipv6_match_and_no_match() {
    let list = cidr_list(&["2001:db8::/32"]);
    assert!(list.is_destination_ip_passthrough(ip("2001:db8::1")));
    assert!(!list.is_destination_ip_passthrough(ip("2001:db9::1")));
}

#[test]
fn test_cidr_multiple_ranges_all_checked() {
    let list = cidr_list(&["100.64.0.0/10", "10.0.0.0/8"]);
    assert!(list.is_destination_ip_passthrough(ip("100.64.1.1"))); // first
    assert!(list.is_destination_ip_passthrough(ip("10.1.2.3"))); // second
    assert!(!list.is_destination_ip_passthrough(ip("8.8.8.8"))); // neither
}

#[test]
fn test_cidr_mixed_ipv4_and_ipv6() {
    let list = cidr_list(&["100.64.0.0/10", "2001:db8::/32"]);
    assert!(list.is_destination_ip_passthrough(ip("100.64.0.1")));
    assert!(list.is_destination_ip_passthrough(ip("2001:db8::1")));
    assert!(!list.is_destination_ip_passthrough(ip("8.8.8.8")));
    assert!(!list.is_destination_ip_passthrough(ip("::1")));
}

#[test]
fn test_cidr_empty_list_returns_false() {
    let list = cidr_list(&[]);
    assert!(!list.is_destination_ip_passthrough(ip("100.64.0.1")));
}

#[test]
fn test_cidr_invalid_entries_are_skipped() {
    // Invalid strings are silently dropped; valid entries still work.
    let list = cidr_list(&["notacidr", "100.64.0.0/10", "256.0.0.0/8", ""]);
    assert!(list.is_destination_ip_passthrough(ip("100.64.1.1")));
    assert!(!list.is_destination_ip_passthrough(ip("8.8.8.8")));
}

// --- End-to-end tests: JSON response → PassthroughList → passthrough decision ---
//
// These tests exercise the full pipeline that runs at runtime:
//   fetchDisabledApps HTTP response  (JSON)
//     → ApiResponse (serde deserialization)
//       → PassthroughList (build_state logic)
//         → is_destination_ip_passthrough / is_match (flow decision)
//
// They intentionally replicate the build_state construction so that a bug in
// either deserialization or list-building will surface here, not just in unit
// tests of individual pieces.

/// Mirrors the `build_state` body: converts a parsed `ApiResponse` into a
/// `PassthroughList` exactly the way the production code does.
fn list_from_api_response(response: ApiResponse) -> PassthroughList {
    let mut apps = Trie::new();
    for app_config in response.disabled_apps_mac {
        let matcher: DomainMatcher = app_config.domains.into_iter().collect();
        apps.insert(app_config.app_id, matcher);
    }
    let cidrs = response
        .passthrough_cidrs
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    PassthroughList { apps, cidrs }
}

fn parse_response(json: &str) -> PassthroughList {
    let response: ApiResponse = serde_json::from_str(json).unwrap();
    list_from_api_response(response)
}

#[test]
fn test_e2e_passthrough_cidrs_field_is_deserialized() {
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": ["100.64.0.0/10", "10.0.0.0/8"]
    }"#;
    let response: ApiResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.passthrough_cidrs, ["100.64.0.0/10", "10.0.0.0/8"]);
}

#[test]
fn test_e2e_missing_passthrough_cidrs_defaults_to_empty() {
    // Responses from older API versions omit the field; they must still parse.
    let json = r#"{"disabled_apps_mac": []}"#;
    let response: ApiResponse = serde_json::from_str(json).unwrap();
    assert!(response.passthrough_cidrs.is_empty());
}

#[test]
fn test_e2e_twingate_cgnat_range_is_passed_through() {
    // The motivating real-world scenario: 100.64.0.0/10 added via the API so
    // that connections to Twingate virtual IPs are not intercepted.
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": ["100.64.0.0/10"]
    }"#;
    let list = parse_response(json);

    // Addresses inside Twingate's CGNAT range must be passthrough.
    assert!(list.is_destination_ip_passthrough(ip("100.64.0.0")));
    assert!(list.is_destination_ip_passthrough(ip("100.64.1.1")));
    assert!(list.is_destination_ip_passthrough(ip("100.127.255.255")));

    // Addresses outside the range must not be passthrough.
    assert!(!list.is_destination_ip_passthrough(ip("100.128.0.0")));
    assert!(!list.is_destination_ip_passthrough(ip("8.8.8.8")));
}

#[test]
fn test_e2e_app_and_cidr_passthrough_coexist() {
    // A single response can carry both app-level and CIDR-level exclusions;
    // they must operate independently without interfering.
    //
    // Note: an app entry requires "domains": ["*"] for it to match when no
    // domain is presented (the wildcard case used by is_passthrough_flow).
    // An empty domains array means "match nothing", consistent with
    // test_empty_domains_allowlist_matches_nothing.
    let json = r#"{
        "disabled_apps_mac": [
            {"app_id": "com.twingate.macos", "domains": ["*"]}
        ],
        "passthrough_cidrs": ["100.64.0.0/10"]
    }"#;
    let list = parse_response(json);

    let domain = Domain::from_static("example.com");

    // App-level passthrough for Twingate's own process (wildcard domain).
    assert!(list.is_match(&flow(None, Some("com.twingate.macos"))));
    assert!(list.is_match(&flow(Some(&domain), Some("com.twingate.macos"))));

    // CIDR-level passthrough for connections going to Twingate virtual IPs.
    assert!(list.is_destination_ip_passthrough(ip("100.64.0.1")));

    // An unrelated app connecting to a public IP must NOT be passed through.
    assert!(!list.is_match(&flow(Some(&domain), Some("com.other.app"))));
    assert!(!list.is_destination_ip_passthrough(ip("1.2.3.4")));
}

#[test]
fn test_e2e_invalid_cidrs_in_json_are_silently_dropped() {
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": ["not-a-cidr", "100.64.0.0/10", "300.0.0.0/8"]
    }"#;
    let list = parse_response(json);

    // The valid entry still works.
    assert!(list.is_destination_ip_passthrough(ip("100.64.1.1")));
    // The invalid entries did not produce spurious matches.
    assert!(!list.is_destination_ip_passthrough(ip("1.2.3.4")));
}

#[test]
fn test_e2e_multiple_cidrs_across_both_families() {
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "fc00::/7"]
    }"#;
    let list = parse_response(json);

    assert!(list.is_destination_ip_passthrough(ip("10.1.2.3")));
    assert!(list.is_destination_ip_passthrough(ip("172.20.0.1")));
    assert!(list.is_destination_ip_passthrough(ip("fc00::1")));
    assert!(list.is_destination_ip_passthrough(ip("fdff:ffff::1")));

    assert!(!list.is_destination_ip_passthrough(ip("11.0.0.0")));
    assert!(!list.is_destination_ip_passthrough(ip("172.32.0.0")));
    assert!(!list.is_destination_ip_passthrough(ip("fe80::1")));
}

#[test]
fn test_e2e_empty_passthrough_cidrs_array_changes_nothing() {
    // An explicit empty array must be treated identically to a missing field.
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": []
    }"#;
    let list = parse_response(json);
    assert!(!list.is_destination_ip_passthrough(ip("100.64.0.1")));
    assert!(!list.is_destination_ip_passthrough(ip("10.0.0.1")));
}

#[test]
fn test_e2e_cidr_passthrough_does_not_affect_app_matching() {
    // Adding a CIDR must not grant any app-bundle passthrough.
    let json = r#"{
        "disabled_apps_mac": [],
        "passthrough_cidrs": ["0.0.0.0/0"]
    }"#;
    let list = parse_response(json);
    let domain = Domain::from_static("example.com");

    // All IPs are covered by the catch-all CIDR...
    assert!(list.is_destination_ip_passthrough(ip("1.2.3.4")));
    // ...but no app bundles are matched because the app list is empty.
    assert!(!list.is_match(&flow(Some(&domain), Some("com.any.app"))));
    assert!(!list.is_match(&flow(None, Some("com.any.app"))));
}
