use super::*;
use crate::http::firewall::{IncomingFlowInfo, domain_matcher::DomainMatcher};
use rama::net::address::Domain;

fn make_list(apps: impl IntoIterator<Item = (String, DomainMatcher)>) -> PassthroughList {
    let mut trie = Trie::new();
    for (name, matcher) in apps {
        trie.insert(name, matcher);
    }
    PassthroughList { apps: trie }
}

fn wildcard_list(app_name: &str) -> PassthroughList {
    allowlist_list(app_name, &["*"])
}

fn allowlist_list(app_name: &str, domains: &[&'static str]) -> PassthroughList {
    let matcher: DomainMatcher = domains.iter().copied().collect();
    make_list([(app_name.to_owned(), matcher)])
}

fn flow<'a>(domain: &'a Domain, app_bundle_id: Option<&'a str>) -> IncomingFlowInfo<'a> {
    IncomingFlowInfo {
        domain,
        app_bundle_id,
        source_process_path: None,
    }
}

#[test]
fn test_matches_no_bundle_id_returns_false() {
    let list = wildcard_list("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!list.is_match(&flow(&domain, None)));
}

#[test]
fn test_matches_wrong_bundle_id_returns_false() {
    let list = wildcard_list("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!list.is_match(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_wildcard_domain_accepts_any_domain() {
    let list = wildcard_list("com.docker.docker");

    for domain_str in &["registry.hub.docker.com", "github.com", "example.com"] {
        let domain = domain_str.parse::<Domain>().unwrap();
        assert!(
            list.is_match(&flow(&domain, Some("com.docker.docker"))),
            "expected wildcard to match {domain_str}"
        );
    }
}

#[test]
fn test_matches_specific_domain_hit() {
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(list.is_match(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_specific_domain_miss() {
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("google.com");
    assert!(!list.is_match(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_bundle_id_prefix() {
    // starts_with: "com.google.Chrome.canary" starts with "com.google.Chrome"
    let list = allowlist_list("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(list.is_match(&flow(&domain, Some("com.google.Chrome.canary"))));
}

#[test]
fn test_matches_bundle_id_partial_prefix_does_not_match() {
    // "com.google.Chrom" is shorter than "com.google.Chrome" — no match
    let list = wildcard_list("com.google.Chrome");
    let domain = Domain::from_static("example.com");
    assert!(!list.is_match(&flow(&domain, Some("com.google.Chrom"))));
}

#[test]
fn test_invalid_domains_are_filtered_out() {
    // "not a domain!!" is not a valid Domain and should be silently dropped.
    let list = allowlist_list("com.example.app", &["valid.example.com", "not a domain!!"]);
    let valid = Domain::from_static("valid.example.com");
    let invalid = Domain::from_static("notadomain.example.com");
    assert!(list.is_match(&flow(&valid, Some("com.example.app"))));
    assert!(!list.is_match(&flow(&invalid, Some("com.example.app"))));
}

#[test]
fn test_empty_domains_allowlist_matches_nothing() {
    // All domains invalid → empty allowlist → nothing matches
    let list = allowlist_list("com.example.app", &["not a domain!!"]);
    let domain = Domain::from_static("example.com");
    assert!(!list.is_match(&flow(&domain, Some("com.example.app"))));
}
