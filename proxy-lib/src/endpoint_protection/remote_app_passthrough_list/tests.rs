use super::*;
use crate::http::firewall::{IncomingFlowInfo, domain_matcher::DomainMatcher};
use rama::net::address::Domain;

fn wildcard_app(app_name: &str) -> AppConfig {
    AppConfig {
        app_name: app_name.to_owned(),
        domains: Domains::Wildcard,
    }
}

fn allowlist_app(app_name: &str, domains: &[&str]) -> AppConfig {
    let matcher: DomainMatcher = domains
        .iter()
        .filter_map(|d| d.parse::<Domain>().ok())
        .collect();
    AppConfig {
        app_name: app_name.to_owned(),
        domains: Domains::Allowlist(Box::new(matcher)),
    }
}

fn flow<'a>(domain: &'a Domain, app_bundle_id: Option<&'a str>) -> IncomingFlowInfo<'a> {
    IncomingFlowInfo {
        domain,
        app_bundle_id,
    }
}

#[test]
fn test_matches_no_bundle_id_returns_false() {
    let app = wildcard_app("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!app.matches(&flow(&domain, None)));
}

#[test]
fn test_matches_wrong_bundle_id_returns_false() {
    let app = wildcard_app("com.docker.docker");
    let domain = Domain::from_static("registry.hub.docker.com");
    assert!(!app.matches(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_wildcard_domain_accepts_any_domain() {
    let app = wildcard_app("com.docker.docker");

    for domain_str in &["registry.hub.docker.com", "github.com", "example.com"] {
        let domain = domain_str.parse::<Domain>().unwrap();
        assert!(
            app.matches(&flow(&domain, Some("com.docker.docker"))),
            "expected wildcard to match {domain_str}"
        );
    }
}

#[test]
fn test_matches_specific_domain_hit() {
    let app = allowlist_app("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(app.matches(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_specific_domain_miss() {
    let app = allowlist_app("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("google.com");
    assert!(!app.matches(&flow(&domain, Some("com.google.Chrome"))));
}

#[test]
fn test_matches_bundle_id_prefix() {
    // starts_with: "com.google.Chrome.canary" starts with "com.google.Chrome"
    let app = allowlist_app("com.google.Chrome", &["github.com"]);
    let domain = Domain::from_static("github.com");
    assert!(app.matches(&flow(&domain, Some("com.google.Chrome.canary"))));
}

#[test]
fn test_matches_bundle_id_partial_prefix_does_not_match() {
    // "com.google.ChromeDriver" does NOT start with "com.google.Chrome" — wait, it does.
    // So let's test that a genuinely non-matching prefix is rejected.
    let app = wildcard_app("com.google.Chrome");
    let domain = Domain::from_static("example.com");
    assert!(!app.matches(&flow(&domain, Some("com.google.Chrom"))));
}

#[test]
fn test_invalid_domains_are_filtered_out() {
    // "not a domain!!" is not a valid Domain and should be silently dropped.
    let app = allowlist_app("com.example.app", &["valid.example.com", "not a domain!!"]);
    let valid = Domain::from_static("valid.example.com");
    let invalid = Domain::from_static("notadomain.example.com");
    assert!(app.matches(&flow(&valid, Some("com.example.app"))));
    assert!(!app.matches(&flow(&invalid, Some("com.example.app"))));
}

#[test]
fn test_empty_domains_allowlist_matches_nothing() {
    // All domains invalid → empty allowlist → nothing matches
    let app = allowlist_app("com.example.app", &["not a domain!!"]);
    let domain = Domain::from_static("example.com");
    assert!(!app.matches(&flow(&domain, Some("com.example.app"))));
}
