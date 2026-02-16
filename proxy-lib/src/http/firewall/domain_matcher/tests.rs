use super::*;

#[test]
fn test_domain_matcher_empty() {
    let matcher = <DomainMatcher as FromIterator<&'static str>>::from_iter([]);
    assert!(matcher.iter().next().is_none());
    assert!(!matcher.is_match(&Domain::example()));
}

#[test]
fn test_domain_matcher_exact() {
    let matcher: DomainMatcher = ["example.com", "aikido.dev"].into_iter().collect();

    let mut domains: Vec<_> = matcher.iter().map(|d| d.to_string()).collect();
    assert_eq!(2, domains.len());
    domains.sort();
    assert_eq!("aikido.dev", domains[0]);
    assert_eq!("example.com", domains[1]);

    assert!(matcher.is_match(&Domain::example()));
    assert!(matcher.is_match(&Domain::from_static("aikido.dev")));
    assert!(!matcher.is_match(&Domain::from_static("cdn.aikido.dev")));
    assert!(!matcher.is_match(&Domain::from_static("foo.bar")));
}

fn test_domain_matcher_inner(matcher: DomainMatcher) {
    let mut domains: Vec<_> = matcher.iter().map(|d| d.to_string()).collect();
    assert_eq!(2, domains.len());
    domains.sort();
    assert_eq!("aikido.dev", domains[0]);
    assert_eq!("example.com", domains[1]);

    assert!(matcher.is_match(&Domain::example()));
    assert!(matcher.is_match(&Domain::from_static("aikido.dev")));
    assert!(matcher.is_match(&Domain::from_static("cdn.aikido.dev")));
    assert!(!matcher.is_match(&Domain::from_static("foo.example.com")));
    assert!(!matcher.is_match(&Domain::from_static("foo.bar")));
}

#[test]
fn test_domain_matcher_parent() {
    let matcher: DomainMatcher = ["example.com", "*.aikido.dev"].into_iter().collect();
    test_domain_matcher_inner(matcher);
}

#[test]
fn test_domain_matcher_parent_collide() {
    let matcher: DomainMatcher = ["example.com", "*.aikido.dev", "aikido.dev"]
        .into_iter()
        .collect();
    test_domain_matcher_inner(matcher);
}

#[test]
fn test_domain_matcher_parent_collide_rev() {
    let matcher: DomainMatcher = ["example.com", "aikido.dev", "*.aikido.dev"]
        .into_iter()
        .collect();
    test_domain_matcher_inner(matcher);
}

#[test]
fn test_domain_matcher_parent_collide_dup() {
    let matcher: DomainMatcher = ["example.com", "*.aikido.dev", "*.aikido.dev"]
        .into_iter()
        .collect();
    test_domain_matcher_inner(matcher);
}
