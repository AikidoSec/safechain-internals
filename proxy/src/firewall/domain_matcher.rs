use rama::net::address::{AsDomainRef, Domain, DomainParentMatch, DomainTrie};

#[derive(Debug)]
pub(super) struct DomainMatcher(DomainTrie<DomainAllowMode>);

impl DomainMatcher {
    pub(super) fn is_match(&self, domain: &Domain) -> bool {
        match self.0.match_parent(domain) {
            None => false,
            Some(DomainParentMatch {
                value: DomainAllowMode::Exact,
                is_exact,
                ..
            }) => is_exact,
            Some(DomainParentMatch {
                value: DomainAllowMode::Parent,
                ..
            }) => true,
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = Domain> {
        self.0.iter().map(|t| t.0)
    }
}

impl<D: AsDomainRef> FromIterator<D> for DomainMatcher {
    fn from_iter<T: IntoIterator<Item = D>>(iter: T) -> Self {
        let mut domains = DomainTrie::new();
        for domain in iter {
            if let Some(parent) = domain.as_wildcard_parent()
                && let Ok(_) = parent.try_as_wildcard()
            {
                domains.insert_domain(parent, DomainAllowMode::Parent);
            } else {
                if domains
                    .match_parent(&domain)
                    .map(|m| *m.value == DomainAllowMode::Parent)
                    .unwrap_or_default()
                {
                    // ignore exact mode if already a parent-mode exists for the key
                    // in order to prevent accidental collisions.
                    continue;
                }
                domains.insert_domain(domain, DomainAllowMode::Exact);
            }
        }
        Self(domains)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainAllowMode {
    Exact,
    Parent,
}

#[cfg(test)]
mod tests {
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
}
