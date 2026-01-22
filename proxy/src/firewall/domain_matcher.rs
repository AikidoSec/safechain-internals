use rama::net::address::{AsDomainRef, Domain, DomainParentMatch, DomainTrie};

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
                domains.insert_domain(domain, DomainAllowMode::Exact);
            }
        }
        Self(domains)
    }
}

#[derive(Debug, Clone)]
enum DomainAllowMode {
    Exact,
    Parent,
}
