use rama::net::address::{AsDomainRef, Domain, DomainParentMatch, DomainTrie};

#[derive(Debug)]
pub struct DomainMatcher {
    trie: DomainTrie<DomainAllowMode>,
}

impl DomainMatcher {
    pub fn is_match(&self, domain: &Domain) -> bool {
        match self.trie.match_parent(domain) {
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

    pub fn iter(&self) -> impl Iterator<Item = Domain> {
        self.trie.iter().map(|t| t.0)
    }
}

impl<D: AsDomainRef> FromIterator<D> for DomainMatcher {
    fn from_iter<T: IntoIterator<Item = D>>(iter: T) -> Self {
        let mut trie = DomainTrie::new();
        for domain in iter {
            if let Some(parent) = domain.as_wildcard_parent()
                && let Ok(_) = parent.try_as_wildcard()
            {
                trie.insert_domain(parent, DomainAllowMode::Parent);
                continue;
            }

            if trie
                .match_parent(&domain)
                .map(|m| *m.value == DomainAllowMode::Parent)
                .unwrap_or_default()
            {
                // ignore exact mode if already a parent-mode exists for the key
                // in order to prevent accidental collisions.
                continue;
            }
            trie.insert_domain(domain, DomainAllowMode::Exact);
        }

        Self { trie }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainAllowMode {
    Exact,
    Parent,
}

#[cfg(test)]
mod tests;
