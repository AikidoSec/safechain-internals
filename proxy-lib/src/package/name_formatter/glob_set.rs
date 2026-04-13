//! Typed compiled glob matcher for package names.
//!
//! Design intent:
//! - keep package-name matching type-safe (`GlobSet<K>`)
//! - keep exact matches fast (`HashSet<K>`)
//! - compile wildcard patterns (`*`) into a shared graph so common prefix /
//!   contains paths are reused
//! - match against borrowed refs to avoid extra allocations on hot paths
//!
//! Supported wildcard syntax is only `*` (zero or more characters).

use std::{collections::HashSet, hash::Hash, iter::FromIterator};

use super::{PackageName, PackageNameRef};
use rama::utils::collections::smallvec::SmallVec;

type NodeId = usize;

const INLINE_EDGE_CAPACITY: usize = 4;
const INLINE_SUFFIX_CAPACITY: usize = 4;
const INLINE_STACK_CAPACITY: usize = 16;

#[derive(Debug, Clone)]
struct GlobNode<K: PackageName> {
    prefix_edges: SmallVec<[(K, NodeId); INLINE_EDGE_CAPACITY]>,
    contains_edges: SmallVec<[(K, NodeId); INLINE_EDGE_CAPACITY]>,
    suffix_accepts: SmallVec<[K; INLINE_SUFFIX_CAPACITY]>,
    terminal: bool,
    wildcard_terminal: bool,
}

impl<K: PackageName> Default for GlobNode<K> {
    fn default() -> Self {
        Self {
            prefix_edges: SmallVec::new(),
            contains_edges: SmallVec::new(),
            suffix_accepts: SmallVec::new(),
            terminal: false,
            wildcard_terminal: false,
        }
    }
}

/// Typed compiled glob matcher for package names.
///
/// Supported syntax:
/// - `*` means zero or more characters
/// - all other characters are matched literally
///
/// Compilation model:
/// - optional prefix edge when pattern does not start with `*`
/// - zero or more contains edges for middle literal parts
/// - optional suffix acceptance when pattern does not end with `*`
/// - wildcard-terminal acceptance when pattern ends with `*`
///
/// Exact patterns (no `*`) are kept in `exact` for O(1) lookups.
#[derive(Debug, Clone)]
pub struct GlobSet<K: PackageName + Hash> {
    exact: HashSet<K>,
    nodes: Vec<GlobNode<K>>,
}

impl<K: PackageName + Hash> Default for GlobSet<K> {
    fn default() -> Self {
        Self {
            exact: HashSet::new(),
            nodes: vec![GlobNode::default()],
        }
    }
}

impl<K: PackageName + Hash> GlobSet<K> {
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.nodes.len() == 1
            && self.nodes[0].prefix_edges.is_empty()
            && self.nodes[0].contains_edges.is_empty()
            && self.nodes[0].suffix_accepts.is_empty()
            && !self.nodes[0].terminal
            && !self.nodes[0].wildcard_terminal
    }

    #[inline(always)]
    pub fn match_package_name(&self, package_name: &K) -> bool {
        if self.exact.contains(package_name) {
            return true;
        }
        self.match_package_name_ref(package_name.as_ref())
    }

    pub fn match_package_name_ref<'a>(&'a self, package_name: K::Ref<'a>) -> bool
    where
        K: 'a,
    {
        let mut stack: SmallVec<[(NodeId, K::Ref<'a>); INLINE_STACK_CAPACITY]> = SmallVec::new();
        stack.push((0, package_name));

        while let Some((node_id, candidate)) = stack.pop() {
            let node = &self.nodes[node_id];

            if node.wildcard_terminal {
                return true;
            }

            if node.terminal && candidate.is_empty() {
                return true;
            }

            if node
                .suffix_accepts
                .iter()
                .any(|suffix| candidate.has_suffix(suffix.as_ref()))
            {
                return true;
            }

            for (prefix, next_node_id) in &node.prefix_edges {
                if let Some(remaining) = candidate.strip_prefix(prefix.as_ref()) {
                    stack.push((*next_node_id, remaining));
                }
            }

            for (needle, next_node_id) in &node.contains_edges {
                for remaining in candidate.match_after_needle_all(needle.as_ref()) {
                    stack.push((*next_node_id, remaining));
                }
            }
        }

        false
    }

    fn insert_glob_pattern(&mut self, raw_pattern: &str) {
        let parsed = ParsedPattern::from_raw(raw_pattern);

        let mut node_id = 0;

        if let Some(prefix) = parsed.prefix {
            node_id = self.get_or_insert_edge(node_id, EdgeKind::Prefix, K::normalize(&prefix));
        }

        for contains in parsed.contains {
            node_id = self.get_or_insert_edge(node_id, EdgeKind::Contains, K::normalize(&contains));
        }

        if let Some(suffix) = parsed.suffix {
            if suffix.is_empty() {
                self.nodes[node_id].terminal = true;
            } else {
                let suffix = K::normalize(&suffix);
                if !self.nodes[node_id].suffix_accepts.contains(&suffix) {
                    self.nodes[node_id].suffix_accepts.push(suffix);
                }
            }
        } else {
            self.nodes[node_id].wildcard_terminal = true;
        }
    }

    fn get_or_insert_edge(&mut self, node_id: NodeId, kind: EdgeKind, value: K) -> NodeId {
        {
            let edges = match kind {
                EdgeKind::Prefix => &mut self.nodes[node_id].prefix_edges,
                EdgeKind::Contains => &mut self.nodes[node_id].contains_edges,
            };

            if let Some((_, existing_id)) = edges.iter().find(|(existing, _)| existing == &value) {
                return *existing_id;
            }
        }

        let next_id = self.nodes.len();
        self.nodes.push(GlobNode::default());

        let edges = match kind {
            EdgeKind::Prefix => &mut self.nodes[node_id].prefix_edges,
            EdgeKind::Contains => &mut self.nodes[node_id].contains_edges,
        };
        edges.push((value, next_id));
        next_id
    }

    #[cfg(test)]
    fn node(&self, node_id: NodeId) -> &GlobNode<K> {
        &self.nodes[node_id]
    }

    #[cfg(test)]
    fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl<K: PackageName + Hash, U: AsRef<str>> FromIterator<U> for GlobSet<K> {
    fn from_iter<T: IntoIterator<Item = U>>(iter: T) -> Self {
        let mut set = Self::default();
        for raw_pattern in iter {
            let raw_pattern = raw_pattern.as_ref();
            if raw_pattern.contains('*') {
                set.insert_glob_pattern(raw_pattern);
            } else {
                set.exact.insert(K::normalize(raw_pattern));
            }
        }
        set
    }
}

#[derive(Debug, Clone, Copy)]
enum EdgeKind {
    Prefix,
    Contains,
}

#[derive(Debug, Clone)]
struct ParsedPattern {
    prefix: Option<String>,
    contains: Vec<String>,
    suffix: Option<String>,
}

impl ParsedPattern {
    fn from_raw(raw: &str) -> Self {
        if !raw.contains('*') {
            return Self {
                prefix: Some(raw.to_owned()),
                contains: Vec::new(),
                suffix: Some(String::new()),
            };
        }

        let starts_with_star = raw.starts_with('*');
        let ends_with_star = raw.ends_with('*');
        let parts: Vec<&str> = raw.split('*').collect();

        let prefix = if starts_with_star {
            None
        } else {
            Some(parts[0].to_owned())
        };

        let mut contains = Vec::new();
        let contains_start = if starts_with_star { 0 } else { 1 };
        let contains_end = if ends_with_star {
            parts.len()
        } else {
            parts.len().saturating_sub(1)
        };

        for segment in &parts[contains_start..contains_end] {
            if segment.is_empty() {
                continue;
            }
            contains.push((*segment).to_owned());
        }

        let suffix = if ends_with_star {
            None
        } else {
            Some(parts[parts.len() - 1].to_owned())
        };

        Self {
            prefix,
            contains,
            suffix,
        }
    }
}

#[cfg(test)]
#[path = "glob_set_tests.rs"]
mod tests;
