use super::*;
use crate::package::name_formatter::{LowerCasePackageName, PackageName, PackageNameRef};

fn lower_set(patterns: &[&str]) -> GlobSet<LowerCasePackageName> {
    patterns.iter().copied().collect()
}

fn name(raw: &str) -> LowerCasePackageName {
    LowerCasePackageName::from(raw)
}

fn naive_glob_matches(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = text;

    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        if !rest.starts_with(first) {
            return false;
        }
        rest = &rest[first.len()..];
    }

    for segment in &parts[1..parts.len() - 1] {
        if segment.is_empty() {
            continue;
        }
        match rest.find(segment) {
            Some(idx) => rest = &rest[idx + segment.len()..],
            None => return false,
        }
    }

    let last = parts[parts.len() - 1];
    if last.is_empty() {
        true
    } else {
        rest.ends_with(last)
    }
}

#[test]
fn package_name_ref_basics() {
    let value = name("FooBar");
    let r = value.as_ref();
    let suffix = name("bar");
    let prefix = name("foo");

    assert!(r.has_suffix(suffix.as_ref()));
    assert_eq!(r.strip_prefix(prefix.as_ref()), Some(suffix.as_ref()));
}

#[test]
fn package_name_ref_match_after_needle_all_supports_overlaps() {
    let value = name("ababa");
    let needle = name("aba");
    let expected_tail_1 = name("ba");
    let expected_tail_2 = name("");
    let tails: Vec<_> = value
        .as_ref()
        .match_after_needle_all(needle.as_ref())
        .collect();

    assert_eq!(
        tails,
        vec![expected_tail_1.as_ref(), expected_tail_2.as_ref()]
    );
}

#[test]
fn wildcard_star_matches_everything() {
    let set = lower_set(&["*"]);

    assert!(set.match_package_name(&name("")));
    assert!(set.match_package_name(&name("abc")));
    assert!(set.match_package_name(&name("@scope/pkg")));
}

#[test]
fn exact_pattern_matches_exact_normalized_value_only() {
    let set = lower_set(&["requests"]);

    assert!(set.match_package_name(&name("Requests")));
    assert!(!set.match_package_name(&name("request")));
    assert!(!set.match_package_name(&name("requests-extra")));
}

#[test]
fn prefix_suffix_and_contains_patterns_match() {
    let set = lower_set(&["abc*", "*xyz", "ab*yz", "a*b*c", "a**b"]);

    assert!(set.match_package_name(&name("abcdef")));
    assert!(set.match_package_name(&name("prefixxyz")));
    assert!(set.match_package_name(&name("abzzzyz")));
    assert!(set.match_package_name(&name("axbyc")));
    assert!(set.match_package_name(&name("ab")));
    assert!(!set.match_package_name(&name("cab")));
}

#[test]
fn empty_glob_set_matches_nothing() {
    let set = lower_set(&[]);
    assert!(set.is_empty());
    assert!(!set.match_package_name(&name("anything")));
}

#[test]
fn exact_patterns_are_stored_in_hashset_fast_path() {
    let set = lower_set(&["abc", "abc", "def"]);

    assert_eq!(set.exact.len(), 2);
    assert_eq!(set.node_count(), 1);
    assert!(set.match_package_name(&name("ABC")));
    assert!(set.match_package_name(&name("def")));
    assert!(!set.match_package_name(&name("ghi")));
}

#[test]
fn graph_shares_common_prefix_and_contains_paths() {
    let set = lower_set(&["@aaa/*.c*c", "@aaa/*.c*d", "@aaa/*.d*x"]);

    // root + shared prefix node + shared '.c' node + '.d' node
    assert_eq!(set.node_count(), 4);
    assert_eq!(set.node(0).prefix_edges.len(), 1);

    let prefix_node = set.node(0).prefix_edges[0].1;
    assert_eq!(set.node(prefix_node).contains_edges.len(), 2);

    let contains_c_node = set.node(prefix_node).contains_edges[0].1;
    assert_eq!(set.node(contains_c_node).suffix_accepts.len(), 2);
}

#[test]
fn regression_against_naive_matcher_for_star_only_glob_syntax() {
    let patterns = [
        "", "*", "a", "ab", "a*", "*a", "a*b", "a*b*c", "a**b", "@scope/*", "*needle*", "abc***",
        "***xyz",
    ];

    let texts = [
        "",
        "a",
        "ab",
        "abc",
        "axbyc",
        "@scope/pkg",
        "@other/pkg",
        "hayneedlestack",
        "xyz",
        "abcxyz",
        "aaaa",
    ];

    for pattern in patterns {
        let set = lower_set(&[pattern]);
        for text in texts {
            let expected =
                naive_glob_matches(&pattern.to_ascii_lowercase(), &text.to_ascii_lowercase());
            let observed = set.match_package_name(&name(text));
            assert_eq!(
                observed, expected,
                "pattern={pattern:?} text={text:?} observed={observed} expected={expected}"
            );
        }
    }
}

#[test]
fn empty_pattern_matches_only_empty_name() {
    let set = lower_set(&[""]);

    assert!(set.match_package_name(&name("")));
    assert!(!set.match_package_name(&name("x")));
}

#[test]
fn match_wildcard_only_skips_exact_set() {
    let set = lower_set(&["@aikidosec/*", "requests"]);

    // wildcard pattern: matches via the trie
    assert!(set.match_wildcard_only(&name("@aikidosec/ci-api-client")));
    // exact pattern: must NOT count as a wildcard match
    assert!(!set.match_wildcard_only(&name("requests")));
    // unrelated name: no match
    assert!(!set.match_wildcard_only(&name("numpy")));

    // sanity: the regular matcher still treats both as allowed
    assert!(set.match_package_name(&name("@aikidosec/ci-api-client")));
    assert!(set.match_package_name(&name("requests")));
}

#[test]
fn match_wildcard_only_treats_any_star_position_as_wildcard() {
    // Any pattern containing `*` (anywhere) is compiled into the trie, so
    // `match_wildcard_only` returns true regardless of star position.
    let set = lower_set(&["trail*", "*lead", "mid*dle", "*"]);

    assert!(set.match_wildcard_only(&name("trail-anything")));
    assert!(set.match_wildcard_only(&name("anythinglead")));
    assert!(set.match_wildcard_only(&name("midXdle")));
    // `*` alone matches everything via wildcard_terminal at the root.
    assert!(set.match_wildcard_only(&name("totally-unrelated")));
}

#[test]
fn match_exact_only_ignores_wildcards() {
    // `match_exact_only` consults only the exact-match HashSet — wildcard
    // patterns must never satisfy it, even when the name happens to fall
    // within a wildcard's reach.
    let set = lower_set(&["requests", "trail*", "*lead", "mid*dle"]);

    assert!(set.match_exact_only(&name("requests")));
    assert!(!set.match_exact_only(&name("trail-anything")));
    assert!(!set.match_exact_only(&name("anythinglead")));
    assert!(!set.match_exact_only(&name("midXdle")));
    assert!(!set.match_exact_only(&name("numpy")));
}

#[test]
fn wildcard_and_exact_matchers_are_disjoint_per_entry() {
    // For any single pattern the two predicates partition match results:
    // an exact pattern only fires `match_exact_only`, a wildcard pattern
    // only fires `match_wildcard_only`. The pair never both return true
    // for the same (set, name).
    let cases = [
        // (pattern, matching_name, is_wildcard)
        ("requests", "requests", false),
        ("@aikidosec/*", "@aikidosec/ci-api-client", true),
        ("*-test", "pkg-test", true),
        ("pkg-*-evil", "pkg-x-evil", true),
        ("*", "anything", true),
    ];

    for (pattern, matching_name, is_wildcard) in cases {
        let set = lower_set(&[pattern]);
        let n = name(matching_name);

        assert!(
            set.match_package_name(&n),
            "pattern={pattern:?} should match {matching_name:?}"
        );
        assert_eq!(
            set.match_wildcard_only(&n),
            is_wildcard,
            "pattern={pattern:?} match_wildcard_only mismatch"
        );
        assert_eq!(
            set.match_exact_only(&n),
            !is_wildcard,
            "pattern={pattern:?} match_exact_only mismatch"
        );
    }
}
