use super::*;

fn make_trie(entries: Vec<ReleasedPackageData>, now_secs: i64) -> ReleasedPackagesTrie {
    trie_from_released_packages_list(entries, now_secs, LowerCaseReleasedPackageFormatter)
}

fn pv(s: &str) -> PackageVersion {
    s.parse().unwrap()
}

fn make_list(package_name: &str, version: &str, released_on: i64) -> RemoteReleasedPackagesList {
    let trie = trie_from_released_packages_list(
        vec![ReleasedPackageData {
            package_name: package_name.to_owned(),
            version: pv(version),
            released_on,
        }],
        released_on + 3600, // now = 1h after release
        LowerCaseReleasedPackageFormatter,
    );
    RemoteReleasedPackagesList {
        trie: Arc::new(ArcSwap::new(Arc::new(trie))),
    }
}

#[test]
fn test_is_recently_released_specific_version_match() {
    // package released 1h ago, cutoff = 2h ago → should be recent
    let released_on = 1_000_000_i64;
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - 7200; // 2h before release
    assert!(list.is_recently_released("my-ext", Some(&pv("1.0.0")), cutoff));
}

#[test]
fn test_is_recently_released_specific_version_no_match_wrong_version() {
    let released_on = 1_000_000_i64;
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - 7200;
    assert!(!list.is_recently_released("my-ext", Some(&pv("2.0.0")), cutoff));
}

#[test]
fn test_is_recently_released_any_version() {
    let released_on = 1_000_000_i64;
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - 7200;
    assert!(list.is_recently_released("my-ext", None, cutoff));
}

#[test]
fn test_is_recently_released_stale_entry() {
    // released_on is BEFORE the cutoff → not recent
    let released_on = 1_000_000_i64;
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on + 3600; // cutoff is 1h AFTER release
    assert!(!list.is_recently_released("my-ext", Some(&pv("1.0.0")), cutoff));
}

#[test]
fn test_is_recently_released_unknown_package() {
    let released_on = 1_000_000_i64;
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - 7200;
    assert!(!list.is_recently_released("unknown-ext", None, cutoff));
}

#[test]
fn test_trie_filters_old_entries() {
    let now_secs = 1_000_000_i64;
    let cutoff = now_secs.saturating_sub(MAX_ENTRY_AGE_SECS);
    let entries = vec![
        ReleasedPackageData {
            package_name: "old-pkg".to_owned(),
            version: pv("1.0.0"),
            released_on: cutoff - 1, // older than max age
        },
        ReleasedPackageData {
            package_name: "new-pkg".to_owned(),
            version: pv("1.0.0"),
            released_on: cutoff + 1, // within max age
        },
    ];
    let trie = make_trie(entries, now_secs);
    assert!(trie.get("old-pkg").is_none());
    assert!(trie.get("new-pkg").is_some());
}

#[test]
fn test_is_recently_released_case_insensitive() {
    let released_on = 1_000_000_i64;
    let list = make_list("My-Ext", "1.0.0", released_on);
    let cutoff = released_on - 7200;
    // Name normalization is the caller's responsibility (LowerCaseReleasedPackageFormatter
    // lowercases keys at trie-build time), so the lookup key must already be lowercase.
    assert!(list.is_recently_released("my-ext", Some(&pv("1.0.0")), cutoff));
}
