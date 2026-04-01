use super::*;
use crate::{
    package::name_formatter::{LowerCasePackageName, LowerCasePackageNameFormatter},
    utils::remote_resource::RemoteResource,
};

fn make_trie(
    entries: Vec<ReleasedPackageData>,
    now: SystemTimestampMilliseconds,
) -> ReleasedPackagesTrie<LowerCasePackageNameFormatter> {
    trie_from_released_packages_list(entries, now, &LowerCasePackageNameFormatter::new())
}

fn pv(s: &str) -> PackageVersion {
    s.parse().unwrap()
}

fn make_list(
    package_name: &str,
    version: &str,
    released_on: SystemTimestampMilliseconds,
) -> RemoteReleasedPackagesList<LowerCasePackageNameFormatter> {
    let trie = trie_from_released_packages_list(
        vec![ReleasedPackageData {
            package_name: package_name.to_owned(),
            version: pv(version),
            released_on,
        }],
        released_on + SystemDuration::hours(1),
        &LowerCasePackageNameFormatter::new(),
    );
    RemoteReleasedPackagesList {
        trie: RemoteResource::from_state(trie),
    }
}

#[test]
fn test_is_recently_released_specific_version_match() {
    // package released 1h ago, cutoff = 2h ago → should be recent
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - SystemDuration::hours(2);
    assert!(list.is_recently_released(
        &LowerCasePackageName::from("my-ext"),
        Some(&pv("1.0.0")),
        cutoff
    ));
}

#[test]
fn test_is_recently_released_specific_version_no_match_wrong_version() {
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let list = make_list("my-ext", "1.0.0", released_on);
    let cutoff = released_on - SystemDuration::hours(2);
    assert!(!list.is_recently_released(
        &LowerCasePackageName::from("my-ext"),
        Some(&pv("2.0.0")),
        cutoff
    ));
}

#[test]
fn test_is_recently_released_any_version() {
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let cutoff = released_on - SystemDuration::hours(2);
    let list = make_list("my-ext", "1.0.0", released_on);
    assert!(list.is_recently_released(&LowerCasePackageName::from("my-ext"), None, cutoff));
}

#[test]
fn test_is_recently_released_stale_entry() {
    // released_on is BEFORE the cutoff → not recent
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let cutoff = released_on + SystemDuration::hours(1); // cutoff is 1h AFTER release
    let list = make_list("my-ext", "1.0.0", released_on);
    assert!(!list.is_recently_released(
        &LowerCasePackageName::from("my-ext"),
        Some(&pv("1.0.0")),
        cutoff
    ));
}

#[test]
fn test_is_recently_released_unknown_package() {
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let cutoff = released_on - SystemDuration::hours(2);
    let list = make_list("my-ext", "1.0.0", released_on);
    assert!(!list.is_recently_released(&LowerCasePackageName::from("unknown-ext"), None, cutoff));
}

#[test]
fn test_trie_filters_old_entries() {
    let now_ts = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let cutoff = now_ts - MAX_ENTRY_AGE;
    let entries = vec![
        ReleasedPackageData {
            package_name: "old-pkg".to_owned(),
            version: pv("1.0.0"),
            released_on: cutoff - SystemDuration::milliseconds(1), // older than max age
        },
        ReleasedPackageData {
            package_name: "new-pkg".to_owned(),
            version: pv("1.0.0"),
            released_on: cutoff + SystemDuration::milliseconds(1), // within max age
        },
    ];
    let trie = make_trie(entries, now_ts);
    assert!(trie.get(&LowerCasePackageName::from("old-pkg")).is_none());
    assert!(trie.get(&LowerCasePackageName::from("new-pkg")).is_some());
}

#[test]
fn test_is_recently_released_case_insensitive() {
    let released_on = SystemTimestampMilliseconds::EPOCH + SystemDuration::milliseconds(1_000_000);
    let list = make_list("My-Ext", "1.0.0", released_on);
    let cutoff = released_on - SystemDuration::hours(2);
    // Name normalization is the caller's responsibility (LowerCasePackageNameFormatter
    // lowercases keys at trie-build time), so the lookup key must already be lowercase.
    assert!(list.is_recently_released(
        &LowerCasePackageName::from("my-ext"),
        Some(&pv("1.0.0")),
        cutoff
    ));
}
