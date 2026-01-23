use crate::firewall::malware_list::{MalwareEntry, PackageVersion, Reason};
use radix_trie::Trie;
use rama::http::{Body, Request, Uri};

use super::*;

impl RuleChrome {
    fn new_test<I, S>(malware_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut trie = Trie::new();
        for id in malware_ids {
            trie.insert(
                id.into(),
                vec![MalwareEntry {
                    version: PackageVersion::Any,
                    reason: Reason::Malware,
                }],
            );
        }

        Self {
            target_domains: [
                "clients2.google.com",
                "update.googleapis.com",
                "clients2.googleusercontent.com",
            ]
            .into_iter()
            .map(|domain| (Domain::from_static(domain), ()))
            .collect(),
            remote_malware_list:
                crate::firewall::malware_list::RemoteMalwareList::from_trie_for_test(trie),
        }
    }
}

#[test]
fn test_parse_crx_download_url() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.googleusercontent.com/crx/blobs/AV8Xwo6UfyG1svQNvX84OhvpXB-Xw-uQDkg-cYbGRZ1gTKj4oShAxmclsKXkB0kLKqSPOZKKKAM2nElpPWIO-TMWGIZoe0XewyHPPrbTLd4pehbXVSMHQGUvXt6EYD_UJ_XoAMZSmuU75EcMvYc0IzAknEyj-bKQuwE5Rw/GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB_6_45_0_0.crx",
        ))
        .body(Body::empty())
        .unwrap();

    let result = rule.parse_crx_download_url(&req);
    assert!(result.is_some());

    let (extension_id, version) = result.unwrap();
    assert_eq!(extension_id.as_str(), "GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB");
    assert_eq!(version, PackageVersion::Unknown("6.45.0.0".into()));
}

#[tokio::test]
async fn test_evaluate_request_no_match_domain() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://example.com/service/update2/crx?x=id=abcdefghijklmnop",
        ))
        .body(Body::empty())
        .unwrap();

    let action = rule.evaluate_request(req).await.unwrap();

    match action {
        RequestAction::Allow(_) => {}
        RequestAction::Block(_) => panic!("expected request to be allowed (domain mismatch)"),
    }
}

#[tokio::test]
async fn test_evaluate_request_blocks_crx_crx_when_malware() {
    let rule = RuleChrome::new_test(["Malicious Extension - Chrome Web Store@ABCDEFGHIJKLMNOP"]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.googleusercontent.com/crx/blobs/somehash/ABCDEFGHIJKLMNOP_1_0_0_0.crx",
        ))
        .body(Body::empty())
        .unwrap();

    let action = rule.evaluate_request(req).await.unwrap();

    match action {
        RequestAction::Block(blocked) => {
            assert_eq!(blocked.info.artifact.product.as_str(), "chrome");
            assert_eq!(
                blocked.info.artifact.identifier.as_str(),
                "ABCDEFGHIJKLMNOP"
            );
            assert!(blocked.info.artifact.version.is_some());
        }
        RequestAction::Allow(_) => panic!("expected request to be blocked"),
    }
}

#[tokio::test]
async fn test_evaluate_request_allows_when_not_malware() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.googleusercontent.com/crx/blobs/somehash/ABCDEFGHIJKLMNOP_1_0_0_0.crx",
        ))
        .body(Body::empty())
        .unwrap();

    let action = rule.evaluate_request(req).await.unwrap();

    match action {
        RequestAction::Allow(_) => {}
        RequestAction::Block(_) => panic!("expected request to be allowed"),
    }
}

#[test]
fn test_chrome_matches_malware_entry_case_insensitive() {
    let rule = RuleChrome::new_test(["Malware - Chrome Web Store@TestID123"]);
    assert!(rule.matches_malware_entry("testid123", &PackageVersion::None));
    assert!(rule.matches_malware_entry("TESTID123", &PackageVersion::None));
}

#[test]
fn test_chrome_matches_malware_entry_multiple_entries() {
    let rule = RuleChrome::new_test([
        "Malware A - Chrome Web Store@malware-a",
        "Malware B - Chrome Web Store@malware-b",
        "Malware C - Chrome Web Store@malware-c",
    ]);
    assert!(rule.matches_malware_entry("malware-a", &PackageVersion::None));
    assert!(rule.matches_malware_entry("malware-b", &PackageVersion::None));
    assert!(rule.matches_malware_entry("malware-c", &PackageVersion::None));
    assert!(!rule.matches_malware_entry("safe-extension", &PackageVersion::None));
}
