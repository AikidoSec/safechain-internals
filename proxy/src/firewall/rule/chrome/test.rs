use radix_trie::Trie;
use rama::http::{Body, Request, Uri};

use crate::firewall::malware_list::{MalwareEntry, PackageVersion, Reason};

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
            target_domains: ["clients2.google.com"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
            remote_malware_list:
                crate::firewall::malware_list::RemoteMalwareList::from_trie_for_test(trie),
        }
    }
}

#[test]
fn test_extract_chrome_ext_info_from_req_parses_product_id() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?x=id=abcdefghijklmnop",
        ))
        .body(Body::empty())
        .unwrap();

    let info = rule
        .extract_chrome_ext_info_from_req(&req)
        .expect("expected chrome extension request info");

    assert_eq!(info.product_id.as_str(), "abcdefghijklmnop");
    assert_eq!(info.version, None);
}

#[test]
fn test_extract_chrome_ext_info_from_req_parses_version_unencoded() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?x=id=abcdefghijklmnop&v=2.0.1",
        ))
        .body(Body::empty())
        .unwrap();

    let info = rule
        .extract_chrome_ext_info_from_req(&req)
        .expect("expected chrome extension request info");

    assert_eq!(info.product_id.as_str(), "abcdefghijklmnop");
    assert_eq!(
        info.version,
        Some(PackageVersion::Semver(
            semver::Version::parse("2.0.1").unwrap()
        ))
    );
}

#[test]
fn test_extract_chrome_ext_info_from_req_strips_encoded_ampersand_suffix() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?x=id%3Dabcdefghijklmnop%26v%3D1.2.3",
        ))
        .body(Body::empty())
        .unwrap();

    let info = rule
        .extract_chrome_ext_info_from_req(&req)
        .expect("expected chrome extension request info");

    assert_eq!(info.product_id.as_str(), "abcdefghijklmnop");
    assert_eq!(
        info.version,
        Some(PackageVersion::Semver(
            semver::Version::parse("1.2.3").unwrap()
        ))
    );
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

#[test]
fn test_extract_chrome_ext_info_from_req_no_match_path() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/not_update2/crx?x=id=abcdefghijklmnop",
        ))
        .body(Body::empty())
        .unwrap();

    assert!(rule.extract_chrome_ext_info_from_req(&req).is_none());
}

#[tokio::test]
async fn test_evaluate_request_blocks_when_malware() {
    // Use the actual Chrome malware list format: "Title - Chrome Web Store@<id>"
    let rule = RuleChrome::new_test(["Malicious Extension - Chrome Web Store@abcdefghijklmnop"]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?x=id=abcdefghijklmnop",
        ))
        .body(Body::empty())
        .unwrap();

    let action = rule.evaluate_request(req).await.unwrap();

    match action {
        RequestAction::Block(blocked) => {
            assert_eq!(blocked.info.artifact.product.as_str(), "chrome");
            assert_eq!(
                blocked.info.artifact.identifier.as_str(),
                "abcdefghijklmnop"
            );
            assert!(blocked.info.artifact.version.is_none());
        }
        RequestAction::Allow(_) => panic!("expected request to be blocked"),
    }
}

#[tokio::test]
async fn test_evaluate_request_allows_when_not_malware() {
    let rule = RuleChrome::new_test::<[&str; 0], _>([]);

    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?x=id=abcdefghijklmnop",
        ))
        .body(Body::empty())
        .unwrap();

    let action = rule.evaluate_request(req).await.unwrap();

    match action {
        RequestAction::Allow(_) => {}
        RequestAction::Block(_) => panic!("expected request to be allowed"),
    }
}
