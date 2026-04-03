use rama::utils::time::now_unix_ms;

use crate::package::released_packages_list::{
    PyPINormalizedReleasedPackageFormatter, ReleasedPackageData, RemoteReleasedPackagesList,
};

use super::{AnchorDecision, analyze_anchor_href, rewrite_response};

fn make_released_packages(entries: &[(&str, &str, u64)]) -> RemoteReleasedPackagesList {
    let now_secs = now_unix_ms() / 1000;

    RemoteReleasedPackagesList::from_entries_for_tests(
        entries
            .iter()
            .map(|(package_name, version, hours_ago)| ReleasedPackageData {
                package_name: (*package_name).to_owned(),
                version: version.parse().unwrap(),
                released_on: now_secs - (*hours_ago as i64 * 3600),
            })
            .collect(),
        now_secs,
        PyPINormalizedReleasedPackageFormatter,
    )
}

fn default_cutoff_secs() -> i64 {
    (now_unix_ms() / 1000) - (48 * 3600)
}

#[test]
fn analyze_anchor_href_keeps_unparseable_href() {
    let list = make_released_packages(&[]);

    assert!(matches!(
        analyze_anchor_href(
            "https://example.test/not-a-package",
            default_cutoff_secs(),
            &list
        ),
        AnchorDecision::Keep
    ));
}

#[test]
fn analyze_anchor_href_removes_recent_package_href() {
    let list = make_released_packages(&[("my-package", "2.0.0", 1)]);

    match analyze_anchor_href(
        "https://files.pythonhosted.org/packages/source/m/my-package/my_package-2.0.0.tar.gz",
        default_cutoff_secs(),
        &list,
    ) {
        AnchorDecision::Keep => panic!("expected recent package href to be removed"),
        AnchorDecision::Remove {
            package_name,
            version,
        } => {
            assert_eq!(package_name.as_str(), "my-package");
            assert_eq!(version, "2.0.0");
        }
    }
}

#[test]
fn rewrite_response_removes_recent_links_from_simple_html() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-2.0.0.tar.gz">new</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);

    let result = rewrite_response(body.as_bytes(), default_cutoff_secs(), &list).unwrap();
    let html = String::from_utf8(result.bytes).unwrap();

    assert!(html.contains("my_package-1.0.0.tar.gz"));
    assert!(!html.contains("my_package-2.0.0.tar.gz"));
    assert_eq!(result.package_name.as_str(), "my-package");
    assert_eq!(result.suppressed_versions, vec!["2.0.0"]);
}

#[test]
fn rewrite_response_returns_none_when_html_is_unchanged() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "1.0.0", 72)]);

    assert!(rewrite_response(body.as_bytes(), default_cutoff_secs(), &list).is_none());
}
