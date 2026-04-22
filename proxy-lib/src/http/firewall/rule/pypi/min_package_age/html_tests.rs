use parking_lot::Mutex;
use rama::http::{Body, body::util::BodyExt as _};

use crate::package::{
    name_formatter::LowerCasePackageName,
    released_packages_list::{ReleasedPackageData, RemoteReleasedPackagesList},
    version::PackageVersion,
};
use crate::utils::time::{SystemDuration, SystemTimestampMilliseconds};

use super::{AnchorDecision, HtmlRewriteOutcome, analyze_anchor_href, rewrite_body};

fn make_released_packages(
    entries: &[(&str, &str, u64)],
) -> RemoteReleasedPackagesList<LowerCasePackageName> {
    let now_ts = SystemTimestampMilliseconds::now();

    RemoteReleasedPackagesList::from_entries_for_tests(
        entries
            .iter()
            .map(|(package_name, version, hours_ago)| ReleasedPackageData {
                package_name: (*package_name).to_owned(),
                version: version.parse().unwrap(),
                released_on: now_ts - SystemDuration::hours(*hours_ago as u16),
            })
            .collect(),
        now_ts,
    )
}

fn default_cutoff_ts() -> SystemTimestampMilliseconds {
    SystemTimestampMilliseconds::now() - SystemDuration::hours(48)
}

// ── analyze_anchor_href unit tests ───────────────────────────────────────────

#[test]
fn analyze_anchor_href_keeps_unparseable_href() {
    let list = make_released_packages(&[]);

    assert!(matches!(
        analyze_anchor_href(
            "https://example.test/not-a-package",
            default_cutoff_ts(),
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
        default_cutoff_ts(),
        &list,
    ) {
        AnchorDecision::Keep => panic!("expected recent package href to be removed"),
        AnchorDecision::Remove {
            package_name,
            version,
        } => {
            assert_eq!(package_name.as_str(), "my-package");
            assert_eq!(version, "2.0.0".parse::<PackageVersion>().unwrap());
        }
    }
}

// ── LolHtmlBody integration tests ────────────────────────────────────────────

async fn rewrite_html(
    html: &str,
    list: RemoteReleasedPackagesList<LowerCasePackageName>,
) -> Option<(String, String, Vec<PackageVersion>)> {
    let outcome = std::sync::Arc::new(Mutex::new(None::<HtmlRewriteOutcome>));
    let body = rewrite_body(Body::from(html.to_owned()), default_cutoff_ts(), list, {
        let outcome = outcome.clone();
        move |rewrite| {
            *outcome.lock() = rewrite;
        }
    });
    let bytes = Body::new(body).collect().await.unwrap().to_bytes();
    let html_out = String::from_utf8(bytes.to_vec()).unwrap();
    let rewrite = outcome.lock().take()?;
    Some((
        html_out,
        rewrite.package_name.to_string(),
        rewrite.suppressed_versions,
    ))
}

#[tokio::test]
async fn rewrite_body_removes_recent_links_from_simple_html() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-2.0.0.tar.gz">new</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "2.0.0", 1), ("my-package", "1.0.0", 72)]);

    let (html, package_name, suppressed) = rewrite_html(body, list).await.unwrap();

    assert!(html.contains("my_package-1.0.0.tar.gz"));
    assert!(!html.contains("my_package-2.0.0.tar.gz"));
    assert_eq!(package_name, "my-package");
    assert_eq!(suppressed, vec!["2.0.0".parse::<PackageVersion>().unwrap()]);
}

#[tokio::test]
async fn rewrite_body_returns_none_when_html_is_unchanged() {
    let body = r#"
        <html><body>
            <a href="https://files.pythonhosted.org/packages/source/m/my-package/my_package-1.0.0.tar.gz">old</a>
        </body></html>
    "#;
    let list = make_released_packages(&[("my-package", "1.0.0", 72)]);

    assert!(rewrite_html(body, list).await.is_none());
}
