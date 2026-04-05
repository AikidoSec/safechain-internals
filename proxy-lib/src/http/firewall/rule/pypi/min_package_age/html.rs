use std::collections::BTreeSet;

use lol_html::{RewriteStrSettings, element, html_content::Element, rewrite_str};
use rama::utils::str::arcstr::ArcStr;

use crate::package::released_packages_list::RemoteReleasedPackagesList;

use super::super::parser::parse_package_info_from_url;
use super::RewriteResult;

enum AnchorDecision {
    Keep,
    Remove {
        package_name: ArcStr,
        version: String,
    },
}

/// Rewrite a PyPI simple-index HTML page by removing links to too-young files.
///
/// Example:
/// - input: `<a href=".../my_package-1.0.0.tar.gz">old</a><a href=".../my_package-2.0.0.tar.gz">new</a>`
/// - output: only the `1.0.0` anchor remains when `2.0.0` is newer than the cutoff
pub(super) fn rewrite_response(
    bytes: &[u8],
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> Option<RewriteResult> {
    let html = std::str::from_utf8(bytes).ok()?;

    let mut modified = false;
    let mut package_name: Option<ArcStr> = None;
    let mut suppressed_versions = BTreeSet::new();

    let anchor_handler = element!("a[href]", |el| {
        remove_if_too_young(
            el,
            cutoff_secs,
            released_packages,
            &mut modified,
            &mut package_name,
            &mut suppressed_versions,
        )
    });

    let settings = RewriteStrSettings {
        element_content_handlers: vec![anchor_handler],
        ..RewriteStrSettings::default()
    };

    let rewritten = rewrite_str(html, settings).ok()?;

    if !modified {
        return None;
    }

    let package_name = package_name?;

    Some(RewriteResult {
        bytes: rewritten.into_bytes(),
        package_name,
        suppressed_versions: suppressed_versions.into_iter().collect(),
    })
}

/// Removes the element and records its package name and version in the caller's
/// accumulators if the linked file is newer than `cutoff_secs`. Anchors that
/// cannot be parsed or that predate the cutoff are left untouched.
fn remove_if_too_young(
    el: &mut Element,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
    modified: &mut bool,
    package_name: &mut Option<ArcStr>,
    suppressed_versions: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(href) = el.get_attribute("href") else {
        return Ok(());
    };

    let AnchorDecision::Remove {
        package_name: removed_package_name,
        version,
    } = analyze_anchor_href(&href, cutoff_secs, released_packages)
    else {
        return Ok(());
    };

    *modified = true;
    package_name.get_or_insert(removed_package_name);
    suppressed_versions.insert(version);
    el.remove();

    Ok(())
}

/// Decide whether a single simple-index anchor should be kept or removed.
///
/// `Remove` is only returned when the anchor resolves to a parseable package
/// file and that exact version is newer than the configured cutoff.
fn analyze_anchor_href(
    href: &str,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> AnchorDecision {
    let Some(package) = parse_package_info_from_url(href) else {
        return AnchorDecision::Keep;
    };

    // The HTML simple index only contains filenames and URLs — no upload timestamps.
    // Unlike the JSON responses (which carry `upload_time_iso_8601` / `upload-time`),
    // we can only consult the releases list here.
    if !released_packages.is_recently_released(
        package.name.as_str(),
        Some(&package.version),
        cutoff_secs,
    ) {
        return AnchorDecision::Keep;
    }

    AnchorDecision::Remove {
        package_name: ArcStr::from(package.name.as_str()),
        version: package.version.to_string(),
    }
}

#[cfg(test)]
#[path = "html_tests.rs"]
mod tests;
