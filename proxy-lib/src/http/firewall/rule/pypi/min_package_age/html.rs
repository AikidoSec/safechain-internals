use std::sync::Arc;

use lol_html::send::Settings;
use parking_lot::Mutex;
use rama::{http::Body, utils::str::arcstr::ArcStr};

use crate::{
    http::{LolHtmlBody, firewall::rule::pypi::parser::parse_package_info_from_url},
    package::{released_packages_list::RemoteReleasedPackagesList, version::PackageVersion},
};

pub(super) struct HtmlRewriteOutcome {
    pub package_name: ArcStr,
    pub suppressed_versions: Vec<PackageVersion>,
}

#[derive(Default)]
struct HtmlRewriteState {
    package_name: Option<ArcStr>,
    suppressed_versions: Vec<PackageVersion>,
}

impl HtmlRewriteState {
    fn record_suppressed(&mut self, package_name: ArcStr, version: PackageVersion) {
        self.package_name.get_or_insert(package_name);
        if !self.suppressed_versions.contains(&version) {
            self.suppressed_versions.push(version);
        }
    }

    fn outcome(&self) -> Option<HtmlRewriteOutcome> {
        Some(HtmlRewriteOutcome {
            package_name: self.package_name.clone()?,
            suppressed_versions: self.suppressed_versions.clone(),
        })
    }
}

pub(super) fn rewrite_body<F>(
    body: Body,
    cutoff_secs: i64,
    released_packages: RemoteReleasedPackagesList,
    on_end: F,
) -> LolHtmlBody
where
    F: FnOnce(Option<HtmlRewriteOutcome>) + Send + 'static,
{
    let state = Arc::new(Mutex::new(HtmlRewriteState::default()));
    let state_handler = Arc::clone(&state);

    let handler = lol_html::element!("a[href]", move |el| {
        let Some(href) = el.get_attribute("href") else {
            return Ok(());
        };

        let (removed_name, version) =
            match analyze_anchor_href(&href, cutoff_secs, &released_packages) {
                AnchorDecision::Keep => return Ok(()),
                AnchorDecision::Remove {
                    package_name: removed_name,
                    version,
                } => (removed_name, version),
            };

        state_handler
            .lock()
            .record_suppressed(removed_name, version);
        el.remove();
        Ok(())
    });

    let settings = Settings {
        element_content_handlers: vec![handler],
        ..Settings::new_send()
    };

    LolHtmlBody::new(body, settings, move || {
        let rewrite = state.lock().outcome();
        on_end(rewrite);
    })
}

enum AnchorDecision {
    Keep,
    Remove {
        package_name: ArcStr,
        version: PackageVersion,
    },
}

/// Decide whether a single simple-index anchor should be kept or removed.
///
/// `Remove` is returned only when the href resolves to a parseable package file
/// and that exact version is newer than the configured cutoff.
fn analyze_anchor_href(
    href: &str,
    cutoff_secs: i64,
    released_packages: &RemoteReleasedPackagesList,
) -> AnchorDecision {
    let Some(package) = parse_package_info_from_url(href) else {
        return AnchorDecision::Keep;
    };

    // The HTML simple index only carries filenames/URLs — no upload timestamps.
    // Unlike JSON responses we can only consult the releases list here.
    if !released_packages.is_recently_released(
        package.name.as_str(),
        Some(&package.version),
        cutoff_secs,
    ) {
        return AnchorDecision::Keep;
    }

    AnchorDecision::Remove {
        package_name: ArcStr::from(package.name.as_str()),
        version: package.version,
    }
}

#[cfg(test)]
#[path = "html_tests.rs"]
mod tests;
