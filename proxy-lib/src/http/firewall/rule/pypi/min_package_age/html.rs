use std::sync::Arc;

use lol_html::send::Settings;
use parking_lot::Mutex;
use rama::{http::Body, utils::str::arcstr::ArcStr};

use crate::{
    http::{LolHtmlBody, firewall::rule::pypi::parser::parse_package_info_from_url},
    package::{
        name_formatter::LowerCasePackageName, released_packages_list::RemoteReleasedPackagesList,
        version::PackageVersion,
    },
    utils::time::SystemTimestampMilliseconds,
};

#[derive(Debug)]
pub(super) struct HtmlRewriteOutcome {
    pub package_name: ArcStr,
    pub suppressed_versions: Vec<PackageVersion>,
}

#[derive(Debug, Default)]
struct HtmlRewriteState {
    package_name: Option<ArcStr>,
    suppressed_versions: Vec<PackageVersion>,
}

impl HtmlRewriteState {
    fn set_package(&mut self, package_name: ArcStr) {
        self.package_name.get_or_insert(package_name);
    }

    fn record_version(&mut self, version: PackageVersion) {
        if !self.suppressed_versions.contains(&version) {
            self.suppressed_versions.push(version);
        }
    }

    fn outcome(&mut self) -> Option<HtmlRewriteOutcome> {
        Some(HtmlRewriteOutcome {
            package_name: self.package_name.take()?,
            suppressed_versions: std::mem::take(&mut self.suppressed_versions),
        })
    }
}

pub(super) fn rewrite_body<F>(
    body: Body,
    cutoff_ts: SystemTimestampMilliseconds,
    released_packages: RemoteReleasedPackagesList<LowerCasePackageName>,
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
            match analyze_anchor_href(&href, cutoff_ts, &released_packages) {
                AnchorDecision::Keep => return Ok(()),
                AnchorDecision::Remove {
                    package_name: removed_name,
                    version,
                } => (removed_name, version),
            };

        let mut state = state_handler.lock();
        state.set_package(removed_name);
        state.record_version(version);
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

#[derive(Debug)]
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
    cutoff_ts: SystemTimestampMilliseconds,
    released_packages: &RemoteReleasedPackagesList<LowerCasePackageName>,
) -> AnchorDecision {
    let Some(package) = parse_package_info_from_url(href) else {
        return AnchorDecision::Keep;
    };

    // The HTML simple index only carries filenames/URLs — no upload timestamps.
    // Unlike JSON responses we can only consult the releases list here.
    if !released_packages.is_recently_released(&package.name, Some(&package.version), cutoff_ts) {
        return AnchorDecision::Keep;
    }

    AnchorDecision::Remove {
        package_name: package.name.into_arcstr(),
        version: package.version,
    }
}

#[cfg(test)]
#[path = "html_tests.rs"]
mod tests;
