use std::str::FromStr;

use rama::{net::uri::util::percent_encoding, telemetry::tracing};

use crate::package::version::PragmaticSemver;

#[path = "module_escape.rs"]
mod module_escape;
use module_escape::go_module_unescape;

pub(super) struct GoPackage {
    pub(super) fully_qualified_name: String,
    pub(super) version: PragmaticSemver,
}

pub(super) fn is_zip_download(path: &str) -> bool {
    path.ends_with(".zip") && path.contains("/@v/")
}

/// Parses a Go module proxy zip URL path (`/{module}/@v/{version}.zip`) into a normalized
/// module name and version. Reverses both encoding layers (percent-encoding + Go module escaping)
/// and lowercases for malware-list lookup.
pub(super) fn parse_package_from_path(path: &str) -> Option<GoPackage> {
    let path = path.trim_matches('/');

    let (module_path_raw, rest) = path.split_once("/@v/")?;
    let version_raw = rest.strip_suffix(".zip")?;

    if module_path_raw.is_empty() || version_raw.is_empty() {
        return None;
    }

    let module_name = normalize_module_path(module_path_raw);

    // Go versions always carry a 'v' prefix in the proxy URL; strip it for semver parsing
    let version_str = version_raw.strip_prefix('v').unwrap_or(version_raw);
    let version = PragmaticSemver::from_str(version_str)
        .inspect_err(|err| {
            tracing::debug!(
                "failed to parse golang module ({module_name}) version (raw = {version_raw}): err = {err}"
            );
        })
        .ok()?;

    Some(GoPackage {
        fully_qualified_name: module_name,
        version,
    })
}

/// Parses a Go module proxy list URL path into a normalized module name.
///
/// Expected path shape: `/{module_path}/@v/list`
pub(super) fn parse_module_from_list_path(path: &str) -> Option<String> {
    let path = path.trim_matches('/');
    let module_path_raw = path.strip_suffix("/@v/list")?;
    if module_path_raw.is_empty() {
        return None;
    }
    Some(normalize_module_path(module_path_raw))
}

/// Normalizes a raw module path segment from a Go proxy URL to a canonical lowercase name.
///
/// Reverses both encoding layers applied by the Go toolchain:
///   1. Percent-decode (`%21` → `!`)
///   2. Module-unescape (`!x` → uppercase `X`, per `golang.org/x/mod/module.UnescapePath`)
/// Then lowercases the result for consistent malware-list lookup.
fn normalize_module_path(raw: &str) -> String {
    let percent_decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
    let unescaped = go_module_unescape(&percent_decoded);
    unescaped.to_ascii_lowercase()
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
