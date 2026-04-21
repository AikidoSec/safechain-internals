use std::str::FromStr;

use rama::telemetry::tracing;

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

/// Parses a Go module proxy zip URL path into a normalized module name and version.
///
/// Expected path shape: `/{module_path}/@v/{version}.zip`
///
/// Go module paths go through two layers of encoding in proxy URLs:
///   1. Module escaping (`golang.org/x/mod/module.EscapePath`): each uppercase letter
///      becomes `!` + its lowercase equivalent — e.g. `AikidoSec` → `!aikido!sec`.
///   2. Percent-encoding of `!` in the URL: `!` → `%21`.
///
/// So `github.com/AikidoSec/firewall-go` appears in the URL as
/// `github.com/%21aikido%21sec/firewall-go`.
///
/// We reverse both layers then lowercase for malware-list lookup
/// (which uses `LowerCaseEntryFormatter`).
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
    let percent_decoded = percent_decode(raw);
    let unescaped = go_module_unescape(&percent_decoded);
    unescaped.to_ascii_lowercase()
}

/// Decodes percent-encoded characters in a URL path segment.
/// Only handles the ASCII subset relevant to Go module paths (`%21` → `!`, etc.).
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
