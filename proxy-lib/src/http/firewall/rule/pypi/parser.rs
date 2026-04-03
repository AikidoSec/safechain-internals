use std::{borrow::Cow, str::FromStr};

use rama::net::uri::util::percent_encoding;
use rama::utils::collections::smallvec::SmallVec;
use rama::utils::str::smol_str::SmolStr;

use crate::package::{
    released_packages_list::{
        PyPINormalizedReleasedPackageFormatter, ReleasedPackageData, ReleasedPackageEntryFormatter,
    },
    version::PackageVersion,
};

pub(super) struct PackageInfo {
    pub(super) name: SmolStr,
    pub(super) version: PackageVersion,
}

impl PackageInfo {
    pub(super) fn is_metadata_request(&self) -> bool {
        matches!(self.version, PackageVersion::None)
    }
}

pub(super) fn normalize_package_name(raw: &str) -> SmolStr {
    PyPINormalizedReleasedPackageFormatter
        .format(&ReleasedPackageData {
            package_name: raw.to_owned(),
            version: PackageVersion::None,
            released_on: 0,
        })
        .into()
}

fn percent_decode(input: &str) -> Cow<'_, str> {
    percent_encoding::percent_decode_str(input).decode_utf8_lossy()
}

/// Parse package info from a PyPI-style request path.
///
/// This accepts both metadata endpoints and artifact download paths.
///
/// Examples:
/// - `/simple/requests/` => `requests`, metadata request
/// - `/pypi/requests/json` => `requests`, metadata request
/// - `/packages/.../requests-2.31.0.tar.gz` => `requests@2.31.0`
pub(super) fn parse_package_info_from_path(path: &str) -> Option<PackageInfo> {
    let segments = decoded_path_segments(path);

    parse_metadata_package_info(&segments).or_else(|| {
        segments
            .last()
            .and_then(|filename| parse_package_info_from_filename(filename))
    })
}

/// Parse package info from a single PyPI artifact filename.
///
/// Examples:
/// - `requests-2.31.0.tar.gz` => `requests@2.31.0`
/// - `requests-2.31.0-py3-none-any.whl` => `requests@2.31.0`
pub(super) fn parse_package_info_from_filename(filename: &str) -> Option<PackageInfo> {
    parse_wheel_filename(filename).or_else(|| parse_source_dist_filename(filename))
}

/// Parse package info from a full PyPI-style URL.
///
/// Only artifact URLs are recognized here. Metadata URLs should be parsed via
/// [`parse_package_info_from_path`].
///
/// Examples:
/// - `https://files.pythonhosted.org/.../requests-2.31.0.tar.gz` => `requests@2.31.0`
/// - `https://files.pythonhosted.org/.../requests-2.31.0.whl.metadata` => `requests@2.31.0`
pub(super) fn parse_package_info_from_url(url: &str) -> Option<PackageInfo> {
    let url = rama::http::Uri::from_str(url).ok()?;
    let filename = decoded_path_segments(url.path()).pop()?;

    parse_package_info_from_filename(&filename)
}

/// Split a request path into percent-decoded, non-empty segments.
///
/// Examples:
/// - `/simple/requests/` => `["simple", "requests"]`
/// - `/pypi/my%20package/json` => `["pypi", "my package", "json"]`
fn decoded_path_segments(path: &str) -> SmallVec<[Cow<'_, str>; 3]> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect()
}

/// Parse metadata endpoints from already-decoded path segments.
///
/// Examples:
/// - `["simple", "requests"]` => metadata for `requests`
/// - `["pypi", "requests", "json"]` => metadata for `requests`
/// - `["packages", "source", "r", "requests-2.31.0.tar.gz"]` => `None`
fn parse_metadata_package_info(segments: &[Cow<'_, str>]) -> Option<PackageInfo> {
    match segments {
        [prefix, package_name, suffix] if *prefix == "pypi" && *suffix == "json" => {
            Some(PackageInfo {
                name: normalize_package_name(package_name),
                version: PackageVersion::None,
            })
        }
        [prefix, package_name, ..] if *prefix == "simple" => Some(PackageInfo {
            name: normalize_package_name(package_name),
            version: PackageVersion::None,
        }),
        _ => None,
    }
}

/// Parse wheel filename.
///
/// Wheel format: {distribution}-{version}(-...tags).whl
/// Examples:
///   foo_bar-2.0.0-py3-none-any.whl
///   foo_bar-2.0.0-py3-none-any.whl.metadata
pub(super) fn parse_wheel_filename(filename: &str) -> Option<PackageInfo> {
    let base = filename
        .strip_suffix(".whl.metadata")
        .or_else(|| filename.strip_suffix(".whl"))?;

    let (dist, rest) = base.split_once('-')?;

    let version = rest.split('-').next()?;

    if version.eq_ignore_ascii_case("latest") || dist.is_empty() || version.is_empty() {
        return None;
    }

    Some(PackageInfo {
        name: normalize_package_name(dist),
        version: PackageVersion::from_str(version).unwrap(),
    })
}

/// Parse source distribution filename.
///
/// Sdist format: {name}-{version}.{ext}
/// Extensions: .tar.gz, .zip, .tar.bz2, .tar.xz (with optional .metadata suffix)
/// Examples:
///   requests-2.28.1.tar.gz
///   requests-2.28.1.tar.gz.metadata
pub(super) fn parse_source_dist_filename(filename: &str) -> Option<PackageInfo> {
    const SDIST_EXTS: &[&str] = &[".tar.gz", ".zip", ".tar.bz2", ".tar.xz"];

    let working = filename.strip_suffix(".metadata").unwrap_or(filename);

    let base = SDIST_EXTS
        .iter()
        .find_map(|ext| working.strip_suffix(ext))?;

    let (dist, version) = base.rsplit_once('-')?;
    if version.eq_ignore_ascii_case("latest") || dist.is_empty() || version.is_empty() {
        return None;
    }

    Some(PackageInfo {
        name: normalize_package_name(dist),
        version: PackageVersion::from_str(version).unwrap(),
    })
}
