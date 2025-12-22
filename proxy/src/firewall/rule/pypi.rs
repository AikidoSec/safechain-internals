use std::{str::FromStr, time::Duration};

use crate::firewall::{
    malware_list::RemoteMalwareList,
    rule::{PacScriptGenerator, RequestAction, Rule},
};
use percent_encoding;
use rama::{
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Uri},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
};

use crate::{
    http::response::generate_blocked_response_with_context, storage::SyncCompactDataStorage,
};

/// Blocks malicious PyPI packages by inspecting download URLs against a remote malware list.
///
/// This rule intercepts requests to PyPI domains (`pypi.org`, `files.pythonhosted.org`, etc.)
/// and performs the following logic:
///
/// 1.  **Domain Matching**: It first checks if the request is for a known PyPI domain.
/// 2.  **Package Info Extraction**: It parses the request URL to extract a package name and version.
///     This logic handles three main URL types:
///     - PyPI JSON API (`/pypi/<pkg>/json`): Identifies the package name. These are considered
///       metadata requests and are NOT blocked, to allow dependency resolution.
///     - Simple API HTML pages (`/simple/<pkg>/`): Also treated as metadata and NOT blocked.
///     - Package downloads (`.../pkg-1.0.0.whl` or `.../pkg-1.0.0.tar.gz`): Extracts both
///       package and version. These are the primary targets for blocking.
/// 3.  **Malware Check**: If a package file download is identified, it checks the package name
///     and version against the Aikido Intel malware list. It handles name normalization
///     (e.g., `_` vs. `-`).
/// 4.  **Blocking**: If the package/version is found in the malware list, the download is
///     blocked with a 403 Forbidden status and a clear JSON/HTML/text response body.
pub(in crate::firewall) struct RulePyPI {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RulePyPI {
    /// Creates a new PyPI firewall rule.
    ///
    /// This constructor is asynchronous because it needs to perform an initial fetch
    /// (or load from cache) of the PyPI malware list.
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: rama::Service<Request, Output = rama::http::Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_pypi.json"),
            Duration::from_secs(60 * 10),
            sync_storage,
            remote_malware_list_https_client,
        )
        .await
        .context("create remote malware list for pypi block rule")?;

        let target_domains = ["pypi.org", "files.pythonhosted.org", "pypi.python.org"]
            .into_iter()
            .map(|d| (Domain::from_static(d), ()))
            .collect();

        Ok(Self {
            target_domains,
            remote_malware_list,
        })
    }

    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    fn is_blocked(&self, package_name: &str, version: Option<&str>) -> Result<bool, OpaqueError> {
        let entries = self.remote_malware_list.find_entries(package_name);
        let Some(entries) = entries.entries() else {
            return Ok(false);
        };

        if let Some(version) = version {
            let req_version = parse_package_version(version);
            return Ok(entries
                .iter()
                .any(|entry| version_matches(&entry.version, &req_version)));
        }

        // No version provided: block if any entry exists for the package (conservative).
        Ok(!entries.is_empty())
    }

    /// Extracts package name and version from a PyPI request.
    ///
    /// Returns `(package_name, version)` where version is `None` for metadata requests.
    fn extract_package_info(req: &Request) -> Option<(String, Option<String>)> {
        let uri = req.uri();
        let path = uri.path();

        // Path segments, e.g. "/packages/abc/foo.whl" -> ["packages", "abc", "foo.whl"]
        let segments = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_decode)
            .collect::<Vec<_>>();

        // JSON metadata endpoint: /pypi/<name>/json
        if segments.len() == 3 && segments[0] == "pypi" && segments[2] == "json" {
            let name = normalize_package_name(&segments[1]);
            return Some((name, None));
        }

        // Simple package listing: /simple/<name>/
        if segments.len() >= 2 && segments[0] == "simple" {
            let name = normalize_package_name(&segments[1]);
            return Some((name, None));
        }

        // Package file download (e.g. .../foo-1.0.0.whl or .../bar-2.3.4.tar.gz)
        if let Some(filename) = segments.last()
            && let Some((dist, version)) =
                parse_wheel_filename(filename).or_else(|| parse_sdist_filename(filename))
        {
            let name = normalize_package_name(&dist);
            return Some((name, Some(version)));
        }

        None
    }
}

/// Normalizes a PyPI package name: lowercase and replace underscores with hyphens.
fn normalize_package_name(raw: &str) -> String {
    raw.to_lowercase().replace('_', "-")
}

impl Rule for RulePyPI {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "PyPI"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.match_domain(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        let Some(domain) = crate::http::try_get_domain_for_req(&req) else {
            return Ok(RequestAction::Allow(req));
        };
        if !self.match_domain(&domain) {
            return Ok(RequestAction::Allow(req));
        }

        tracing::trace!(http.url.full = %req.uri(), http.host = %domain, "PyPI rule matched domain");

        let Some((package_name, version)) = Self::extract_package_info(&req) else {
            // Not a URL pattern we inspect, so allow it.
            return Ok(RequestAction::Allow(req));
        };

        // If version is None, it's a metadata request (e.g., /pypi/<pkg>/json).
        // We DO NOT block metadata requests, as this would break dependency resolution
        // for legitimate packages that happen to have a malicious dependency.
        // We only block the final package download.
        if version.is_none() {
            tracing::trace!(package = %package_name, "allowing metadata request for PyPI package");
            return Ok(RequestAction::Allow(req));
        }

        let mut blocked = self.is_blocked(&package_name, version.as_deref())?;
        if !blocked && package_name.contains('_') {
            // Normalize underscores to hyphens (PyPI treats them as equivalent) and re-check.
            let hyphen_name = package_name.replace('_', "-");
            blocked = self.is_blocked(&hyphen_name, version.as_deref())?;
        }

        if blocked {
            tracing::debug!(package = %package_name, version = ?version, "blocked PyPI package download");
            return Ok(RequestAction::Block(
                generate_blocked_response_with_context(
                    req,
                    "PyPI",
                    &package_name,
                    version.as_deref(),
                    "Listed as malware in Aikido Intel",
                ),
            ));
        }

        Ok(RequestAction::Allow(req))
    }
}

/// Decodes a percent-encoded URL segment.
fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .to_string()
}

/// Parses a wheel filename (e.g., "foo_bar-2.0.0-py3-none-any.whl") to extract the
/// distribution name and version. Also handles `.whl.metadata` files.
fn parse_wheel_filename(filename: &str) -> Option<(String, String)> {
    // Accept .whl or .whl.metadata suffixes
    let trimmed = filename
        .strip_suffix(".whl.metadata")
        .or_else(|| filename.strip_suffix(".whl"))?;

    let (dist, rest) = trimmed.split_once('-')?;
    let mut rest_parts = rest.splitn(2, '-');
    let version = rest_parts.next()?;
    if version.eq_ignore_ascii_case("latest") || dist.is_empty() || version.is_empty() {
        return None;
    }
    Some((dist.to_string(), version.to_string()))
}

/// Parses a source distribution filename (e.g., "requests-2.31.0.tar.gz") to extract
/// the distribution name and version.
fn parse_sdist_filename(filename: &str) -> Option<(String, String)> {
    // Accept common sdist suffixes (with optional .metadata)
    const SDIST_SUFFIXES: &[&str] = &[".tar.gz", ".zip", ".tar.bz2", ".tar.xz"];

    let (base, matched) = SDIST_SUFFIXES
        .iter()
        .find_map(|suffix| {
            filename
                .strip_suffix(&format!("{suffix}.metadata"))
                .map(|b| (b, true))
                .or_else(|| filename.strip_suffix(*suffix).map(|b| (b, true)))
        })
        .unwrap_or((filename, false));

    if !matched {
        return None;
    }

    let last_dash = base.rfind('-')?;
    if last_dash == 0 || last_dash >= base.len() - 1 {
        return None;
    }

    let dist = &base[..last_dash];
    let version = &base[last_dash + 1..];
    if version.eq_ignore_ascii_case("latest") || dist.is_empty() || version.is_empty() {
        return None;
    }

    Some((dist.to_string(), version.to_string()))
}

/// Parses a raw version string into a `PackageVersion` enum.
fn parse_package_version(raw: &str) -> crate::firewall::malware_list::PackageVersion {
    use crate::firewall::malware_list::PackageVersion;

    let raw = raw.trim();
    if raw.is_empty() {
        return PackageVersion::None;
    }
    if raw == "*" {
        return PackageVersion::Any;
    }
    match semver::Version::from_str(raw) {
        Ok(v) => PackageVersion::Semver(v),
        Err(_) => PackageVersion::Unknown(raw.into()),
    }
}

/// Checks if a requested version matches a version specified in the malware list.
fn version_matches(
    entry_version: &crate::firewall::malware_list::PackageVersion,
    req_version: &crate::firewall::malware_list::PackageVersion,
) -> bool {
    use crate::firewall::malware_list::PackageVersion;

    match (entry_version, req_version) {
        (PackageVersion::Any, _) => true,
        (PackageVersion::None, PackageVersion::None) => true,
        (PackageVersion::Semver(a), PackageVersion::Semver(b)) => a == b,
        (PackageVersion::Unknown(a), PackageVersion::Unknown(b)) => a.eq_ignore_ascii_case(b),
        // Treat entry Unknown as match for exact (case-insensitive) unknown; otherwise no match
        (PackageVersion::Unknown(a), PackageVersion::Semver(b)) => a.as_ref() == b.to_string(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wheel_filename() {
        assert_eq!(
            parse_wheel_filename("requests-2.31.0-py3-none-any.whl"),
            Some(("requests".to_string(), "2.31.0".to_string()))
        );
        assert_eq!(
            parse_wheel_filename("foo_bar-1.0.0-py2.py3-none-any.whl"),
            Some(("foo_bar".to_string(), "1.0.0".to_string()))
        );
        assert_eq!(parse_wheel_filename("pkg-latest-py3-none-any.whl"), None);
    }

    #[test]
    fn test_parse_sdist_filename() {
        assert_eq!(
            parse_sdist_filename("requests-2.31.0.tar.gz"),
            Some(("requests".to_string(), "2.31.0".to_string()))
        );
        assert_eq!(
            parse_sdist_filename("foo_bar-1.0.0.zip"),
            Some(("foo_bar".to_string(), "1.0.0".to_string()))
        );
        assert_eq!(parse_sdist_filename("pkg-latest.tar.gz"), None);
    }

    #[test]
    fn test_normalize_package_name() {
        assert_eq!(normalize_package_name("Requests"), "requests");
        assert_eq!(normalize_package_name("foo_bar"), "foo-bar");
        assert_eq!(normalize_package_name("FOO_BAR_BAZ"), "foo-bar-baz");
    }
}
