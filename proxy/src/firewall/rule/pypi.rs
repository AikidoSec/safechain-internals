use std::{fmt, str::FromStr, time::Duration};

use percent_encoding;
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
};

use crate::{
    firewall::{
        malware_list::{MalwareEntry, PackageVersion, RemoteMalwareList},
        pac::PacScriptGenerator,
    },
    http::response::generate_generic_blocked_response_for_req,
    storage::SyncCompactDataStorage,
};

use super::{RequestAction, Rule};

struct PackageInfo {
    name: String,
    version: PackageVersion,
}

impl PackageInfo {
    fn is_metadata_request(&self) -> bool {
        matches!(self.version, PackageVersion::None)
    }

    fn matches(&self, entry: &MalwareEntry) -> bool {
        version_matches(&entry.version, &self.version)
    }
}

pub(in crate::firewall) struct RulePyPI {
    target_domains: DomainTrie<()>,
    remote_malware_list: RemoteMalwareList,
}

impl RulePyPI {
    pub(in crate::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_pypi.json"),
            Duration::from_secs(60 * 10), // Refresh every 10 minutes
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

    fn is_blocked(&self, package_info: &PackageInfo) -> Result<bool, OpaqueError> {
        let entries = self.remote_malware_list.find_entries(&package_info.name);
        let Some(entries) = entries.entries() else {
            return Ok(false);
        };

        Ok(entries.iter().any(|entry| package_info.matches(entry)))
    }

    /// Extracts package name and version from a PyPI request.
    ///
    /// Returns `PackageInfo` where version is `PackageVersion::None` for metadata requests.
    fn extract_package_info(req: &Request) -> Option<PackageInfo> {
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
            return Some(PackageInfo {
                name: normalize_package_name(&segments[1]),
                version: PackageVersion::None,
            });
        }

        // Simple package listing: /simple/<name>/
        if segments.len() >= 2 && segments[0] == "simple" {
            return Some(PackageInfo {
                name: normalize_package_name(&segments[1]),
                version: PackageVersion::None,
            });
        }

        // Package file download (e.g. .../foo-1.0.0.whl or .../bar-2.3.4.tar.gz)
        if let Some(filename) = segments.last() {
            return parse_wheel_filename(filename).or_else(|| parse_sdist_filename(filename));
        }

        None
    }
}

/// Normalizes a PyPI package name: lowercase and replace underscores with hyphens.
fn normalize_package_name(raw: &str) -> String {
    raw.to_lowercase().replace('_', "-")
}

impl fmt::Debug for RulePyPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RulePyPI").finish()
    }
}

impl Rule for RulePyPI {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "PyPI"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        if !crate::http::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("PyPI rule did not match incoming request: passthrough");
            return Ok(RequestAction::Allow(req));
        }

        let Some(package_info) = Self::extract_package_info(&req) else {
            tracing::trace!("PyPI url: path not recognized: passthrough");
            return Ok(RequestAction::Allow(req));
        };

        // NOTE: metadata requests (version=None, e.g., /pypi/<pkg>/json or /simple/<pkg>/) are NOT blocked.
        // Blocking metadata would break dependency resolution for legitimate packages that depend on
        // a malicious package. We only block the actual package file downloads.
        if package_info.is_metadata_request() {
            tracing::trace!(package = %package_info.name, "allowing metadata request for PyPI package");
            return Ok(RequestAction::Allow(req));
        }

        // Package names are already normalized by extract_package_info (underscores -> hyphens),
        // so we can check directly against the malware list
        if self.is_blocked(&package_info)? {
            tracing::debug!(package = %package_info.name, version = ?package_info.version, "blocked PyPI package download");

            return Ok(RequestAction::Block(
                generate_generic_blocked_response_for_req(req),
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
/// package info. Also handles `.whl.metadata` files.
fn parse_wheel_filename(filename: &str) -> Option<PackageInfo> {
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
    Some(PackageInfo {
        name: normalize_package_name(dist),
        version: parse_package_version(version),
    })
}

/// Parses a source distribution filename (e.g., "requests-2.31.0.tar.gz") to extract
/// the package info.
fn parse_sdist_filename(filename: &str) -> Option<PackageInfo> {
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

    Some(PackageInfo {
        name: normalize_package_name(dist),
        version: parse_package_version(version),
    })
}

/// Parses a raw version string into a `PackageVersion` enum.
fn parse_package_version(raw: &str) -> PackageVersion {
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
fn version_matches(entry_version: &PackageVersion, req_version: &PackageVersion) -> bool {
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
        let test_cases = vec![
            // (input, expected_name, expected_version)
            (
                "requests-2.31.0-py3-none-any.whl",
                Some(("requests", "2.31.0")),
            ),
            (
                "foo_bar-1.0.0-py2.py3-none-any.whl",
                Some(("foo-bar", "1.0.0")), // Normalized
            ),
            (
                "my_package_name-2.0.0-py3-none-any.whl",
                Some(("my-package-name", "2.0.0")), // Multiple underscores normalized
            ),
            ("pkg-latest-py3-none-any.whl", None),
            // With metadata suffix
            (
                "Django-4.2.0-py3-none-any.whl.metadata",
                Some(("django", "4.2.0")), // Normalized
            ),
            // Real-world: dots in name
            (
                "zope.interface-6.0-cp311-cp311-macosx_10_9_x86_64.whl",
                Some(("zope.interface", "6.0")),
            ),
            // Real-world: numbers in name
            ("boto3-1.28.85-py3-none-any.whl", Some(("boto3", "1.28.85"))),
            // Invalid cases
            ("notawheelfile.tar.gz", None),
            ("package-latest-py3-none-any.whl", None),
            ("package--py3-none-any.whl", None),
        ];

        for (input, expected) in test_cases {
            let result = parse_wheel_filename(input);
            match expected {
                Some((expected_name, expected_version)) => {
                    let info = result.unwrap_or_else(|| panic!("Expected Some for: {}", input));
                    assert_eq!(info.name, expected_name, "Failed for input: {}", input);
                    match &info.version {
                        PackageVersion::Semver(v) => {
                            assert_eq!(
                                v.to_string(),
                                expected_version,
                                "Failed for input: {}",
                                input
                            );
                        }
                        PackageVersion::Unknown(v) => {
                            assert_eq!(v.as_str(), expected_version, "Failed for input: {}", input);
                        }
                        _ => panic!(
                            "Expected Semver or Unknown version for: {}, got {:?}",
                            input, info.version
                        ),
                    }
                }
                None => {
                    assert!(result.is_none(), "Expected None for input: {}", input);
                }
            }
        }
    }

    #[test]
    fn test_parse_sdist_filename() {
        let test_cases = vec![
            // (input, expected_name, expected_version)
            ("requests-2.31.0.tar.gz", Some(("requests", "2.31.0"))),
            ("foo_bar-1.0.0.zip", Some(("foo-bar", "1.0.0"))), // Normalized
            (
                "test_package_with_underscores-3.2.1.tar.gz",
                Some(("test-package-with-underscores", "3.2.1")), // Multiple underscores normalized
            ),
            ("pkg-latest.tar.gz", None),
            // With metadata suffix
            ("numpy-1.24.3.tar.gz.metadata", Some(("numpy", "1.24.3"))),
            // Real-world: multiple hyphens
            (
                "django-rest-framework-3.14.0.tar.gz",
                Some(("django-rest-framework", "3.14.0")),
            ),
            // Prerelease versions
            ("package-1.0.0a1.tar.gz", Some(("package", "1.0.0a1"))),
            ("package-2.0.0rc1.tar.gz", Some(("package", "2.0.0rc1"))),
            (
                "package-3.0.0.post1.tar.gz",
                Some(("package", "3.0.0.post1")),
            ),
            // Alternative formats
            ("package-1.0.0.zip", Some(("package", "1.0.0"))),
            ("package-2.0.0.tar.bz2", Some(("package", "2.0.0"))),
            ("package-3.0.0.tar.xz", Some(("package", "3.0.0"))),
            // Invalid cases
            ("no-extension-1.0.0", None),
            ("package-latest.tar.gz", None),
            ("-1.0.0.tar.gz", None),
        ];

        for (input, expected) in test_cases {
            let result = parse_sdist_filename(input);
            match expected {
                Some((expected_name, expected_version)) => {
                    let info = result.unwrap_or_else(|| panic!("Expected Some for: {}", input));
                    assert_eq!(info.name, expected_name, "Failed for input: {}", input);
                    match &info.version {
                        PackageVersion::Semver(v) => {
                            assert_eq!(
                                v.to_string(),
                                expected_version,
                                "Failed for input: {}",
                                input
                            );
                        }
                        PackageVersion::Unknown(v) => {
                            assert_eq!(v.as_str(), expected_version, "Failed for input: {}", input);
                        }
                        _ => panic!("Expected Semver or Unknown version for: {}", input),
                    }
                }
                None => {
                    assert!(result.is_none(), "Expected None for input: {}", input);
                }
            }
        }
    }

    #[test]
    fn test_normalize_package_name() {
        let test_cases = vec![
            ("Requests", "requests"),
            ("foo_bar", "foo-bar"),
            ("FOO_BAR_BAZ", "foo-bar-baz"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(
                normalize_package_name(input),
                expected,
                "Failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_package_info_is_metadata_request() {
        let metadata_info = PackageInfo {
            name: "requests".to_string(),
            version: PackageVersion::None,
        };
        assert!(metadata_info.is_metadata_request());

        let file_info = PackageInfo {
            name: "requests".to_string(),
            version: PackageVersion::Semver(semver::Version::new(2, 31, 0)),
        };
        assert!(!file_info.is_metadata_request());

        let any_version_info = PackageInfo {
            name: "requests".to_string(),
            version: PackageVersion::Any,
        };
        assert!(!any_version_info.is_metadata_request());
    }

    #[test]
    fn test_package_info_matches() {
        use crate::firewall::malware_list::{MalwareEntry, Reason};

        let package_info = PackageInfo {
            name: "malicious-pkg".to_string(),
            version: PackageVersion::Semver(semver::Version::new(1, 0, 0)),
        };

        // Exact match
        let entry_exact = MalwareEntry {
            version: PackageVersion::Semver(semver::Version::new(1, 0, 0)),
            reason: Reason::Malware,
        };
        assert!(package_info.matches(&entry_exact));

        // No match - different version
        let entry_different = MalwareEntry {
            version: PackageVersion::Semver(semver::Version::new(2, 0, 0)),
            reason: Reason::Malware,
        };
        assert!(!package_info.matches(&entry_different));

        // Match with Any
        let entry_any = MalwareEntry {
            version: PackageVersion::Any,
            reason: Reason::Malware,
        };
        assert!(package_info.matches(&entry_any));
    }

    #[test]
    fn test_extract_package_info() {
        use rama::http::{Body, Request, Uri};

        let test_cases = vec![
            // (uri, expected_name, is_metadata, version_check)
            (
                "https://pypi.org/pypi/requests/json",
                Some(("requests", true, None)),
            ),
            (
                "https://pypi.org/simple/django/",
                Some(("django", true, None)),
            ),
            (
                "https://pypi.org/simple/my_package/",
                Some(("my-package", true, None)), // Normalized
            ),
            (
                "https://files.pythonhosted.org/packages/abc/def/requests-2.31.0-py3-none-any.whl",
                Some(("requests", false, Some("2.31.0"))),
            ),
            (
                "https://files.pythonhosted.org/packages/source/d/django/Django-4.2.0.tar.gz",
                Some(("django", false, Some("4.2.0"))),
            ),
            (
                "https://pypi.org/pypi/my%20package/json",
                Some(("my package", true, None)), // Percent-encoded
            ),
            // Unrecognized URLs
            ("https://pypi.org/", None),
            ("https://pypi.org/help/", None),
        ];

        for (uri, expected) in test_cases {
            let req = Request::builder()
                .uri(Uri::from_static(uri))
                .body(Body::empty())
                .unwrap();

            let result = RulePyPI::extract_package_info(&req);

            match expected {
                Some((expected_name, is_metadata, version_str)) => {
                    let info = result.unwrap_or_else(|| panic!("Expected Some for URI: {}", uri));
                    assert_eq!(info.name, expected_name, "Failed for URI: {}", uri);
                    assert_eq!(
                        info.is_metadata_request(),
                        is_metadata,
                        "Failed metadata check for URI: {}",
                        uri
                    );

                    if let Some(v_str) = version_str {
                        match &info.version {
                            PackageVersion::Semver(v) => {
                                assert_eq!(
                                    v.to_string(),
                                    v_str,
                                    "Failed version check for URI: {}",
                                    uri
                                );
                            }
                            _ => panic!("Expected Semver version for URI: {}", uri),
                        }
                    }
                }
                None => {
                    assert!(result.is_none(), "Expected None for URI: {}", uri);
                }
            }
        }
    }
}
