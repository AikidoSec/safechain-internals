use std::{borrow::Cow, fmt, str::FromStr};

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    graceful::ShutdownGuard,
    http::{Request, Response, Uri},
    net::{address::Domain, uri::util::percent_encoding},
    telemetry::tracing,
    utils::{
        collections::smallvec::SmallVec,
        str::smol_str::{SmolStr, StrExt},
    },
};

use rama::utils::str::arcstr::{ArcStr, arcstr};

use crate::{
    http::{
        firewall::{
            domain_matcher::DomainMatcher,
            events::{BlockedArtifact, BlockedEventInfo},
        },
        response::generate_generic_blocked_response_for_req,
    },
    package::{
        malware_list::{LowerCaseEntryFormatter, MalwareEntry, RemoteMalwareList},
        version::PackageVersion,
    },
    storage::SyncCompactDataStorage,
};

#[cfg(feature = "pac")]
use crate::http::firewall::pac::PacScriptGenerator;

use super::{BlockedRequest, RequestAction, Rule};

struct PackageInfo {
    name: SmolStr,
    version: PackageVersion,
}

impl PackageInfo {
    fn is_metadata_request(&self) -> bool {
        matches!(self.version, PackageVersion::None)
    }

    fn matches(&self, entry: &MalwareEntry) -> bool {
        entry.version == self.version
    }
}

pub(in crate::http::firewall) struct RulePyPI {
    target_domains: DomainMatcher,
    remote_malware_list: RemoteMalwareList,
}

impl RulePyPI {
    pub(in crate::http::firewall) async fn try_new<C>(
        guard: ShutdownGuard,
        remote_malware_list_https_client: C,
        sync_storage: SyncCompactDataStorage,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = BoxError>,
    {
        let remote_malware_list = RemoteMalwareList::try_new(
            guard,
            Uri::from_static("https://malware-list.aikido.dev/malware_pypi.json"),
            sync_storage,
            remote_malware_list_https_client,
            LowerCaseEntryFormatter,
        )
        .await
        .context("create remote malware list for pypi block rule")?;

        let target_domains = ["pypi.org", "files.pythonhosted.org", "pypi.python.org"]
            .into_iter()
            .collect();

        Ok(Self {
            target_domains,
            remote_malware_list,
        })
    }

    fn is_blocked(&self, package_info: &PackageInfo) -> Result<bool, BoxError> {
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

        let segments: SmallVec<[_; 3]> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_decode)
            .collect();

        if segments.len() == 3 && segments[0] == "pypi" && segments[2] == "json" {
            return Some(PackageInfo {
                name: normalize_package_name(&segments[1]),
                version: PackageVersion::None,
            });
        }

        if segments.len() >= 2 && segments[0] == "simple" {
            return Some(PackageInfo {
                name: normalize_package_name(&segments[1]),
                version: PackageVersion::None,
            });
        }

        if let Some(filename) = segments.last() {
            return parse_wheel_filename(filename).or_else(|| parse_source_dist_filename(filename));
        }

        None
    }
}

fn normalize_package_name(raw: &str) -> SmolStr {
    raw.to_lowercase_smolstr().replace_smolstr("_", "-")
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
        self.target_domains.is_match(domain)
    }

    #[cfg(feature = "pac")]
    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for domain in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, BoxError> {
        // Pass through for now - response modification can be added in future PR
        Ok(resp)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, BoxError> {
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

            return Ok(RequestAction::Block(BlockedRequest {
                response: generate_generic_blocked_response_for_req(req),
                info: BlockedEventInfo {
                    artifact: BlockedArtifact {
                        product: arcstr!("pypi"),
                        identifier: ArcStr::from(package_info.name.as_str()),
                        version: Some(package_info.version.clone()),
                    },
                },
            }));
        }

        Ok(RequestAction::Allow(req))
    }
}

fn percent_decode(input: &str) -> Cow<'_, str> {
    percent_encoding::percent_decode_str(input).decode_utf8_lossy()
}

/// Parse wheel filename.
///
/// Wheel format: {distribution}-{version}(-...tags).whl
/// Examples:
///   foo_bar-2.0.0-py3-none-any.whl
///   foo_bar-2.0.0-py3-none-any.whl.metadata
fn parse_wheel_filename(filename: &str) -> Option<PackageInfo> {
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
fn parse_source_dist_filename(filename: &str) -> Option<PackageInfo> {
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

#[cfg(test)]
mod tests {
    use crate::package::version::PragmaticSemver;

    use super::*;

    #[test]
    fn test_parse_wheel_filename() {
        let test_cases = vec![
            // (input, expected_name, expected_version)
            // Basic cases
            (
                "requests-2.31.0-py3-none-any.whl",
                Some(("requests", PragmaticSemver::new_two_components(2, 31))),
            ),
            (
                "Django-4.2.0-py3-none-any.whl",
                Some(("django", PragmaticSemver::new_two_components(4, 2))),
            ),
            (
                "boto3-1.28.85-py3-none-any.whl",
                Some(("boto3", PragmaticSemver::new_semver(1, 28, 85))),
            ),
            // Package names with hyphens (wheels use underscores per PEP 427)
            (
                "safe_chain_pi_test-0.1.0-py3-none-any.whl",
                Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
            ),
            (
                "pip_tools-6.12.0-py3-none-any.whl",
                Some(("pip-tools", PragmaticSemver::new_two_components(6, 12))),
            ),
            // Package names with underscores (normalized to hyphens)
            (
                "foo_bar-1.0.0-py2.py3-none-any.whl",
                Some(("foo-bar", PragmaticSemver::new_single(1))),
            ),
            (
                "my_package_name-2.0.0-py3-none-any.whl",
                Some(("my-package-name", PragmaticSemver::new_single(2))),
            ),
            (
                "safe_chain_pi_test-0.1.0-py3-none-any.whl",
                Some((
                    "safe-chain-pi-test",
                    PragmaticSemver::new_two_components(0, 1),
                )),
            ),
            // Package names with dots
            (
                "zope.interface-6.0-cp311-cp311-macosx_10_9_x86_64.whl",
                Some(("zope.interface", PragmaticSemver::new_single(6))),
            ),
            (
                "backports.zoneinfo-0.2.1-cp36-cp36m-win_amd64.whl",
                Some(("backports.zoneinfo", PragmaticSemver::new_semver(0, 2, 1))),
            ),
            // WITH BUILD TAG (per PEP 427/491)
            (
                "distribution-1.0-1-py27-none-any.whl",
                Some(("distribution", PragmaticSemver::new_single(1))),
            ),
            (
                "package-2.0-123-py3-none-any.whl",
                Some(("package", PragmaticSemver::new_single(2))),
            ),
            // Platform-specific wheels
            (
                "numpy-1.24.0-cp311-cp311-macosx_10_9_x86_64.whl",
                Some(("numpy", PragmaticSemver::new_semver(1, 24, 0))),
            ),
            (
                "Pillow-10.0.0-cp311-cp311-win_amd64.whl",
                Some(("pillow", PragmaticSemver::new_single(10))),
            ),
            // With metadata suffix
            (
                "Django-4.2.0-py3-none-any.whl.metadata",
                Some(("django", PragmaticSemver::new_semver(4, 2, 0))),
            ),
            // Multiple python versions
            (
                "six-1.16.0-py2.py3-none-any.whl",
                Some(("six", PragmaticSemver::new_semver(1, 16, 0))),
            ),
            // ABI3 stable ABI
            (
                "cryptography-41.0.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                Some(("cryptography", PragmaticSemver::new_single(41))),
            ),
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
                    assert_eq!(
                        info.version, expected_version,
                        "Failed for input: {}",
                        input
                    );
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
            // Basic tar.gz (most common)
            (
                "requests-2.31.0.tar.gz",
                Some(("requests", PragmaticSemver::new_semver(2, 31, 0))),
            ),
            (
                "Django-4.2.0.tar.gz",
                Some(("django", PragmaticSemver::new_semver(4, 2, 0))),
            ),
            (
                "numpy-1.24.0.tar.gz",
                Some(("numpy", PragmaticSemver::new_semver(1, 24, 0))),
            ),
            // Other compression formats
            (
                "package-1.0.0.zip",
                Some(("package", PragmaticSemver::new_semver(1, 0, 0))),
            ),
            (
                "package-2.0.0.tar.bz2",
                Some(("package", PragmaticSemver::new_semver(2, 0, 0))),
            ),
            (
                "package-3.0.0.tar.xz",
                Some(("package", PragmaticSemver::new_semver(3, 0, 0))),
            ),
            // Package names with hyphens
            (
                "pip-tools-6.12.0.tar.gz",
                Some(("pip-tools", PragmaticSemver::new_semver(6, 12, 0))),
            ),
            (
                "safe-chain-pi-test-0.1.0.tar.gz",
                Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
            ),
            (
                "django-rest-framework-3.14.0.tar.gz",
                Some((
                    "django-rest-framework",
                    PragmaticSemver::new_semver(3, 14, 0),
                )),
            ),
            // Package names with underscores (normalized to hyphens)
            (
                "foo_bar-1.0.0.zip",
                Some(("foo-bar", PragmaticSemver::new_semver(1, 0, 0))),
            ),
            (
                "safe_chain_pi_test-0.1.0.tar.gz",
                Some(("safe-chain-pi-test", PragmaticSemver::new_semver(0, 1, 0))),
            ),
            (
                "test_package_with_underscores-3.2.1.tar.gz",
                Some((
                    "test-package-with-underscores",
                    PragmaticSemver::new_semver(3, 2, 1),
                )),
            ),
            // Package names with dots
            (
                "zope.interface-6.0.tar.gz",
                Some(("zope.interface", PragmaticSemver::new_two_components(6, 0))),
            ),
            (
                "backports.zoneinfo-0.2.1.tar.gz",
                Some(("backports.zoneinfo", PragmaticSemver::new_semver(0, 2, 1))),
            ),
            // Prerelease versions
            (
                "package-1.0.0a1.tar.gz",
                Some((
                    "package",
                    PragmaticSemver::new_semver(1, 0, 0).with_pre("a1"),
                )),
            ),
            (
                "package-2.0.0rc1.tar.gz",
                Some((
                    "package",
                    PragmaticSemver::new_semver(2, 0, 0).with_pre("rc1"),
                )),
            ),
            (
                "package-3.0.0.post1.tar.gz",
                Some((
                    "package",
                    PragmaticSemver::new_semver(3, 0, 0).with_pre("post1"),
                )),
            ),
            // With metadata suffix
            (
                "numpy-1.24.3.tar.gz.metadata",
                Some(("numpy", PragmaticSemver::new_semver(1, 24, 3))),
            ),
            // Invalid cases
            ("pkg-latest.tar.gz", None),
            ("package-latest.tar.gz", None),
            ("no-extension-1.0.0", None),
            ("-1.0.0.tar.gz", None),
            ("notasdist.whl", None),
            ("package-1.0.0.txt", None),
            // Unsupported formats (should return None)
            ("package-4.0.0.tar.zst", None),
            ("setuptools-68.0.0.egg", None),
        ];

        for (input, expected) in test_cases {
            let result = parse_source_dist_filename(input);
            match expected {
                Some((expected_name, expected_version)) => {
                    let info = result.unwrap_or_else(|| panic!("Expected Some for: {}", input));
                    assert_eq!(info.name, expected_name, "Failed for input: {}", input);
                    assert_eq!(
                        info.version, expected_version,
                        "Failed for input: {}",
                        input
                    );
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
            name: SmolStr::from("requests"),
            version: PackageVersion::None,
        };
        assert!(metadata_info.is_metadata_request());

        let file_info = PackageInfo {
            name: SmolStr::from("requests"),
            version: PackageVersion::Semver(PragmaticSemver::new_semver(2, 31, 0)),
        };
        assert!(!file_info.is_metadata_request());

        let any_version_info = PackageInfo {
            name: SmolStr::from("requests"),
            version: PackageVersion::Any,
        };
        assert!(!any_version_info.is_metadata_request());
    }

    #[test]
    fn test_package_info_matches() {
        use crate::package::malware_list::{MalwareEntry, Reason};

        let package_info = PackageInfo {
            name: SmolStr::from("malicious-pkg"),
            version: PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0)),
        };

        // Exact match
        let entry_exact = MalwareEntry {
            version: PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0)),
            reason: Reason::Malware,
        };
        assert!(package_info.matches(&entry_exact));

        // No match - different version
        let entry_different = MalwareEntry {
            version: PackageVersion::Semver(PragmaticSemver::new_semver(2, 0, 0)),
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
                Some((
                    "requests",
                    false,
                    Some(PragmaticSemver::new_semver(2, 31, 0)),
                )),
            ),
            (
                "https://files.pythonhosted.org/packages/source/d/django/Django-4.2.0.tar.gz",
                Some(("django", false, Some(PragmaticSemver::new_semver(4, 2, 0)))),
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
                Some((expected_name, is_metadata, maybe_semver)) => {
                    let info = result.unwrap_or_else(|| panic!("Expected Some for URI: {}", uri));
                    assert_eq!(info.name, expected_name, "Failed for URI: {}", uri);
                    assert_eq!(
                        info.version.clone(),
                        match maybe_semver {
                            Some(semver) => PackageVersion::Semver(semver),
                            None => PackageVersion::None,
                        },
                        "Failed for URI: {}",
                        uri
                    );
                    assert_eq!(
                        info.is_metadata_request(),
                        is_metadata,
                        "Failed metadata check for URI: {}",
                        uri
                    );
                }
                None => {
                    assert!(result.is_none(), "Expected None for URI: {}", uri);
                }
            }
        }
    }
}
