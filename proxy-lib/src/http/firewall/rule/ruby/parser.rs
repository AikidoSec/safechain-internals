//! URL parsing for the RubyGems firewall rule.
//!
//! RubyGems serves `.gem` tarballs at `/gems/<name>-<version>[-<platform>].gem`.
//! The filename encodes three things joined by `-`:
//!
//! - the gem name, which may itself contain hyphens (e.g. `net-http-persistent`)
//! - the version, which in modern RubyGems is always a dotted run of digits
//!   optionally followed by a dotted pre-release tag (`1.2.3`, `1.0.0.rc1`)
//! - an optional platform suffix for native gems (`x86_64-linux`, `arm64-darwin`,
//!   `java`, `universal-darwin`, `x64-mingw32`, …)
//!
//! The malware feed is keyed on name + version only, so this module's job is to
//! recover those two parts and drop any platform suffix.

use rama::telemetry::tracing;

use crate::package::version::PragmaticSemver;

/// A parsed RubyGems gem filename, with the package name normalized to the
/// lowercase form used by the malware feed.
#[derive(Debug)]
pub(super) struct RubyPackage {
    pub(super) fully_qualified_name: String,
    pub(super) version: PragmaticSemver,
}

impl RubyPackage {
    fn new(name: &str, version: PragmaticSemver) -> Self {
        Self {
            fully_qualified_name: name.trim().to_ascii_lowercase(),
            version,
        }
    }
}

impl std::fmt::Display for RubyPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.fully_qualified_name, self.version)
    }
}

/// Returns `true` iff the path looks like a `.gem` tarball download and is
/// therefore worth parsing. Everything else (metadata, compact index, `/api/*`,
/// `/versions`, `.gemspec.rz`, …) must pass through unmodified.
#[inline]
pub(super) fn is_gem_download_path(path: &str) -> bool {
    path.starts_with("/gems/") && path.ends_with(".gem")
}

/// Parses a RubyGems gem download path into a normalized [`RubyPackage`].
///
/// Returns [`None`] for any path that is not a well-formed
/// `/gems/<name>-<version>[-<platform>].gem`. In particular, this deliberately
/// ignores everything outside `/gems/`, so the caller can safely pass any path
/// it already confirmed via [`is_gem_download_path`].
pub(super) fn parse_package_from_path(path: &str) -> Option<RubyPackage> {
    let stem = path
        .trim_start_matches('/')
        .strip_prefix("gems/")?
        .strip_suffix(".gem")?;

    find_name_and_version(stem).map(|(name, version)| RubyPackage::new(name, version))
}

/// Locates the `{name}-{version}` split inside a gem filename stem (the part
/// with `/gems/` and `.gem` already stripped), discarding any trailing
/// `-{platform}` segment.
///
/// The scan runs left-to-right and stops at the first `-` whose dotted run
/// parses as a [`PragmaticSemver`]:
///
/// 1. The `-` must be followed by an ASCII digit — Ruby versions always start
///    with one.
/// 2. The candidate version is taken from that digit up to the next `-`
///    (or end of stem). Any tail past that next `-` is the platform suffix
///    and is discarded; the malware feed doesn't key on platform.
/// 3. The candidate must contain at least one `.`. Ruby gem versions are
///    always dotted, so this rules out a stray numeric segment that happens
///    to live inside a gem name (e.g. `lib-1-foo-2.3.4` → name=`lib-1-foo`,
///    version=`2.3.4`, *not* name=`lib`, version=`1`).
/// 4. The candidate must parse as a [`PragmaticSemver`].
fn find_name_and_version(stem: &str) -> Option<(&str, PragmaticSemver)> {
    for (idx, _) in stem.match_indices('-') {
        let name = &stem[..idx];
        if name.is_empty() {
            continue;
        }

        let after = &stem[idx + 1..];
        if !after.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }

        let version_str = match after.find('-') {
            Some(end) => &after[..end],
            None => after,
        };
        if !version_str.contains('.') {
            continue;
        }

        let version = match PragmaticSemver::parse(version_str) {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    gem.name = %name,
                    gem.version_raw = %version_str,
                    %err,
                    "failed to parse ruby gem version"
                );
                continue;
            }
        };

        return Some((name, version));
    }

    None
}
