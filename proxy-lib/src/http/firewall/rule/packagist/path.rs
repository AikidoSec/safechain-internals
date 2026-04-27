/// Extract the vendor/package name from a Packagist v2 metadata path.
///
/// Recognises `/p2/vendor/package.json` and `/p2/vendor/package~dev.json`.
/// Returns the name lowercased, e.g. `"league/flysystem-local"`.
pub(super) fn parse_package_name_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/p2/")?;
    let rest = rest
        .strip_suffix("~dev.json")
        .or_else(|| rest.strip_suffix(".json"))?;
    // Must be exactly "vendor/package" (one slash, two non-empty segments).
    (rest.matches('/').count() == 1 && !rest.starts_with('/') && !rest.ends_with('/'))
        .then(|| rest.to_ascii_lowercase())
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
