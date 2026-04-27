use super::parse_package_name_from_path;

#[test]
fn parses_standard_path() {
    assert_eq!(
        parse_package_name_from_path("/p2/league/flysystem-local.json"),
        Some("league/flysystem-local".to_owned())
    );
}

#[test]
fn parses_dev_path() {
    assert_eq!(
        parse_package_name_from_path("/p2/league/flysystem-local~dev.json"),
        Some("league/flysystem-local".to_owned())
    );
}

#[test]
fn lowercases_name() {
    assert_eq!(
        parse_package_name_from_path("/p2/League/Flysystem-Local.json"),
        Some("league/flysystem-local".to_owned())
    );
}

#[test]
fn rejects_missing_p2_prefix() {
    assert!(parse_package_name_from_path("/p/vendor/pkg.json").is_none());
}

#[test]
fn rejects_no_vendor_separator() {
    assert!(parse_package_name_from_path("/p2/vendor.json").is_none());
}

#[test]
fn rejects_too_many_segments() {
    assert!(parse_package_name_from_path("/p2/a/b/c.json").is_none());
}

#[test]
fn rejects_missing_json_suffix() {
    assert!(parse_package_name_from_path("/p2/vendor/pkg").is_none());
}

#[test]
fn rejects_packages_json() {
    assert!(parse_package_name_from_path("/packages.json").is_none());
}
