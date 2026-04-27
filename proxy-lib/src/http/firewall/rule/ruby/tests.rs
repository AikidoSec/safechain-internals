use crate::package::version::PragmaticSemver;

use super::parser::{is_gem_download_path, parse_package_from_path};

#[test]
fn test_parse_ruby_package_from_path_happy_paths() {
    fn assert_parsed(path: &str, expected_name: &str, expected_version: &str) {
        let package = parse_package_from_path(path)
            .unwrap_or_else(|| panic!("expected ruby gem to parse: path={path}"));

        assert_eq!(package.fully_qualified_name, expected_name);
        assert_eq!(
            package.version,
            PragmaticSemver::parse(expected_version).unwrap_or_else(|err| panic!(
                "expected version to parse: {expected_version}: {err}"
            )),
        );
    }

    let cases = &[
        ("/gems/rake-13.4.2.gem", "rake", "13.4.2"),
        ("/gems/rake-13.4.1.gem", "rake", "13.4.1"),
        (
            "/gems/activerecord-session_store-2.1.0.gem",
            "activerecord-session_store",
            "2.1.0",
        ),
        (
            "/gems/net-http-persistent-4.0.4.gem",
            "net-http-persistent",
            "4.0.4",
        ),
        ("/gems/rails-7.1.3.2.gem", "rails", "7.1.3.2"),
        ("/gems/Rake-13.4.2.gem", "rake", "13.4.2"),
        // Platform-native gems: the trailing `-<platform>` is stripped so the
        // version matches the malware feed entries, which are keyed on
        // name + version only.
        (
            "/gems/nokogiri-1.16.0-x86_64-linux.gem",
            "nokogiri",
            "1.16.0",
        ),
        (
            "/gems/nokogiri-1.16.0-arm64-darwin.gem",
            "nokogiri",
            "1.16.0",
        ),
        ("/gems/bcrypt-3.1.20-java.gem", "bcrypt", "3.1.20"),
        (
            "/gems/sassc-embedded-1.83.4-arm64-darwin.gem",
            "sassc-embedded",
            "1.83.4",
        ),
        (
            "/gems/libv8-node-23.3.1.553-x86_64-linux.gem",
            "libv8-node",
            "23.3.1.553",
        ),
        ("/gems/grpc-1.63.0-universal-darwin.gem", "grpc", "1.63.0"),
        ("/gems/sqlite3-2.0.0-x64-mingw32.gem", "sqlite3", "2.0.0"),
    ];

    for (path, expected_name, expected_version) in cases {
        assert_parsed(path, expected_name, expected_version);
    }
}

#[test]
fn test_parse_ruby_package_from_path_rejects_non_gem_paths() {
    let cases = &[
        "/quick/Marshal.4.8/rake-13.4.2.gemspec.rz",
        "/api/v1/dependencies?gems=rake",
        "/versions",
        "/info/rake",
        "/specs.4.8.gz",
        "/gems/",
        "/gems/rake.gem",
        "/gems/broken.gem",
        "/gems/no-version-here.gem",
        "/gems/-1.0.0.gem",
        "",
    ];

    for path in cases {
        assert!(
            parse_package_from_path(path).is_none(),
            "expected path to NOT parse as a ruby gem: {path}"
        );
    }
}

#[test]
fn test_is_gem_download_path() {
    assert!(is_gem_download_path("/gems/rake-13.4.2.gem"));
    assert!(is_gem_download_path("/gems/net-http-persistent-4.0.4.gem"));

    assert!(!is_gem_download_path(
        "/quick/Marshal.4.8/rake-13.4.2.gemspec.rz"
    ));
    assert!(!is_gem_download_path("/api/v1/dependencies"));
    assert!(!is_gem_download_path("/gems/rake-13.4.2.gem.sig"));
    assert!(!is_gem_download_path("/other/rake-13.4.2.gem"));
    assert!(!is_gem_download_path(""));
}
