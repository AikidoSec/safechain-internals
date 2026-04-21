use crate::package::version::PragmaticSemver;

use super::parse_package_from_path;

fn assert_parsed(path: &str, expected_name: &str, expected_version: &str) {
    let pkg = parse_package_from_path(path)
        .unwrap_or_else(|| panic!("expected package to parse: {path}"));
    assert_eq!(pkg.fully_qualified_name, expected_name, "path: {path}");
    assert_eq!(
        pkg.version,
        PragmaticSemver::parse(expected_version).unwrap(),
        "path: {path}"
    );
}

#[test]
fn test_parse_simple_module() {
    assert_parsed(
        "github.com/gorilla/mux/@v/v1.8.0.zip",
        "github.com/gorilla/mux",
        "1.8.0",
    );
}

#[test]
fn test_parse_with_leading_slash() {
    assert_parsed(
        "/github.com/gorilla/mux/@v/v1.8.0.zip",
        "github.com/gorilla/mux",
        "1.8.0",
    );
}

#[test]
fn test_parse_deep_module_path() {
    assert_parsed(
        "github.com/aikidosec/firewall-go/cmd/zen-go/@v/v1.0.0.zip",
        "github.com/aikidosec/firewall-go/cmd/zen-go",
        "1.0.0",
    );
}

#[test]
fn test_parse_percent_encoded_uppercase() {
    // %21 is !, and !x encodes uppercase X in Go's module proxy protocol
    // github.com/%21aikido%21sec/firewall-go → github.com/!aikido!sec/firewall-go → lowercase
    assert_parsed(
        "github.com/%21aikido%21sec/firewall-go/cmd/zen-go/@v/v1.0.0.zip",
        "github.com/!aikido!sec/firewall-go/cmd/zen-go",
        "1.0.0",
    );
}

#[test]
fn test_parse_golang_org_module() {
    assert_parsed(
        "golang.org/x/sys/@v/v0.15.0.zip",
        "golang.org/x/sys",
        "0.15.0",
    );
}

#[test]
fn test_parse_prerelease_version() {
    assert_parsed(
        "github.com/foo/bar/@v/v1.0.0-alpha.1.zip",
        "github.com/foo/bar",
        "1.0.0-alpha.1",
    );
}

#[test]
fn test_reject_mod_file() {
    assert!(
        parse_package_from_path("github.com/gorilla/mux/@v/v1.8.0.mod").is_none(),
        "should not parse .mod files"
    );
}

#[test]
fn test_reject_info_file() {
    assert!(
        parse_package_from_path("github.com/gorilla/mux/@v/v1.8.0.info").is_none(),
        "should not parse .info files"
    );
}

#[test]
fn test_reject_list_endpoint() {
    assert!(
        parse_package_from_path("github.com/gorilla/mux/@v/list").is_none(),
        "should not parse /@v/list"
    );
}

#[test]
fn test_reject_no_at_v_segment() {
    assert!(
        parse_package_from_path("github.com/gorilla/mux/v1.8.0.zip").is_none(),
        "should not parse paths without /@v/"
    );
}

#[test]
fn test_parse_pseudo_version() {
    // Pseudo-versions are used for commits not tagged with a semver
    assert_parsed(
        "github.com/some/pkg/@v/v0.0.0-20231215000000-abc1234def56.zip",
        "github.com/some/pkg",
        "0.0.0-20231215000000-abc1234def56",
    );
}
