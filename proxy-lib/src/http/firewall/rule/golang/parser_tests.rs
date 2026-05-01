use crate::package::version::PragmaticSemver;

use super::{parse_module_from_list_path, parse_package_from_path};

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

// --- parse_package_from_path tests (zip downloads) ---

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
    // github.com/%21aikido%21sec → percent-decode → github.com/!aikido!sec
    //   → module-unescape → github.com/AikidoSec → lowercase → github.com/aikidosec
    assert_parsed(
        "github.com/%21aikido%21sec/firewall-go/cmd/zen-go/@v/v1.0.0.zip",
        "github.com/aikidosec/firewall-go/cmd/zen-go",
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

#[test]
fn test_parse_non_github_domain() {
    // Malware entries can use arbitrary domains, not just github.com
    assert_parsed(
        "github.web.gylab.com/mrz1836/go-pandadoc/@v/v1.0.1.zip",
        "github.web.gylab.com/mrz1836/go-pandadoc",
        "1.0.1",
    );
}

// --- parse_module_from_list_path tests ---

#[test]
fn test_parse_list_path() {
    assert_eq!(
        parse_module_from_list_path("github.com/gorilla/mux/@v/list"),
        Some("github.com/gorilla/mux".to_owned())
    );
}

#[test]
fn test_parse_list_path_leading_slash() {
    assert_eq!(
        parse_module_from_list_path("/github.com/gorilla/mux/@v/list"),
        Some("github.com/gorilla/mux".to_owned())
    );
}

#[test]
fn test_parse_list_path_deep_module() {
    assert_eq!(
        parse_module_from_list_path("github.com/aikidosec/firewall-go/cmd/zen-go/@v/list"),
        Some("github.com/aikidosec/firewall-go/cmd/zen-go".to_owned())
    );
}

#[test]
fn test_parse_list_path_percent_encoded() {
    // %21 → !, then lowercased
    assert_eq!(
        parse_module_from_list_path("github.com/%21Aikido/pkg/@v/list"),
        Some("github.com/!aikido/pkg".to_owned())
    );
}

#[test]
fn test_reject_list_path_no_module() {
    assert!(
        parse_module_from_list_path("/@v/list").is_none(),
        "should return None when module path is empty"
    );
}

#[test]
fn test_reject_non_list_path() {
    assert!(
        parse_module_from_list_path("github.com/gorilla/mux/@v/v1.8.0.zip").is_none(),
        "should not parse zip paths as list"
    );
}

#[test]
fn test_reject_list_path_wrong_suffix() {
    assert!(
        parse_module_from_list_path("github.com/gorilla/mux/@v/v1.8.0.mod").is_none(),
        "should not parse non-list paths"
    );
}
