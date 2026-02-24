use super::*;
use crate::utils::io::tmp_dir;
use std::fs;

#[test]
fn test_try_parse_valid() {
    let token = PermissionToken::try_parse("some-valid-test-token").unwrap();
    assert_eq!(token.as_str(), "some-valid-test-token");
}

#[test]
fn test_try_parse_trims_whitespace() {
    let token = PermissionToken::try_parse("  some-valid-test-token  \n").unwrap();
    assert_eq!(token.as_str(), "some-valid-test-token");
}

#[test]
fn test_try_parse_empty() {
    assert!(PermissionToken::try_parse("").is_err());
    assert!(PermissionToken::try_parse("   \n  ").is_err());
}

#[test]
fn test_try_parse_control_chars() {
    assert!(PermissionToken::try_parse("abc\x00def123456").is_err());
    assert!(PermissionToken::try_parse("abc\ndef_12345678").is_err());
}

#[test]
fn test_try_parse_non_ascii() {
    assert!(PermissionToken::try_parse("tökén_12345678").is_err());
}

#[test]
fn test_load_from_path_success() {
    let dir = tmp_dir::try_new("test_load_token_success").unwrap();
    let token_path = dir.join(".token");

    fs::write(&token_path, "some-valid-test-token").unwrap();

    let result = try_load_from_path(&token_path);
    assert_eq!(result.unwrap().as_str(), "some-valid-test-token");
}

#[test]
fn test_load_from_path_not_exists() {
    let dir = tmp_dir::try_new("test_load_token_not_exists").unwrap();
    let token_path = dir.join(".token");

    assert!(try_load_from_path(&token_path).is_none());
}

#[test]
fn test_load_from_path_empty_file() {
    let dir = tmp_dir::try_new("test_load_token_empty").unwrap();
    let token_path = dir.join(".token");

    fs::write(&token_path, "  \n  ").unwrap();

    assert!(try_load_from_path(&token_path).is_none());
}

#[test]
fn test_load_from_path_too_large() {
    let dir = tmp_dir::try_new("test_load_token_too_large").unwrap();
    let token_path = dir.join(".token");

    let large_token = "a".repeat(2 * 1024);
    fs::write(&token_path, large_token).unwrap();

    assert!(try_load_from_path(&token_path).is_none());
}
