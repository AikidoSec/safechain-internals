use super::*;
use crate::utils::io::tmp_dir;
use std::fs;

#[test]
fn test_load_full_config() {
    let dir = tmp_dir::try_new("test_load_full_config").unwrap();
    let config_path = dir.join("config.json");

    fs::write(
        &config_path,
        r#"{"token":"some-valid-test-token","device_id":"abc123"}"#,
    )
    .unwrap();

    let result = AgentIdentity::try_load_from_path(&config_path).unwrap();
    assert_eq!(result.token.unwrap().as_str(), "some-valid-test-token");
    assert_eq!(result.device_id.unwrap().as_str(), "abc123");
}

#[test]
fn test_load_partial_config() {
    let dir = tmp_dir::try_new("test_load_partial_config").unwrap();
    let config_path = dir.join("config.json");

    fs::write(&config_path, r#"{"token":"some-valid-test-token"}"#).unwrap();

    let result = AgentIdentity::try_load_from_path(&config_path).unwrap();
    assert_eq!(result.token.unwrap().as_str(), "some-valid-test-token");
    assert!(result.device_id.is_none());
}

#[test]
fn test_file_not_found() {
    let dir = tmp_dir::try_new("test_file_not_found").unwrap();
    assert!(AgentIdentity::try_load_from_path(&dir.join("config.json")).is_none());
}

#[test]
fn test_invalid_json() {
    let dir = tmp_dir::try_new("test_invalid_json").unwrap();
    let config_path = dir.join("config.json");

    fs::write(&config_path, "not-valid-json").unwrap();

    assert!(AgentIdentity::try_load_from_path(&config_path).is_none());
}

#[test]
fn test_file_too_large() {
    let dir = tmp_dir::try_new("test_file_too_large").unwrap();
    let config_path = dir.join("config.json");

    fs::write(&config_path, "a".repeat(4097)).unwrap();

    assert!(AgentIdentity::try_load_from_path(&config_path).is_none());
}

#[test]
fn test_whitespace_handling() {
    let dir = tmp_dir::try_new("test_whitespace_handling").unwrap();
    let config_path = dir.join("config.json");

    fs::write(
        &config_path,
        r#"{"token":"  some-valid-test-token  ","device_id":"   "}"#,
    )
    .unwrap();

    let result = AgentIdentity::try_load_from_path(&config_path).unwrap();
    assert_eq!(result.token.unwrap().as_str(), "some-valid-test-token");
    assert!(result.device_id.is_none());
}
