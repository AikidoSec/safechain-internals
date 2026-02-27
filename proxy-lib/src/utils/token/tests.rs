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
    assert_eq!(result.token, "some-valid-test-token");
    assert_eq!(result.device_id, "abc123");
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
fn test_size_limit_boundary() {
    let dir = tmp_dir::try_new("test_size_limit_boundary").unwrap();
    let config_path = dir.join("config.json");

    let prefix = r#"{"token":""#;
    let mid = r#"","device_id":"x"}"#;
    let fill_len = 4096usize - prefix.len() - mid.len();
    let content = format!("{prefix}{}{mid}", "a".repeat(fill_len));
    assert_eq!(content.len(), 4096);
    fs::write(&config_path, content).unwrap();

    let result = AgentIdentity::try_load_from_path(&config_path).unwrap();
    assert_eq!(result.token.len(), fill_len);
    assert_eq!(result.device_id, "x");
}

#[test]
fn test_incomplete_identity_is_rejected() {
    let dir = tmp_dir::try_new("test_incomplete_identity").unwrap();
    let config_path = dir.join("config.json");

    fs::write(&config_path, r#"{"token":"some-valid-test-token"}"#).unwrap();

    assert!(AgentIdentity::try_load_from_path(&config_path).is_none());
}
