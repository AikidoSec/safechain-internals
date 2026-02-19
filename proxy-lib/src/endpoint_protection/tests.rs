use super::*;

#[test]
fn test_parse_endpoint_config_npm() {
    let json = r#"{
        "version": "1.0.0",
        "updated_at": "2026-02-19T10:30:00Z",
        "permission_group_id": 123,
        "permission_group_name": "Development",
        "ecosystems": {
            "npm": {
                "enabled": true,
                "block_all_installs": false,
                "force_requests_for_new_packages": true,
                "exceptions": {
                    "blocked_packages": ["evil-package", "malicious-lib"],
                    "allowed_packages": ["lodash", "express"]
                }
            }
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.version.as_str(), "1.0.0");
    assert_eq!(config.permission_group_id, 123);
    assert_eq!(config.permission_group_name.as_str(), "Development");

    let npm_config = config.ecosystems.get("npm").unwrap();
    assert!(npm_config.enabled);
    assert!(!npm_config.block_all_installs);
    assert!(npm_config.force_requests_for_new_packages);
    assert_eq!(npm_config.exceptions.blocked_packages.len(), 2);
    assert_eq!(npm_config.exceptions.allowed_packages.len(), 2);
}

#[test]
fn test_parse_endpoint_config_pypi_minimal() {
    let json = r#"{
        "version": "1.0.0",
        "permission_group_id": 456,
        "permission_group_name": "Admin",
        "ecosystems": {
            "pypi": {
                "enabled": true,
                "block_all_installs": false,
                "force_requests_for_new_packages": false,
                "exceptions": {
                    "blocked_packages": ["malicious-lib"],
                    "allowed_packages": ["numpy", "pandas"]
                }
            }
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.version.as_str(), "1.0.0");
    assert_eq!(config.permission_group_id, 456);

    let pypi_config = config.ecosystems.get("pypi").unwrap();
    assert!(pypi_config.enabled);
}

#[test]
fn test_parse_endpoint_config_defaults() {
    let json = r#"{
        "version": "1.0.0",
        "permission_group_id": 789,
        "permission_group_name": "Test",
        "ecosystems": {
            "maven": {}
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();

    let maven_config = config.ecosystems.get("maven").unwrap();
    assert!(maven_config.enabled);
    assert!(!maven_config.block_all_installs);
    assert!(!maven_config.force_requests_for_new_packages);
    assert!(maven_config.exceptions.blocked_packages.is_empty());
    assert!(maven_config.exceptions.allowed_packages.is_empty());
}

#[test]
fn test_empty_ecosystems() {
    let json = r#"{
        "version": "1.0.0",
        "permission_group_id": 999,
        "permission_group_name": "Empty"
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();
    assert!(config.ecosystems.is_empty());
}
