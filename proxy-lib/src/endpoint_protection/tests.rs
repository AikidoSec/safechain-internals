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
                "request_installs": true,
                "minimum_allowed_age_value": 7,
                "minimum_allowed_age_unit": "days",
                "exceptions": [
                    {
                        "exception_type": "block_specified_installs",
                        "permission_group_ids": [123, 456],
                        "related_packages": ["evil-package", "malicious-lib"]
                    },
                    {
                        "exception_type": "allow_specified_installs",
                        "permission_group_ids": [123],
                        "related_packages": ["lodash", "express"]
                    }
                ]
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
    assert!(npm_config.request_installs);
    assert_eq!(npm_config.minimum_allowed_age_value, Some(7));
    assert_eq!(npm_config.minimum_allowed_age_unit.as_deref(), Some("days"));
    assert_eq!(npm_config.exceptions.len(), 2);
    assert_eq!(
        npm_config.exceptions[0].exception_type.as_str(),
        "block_specified_installs"
    );
    assert_eq!(npm_config.exceptions[0].related_packages.len(), 2);
    assert_eq!(
        npm_config.exceptions[1].exception_type.as_str(),
        "allow_specified_installs"
    );
    assert_eq!(npm_config.exceptions[1].related_packages.len(), 2);
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
                "request_installs": false,
                "exceptions": [
                    {
                        "exception_type": "block_specified_installs",
                        "related_packages": ["malicious-lib"]
                    }
                ]
            }
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.version.as_str(), "1.0.0");
    assert_eq!(config.permission_group_id, 456);

    let pypi_config = config.ecosystems.get("pypi").unwrap();
    assert!(pypi_config.enabled);
    assert_eq!(pypi_config.minimum_allowed_age_value, None);
    assert_eq!(pypi_config.minimum_allowed_age_unit, None);
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
    assert!(!maven_config.request_installs);
    assert_eq!(maven_config.minimum_allowed_age_value, None);
    assert_eq!(maven_config.minimum_allowed_age_unit, None);
    assert!(maven_config.exceptions.is_empty());
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

#[test]
fn test_parse_exception_with_permission_groups() {
    let json = r#"{
        "version": "1.0.0",
        "permission_group_id": 100,
        "permission_group_name": "Sales",
        "ecosystems": {
            "npm": {
                "exceptions": [
                    {
                        "exception_type": "block_all_installs",
                        "permission_group_ids": [100, 200, 300]
                    },
                    {
                        "exception_type": "request_installs",
                        "permission_group_ids": [100]
                    }
                ]
            }
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();
    let npm_config = config.ecosystems.get("npm").unwrap();

    assert_eq!(npm_config.exceptions.len(), 2);
    assert_eq!(
        npm_config.exceptions[0].exception_type.as_str(),
        "block_all_installs"
    );
    assert_eq!(
        npm_config.exceptions[0].permission_group_ids,
        vec![100, 200, 300]
    );
    assert!(npm_config.exceptions[0].related_packages.is_empty());
    assert_eq!(
        npm_config.exceptions[1].exception_type.as_str(),
        "request_installs"
    );
    assert_eq!(npm_config.exceptions[1].permission_group_ids, vec![100]);
}
