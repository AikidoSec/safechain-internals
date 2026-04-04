use crate::utils::time::{SystemDuration, SystemTimestampMilliseconds};

use super::*;

#[test]
fn test_parse_fetch_permissions_payload() {
    let json = r#"{
        "permission_group": {
            "id": 123,
            "name": "Development"
        },
        "ecosystems": {
            "pypi": {
                "block_all_installs": false,
                "request_installs": true,
                "minimum_allowed_age_timestamp": 1740172800,
                "exceptions": {
                    "allowed_packages": ["requests", "numpy"],
                    "rejected_packages": ["evil-package"]
                }
            }
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.permission_group.id, 123);
    assert_eq!(config.permission_group.name.as_str(), "Development");

    let pypi = config
        .ecosystems
        .get(&EcosystemKey::from_static("pypi"))
        .unwrap();
    assert!(!pypi.block_all_installs);
    assert!(pypi.request_installs);
    assert_eq!(
        pypi.minimum_allowed_age_timestamp,
        Some(SystemTimestampMilliseconds::EPOCH + SystemDuration::seconds(1740172800))
    );
    assert_eq!(pypi.exceptions.allowed_packages.len(), 2);
    assert_eq!(pypi.exceptions.rejected_packages.len(), 1);
}

#[test]
fn test_parse_fetch_permissions_defaults() {
    let json = r#"{
        "permission_group": {
            "id": 42,
            "name": "Sales"
        },
        "ecosystems": {
            "npm": {}
        }
    }"#;

    let config: EndpointConfig = serde_json::from_str(json).unwrap();
    let npm = config
        .ecosystems
        .get(&EcosystemKey::from_static("npm"))
        .unwrap();

    assert!(!npm.block_all_installs);
    assert!(!npm.request_installs);
    assert_eq!(npm.minimum_allowed_age_timestamp, None);
    assert!(npm.exceptions.allowed_packages.is_empty());
    assert!(npm.exceptions.rejected_packages.is_empty());
}

#[test]
fn test_parse_fetch_permissions_timestamp_true_is_invalid() {
    let json = r#"{
        "permission_group": {
            "id": 1,
            "name": "Default"
        },
        "ecosystems": {
            "maven": {
                "minimum_allowed_age_timestamp": true
            }
        }
    }"#;

    let err = serde_json::from_str::<EndpointConfig>(json).unwrap_err();
    assert!(err.to_string().contains("invalid type: boolean `true`"));
}

#[test]
fn test_parse_fetch_permissions_timestamp_false_is_invalid() {
    let json = r#"{
        "permission_group": {
            "id": 1,
            "name": "Default"
        },
        "ecosystems": {
            "maven": {
                "minimum_allowed_age_timestamp": false
            }
        }
    }"#;

    let err = serde_json::from_str::<EndpointConfig>(json).unwrap_err();
    assert!(err.to_string().contains("invalid type: boolean `false`"));
}
