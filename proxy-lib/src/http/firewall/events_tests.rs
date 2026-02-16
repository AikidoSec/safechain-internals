use std::str::FromStr;

use rama::utils::str::arcstr::arcstr;

use crate::package::version::PackageVersion;

use super::*;

#[test]
fn blocked_event_serializes_with_expected_keys() {
    let event = BlockedEvent {
        ts_ms: 42,
        artifact: BlockedArtifact {
            product: arcstr!("npm"),
            identifier: arcstr!("foo"),
            version: Some(PackageVersion::from_str("1.3.0").unwrap()),
        },
    };

    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["ts_ms"], 42);
    assert_eq!(json["artifact"]["product"], "npm");
    assert_eq!(json["artifact"]["identifier"], "foo");
    assert_eq!(json["artifact"]["version"], "1.3.0");
}

#[test]
fn blocked_event_from_info_sets_timestamp_and_copies_artifact() {
    let event = BlockedEvent::from_info(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: arcstr!("npm"),
            identifier: arcstr!("foo"),
            version: None,
        },
    });

    assert!(event.ts_ms > 0);
    assert_eq!(event.artifact.product.as_ref() as &str, "npm");
    assert_eq!(event.artifact.identifier.as_ref() as &str, "foo");
}
