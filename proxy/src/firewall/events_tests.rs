use super::*;
use rama::utils::str::arcstr::ArcStr;

#[test]
fn blocked_event_serializes_with_expected_keys() {
    let event = BlockedEvent {
        ts_ms: 42,
        artifact: BlockedArtifact {
            product: ArcStr::from("npm"),
            identifier: ArcStr::from("foo"),
            version: Some(ArcStr::from("1.3.0")),
        },
    };

    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["ts_ms"], 42);
    assert_eq!(json["artifact"]["product"], "npm");
    assert_eq!(json["artifact"]["identifier"], "foo");
    assert_eq!(json["artifact"]["version"], "1.3.0");

    // Ensure legacy key names are not emitted.
    assert!(json.get("unix_ts_ms").is_none());
}

#[test]
fn store_enforces_max_events_min_1() {
    let store = BlockedEventsStore::new(0);

    store.record_at(
        10,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("pypi"),
                identifier: ArcStr::from("a"),
                version: Some(ArcStr::from("1.0.0")),
            },
        },
    );

    store.record_at(
        20,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("pypi"),
                identifier: ArcStr::from("b"),
                version: Some(ArcStr::from("2.0.0")),
            },
        },
    );

    let snapshot = store.snapshot_for_tests();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].artifact.identifier.as_ref() as &str, "b");
    assert_eq!(snapshot[0].ts_ms, 20);
}

#[test]
fn store_prunes_by_max_events_keeps_most_recent() {
    let store = BlockedEventsStore::new(2);

    store.record_at(
        10,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("a"),
                version: Some(ArcStr::from("1")),
            },
        },
    );

    store.record_at(
        20,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("b"),
                version: Some(ArcStr::from("1")),
            },
        },
    );

    store.record_at(
        30,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("c"),
                version: Some(ArcStr::from("1")),
            },
        },
    );

    let snapshot = store.snapshot_for_tests();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].artifact.identifier.as_ref() as &str, "b");
    assert_eq!(snapshot[1].artifact.identifier.as_ref() as &str, "c");
    assert_eq!(snapshot[0].ts_ms, 20);
    assert_eq!(snapshot[1].ts_ms, 30);
}

#[test]
fn store_keeps_most_recent_events_with_timestamps() {
    let store = BlockedEventsStore::new(2);

    store.record_at(
        10,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("a"),
                version: None,
            },
        },
    );
    store.record_at(
        20,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("b"),
                version: None,
            },
        },
    );
    store.record_at(
        30,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("c"),
                version: None,
            },
        },
    );
    store.record_at(
        40,
        BlockedEventInfo {
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("d"),
                version: None,
            },
        },
    );

    let snapshot = store.snapshot_for_tests();
    assert_eq!(snapshot.len(), 2);
    // Input is [10, 20, 30, 40]; capacity=2 keeps the most recent two: [30, 40]
    assert_eq!(snapshot[0].ts_ms, 30);
    assert_eq!(snapshot[0].artifact.identifier.as_ref() as &str, "c");
    assert_eq!(snapshot[1].ts_ms, 40);
    assert_eq!(snapshot[1].artifact.identifier.as_ref() as &str, "d");
}
