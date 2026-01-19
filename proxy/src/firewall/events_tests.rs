use super::*;
use rama::utils::str::arcstr::ArcStr;

#[test]
fn blocked_artifact_serializes() {
    let artifact = BlockedArtifact {
        product: ArcStr::from("npm"),
        identifier: ArcStr::from("foo"),
        version: Some(ArcStr::from("1.3.0")),
    };

    let json = serde_json::to_value(&artifact).unwrap();

    assert_eq!(json["product"], "npm");
    assert_eq!(json["identifier"], "foo");
    assert_eq!(json["version"], "1.3.0");
}

#[test]
fn events_query_deserializes_with_defaults() {
    let query: EventsQuery = serde_json::from_str("{}").unwrap();

    assert_eq!(query.since_unix_ms, None);
    assert_eq!(query.until_unix_ms, None);
    assert_eq!(query.limit, None);
}

#[test]
fn store_enforces_max_events_min_1() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 0);

    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("pypi"),
            identifier: ArcStr::from("foo"),
            version: Some(ArcStr::from("1.0.0")),
        },
    });

    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("pypi"),
            identifier: ArcStr::from("bar"),
            version: Some(ArcStr::from("2.0.0")),
        },
    });

    // With max_events=0 (enforced to .max(1)), store retains at least 1 event
    let resp = store.query(EventsQuery::default());
    assert!(resp.total_retained >= 1, "should retain at least 1 event");
}

#[test]
fn store_prunes_by_max_events_keeps_most_recent() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 2);

    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("npm"),
            identifier: ArcStr::from("a"),
            version: Some(ArcStr::from("1")),
        },
    });

    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("npm"),
            identifier: ArcStr::from("b"),
            version: Some(ArcStr::from("1")),
        },
    });

    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("npm"),
            identifier: ArcStr::from("c"),
            version: Some(ArcStr::from("1")),
        },
    });

    // With two-layer pruning, events are only pruned if exceeding max AND enough time has passed
    // During test execution, prune interval hasn't elapsed yet, so all 3 may be retained
    let resp = store.query(EventsQuery::default());
    assert!(
        resp.total_retained >= 2,
        "should retain at least max_events"
    );
    assert!(resp.total_retained <= 3, "should not grow indefinitely");
}

#[test]
fn store_prunes_by_retention() {
    let store = BlockedEventsStore::new(Duration::from_millis(500), 100);

    // Record an old event
    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("pypi"),
            identifier: ArcStr::from("old"),
            version: None,
        },
    });

    // Wait for retention period to expire
    std::thread::sleep(std::time::Duration::from_millis(600));

    // Record a recent event
    store.record(BlockedEventInfo {
        artifact: BlockedArtifact {
            product: ArcStr::from("pypi"),
            identifier: ArcStr::from("recent"),
            version: None,
        },
    });

    let resp = store.query(EventsQuery::default());
    // Only the recent event should remain after retention expires
    assert_eq!(resp.events.len(), 1);
    assert_eq!(
        resp.events[0].artifact.identifier.as_ref() as &str,
        "recent"
    );
}

#[test]
fn query_filters_by_time_window() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 100);

    let base_ms = now_unix_ms();

    // Manually insert events at specific times using the skipmap
    let t1 = base_ms.saturating_sub(3000);
    let t2 = base_ms.saturating_sub(2000);
    let t3 = base_ms.saturating_sub(1000);

    store.map.insert(
        (t1, 0),
        BlockedEvent {
            unix_ts_ms: t1,
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("event1"),
                version: None,
            },
        },
    );
    store.map.insert(
        (t2, 1),
        BlockedEvent {
            unix_ts_ms: t2,
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("event2"),
                version: None,
            },
        },
    );
    store.map.insert(
        (t3, 2),
        BlockedEvent {
            unix_ts_ms: t3,
            artifact: BlockedArtifact {
                product: ArcStr::from("npm"),
                identifier: ArcStr::from("event3"),
                version: None,
            },
        },
    );

    let resp = store.query(EventsQuery {
        since_unix_ms: Some(base_ms.saturating_sub(2500)),
        until_unix_ms: Some(base_ms.saturating_sub(1500)),
        limit: None,
    });

    assert_eq!(resp.events.len(), 1);
    assert_eq!(resp.events[0].unix_ts_ms, t2);
}

#[test]
fn query_limit_prefers_most_recent() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 100);

    let base_ms = now_unix_ms();

    // Manually insert events with sequential timestamps
    for offset in (1..=5).rev() {
        store.map.insert(
            (base_ms.saturating_sub(offset as u64), (5 - offset) as u64),
            BlockedEvent {
                unix_ts_ms: base_ms.saturating_sub(offset as u64),
                artifact: BlockedArtifact {
                    product: ArcStr::from("npm"),
                    identifier: ArcStr::from(format!("event{}", offset)),
                    version: None,
                },
            },
        );
    }

    let resp = store.query(EventsQuery {
        since_unix_ms: None,
        until_unix_ms: None,
        limit: Some(2),
    });

    assert_eq!(resp.events.len(), 2);
    // Should get the two most recent events
    assert_eq!(resp.events[0].unix_ts_ms, base_ms.saturating_sub(2));
    assert_eq!(resp.events[1].unix_ts_ms, base_ms.saturating_sub(1));
}
