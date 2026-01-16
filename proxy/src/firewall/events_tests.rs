use super::*;

#[test]
fn blocked_artifact_serializes_with_kind_tag() {
    let artifact = BlockedArtifact::Npm {
        name: "foo".to_string(),
        version: "1.3.0".to_string(),
    };

    let json = serde_json::to_value(&artifact).unwrap();

    assert_eq!(json["kind"], "npm");
    assert_eq!(json["name"], "foo");
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
        product: "pypi".to_string(),
        artifact: BlockedArtifact::Pypi {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
        },
    });

    store.record(BlockedEventInfo {
        product: "pypi".to_string(),
        artifact: BlockedArtifact::Pypi {
            name: "bar".to_string(),
            version: "2.0.0".to_string(),
        },
    });

    let resp = store.query(EventsQuery::default());
    assert_eq!(resp.total_retained, 1);
    assert_eq!(resp.events.len(), 1);
}

#[test]
fn store_prunes_by_max_events_keeps_most_recent() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 2);

    store.record(BlockedEventInfo {
        product: "npm".to_string(),
        artifact: BlockedArtifact::Npm {
            name: "a".to_string(),
            version: "1".to_string(),
        },
    });

    store.record(BlockedEventInfo {
        product: "npm".to_string(),
        artifact: BlockedArtifact::Npm {
            name: "b".to_string(),
            version: "1".to_string(),
        },
    });

    store.record(BlockedEventInfo {
        product: "npm".to_string(),
        artifact: BlockedArtifact::Npm {
            name: "c".to_string(),
            version: "1".to_string(),
        },
    });

    let resp = store.query(EventsQuery::default());
    assert_eq!(resp.total_retained, 2);
    assert_eq!(resp.events.len(), 2);
}

#[test]
fn store_prunes_by_retention() {
    let store = BlockedEventsStore::new(Duration::from_secs(1), 100);

    let base_ms = now_unix_ms();
    let old_ms = base_ms.saturating_sub(10_000);
    let recent_ms = base_ms.saturating_sub(10);
    {
        let mut state = store.state.lock();
        state.events.push_back(BlockedEvent {
            unix_ts_ms: old_ms,
            product: "pypi".to_string(),
            artifact: BlockedArtifact::Unknown,
        });
        state.events.push_back(BlockedEvent {
            unix_ts_ms: recent_ms,
            product: "pypi".to_string(),
            artifact: BlockedArtifact::Unknown,
        });
    }

    let resp = store.query(EventsQuery::default());
    assert_eq!(resp.total_retained, 1);
    assert_eq!(resp.events.len(), 1);
    assert_eq!(resp.events[0].unix_ts_ms, recent_ms);
}

#[test]
fn query_filters_by_time_window() {
    let store = BlockedEventsStore::new(Duration::from_secs(3600), 100);

    let base_ms = now_unix_ms();
    let t1 = base_ms.saturating_sub(3000);
    let t2 = base_ms.saturating_sub(2000);
    let t3 = base_ms.saturating_sub(1000);

    {
        let mut state = store.state.lock();
        state.events.push_back(BlockedEvent {
            unix_ts_ms: t1,
            product: "npm".to_string(),
            artifact: BlockedArtifact::Unknown,
        });
        state.events.push_back(BlockedEvent {
            unix_ts_ms: t2,
            product: "npm".to_string(),
            artifact: BlockedArtifact::Unknown,
        });
        state.events.push_back(BlockedEvent {
            unix_ts_ms: t3,
            product: "npm".to_string(),
            artifact: BlockedArtifact::Unknown,
        });
    }

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

    {
        let mut state = store.state.lock();
        for offset in (1..=5).rev() {
            state.events.push_back(BlockedEvent {
                unix_ts_ms: base_ms.saturating_sub(offset),
                product: "npm".to_string(),
                artifact: BlockedArtifact::Unknown,
            });
        }
    }

    let resp = store.query(EventsQuery {
        since_unix_ms: None,
        until_unix_ms: None,
        limit: Some(2),
    });

    assert_eq!(resp.events.len(), 2);
    assert_eq!(resp.events[0].unix_ts_ms, base_ms.saturating_sub(2));
    assert_eq!(resp.events[1].unix_ts_ms, base_ms.saturating_sub(1));
}
