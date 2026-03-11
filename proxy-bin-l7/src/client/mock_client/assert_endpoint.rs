use std::convert::Infallible;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        Request, Response, StatusCode,
        service::web::{
            Router,
            extract::State,
            response::{IntoResponse, Json},
        },
    },
    net::user::UserId,
    telemetry::tracing,
    utils::collections::AppendOnlyVec,
};

use crate::server::proxy::FirewallUserConfig;

#[derive(Clone, Debug)]
pub struct MockState {
    pub blocked_events: Arc<ArcSwap<AppendOnlyVec<serde_json::Value>>>,
    pub min_package_age_events: Arc<ArcSwap<AppendOnlyVec<serde_json::Value>>>,
}

impl MockState {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            blocked_events: Default::default(),
            min_package_age_events: Default::default(),
        }
    }
}

pub(super) fn web_svc(
    state: MockState,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new_with_state(state)
        .with_get("/firewall-user-config/echo", safechain_config_echo)
        .with_post("/events/blocks", record_blocked_event)
        .with_get("/blocked-events/take", take_blocked_events)
        .with_get("/blocked-events/clear", clear_blocked_events)
        .with_post("/events/min-package-age", record_min_package_age_event)
        .with_get("/min-package-age-events/take", take_min_package_age_events)
        .with_get(
            "/min-package-age-events/clear",
            clear_min_package_age_events,
        )
}

async fn safechain_config_echo(req: Request) -> impl IntoResponse {
    match req.extensions().get::<FirewallUserConfig>() {
        Some(cfg) => {
            tracing::info!(
                "cfg found for user {:?}: {cfg:?}",
                req.extensions().get::<UserId>()
            );
            Json(cfg).into_response()
        }
        None => {
            tracing::info!(
                "cfg NOT found for user {:?}; return default",
                req.extensions().get::<UserId>()
            );
            Json(serde_json::json!(FirewallUserConfig::default())).into_response()
        }
    }
}

async fn record_blocked_event(
    State(MockState { blocked_events, .. }): State<MockState>,
    Json(value): Json<serde_json::Value>,
) -> impl IntoResponse {
    blocked_events.load().push(value);
    StatusCode::NO_CONTENT
}

async fn take_blocked_events(
    State(MockState { blocked_events, .. }): State<MockState>,
) -> impl IntoResponse {
    let previous_blocked_events = blocked_events.swap(Default::default());
    Json(previous_blocked_events.iter().collect::<Vec<_>>()).into_response()
}

async fn clear_blocked_events(
    State(MockState { blocked_events, .. }): State<MockState>,
) -> impl IntoResponse {
    let _ = blocked_events.swap(Default::default());
    StatusCode::NO_CONTENT
}

async fn record_min_package_age_event(
    State(MockState {
        min_package_age_events,
        ..
    }): State<MockState>,
    Json(value): Json<serde_json::Value>,
) -> impl IntoResponse {
    min_package_age_events.load().push(value);
    StatusCode::NO_CONTENT
}

async fn take_min_package_age_events(
    State(MockState {
        min_package_age_events,
        ..
    }): State<MockState>,
) -> impl IntoResponse {
    let previous = min_package_age_events.swap(Default::default());
    Json(previous.iter().collect::<Vec<_>>()).into_response()
}

async fn clear_min_package_age_events(
    State(MockState {
        min_package_age_events,
        ..
    }): State<MockState>,
) -> impl IntoResponse {
    let _ = min_package_age_events.swap(Default::default());
    StatusCode::NO_CONTENT
}
