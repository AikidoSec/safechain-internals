use std::convert::Infallible;
use std::sync::Arc;

use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        Request, Response, StatusCode,
        service::web::extract::State,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
    net::user::UserId,
    telemetry::tracing,
};

use parking_lot::Mutex;

use crate::server::proxy::FirewallUserConfig;

#[derive(Clone, Debug)]
pub struct MockState {
    pub blocked_events: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl MockState {
    pub fn new() -> Self {
        Self {
            blocked_events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

pub(super) fn web_svc(
    state: MockState,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new_with_state(state)
        .with_get("/firewall-user-config/echo", safechain_config_echo)
        .with_post("/blocked-events", record_blocked_event)
        .with_get("/blocked-events/take", take_blocked_events)
        .with_get("/blocked-events/clear", clear_blocked_events)
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
    State(MockState { blocked_events }): State<MockState>,
    Json(value): Json<serde_json::Value>,
) -> impl IntoResponse {
    blocked_events.lock().push(value);
    StatusCode::NO_CONTENT
}

async fn take_blocked_events(
    State(MockState { blocked_events }): State<MockState>,
) -> impl IntoResponse {
    let mut guard = blocked_events.lock();
    let events = std::mem::take(&mut *guard);
    Json(events)
}

async fn clear_blocked_events(
    State(MockState { blocked_events }): State<MockState>,
) -> impl IntoResponse {
    blocked_events.lock().clear();
    StatusCode::NO_CONTENT
}
