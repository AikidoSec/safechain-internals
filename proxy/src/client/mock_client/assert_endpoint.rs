use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use rama::{
    Layer as _, Service,
    extensions::ExtensionsRef as _,
    http::{
        BodyExtractExt as _, Request, Response, StatusCode,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
    layer::AddInputExtensionLayer,
    net::user::UserId,
    telemetry::tracing,
};

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
    AddInputExtensionLayer::new(state).into_layer(
        Router::new()
            .with_get("/firewall-user-config/echo", safechain_config_echo)
            .with_post("/blocked-events", record_blocked_event)
            .with_get("/blocked-events/take", take_blocked_events)
            .with_get("/blocked-events/clear", clear_blocked_events),
    )
}

async fn safechain_config_echo(req: Request) -> impl IntoResponse {
    Json(
        match req.extensions().get::<FirewallUserConfig>().cloned() {
            Some(cfg) => {
                tracing::info!(
                    "cfg found for user {:?}: {cfg:?}",
                    req.extensions().get::<UserId>()
                );
                cfg
            }
            None => {
                tracing::info!(
                    "cfg NOT found for user {:?}; return default",
                    req.extensions().get::<UserId>()
                );
                Default::default()
            }
        },
    )
}

async fn record_blocked_event(req: Request) -> Response {
    let state = req.extensions().get::<MockState>().cloned();

    match req.try_into_json::<serde_json::Value>().await {
        Ok(v) => {
            if let Some(state) = state {
                state
                    .blocked_events
                    .lock()
                    .expect("blocked events mutex poisoned")
                    .push(v);
                StatusCode::NO_CONTENT.into_response()
            } else {
                tracing::warn!("MockState not found in request extensions");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to parse blocked-event notification payload");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn take_blocked_events(req: Request) -> Response {
    if let Some(state) = req.extensions().get::<MockState>().cloned() {
        let mut guard = state
            .blocked_events
            .lock()
            .expect("blocked events mutex poisoned");
        let events = std::mem::take(&mut *guard);
        Json(events).into_response()
    } else {
        tracing::warn!("MockState not found in request extensions");
        Json(Vec::<serde_json::Value>::new()).into_response()
    }
}

async fn clear_blocked_events(req: Request) -> Response {
    if let Some(state) = req.extensions().get::<MockState>().cloned() {
        state
            .blocked_events
            .lock()
            .expect("blocked events mutex poisoned")
            .clear();
        StatusCode::NO_CONTENT.into_response()
    } else {
        tracing::warn!("MockState not found in request extensions");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}
