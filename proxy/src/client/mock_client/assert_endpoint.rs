use std::convert::Infallible;
use std::sync::{Mutex, OnceLock};

use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        BodyExtractExt as _, Request, Response, StatusCode,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
    net::user::UserId,
    telemetry::tracing,
};

use crate::server::proxy::FirewallUserConfig;

static BLOCKED_EVENTS: OnceLock<Mutex<Vec<serde_json::Value>>> = OnceLock::new();

fn blocked_events() -> &'static Mutex<Vec<serde_json::Value>> {
    BLOCKED_EVENTS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(super) fn web_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        .with_get("/firewall-user-config/echo", safechain_config_echo)
        .with_post("/blocked-events", record_blocked_event)
        .with_get("/blocked-events/take", take_blocked_events)
        .with_get("/blocked-events/clear", clear_blocked_events)
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

async fn record_blocked_event(req: Request) -> impl IntoResponse {
    match req.try_into_json::<serde_json::Value>().await {
        Ok(v) => {
            blocked_events()
                .lock()
                .expect("blocked events mutex poisoned")
                .push(v);
            StatusCode::NO_CONTENT
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to parse blocked-event notification payload");
            StatusCode::BAD_REQUEST
        }
    }
}

async fn take_blocked_events() -> impl IntoResponse {
    let mut guard = blocked_events()
        .lock()
        .expect("blocked events mutex poisoned");
    let events = std::mem::take(&mut *guard);
    Json(events)
}

async fn clear_blocked_events() -> impl IntoResponse {
    blocked_events()
        .lock()
        .expect("blocked events mutex poisoned")
        .clear();
    StatusCode::NO_CONTENT
}
