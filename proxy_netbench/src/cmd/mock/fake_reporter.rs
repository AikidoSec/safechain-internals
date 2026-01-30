use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama::{
    Service,
    http::{
        Request, Response, StatusCode,
        service::web::{
            Router,
            extract::{Json, State},
            response::IntoResponse,
        },
    },
};

pub(super) fn fake_reporter_svc()
-> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    Arc::new(
        Router::new_with_state(TotalCounters::default())
            .with_post("/blocked-events", blocked_events)
            .with_get("/counter/blocked-events", blocked_events_counter),
    )
}

#[derive(Debug, Clone, Default)]
struct TotalCounters {
    blocked_events: Arc<AtomicUsize>,
}

async fn blocked_events(
    State(TotalCounters { blocked_events }): State<TotalCounters>,
    Json(_): Json<serde_json::Value>,
) -> impl IntoResponse {
    let _ = blocked_events.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

async fn blocked_events_counter(
    State(TotalCounters { blocked_events }): State<TotalCounters>,
) -> impl IntoResponse {
    blocked_events.load(Ordering::Acquire).to_string()
}
