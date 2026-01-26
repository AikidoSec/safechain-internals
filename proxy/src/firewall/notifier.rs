use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use super::events::BlockedEvent;
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Response, Uri, service::client::HttpClientExt as _},
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};
use serde_json;
use tokio::sync::{Semaphore, SemaphorePermit};

const EVENT_DEDUP_WINDOW: Duration = Duration::from_secs(30);

#[derive(Default)]
struct DedupState {
    last_sent_by_key: HashMap<String, Instant>,
}

#[derive(Clone)]
pub struct EventNotifier {
    exec: Executor,
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: Uri,
    limit: Arc<Semaphore>,
    dedup: Arc<parking_lot::Mutex<DedupState>>,
}

impl std::fmt::Debug for EventNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventNotifier").finish()
    }
}

impl EventNotifier {
    pub fn try_new(exec: Executor, reporting_endpoint: Uri) -> Result<Self, OpaqueError> {
        let client = crate::client::new_web_client()?.boxed();
        let limit = Arc::new(Semaphore::const_new(compute_concurrent_request_count()));
        let dedup = Arc::new(parking_lot::Mutex::new(DedupState::default()));
        Ok(Self {
            exec,
            client,
            reporting_endpoint,
            limit,
            dedup,
        })
    }

    pub async fn notify(&self, event: BlockedEvent) {
        if !should_send_event(&self.dedup, &event) {
            tracing::debug!(
                product = %event.artifact.product,
                identifier = %event.artifact.identifier,
                "suppressed duplicate blocked-event notification"
            );
            return;
        }

        let client = self.client.clone();
        let reporting_endpoint = self.reporting_endpoint.clone();
        let limits = self.limit.clone();

        self.exec.spawn_task(async move {
            let _guard = match acquire_concurrency_guard(&limits).await {
                Ok(guard) => guard,
                Err(err) => {
                    tracing::debug!("failed to send event notification (dropping it): {err}");
                    return;
                }
            };
            send_blocked_event(client, reporting_endpoint, event).await;
        });
    }
}

fn should_send_event(dedup: &parking_lot::Mutex<DedupState>, event: &BlockedEvent) -> bool {
    let key = serde_json::to_string(&event.artifact)
        .unwrap_or_else(|_| format!("{}:{}", event.artifact.product, event.artifact.identifier));

    let now = Instant::now();

    let mut state = dedup.lock();

    if let Some(last_at) = state.last_sent_by_key.get(&key) {
        if last_at.elapsed() < EVENT_DEDUP_WINDOW {
            return false;
        }
    }

    let cleanup_window = EVENT_DEDUP_WINDOW * 2;
    state
        .last_sent_by_key
        .retain(|_, last_at| last_at.elapsed() <= cleanup_window);
    state.last_sent_by_key.insert(key, now);
    true
}

fn compute_concurrent_request_count() -> usize {
    std::env::var("MAX_CONCURRENT_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            cpus * 64
        })
}

async fn acquire_concurrency_guard<'a>(
    limits: &'a Semaphore,
) -> Result<SemaphorePermit<'a>, OpaqueError> {
    tokio::time::timeout(Duration::from_millis(500), limits.acquire())
        .await
        .context("concurrency guard acquisition timeout")?
        .context("concurrency guard acquisition via semaphore")
}

async fn send_blocked_event(
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: Uri,
    event: BlockedEvent,
) {
    tracing::debug!(
        "sending event notification: product={} artifact={:?}",
        event.artifact.product,
        event.artifact
    );

    let resp = match client
        .post(reporting_endpoint.clone())
        .json(&event)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                error = %err,
                endpoint = %reporting_endpoint,
                "failed to send blocked-event notification"
            );
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        tracing::warn!(
            status = %status,
            endpoint = %reporting_endpoint,
            "blocked-event notification endpoint returned non-success status"
        );
        return;
    }

    tracing::debug!("event notification sent successfully");
}
