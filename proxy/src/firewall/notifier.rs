use std::{sync::Arc, time::Duration};

use super::events::BlockedEvent;
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Response, Uri, service::client::HttpClientExt as _},
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
};
use tokio::sync::{Semaphore, SemaphorePermit};

#[derive(Clone)]
pub struct EventNotifier {
    exec: Executor,
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: Uri,
    limit: Arc<Semaphore>,
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
        Ok(Self {
            exec,
            client,
            reporting_endpoint,
            limit,
        })
    }

    pub async fn notify(&self, event: BlockedEvent) {
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
