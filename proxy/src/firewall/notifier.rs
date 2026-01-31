use std::{
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
    time::Duration,
};

use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Response, Uri, service::client::HttpClientExt as _},
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use tokio::sync::{Semaphore, SemaphorePermit};

use crate::firewall::version::{PackageVersion, PackageVersionKey};

use super::events::BlockedEvent;

const EVENT_DEDUP_WINDOW: Duration = Duration::from_secs(30);
const MAX_EVENTS: u64 = 10_000;

type DedupCache = moka::sync::Cache<DedupKey, Arc<AtomicU64>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    /// The product type (e.g., "npm", "pypi", "vscode", "chrome")
    pub product: ArcStr,
    /// The name or identifier of the artifact
    pub identifier: ArcStr,
    /// Optional version of the artifact (e.g. semver)
    pub version: PackageVersionKey,
}

impl From<&BlockedEvent> for DedupKey {
    #[inline(always)]
    fn from(value: &BlockedEvent) -> Self {
        Self {
            product: value.artifact.product.clone(),
            identifier: value.artifact.identifier.clone(),
            version: value
                .artifact
                .version
                .as_ref()
                .map(PackageVersion::as_key)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone)]
pub struct EventNotifier {
    exec: Executor,
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: Uri,
    limit: Arc<Semaphore>,
    dedup: DedupCache,
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
        let dedup = moka::sync::CacheBuilder::new(MAX_EVENTS)
            .time_to_live(EVENT_DEDUP_WINDOW)
            .build();
        Ok(Self {
            exec,
            client,
            reporting_endpoint,
            limit,
            dedup,
        })
    }

    pub async fn notify(&self, event: BlockedEvent) {
        if !self.should_send_event(&event) {
            tracing::debug!(
                product = %event.artifact.product,
                identifier = %event.artifact.identifier,
                version = ?event.artifact.version,
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

    fn should_send_event(&self, event: &BlockedEvent) -> bool {
        self.dedup
            .get_with(DedupKey::from(event), Default::default)
            .fetch_add(1, atomic::Ordering::SeqCst)
            == 0
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
