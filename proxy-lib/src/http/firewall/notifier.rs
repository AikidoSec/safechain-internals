use std::{
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
    time::Duration,
};

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    http::{
        HeaderValue, Request, Response, Uri,
        layer::{
            map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
        service::client::HttpClientExt,
    },
    layer::MapErrLayer,
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
    utils::{backoff::ExponentialBackoff, rng::HasherRng, str::arcstr::ArcStr},
};

use tokio::sync::{Semaphore, SemaphorePermit};

use crate::{
    package::version::{PackageVersion, PackageVersionKey},
    utils::env::{compute_concurrent_request_count, network_service_identifier},
};

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
    pub fn try_new(
        exec: Executor,
        client: impl Service<Request, Output = Response, Error = OpaqueError>,
        reporting_endpoint: Uri,
    ) -> Result<Self, BoxError> {
        let client = create_notifier_https_client(client)?;
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

        self.exec.spawn_task({
            let client = self.client.clone();
            let reporting_endpoint = self.reporting_endpoint.clone();
            let limits = self.limit.clone();

            async move {
                let _guard = match acquire_concurrency_guard(&limits).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        tracing::debug!("failed to send event notification (dropping it): {err}");
                        return;
                    }
                };
                send_blocked_event(client, reporting_endpoint, event).await
            }
        });
    }

    fn should_send_event(&self, event: &BlockedEvent) -> bool {
        self.dedup
            .get_with(DedupKey::from(event), Default::default)
            .fetch_add(1, atomic::Ordering::SeqCst)
            == 0
    }
}

async fn acquire_concurrency_guard<'a>(
    limits: &'a Semaphore,
) -> Result<SemaphorePermit<'a>, BoxError> {
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

fn create_notifier_https_client(
    client: impl Service<Request, Output = Response, Error = OpaqueError>,
) -> Result<BoxService<Request, Response, OpaqueError>, BoxError> {
    let client_middleware = (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        MapErrLayer::into_opaque_error(),
        TimeoutLayer::new(Duration::from_secs(30)),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(20),
                    0.01,
                    HasherRng::default,
                )
                .context("create exponential backoff impl")?,
            ),
        ),
        AddRequiredRequestHeadersLayer::new()
            .with_user_agent_header_value(HeaderValue::from_static(network_service_identifier())),
        MapRequestBodyLayer::new_boxed_streaming_body(),
    );

    let layered_client = client_middleware.into_layer(client);
    Ok(layered_client.boxed())
}
