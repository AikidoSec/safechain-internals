use std::{
    future::Future,
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
    endpoint_protection::types::EndpointConfig,
    http::firewall::events::MinPackageAgeEvent,
    package::version::{PackageVersion, PackageVersionKey},
    utils::env::{compute_concurrent_request_count, network_service_identifier},
};

use super::events::{BlockReason, BlockedEvent, TlsTerminationFailedEvent};

const EVENT_DEDUP_WINDOW: Duration = Duration::from_secs(30);
const MAX_EVENTS: u64 = 10_000;

type DedupCache = moka::sync::Cache<DedupKey, Arc<AtomicU64>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    pub product: ArcStr,
    pub identifier: ArcStr,
    pub version: PackageVersionKey,
    pub block_reason: BlockReason,
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
            block_reason: value.block_reason.clone(),
        }
    }
}

#[derive(Clone)]
pub struct EventNotifier {
    exec: Executor,
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: String,
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
        let reporting_endpoint = reporting_endpoint
            .to_string()
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            exec,
            client,
            reporting_endpoint,
            limit,
            dedup,
        })
    }

    pub async fn notify_blocked(&self, event: BlockedEvent) {
        if !self.should_send_event(&event) {
            tracing::debug!(
                product = %event.artifact.product,
                identifier = %event.artifact.identifier,
                version = ?event.artifact.version,
                block_reason = ?event.block_reason,
                "suppressed duplicate blocked-event notification"
            );
            return;
        }

        self.spawn_event_task(|client, reporting_endpoint| {
            send_blocked_event(client, reporting_endpoint, event)
        });
    }

    pub async fn notify_min_package_age(&self, event: MinPackageAgeEvent) {
        self.spawn_event_task(|client, reporting_endpoint| {
            send_min_package_age_event(client, reporting_endpoint, event)
        });
    }

    pub fn notify_tls_termination_failed(&self, event: TlsTerminationFailedEvent) {
        self.spawn_event_task(|client, reporting_endpoint| {
            send_tls_termination_failed_event(client, reporting_endpoint, event)
        });
    }

    pub fn notify_permissions_updated(&self, config: Arc<Option<EndpointConfig>>) {
        self.spawn_event_task(|client, reporting_endpoint| {
            send_permissions_updated_event(client, reporting_endpoint, config)
        });
    }

    fn spawn_event_task<F, Fut>(&self, f: F)
    where
        F: FnOnce(BoxService<Request, Response, OpaqueError>, String) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
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
                f(client, reporting_endpoint).await
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
    reporting_endpoint: String,
    event: BlockedEvent,
) {
    tracing::debug!(
        "sending blocked event notification: product={} artifact={:?}",
        event.artifact.product,
        event.artifact
    );

    let url = format!("{}/events/blocks", reporting_endpoint);

    send_event(client, reporting_endpoint, event, &url).await;
}

async fn send_min_package_age_event(
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: String,
    event: MinPackageAgeEvent,
) {
    tracing::debug!(
        "sending minimum package age event notification: product={} artifact={:?}",
        event.artifact.product,
        event.artifact
    );

    let url = format!("{}/events/min-package-age", reporting_endpoint);

    send_event(client, reporting_endpoint, event, &url).await;
}

async fn send_tls_termination_failed_event(
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: String,
    event: TlsTerminationFailedEvent,
) {
    let url = format!("{}/events/tls-termination-failed", reporting_endpoint);

    send_event(client, reporting_endpoint, event, &url).await;
}

async fn send_permissions_updated_event(
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: String,
    config: Arc<Option<EndpointConfig>>,
) {
    let Some(config) = config.as_ref() else {
        return;
    };

    tracing::debug!(
        "sending permissions update notification (permission_group_id={})",
        config.permission_group.id,
    );

    let url = format!("{}/events/permissions", reporting_endpoint);

    send_event(client, reporting_endpoint, config, &url).await;
}

async fn send_event<T: serde::Serialize>(
    client: BoxService<Request, Response, OpaqueError>,
    reporting_endpoint: String,
    event: T,
    url: &str,
) {
    let resp = match client.post(url).json(&event).send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                error = %err,
                endpoint = %reporting_endpoint,
                "failed to send event notification"
            );
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        tracing::warn!(
            status = %status,
            endpoint = %reporting_endpoint,
            "event notification endpoint returned non-success status"
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
