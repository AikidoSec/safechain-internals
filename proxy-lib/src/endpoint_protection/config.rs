use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use crate::{
    endpoint_protection::EcosystemKey,
    http::firewall::notifier::EventNotifier,
    storage::SyncCompactDataStorage,
    utils::{
        remote_resource::{self, RefreshHandle, RemoteResource, RemoteResourceSpec},
        time::{SystemDuration, SystemTimestampMilliseconds},
    },
};

use super::types::{EcosystemConfig, EndpointConfig};

pub struct RemoteEndpointConfig {
    config: RemoteResource<Option<EndpointConfig>>,
    refresh_handle: RefreshHandle,
    revision: Arc<AtomicU64>,
}

impl Clone for RemoteEndpointConfig {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            refresh_handle: self.refresh_handle.clone(),
            revision: self.revision.clone(),
        }
    }
}

impl std::fmt::Debug for RemoteEndpointConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteEndpointConfig").finish()
    }
}

impl RemoteEndpointConfig {
    /// Create a new endpoint config service.
    ///
    /// # Arguments
    ///
    /// * `guard` - Graceful shutdown guard for background task
    /// * `uri` - Config endpoint URL
    /// * `token` - Permission group token
    /// * `device_id` - External device identifier sent as `X-Device-Id`
    /// * `sync_storage` - Storage for caching config
    /// * `client` - HTTP client for fetching config
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        uri: Uri,
        token: ArcStr,
        device_id: ArcStr,
        sync_storage: SyncCompactDataStorage,
        client: C,
        notifier: Option<EventNotifier>,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let revision = Arc::new(AtomicU64::new(0));
        let (config, refresh_handle) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            Arc::new(EndpointConfigRemoteResource {
                uri,
                token,
                device_id,
                notifier,
                revision: revision.clone(),
            }),
        )
        .await
        .context("create new remote endpoint config")?;

        Ok(Self {
            config,
            refresh_handle,
            revision,
        })
    }

    pub fn map_ecosystem_config<T>(
        &self,
        ecosystem: &EcosystemKey,
        map: impl FnOnce(&EcosystemConfig) -> T,
    ) -> Option<T> {
        self.config
            .get()
            .as_ref()
            .and_then(|state| state.ecosystems.get(ecosystem).map(map))
    }

    pub fn map_ecosystems<T>(
        &self,
        map: impl FnOnce(&std::collections::HashMap<EcosystemKey, EcosystemConfig>) -> T,
    ) -> Option<T> {
        self.config
            .get()
            .as_ref()
            .map(|state| map(&state.ecosystems))
    }

    pub fn get_package_age_cutoff_ts(
        &self,
        name: &EcosystemKey,
        default_cutoff_age: SystemDuration,
    ) -> SystemTimestampMilliseconds {
        let maybe_ts = self
            .config
            .get()
            .as_ref()
            .and_then(|cfg| cfg.ecosystems.get(name))
            .and_then(|ecosystem_cfg| ecosystem_cfg.minimum_allowed_age_timestamp);
        if let Some(ts_secs) = maybe_ts {
            return ts_secs;
        }
        SystemTimestampMilliseconds::now() - default_cutoff_age
    }

    #[inline(always)]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Trigger an immediate config refresh check.
    pub fn trigger_refresh(&self) {
        self.refresh_handle.trigger_refresh();
    }
}

struct EndpointConfigRemoteResource {
    uri: Uri,
    token: ArcStr,
    device_id: ArcStr,
    notifier: Option<EventNotifier>,
    revision: Arc<AtomicU64>,
}

impl RemoteResourceSpec for EndpointConfigRemoteResource {
    type Payload = EndpointConfig;
    type State = Option<EndpointConfig>;

    fn refresh_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn build_request(&self) -> Result<Request, BoxError> {
        let mut req = Request::builder()
            .uri(self.uri.clone())
            .body(Body::empty())
            .context("build endpoint protection config http request")?;
        req.headers_mut().insert(
            "authorization",
            self.token
                .as_str()
                .try_into()
                .context("convert endpoint token into authorization header value")?,
        );
        req.headers_mut().insert(
            "x-device-id",
            self.device_id
                .as_str()
                .try_into()
                .context("convert endpoint device_id into x-device-id header value")?,
        );
        Ok(req)
    }

    fn build_state(&self, payload: Self::Payload) -> Result<Arc<Self::State>, BoxError> {
        tracing::debug!(
            "decoded endpoint config from '{}' (permission_group_id: {})",
            self.uri,
            payload.permission_group.id,
        );

        let config = Arc::new(Some(payload));

        if let Some(notifier) = self.notifier.as_ref() {
            notifier.notify_permissions_updated(config.clone());
        }

        self.revision.fetch_add(1, Ordering::AcqRel);

        Ok(config)
    }
}
