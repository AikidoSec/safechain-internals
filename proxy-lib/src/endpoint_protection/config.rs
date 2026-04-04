use std::{sync::Arc, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri, header::AUTHORIZATION},
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};
use tokio::sync::broadcast;

use crate::{
    endpoint_protection::EcosystemKey,
    http::{firewall::notifier::EventNotifier, headers::X_DEVICE_ID},
    storage::SyncCompactDataStorage,
    utils::remote_resource::{self, RefreshHandle, RemoteResource, RemoteResourceSpec},
};

use super::types::{EcosystemConfig, EndpointConfig};

pub struct RemoteEndpointConfig {
    config: RemoteResource<Option<EndpointConfig>>,
    refresh_handle: RefreshHandle,
    updates: broadcast::Sender<Arc<Option<EndpointConfig>>>,
}

impl Clone for RemoteEndpointConfig {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            refresh_handle: self.refresh_handle.clone(),
            updates: self.updates.clone(),
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
        let (updates, _) = broadcast::channel(8);
        let (config, refresh_handle) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            Arc::new(EndpointConfigRemoteResource {
                uri,
                token,
                device_id,
                notifier,
                updates: updates.clone(),
            }),
        )
        .await
        .context("create new remote endpoint config")?;

        Ok(Self {
            config,
            refresh_handle,
            updates,
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

    #[inline(always)]
    pub fn current(&self) -> Arc<Option<EndpointConfig>> {
        self.config.get_owned()
    }

    pub fn subscribe(
        &self,
    ) -> (
        Arc<Option<EndpointConfig>>,
        broadcast::Receiver<Arc<Option<EndpointConfig>>>,
    ) {
        (self.current(), self.updates.subscribe())
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
    updates: broadcast::Sender<Arc<Option<EndpointConfig>>>,
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
            AUTHORIZATION,
            self.token
                .as_str()
                .try_into()
                .context("convert endpoint token into authorization header value")?,
        );
        req.headers_mut().insert(
            X_DEVICE_ID,
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

        let _ = self.updates.send(config.clone());

        Ok(config)
    }
}
