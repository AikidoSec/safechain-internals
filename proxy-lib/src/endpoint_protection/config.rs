use std::{marker::PhantomData, sync::Arc, time::Duration};

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
    package::name_formatter::PackageNameFormatter,
    storage::SyncCompactDataStorage,
    utils::{
        remote_resource::{self, RefreshHandle, RemoteResource, RemoteResourceSpec},
        time::{SystemDuration, SystemTimestampMilliseconds},
    },
};

use super::types::{EcosystemConfig, EndpointConfig};

pub struct RemoteEndpointConfig<F: PackageNameFormatter> {
    config: RemoteResource<Option<EndpointConfig<F>>>,
    refresh_handle: RefreshHandle,
}

impl<F: PackageNameFormatter> Clone for RemoteEndpointConfig<F> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            refresh_handle: self.refresh_handle.clone(),
        }
    }
}

impl<F: PackageNameFormatter> std::fmt::Debug for RemoteEndpointConfig<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteEndpointConfig").finish()
    }
}

impl<F: PackageNameFormatter> RemoteEndpointConfig<F> {
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
        let (config, refresh_handle) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            Arc::new(EndpointConfigRemoteResource::<F> {
                uri,
                token,
                device_id,
                notifier,
                _phantom: PhantomData,
            }),
        )
        .await
        .context("create new remote endpoint config")?;

        Ok(Self {
            config,
            refresh_handle,
        })
    }

    pub fn map_ecosystem_config<T>(
        &self,
        ecosystem: &EcosystemKey,
        map: impl FnOnce(&EcosystemConfig<F>) -> T,
    ) -> Option<T> {
        self.config
            .get()
            .as_ref()
            .and_then(|state| state.ecosystems.get(ecosystem).map(map))
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

    /// Trigger an immediate config refresh check.
    pub fn trigger_refresh(&self) {
        self.refresh_handle.trigger_refresh();
    }
}

struct EndpointConfigRemoteResource<F: PackageNameFormatter> {
    uri: Uri,
    token: ArcStr,
    device_id: ArcStr,
    notifier: Option<EventNotifier>,
    _phantom: PhantomData<F>,
}

impl<F: PackageNameFormatter> RemoteResourceSpec for EndpointConfigRemoteResource<F> {
    type Payload = EndpointConfig<F>;
    type State = Option<EndpointConfig<F>>;

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

        Ok(config)
    }
}
