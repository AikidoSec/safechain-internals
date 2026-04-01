use std::{marker::PhantomData, time::Duration};

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
    package::name_formatter::PackageNameFormatter,
    storage::SyncCompactDataStorage,
    utils::remote_resource::{self, RefreshHandle, RemoteResource, RemoteResourceSpec},
};

use super::types::{EcosystemConfig, EndpointConfig};

pub struct RemoteEndpointConfig<F: PackageNameFormatter> {
    config: RemoteResource<Option<EndpointConfig<F>>>,
    trigger_refresh: RefreshHandle,
}

impl<F: PackageNameFormatter> Clone for RemoteEndpointConfig<F> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            trigger_refresh: self.trigger_refresh.clone(),
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
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let (config, trigger_refresh) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            EndpointConfigRemoteResource::<F> {
                uri,
                token,
                device_id,
                _phantom: PhantomData,
            },
        )
        .await
        .context("create new remote endpoint config")?;

        Ok(Self {
            config,
            trigger_refresh,
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

    /// Trigger an immediate config refresh check.
    pub fn trigger_refresh(&self) {
        self.trigger_refresh.trigger_refresh();
    }
}

struct EndpointConfigRemoteResource<F: PackageNameFormatter> {
    uri: Uri,
    token: ArcStr,
    device_id: ArcStr,
    _phantom: PhantomData<F>,
}

impl<F: PackageNameFormatter> Clone for EndpointConfigRemoteResource<F> {
    fn clone(&self) -> Self {
        Self {
            uri: self.uri.clone(),
            token: self.token.clone(),
            device_id: self.device_id.clone(),
            _phantom: self._phantom,
        }
    }
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

    fn build_state(&self, payload: Self::Payload) -> Result<Self::State, BoxError> {
        tracing::debug!(
            "decoded endpoint config from '{}' (permission_group_id: {})",
            self.uri,
            payload.permission_group.id,
        );
        Ok(Some(payload))
    }
}
