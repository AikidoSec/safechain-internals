use std::{collections::HashMap, sync::Arc, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext},
    graceful::ShutdownGuard,
    http::{
        BodyExtractExt, Request, Response, StatusCode, Uri, service::client::HttpClientExt as _,
    },
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use arc_swap::ArcSwap;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{storage::SyncCompactDataStorage, utils::uri::uri_to_filename};

#[derive(Clone)]
pub struct RemoteEndpointConfig {
    config: Arc<ArcSwap<EndpointConfig>>,
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
    /// * `uri` - Config endpoint URL (e.g., `https://config.aikido.dev/api/endpoint_protection/config`)
    /// * `token` - Permission group token from installation command.
    /// * `device_id` - Unique device identifier (UUID).
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
        C: Service<Request, Output = Response, Error = BoxError>,
    {
        let filename = uri_to_filename(&uri);
        let refresh_interval = Duration::from_secs(600); // 10 minutes? Configurable?

        let config_client = RemoteConfigClient {
            uri,
            token,
            device_id,
            filename,
            refresh_interval,
            sync_storage,
            client,
        };

        let (endpoint_config, e_tag) = match config_client.load_cached_config().await {
            Ok(Some(cached_info)) => {
                tracing::debug!(
                    "create new remote endpoint config (uri: {}) with cached config",
                    config_client.uri
                );
                cached_info
            }
            Ok(None) => {
                tracing::debug!(
                    "no cached config found for remote endpoint (uri: {}); download fresh config",
                    config_client.uri
                );

                config_client
                    .download_config(None)
                    .await
                    .context("download new endpoint config")?
                    .context("new endpoint config not available")?
            }
            Err(err) => {
                tracing::warn!(
                    "failed to load cached config for remote endpoint (uri: {}); download fresh config; err = {err}",
                    config_client.uri
                );

                config_client
                    .download_config(None)
                    .await
                    .context("download new endpoint config")?
                    .context("new endpoint config not available")?
            }
        };

        let shared_config = Arc::new(ArcSwap::new(Arc::new(endpoint_config)));

        tokio::spawn(config_update_loop(
            guard,
            config_client,
            e_tag,
            shared_config.clone(),
        ));

        Ok(Self {
            config: shared_config,
        })
    }

    pub fn get(&self) -> Arc<EndpointConfig> {
        self.config.load_full()
    }

    /// Get config for a specific ecosystem.
    pub fn get_ecosystem_config(&self, ecosystem: &str) -> Option<EcosystemConfig> {
        let config = self.config.load();
        config.ecosystems.get(ecosystem).cloned()
    }
}

struct RemoteConfigClient<C> {
    uri: Uri,
    token: ArcStr,
    device_id: ArcStr,
    filename: ArcStr,
    refresh_interval: Duration,
    sync_storage: SyncCompactDataStorage,
    client: C,
}

impl<C> RemoteConfigClient<C>
where
    C: Service<Request, Output = Response, Error = BoxError>,
{
    async fn download_config(
        &self,
        e_tag: Option<&str>,
    ) -> Result<Option<(EndpointConfig, Option<ArcStr>)>, BoxError> {
        let Some((config, new_e_tag)) = self.fetch_remote_config_and_e_tag(e_tag).await? else {
            return Ok(None);
        };

        self.spawn_config_caching_task(config.clone(), new_e_tag.clone());

        tracing::debug!(
            "endpoint config refreshed from remote endpoint '{}'",
            self.uri,
        );

        Ok(Some((config, new_e_tag)))
    }

    async fn fetch_remote_config_and_e_tag(
        &self,
        previous_e_tag: Option<&str>,
    ) -> Result<Option<(EndpointConfig, Option<ArcStr>)>, BoxError> {
        let start = Instant::now();

        let req_builder = self.client.get(self.uri.clone());

        // Add authentication headers
        let req_builder = req_builder
            .header("Authorization", self.token.as_str())
            .header("X-Device-Id", self.device_id.as_str());

        // Add ETag if available
        let req_builder = if let Some(e_tag) = previous_e_tag {
            req_builder.header("if-none-match", e_tag)
        } else {
            req_builder
        };

        let resp = req_builder
            .send()
            .await
            .context("fetch endpoint config from remote endpoint")
            .context_debug_field("tt", start.elapsed())
            .with_context_field("uri", || self.uri.clone())?;

        // Handle 304 Not Modified
        if resp.status() == StatusCode::NOT_MODIFIED {
            tracing::debug!(
                "endpoint config endpoint '{}' reported config is not modified; (tt: {:?})",
                self.uri,
                start.elapsed()
            );
            return Ok(None);
        }

        let e_tag: Option<ArcStr> = resp
            .headers()
            .get("etag")
            .and_then(|v| v.as_bytes().try_into().ok());

        let config: EndpointConfig = resp
            .try_into_json()
            .await
            .context("collect and json-decode endpoint config response payload")
            .with_context_field("uri", || self.uri.clone())
            .with_context_debug_field("tt", || start.elapsed())?;

        tracing::debug!(
            "fetched and decoded new endpoint config from '{}' (permission_group_id: {}) (tt: {:?})",
            self.uri,
            config.permission_group_id,
            start.elapsed(),
        );

        Ok(Some((config, e_tag)))
    }

    fn spawn_config_caching_task(&self, config: EndpointConfig, e_tag: Option<ArcStr>) {
        let storage = self.sync_storage.clone();
        let filename = self.filename.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(err) = storage.store(
                &filename,
                &CachedEndpointConfig {
                    e_tag: e_tag.clone(),
                    config,
                },
            ) {
                tracing::error!("failed to backup downloaded endpoint config @ '{filename}': {err}")
            }
        });
    }

    async fn load_cached_config(
        &self,
    ) -> Result<Option<(EndpointConfig, Option<ArcStr>)>, BoxError> {
        tokio::task::spawn_blocking({
            let storage = self.sync_storage.clone();
            let filename = self.filename.clone();
            move || load_cached_config_sync_inner(storage, filename)
        })
        .await
        .context("wait for blocking task to load cached config")
        .with_context_field("uri", || self.uri.clone())?
    }
}

fn load_cached_config_sync_inner(
    storage: SyncCompactDataStorage,
    filename: ArcStr,
) -> Result<Option<(EndpointConfig, Option<ArcStr>)>, BoxError> {
    let cached_config: Option<CachedEndpointConfig> =
        storage.load(&filename).context("storage failure")?;

    let Some(cached_config) = cached_config else {
        return Ok(None);
    };

    Ok(Some((cached_config.config, cached_config.e_tag)))
}

async fn config_update_loop<C>(
    guard: ShutdownGuard,
    client: RemoteConfigClient<C>,
    e_tag: Option<ArcStr>,
    shared_config: Arc<ArcSwap<EndpointConfig>>,
) where
    C: Service<Request, Output = Response, Error = BoxError>,
{
    tracing::debug!(
        "remote endpoint config (uri = {}), update loop task up and running",
        client.uri
    );

    let mut sleep_for = with_jitter(client.refresh_interval);
    let mut latest_e_tag = e_tag;

    loop {
        tracing::debug!(
            "remote endpoint config (uri = {}), sleep for: {sleep_for:?}",
            client.uri
        );

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {},
            _ = guard.cancelled() => {
                tracing::debug!(
                    "remote endpoint config (uri = {}), guard cancelled; exit",
                    client.uri
                );
                return;
            }
        }

        match client.download_config(latest_e_tag.as_deref()).await {
            Ok(Some((fresh_config, fresh_e_tag))) => {
                tracing::debug!(
                    "remote endpoint config (uri = {}), config updated",
                    client.uri
                );
                shared_config.store(Arc::new(fresh_config));
                sleep_for = with_jitter(client.refresh_interval);
                latest_e_tag = fresh_e_tag;
            }
            Ok(None) => {
                tracing::debug!("endpoint config was unmodified, preserve current one...");
                sleep_for = with_jitter(client.refresh_interval);
            }
            Err(err) => {
                tracing::error!(
                    "remote endpoint config (uri = {}), failed to update (err = {err}), try again in shorter interval...",
                    client.uri
                );
                let fail_interval = Duration::from_secs(std::cmp::max(sleep_for.as_secs() / 2, 60));
                sleep_for = with_jitter(fail_interval);
            }
        }
    }
}

fn with_jitter(refresh: Duration) -> Duration {
    let max_jitter = std::cmp::min(refresh, Duration::from_secs(60));
    let jitter_secs = rand::rng().random_range(0.0..=max_jitter.as_secs_f64());
    refresh + Duration::from_secs_f64(jitter_secs)
}

// ===== Data Structures =====

#[derive(Serialize, Deserialize)]
struct CachedEndpointConfig {
    pub e_tag: Option<ArcStr>,
    pub config: EndpointConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub version: ArcStr,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<ArcStr>,
    pub permission_group_id: u64,
    pub permission_group_name: ArcStr,
    /// Per-ecosystem configurations (npm, maven, pypi, etc.).
    #[serde(default)]
    pub ecosystems: HashMap<ArcStr, EcosystemConfig>,
}

/// Configuration for a specific package ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub block_all_installs: bool,

    #[serde(default)]
    pub force_requests_for_new_packages: bool,

    #[serde(default)]
    pub exceptions: Exceptions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exceptions {
    /// Packages to always block (even if not in malware list).
    #[serde(default)]
    pub blocked_packages: Vec<ArcStr>,

    /// Packages to allow.
    #[serde(default)]
    pub allowed_packages: Vec<ArcStr>,
}

fn default_true() -> bool {
    true
}
