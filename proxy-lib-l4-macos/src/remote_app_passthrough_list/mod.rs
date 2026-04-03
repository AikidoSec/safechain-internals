use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use arc_swap::ArcSwap;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{
        BodyExtractExt, HeaderValue, Request, Response, Uri,
        layer::{
            decompression::DecompressionLayer,
            map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
        service::client::HttpClientExt,
    },
    layer::MapErrLayer,
    net::{
        address::{Domain, HostWithPort},
        apple::networkextension::tproxy::TransparentProxyFlowMeta,
    },
    rt::Executor,
    telemetry::tracing,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};
use rand::RngExt as _;
use safechain_proxy_lib::{
    http::{client::new_http_client_for_internal, firewall::domain_matcher::DomainMatcher},
    utils::{env::network_service_identifier, token::AgentIdentity},
};
use serde::Deserialize;

use crate::config::ProxyConfig;

static REMOTE_APP_PASSTHROUGH_LIST: OnceLock<Option<RemoteAppPassthroughList>> = OnceLock::new();

pub async fn init_remote_app_passthrough_list(guard: ShutdownGuard, conf: ProxyConfig) {
    if REMOTE_APP_PASSTHROUGH_LIST.get().is_some() {
        return;
    }

    let list = if let Some(agent_identity) = conf.agent_identity {
        match RemoteAppPassthroughList::try_new(guard, agent_identity, conf.aikido_url).await {
            Ok(list) => Some(list),
            Err(err) => {
                tracing::error!("failed to initialize remote app passthrough list: {err}");
                None
            }
        }
    } else {
        None
    };

    let _ = REMOTE_APP_PASSTHROUGH_LIST.set(list);
}

pub fn is_source_app_passthrough(meta: &TransparentProxyFlowMeta) -> bool {
    let Some(remote_app_passthrough_list) =
        REMOTE_APP_PASSTHROUGH_LIST.get().and_then(|v| v.as_ref())
    else {
        return false;
    };

    remote_app_passthrough_list.is_source_app_passthrough(meta)
}

struct RemoteAppPassthroughList {
    list: Arc<ArcSwap<Option<PassthroughList>>>,
}

impl RemoteAppPassthroughList {
    async fn try_new(
        guard: ShutdownGuard,
        agent_identity: AgentIdentity,
        aikido_url: Uri,
    ) -> Result<Self, BoxError> {
        let executor = Executor::graceful(guard.clone());
        let http_client = new_http_client_for_internal(executor)
            .context("create http client for app passthrough list")?;

        let uri = passthrough_list_uri(&aikido_url)?;

        let layered_client = (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            MapErrLayer::into_opaque_error(),
            DecompressionLayer::new(),
            TimeoutLayer::new(Duration::from_secs(60)),
            RetryLayer::new(
                ManagedPolicy::default().with_backoff(
                    ExponentialBackoff::new(
                        Duration::from_millis(100),
                        Duration::from_secs(30),
                        0.01,
                        HasherRng::default,
                    )
                    .context("create exponential backoff impl")?,
                ),
            ),
            AddRequiredRequestHeadersLayer::new().with_user_agent_header_value(
                HeaderValue::from_static(network_service_identifier()),
            ),
            MapRequestBodyLayer::new_boxed_streaming_body(),
        )
            .into_layer(http_client)
            .boxed();

        let client = RemoteAppPassthroughListClient {
            agent_identity,
            uri,
            client: layered_client,
        };

        let shared_list: Arc<ArcSwap<Option<PassthroughList>>> =
            Arc::new(ArcSwap::new(Arc::new(None)));

        tokio::spawn(passthrough_list_update_loop(
            guard,
            client,
            shared_list.clone(),
        ));

        Ok(Self { list: shared_list })
    }

    fn is_source_app_passthrough(&self, meta: &TransparentProxyFlowMeta) -> bool {
        let guard = self.list.load();

        let Some(list) = guard.as_ref().as_ref() else {
            return false;
        };

        list.apps.iter().any(|app| app.matches(meta))
    }
}

fn passthrough_list_uri(aikido_url: &Uri) -> Result<Uri, BoxError> {
    let uri_str = format!(
        "{}/api/endpoint_protection/callbacks/fetchDisabledApps",
        aikido_url.to_string().trim_end_matches('/'),
    );
    uri_str
        .parse::<Uri>()
        .context("construct passthrough list URI from aikido_url")
}

struct PassthroughList {
    apps: Vec<AppConfig>,
}

struct AppConfig {
    app_name: String,
    domains: Domains,
}

impl AppConfig {
    fn matches(&self, meta: &TransparentProxyFlowMeta) -> bool {
        let Some(app_name) = meta.source_app_bundle_identifier.as_deref() else {
            return false;
        };

        if !self.app_name.eq_ignore_ascii_case(app_name) {
            return false;
        }
        
        self.domains.matches(meta.local_endpoint.as_ref())
    }
}

enum Domains {
    Wildcard,
    Allowlist(DomainMatcher),
}

impl Domains {
    fn matches(&self, maybe_host: Option<&HostWithPort>) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Allowlist(domains) => {
                let Some(host_with_port) = maybe_host else {
                    return false;
                };
                let Some(domain) = host_with_port.host.as_domain() else {
                    return false;
                };

                domains.is_match(domain)
            }
        }
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    disabled_apps_mac: Vec<ApiAppConfig>,
}

#[derive(Deserialize)]
struct ApiAppConfig {
    app_id: String,
    domains: Vec<String>,
}

struct RemoteAppPassthroughListClient<C> {
    agent_identity: AgentIdentity,
    uri: Uri,
    client: C,
}

impl<C> RemoteAppPassthroughListClient<C>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    async fn fetch(&self) -> Result<PassthroughList, BoxError> {
        let req_builder = self.client.get(self.uri.clone());
        let req_builder = req_builder.header("Authorization", self.agent_identity.token.as_ref());
        let req_builder = req_builder.header("X-Device-Id", self.agent_identity.device_id.as_ref());

        let response = req_builder
            .send()
            .await
            .context("fetch app passthrough list from remote endpoint")
            .with_context_field("uri", || self.uri.clone())?;

        if !response.status().is_success() {
            let http_status_code = response.status();
            let maybe_error_msg = response.try_into_string().await.unwrap_or_default();
            return Err(BoxError::from(
                "failed to download app passthrough list from remote endpoint",
            )
            .with_context_field("uri", || self.uri.clone())
            .context_field("status", http_status_code)
            .context_field("message", maybe_error_msg));
        }

        self.parse_result(response).await
    }

    async fn parse_result(&self, response: Response) -> Result<PassthroughList, BoxError> {
        let api_response = response
            .try_into_json::<ApiResponse>()
            .await
            .context("parse app passthrough list response")?;

        Ok(PassthroughList {
            apps: api_response
                .disabled_apps_mac
                .into_iter()
                .map(|a| AppConfig {
                    app_name: a.app_id.to_owned(),
                    domains: if a.domains == ["*"] {
                        Domains::Wildcard
                    } else {
                        let domain_matcher = a
                            .domains
                            .into_iter()
                            .filter_map(|d| d.parse::<Domain>().ok())
                            .collect();
                        Domains::Allowlist(domain_matcher)
                    },
                })
                .collect(),
        })
    }
}

async fn passthrough_list_update_loop<C>(
    guard: ShutdownGuard,
    client: RemoteAppPassthroughListClient<C>,
    shared_list: Arc<ArcSwap<Option<PassthroughList>>>,
) where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    tracing::debug!(
        "app passthrough list (uri = {}), update loop started",
        client.uri
    );

    let refresh_interval = Duration::from_mins(10);
    let mut sleep_for = with_jitter(refresh_interval);
    let mut is_first = true;

    loop {
        if !is_first {
            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {
                    tracing::debug!("app passthrough list (uri = {}), timer triggered refresh", client.uri);
                }
                _ = guard.cancelled() => {
                    tracing::debug!("app passthrough list (uri = {}), guard cancelled; exit", client.uri);
                    return;
                }
            }
        } else {
            is_first = false;
        }

        match client.fetch().await {
            Ok(fresh_list) => {
                tracing::debug!("app passthrough list (uri = {}), list updated", client.uri);
                shared_list.store(Arc::new(Some(fresh_list)));
                sleep_for = with_jitter(refresh_interval);
            }
            Err(err) => {
                tracing::error!(
                    "app passthrough list (uri = {}), failed to refresh (err = {err}), retrying sooner...",
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
