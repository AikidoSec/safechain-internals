use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use radix_trie::{Trie, TrieCommon};
use rama::{
    Service,
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{BodyExtractExt, Request, Response, Uri, service::client::HttpClientExt},
    net::address::Domain,
    telemetry::tracing,
};
use rand::RngExt as _;
use serde::Deserialize;

use crate::{
    http::firewall::{IncomingFlowInfo, domain_matcher::DomainMatcher},
    utils::token::AgentIdentity,
};

#[derive(Debug, Clone)]
pub struct RemoteAppPassthroughList {
    list: Arc<ArcSwap<Option<PassthroughList>>>,
}

impl RemoteAppPassthroughList {
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        agent_identity: AgentIdentity,
        aikido_url: Uri,
        client: C,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let uri = passthrough_list_uri(&aikido_url)?;
        let client = RemoteAppPassthroughListClient {
            agent_identity,
            uri,
            client,
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

    pub fn is_source_app_passthrough(&self, meta: &IncomingFlowInfo) -> bool {
        let guard = self.list.load();

        let Some(list) = guard.as_ref().as_ref() else {
            return false;
        };

        list.is_match(meta)
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

#[derive(Debug, Clone)]
struct PassthroughList {
    apps: Trie<String, Domains>,
}

impl PassthroughList {
    fn is_match(&self, meta: &IncomingFlowInfo) -> bool {
        let Some(bundle_id) = meta.app_bundle_id else {
            return false;
        };

        // get_ancestor returns the subtrie rooted at the longest stored key that
        // is a prefix of `bundle_id`
        let Some(domains) = self.apps.get_ancestor(bundle_id).and_then(|t| t.value()) else {
            return false;
        };

        domains.matches(meta.domain)
    }

}

#[derive(Debug, Clone)]
enum Domains {
    Wildcard,
    Allowlist(Box<DomainMatcher>),
}

impl Domains {
    fn matches(&self, domain: &Domain) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Allowlist(domains) => domains.is_match(domain),
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

        let mut apps = Trie::new();
        for app_config in api_response.disabled_apps_mac {
            let domains = if app_config.domains == ["*"] {
                Domains::Wildcard
            } else {
                let domain_matcher: DomainMatcher = app_config
                    .domains
                    .into_iter()
                    .filter_map(|d| d.parse::<Domain>().ok())
                    .collect();
                Domains::Allowlist(Box::new(domain_matcher))
            };
            apps.insert(app_config.app_id, domains);
        }
        Ok(PassthroughList { apps })
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

#[cfg(test)]
mod tests;
