use std::sync::Arc;

use radix_trie::{Trie, TrieCommon};
use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
};
use serde::{Deserialize, Serialize};

use crate::{
    http::firewall::{IncomingFlowInfo, domain_matcher::DomainMatcher},
    storage::SyncCompactDataStorage,
    utils::remote_resource::{self, RemoteResource, RemoteResourceSpec},
    utils::token::AgentIdentity,
};

#[derive(Debug, Clone)]
pub struct RemoteAppPassthroughList {
    list: RemoteResource<Option<PassthroughList>>,
}

impl RemoteAppPassthroughList {
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        agent_identity: AgentIdentity,
        aikido_url: Uri,
        data: SyncCompactDataStorage,
        client: C,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let uri = passthrough_list_uri(&aikido_url)?;
        let spec = Arc::new(RemoteAppPassthroughListSpec {
            agent_identity,
            uri,
        });

        let (list, _refresh_handle) = remote_resource::try_new(guard, data, client, spec)
            .await
            .context("create new remote app passthrough list")?;

        Ok(Self { list })
    }

    pub fn is_source_app_passthrough(&self, meta: &IncomingFlowInfo) -> bool {
        let guard = self.list.get();
        let Some(list) = guard.as_ref() else {
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
    apps: Trie<String, DomainMatcher>,
}

impl PassthroughList {
    fn is_match(&self, meta: &IncomingFlowInfo) -> bool {
        let Some(bundle_id) = meta.app_bundle_id else {
            return false;
        };

        // get_ancestor returns the subtrie rooted at the longest stored key that
        // is a prefix of `bundle_id`
        let Some(matcher) = self.apps.get_ancestor(bundle_id).and_then(|t| t.value()) else {
            return false;
        };

        matcher.is_match(meta.domain)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiResponse {
    disabled_apps_mac: Vec<ApiAppConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiAppConfig {
    app_id: String,
    domains: Vec<String>,
}

#[derive(Debug, Clone)]
struct RemoteAppPassthroughListSpec {
    agent_identity: AgentIdentity,
    uri: Uri,
}

impl RemoteResourceSpec for RemoteAppPassthroughListSpec {
    type Payload = ApiResponse;
    type State = Option<PassthroughList>;

    fn build_request(&self) -> Result<Request, BoxError> {
        let mut req = Request::builder()
            .uri(self.uri.clone())
            .body(Body::empty())
            .context("build app passthrough list http request")?;
        self.agent_identity.add_request_headers(&mut req)?;
        Ok(req)
    }

    fn build_state(&self, payload: Self::Payload) -> Result<Arc<Self::State>, BoxError> {
        let mut apps = Trie::new();
        for app_config in payload.disabled_apps_mac {
            let matcher: DomainMatcher = app_config.domains.into_iter().collect();
            apps.insert(app_config.app_id, matcher);
        }
        Ok(Arc::new(Some(PassthroughList { apps })))
    }
}

#[cfg(test)]
mod tests;
