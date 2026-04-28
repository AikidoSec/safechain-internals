use std::{net::IpAddr, sync::Arc};

use radix_trie::{Trie, TrieCommon};
use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
    net::{address::Domain, stream::dep::ipnet::IpNet},
};
use serde::{Deserialize, Serialize};

use crate::{
    http::firewall::domain_matcher::DomainMatcher,
    storage::SyncCompactDataStorage,
    utils::remote_resource::{self, RefreshHandle, RemoteResource, RemoteResourceSpec},
    utils::token::AgentIdentity,
};

pub struct PassthroughMatchContext<'a> {
    pub app_bundle_id: Option<&'a str>,
    pub domain: Option<&'a Domain>,
}

#[derive(Debug, Clone)]
pub struct RemoteAppPassthroughList {
    list: RemoteResource<Option<PassthroughList>>,
    refresh_handle: RefreshHandle,
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

        let (list, refresh_handle) = remote_resource::try_new(guard, data, client, spec)
            .await
            .context("create new remote app passthrough list")?;

        Ok(Self {
            list,
            refresh_handle,
        })
    }

    pub fn trigger_refresh(&self) {
        self.refresh_handle.trigger_refresh();
    }

    pub fn is_source_app_passthrough(&self, passthrough_context: &PassthroughMatchContext) -> bool {
        let guard = self.list.get();
        let Some(list) = guard.as_ref() else {
            return false;
        };

        list.is_match(passthrough_context)
    }

    pub fn is_destination_ip_passthrough(&self, addr: IpAddr) -> bool {
        let guard = self.list.get();
        let Some(list) = guard.as_ref() else {
            return false;
        };

        list.is_destination_ip_passthrough(addr)
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
    cidrs: Vec<IpNet>,
}

impl PassthroughList {
    fn is_match(&self, passthrough_context: &PassthroughMatchContext) -> bool {
        let Some(bundle_id) = passthrough_context.app_bundle_id else {
            return false;
        };

        // get_ancestor returns the subtrie rooted at the longest stored key that
        // is a prefix of `bundle_id`
        let Some(matcher) = self.apps.get_ancestor(bundle_id).and_then(|t| t.value()) else {
            return false;
        };

        match passthrough_context.domain {
            Some(domain) => matcher.is_match(domain),
            None => matcher.matches_no_domain(),
        }
    }

    fn is_destination_ip_passthrough(&self, addr: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&addr))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiResponse {
    disabled_apps_mac: Vec<ApiAppConfig>,
    #[serde(default)]
    passthrough_cidrs: Vec<String>,
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
        let cidrs = payload
            .passthrough_cidrs
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();
        Ok(Arc::new(Some(PassthroughList { apps, cidrs })))
    }
}

#[cfg(test)]
mod tests;
