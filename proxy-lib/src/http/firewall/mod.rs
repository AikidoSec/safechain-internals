use std::{sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    error::{BoxError, ErrorContext as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{
        HeaderValue, Request, Response, Uri,
        layer::{
            decompression::DecompressionLayer,
            map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
    },
    layer::MapErrLayer,
    net::address::Domain,
    rt::Executor,
    service::BoxService,
    telemetry::tracing,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

#[cfg(feature = "pac")]
use rama::{
    http::{header::CONTENT_TYPE, service::web::response::IntoResponse as _},
    net::address::SocketAddress,
};

pub mod domain_matcher;
pub mod events;
pub mod layer;
pub mod notifier;
pub mod rule;

mod matched_rules;
pub use self::matched_rules::{
    FirewallDecompressionMatcher, FirewallHttpRules, FirewallWebSocketRules,
};

#[cfg(feature = "pac")]
mod pac;

use crate::{
    endpoint_protection::{
        RemoteEndpointConfig, remote_app_passthrough_list::RemoteAppPassthroughList,
    },
    http::firewall::{
        notifier::EventNotifier,
        rule::{DynRule, npm::min_package_age::MinPackageAge},
    },
    storage::SyncCompactDataStorage,
    utils::{env::network_service_identifier, token::AgentIdentity},
};

use self::rule::Rule;

#[derive(Debug, Clone)]
pub struct Firewall {
    // NOTE: if we ever want to update these rules on the fly,
    // e.g. removing/adding them, we can ArcSwap these and have
    // a background task update these when needed..
    block_rules: Arc<[self::rule::DynRule]>,
    notifier: Option<self::notifier::EventNotifier>,
    passthrough_list: Option<RemoteAppPassthroughList>,
}

pub struct IncomingFlowInfo<'a> {
    pub domain: &'a Domain,
    pub app_bundle_id: Option<&'a str>,
    pub source_process_path: Option<&'a str>,
}

impl Firewall {
    fn endpoint_config_uri(aikido_url: &Uri) -> Result<Uri, BoxError> {
        let uri_str = format!(
            "{}/api/endpoint_protection/callbacks/fetchPermissions",
            aikido_url.to_string().trim_end_matches('/'),
        );

        uri_str
            .parse::<Uri>()
            .context("aikido_url should always produce a valid absolute http(s) origin")
    }

    pub async fn try_new(
        guard: ShutdownGuard,
        client: impl Service<Request, Output = Response, Error = OpaqueError> + Clone,
        data: SyncCompactDataStorage,
        reporting_endpoint: Option<Uri>,
        agent_identity: Option<AgentIdentity>,
        aikido_url: Uri,
    ) -> Result<Self, BoxError> {
        let layered_client = try_new_layered_client(client.clone())?;
        let notifier = new_event_notifier(guard.clone(), client, reporting_endpoint);

        let endpoint_config_uri = Self::endpoint_config_uri(&aikido_url)?;
        let remote_endpoint_config = match agent_identity.as_ref() {
            Some(identity) => {
                match RemoteEndpointConfig::try_new(
                    guard.clone(),
                    endpoint_config_uri.clone(),
                    identity.clone(),
                    data.clone(),
                    layered_client.clone(),
                    notifier.clone(),
                )
                .await
                {
                    Ok(config) => Some(config),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "failed to initialize endpoint config; config-based policy checks disabled"
                        );
                        None
                    }
                }
            }
            None => None,
        };

        let passthrough_list = match agent_identity {
            Some(identity) => {
                match RemoteAppPassthroughList::try_new(
                    guard.clone(),
                    identity,
                    aikido_url,
                    data.clone(),
                    layered_client.clone(),
                )
                .await
                {
                    Ok(passthrough_list) => Some(passthrough_list),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "failed to initialize app passthrough list"
                        );
                        None
                    }
                }
            }
            None => None,
        };

        Ok(Self {
            block_rules: Arc::from([
                self::rule::vscode::RuleVSCode::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: vscode")?
                .into_dyn(),
                self::rule::nuget::RuleNuget::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: nuget")?
                .into_dyn(),
                self::rule::chrome::RuleChrome::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: chrome")?
                .into_dyn(),
                self::rule::npm::RuleNpm::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    Some(MinPackageAge::new(
                        notifier.clone(),
                        remote_endpoint_config.clone(),
                    )),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: npm")?
                .into_dyn(),
                self::rule::pypi::RulePyPI::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    notifier.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: pypi")?
                .into_dyn(),
                self::rule::maven::RuleMaven::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: maven")?
                .into_dyn(),
                self::rule::open_vsx::RuleOpenVsx::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: open vsx")?
                .into_dyn(),
                self::rule::skills_sh::RuleSkillsSh::try_new(
                    guard,
                    layered_client,
                    data,
                    remote_endpoint_config,
                )
                .await
                .context("create block rule: skills.sh")?
                .into_dyn(),
                self::rule::hijack::RuleHijack::new().into_dyn(),
            ]),
            notifier,
            passthrough_list,
        })
    }

    #[inline]
    pub async fn record_blocked_event(&self, info: self::events::BlockedEventInfo) {
        if let Some(notifier) = self.notifier.as_ref() {
            let event = self::events::BlockedEvent::from_info(info);
            notifier.notify_blocked(event).await;
        }
    }

    pub fn record_tls_termination_failed(&self, event: self::events::TlsTerminationFailedEvent) {
        if let Some(notifier) = self.notifier.as_ref() {
            notifier.notify_tls_termination_failed(event);
        }
    }

    pub fn match_http_rules(
        &self,
        incoming_flow_info: &IncomingFlowInfo,
    ) -> Option<FirewallHttpRules> {
        if self.is_passthrough_traffic(incoming_flow_info) {
            tracing::debug!(
                domain = %incoming_flow_info.domain,
                bundle_id = %incoming_flow_info.app_bundle_id.unwrap_or("default"),
                source_process_path = ?incoming_flow_info.source_process_path,
                "skipping firewall for passthrough app and bundle"
            );
            return None;
        }

        let matched_rules: Arc<[DynRule]> = self
            .block_rules
            .iter()
            .filter(|rule| rule.match_domain(incoming_flow_info.domain))
            .cloned()
            .collect();

        if matched_rules.is_empty() {
            tracing::debug!(
                domain = %incoming_flow_info.domain,
                bundle_id = %incoming_flow_info.app_bundle_id.unwrap_or("default"),
                source_process_path = ?incoming_flow_info.source_process_path,
                "skipping firewall because no rules matched"
            );
            None
        } else {
            let num_rules = matched_rules.len();
            tracing::debug!(
                domain = %incoming_flow_info.domain,
                bundle_id = %incoming_flow_info.app_bundle_id.unwrap_or("default"),
                source_process_path = ?incoming_flow_info.source_process_path,
                "setting up firewall for {num_rules} rules"
            );
            Some(FirewallHttpRules(matched_rules))
        }
    }

    #[cfg(feature = "pac")]
    /// Generates and serves a PAC script,
    /// with the target domains collected using the
    /// [`Firewall`]'s [`Rule`] list.
    ///
    /// See `docs/proxy/pac.md` for in-depth documentation regarding
    /// Proxy Auto Configuration (PAC in short).
    pub fn generate_pac_script_response(
        &self,
        proxy_address: SocketAddress,
        _req: Request,
    ) -> Response {
        // NOTE: in case you ever need to define custom PAC script variants
        // depending on req properties such as the User-Agent,
        // here is where you would differentate on such matters...

        let mut script_generator = self::pac::PacScriptGenerator::new(proxy_address);
        for rule in self.block_rules.iter() {
            rule.collect_pac_domains(&mut script_generator);
        }
        let script_payload = script_generator.into_script();

        (
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
            )],
            script_payload,
        )
            .into_response()
    }

    fn is_passthrough_traffic(&self, incoming_flow_info: &IncomingFlowInfo) -> bool {
        let Some(ref passthrough_list) = self.passthrough_list else {
            return false;
        };

        passthrough_list.is_source_app_passthrough(incoming_flow_info)
    }
}

fn try_new_layered_client(
    client: impl Service<Request, Output = Response, Error = OpaqueError> + Clone,
) -> Result<BoxService<Request, Response, OpaqueError>, BoxError> {
    Ok((
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
        AddRequiredRequestHeadersLayer::new()
            .with_user_agent_header_value(HeaderValue::from_static(network_service_identifier())),
        MapRequestBodyLayer::new_boxed_streaming_body(),
    )
        .into_layer(client.clone())
        .boxed())
}

fn new_event_notifier(
    guard: ShutdownGuard,
    client: impl Service<Request, Output = Response, Error = OpaqueError> + Clone,
    reporting_endpoint: Option<Uri>,
) -> Option<EventNotifier> {
    match reporting_endpoint {
        Some(endpoint) => match self::notifier::EventNotifier::try_new(
            Executor::graceful(guard.clone()),
            client,
            endpoint,
        ) {
            Ok(notifier) => Some(notifier),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to initialize blocked-event notifier; reporting disabled"
                );
                None
            }
        },
        None => None,
    }
}
