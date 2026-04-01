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
    utils::{backoff::ExponentialBackoff, rng::HasherRng, str::arcstr::ArcStr},
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
    endpoint_protection::{PolicyEvaluator, RemoteEndpointConfig},
    http::firewall::rule::{DynRule, npm::min_package_age::MinPackageAge},
    package::name_formatter::PackageNameFormatter,
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
            .into_layer(client.clone())
            .boxed();

        let notifier = match reporting_endpoint {
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
        };

        let endpoint_config_uri = Self::endpoint_config_uri(&aikido_url)?;

        let (lowercase_remote_endpoint_config, lowercase_policy_evaluator) = new_policy_evaluator(
            agent_identity.clone(),
            guard.clone(),
            endpoint_config_uri.clone(),
            data.clone(),
            layered_client.clone(),
        )
        .await;

        let (_, skill_sh_policy_evaluator) = new_policy_evaluator(
            agent_identity.clone(),
            guard.clone(),
            endpoint_config_uri.clone(),
            data.clone(),
            layered_client.clone(),
        )
        .await;

        #[cfg(any(not(feature = "apple-networkextension"), feature = "test-utils", test))]
        let (_, chrome_policy_evaluator) = new_policy_evaluator(
            agent_identity.clone(),
            guard.clone(),
            endpoint_config_uri.clone(),
            data.clone(),
            layered_client.clone(),
        )
        .await;

        Ok(Self {
            block_rules: Arc::from([
                self::rule::vscode::RuleVSCode::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator.clone(),
                    lowercase_remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: vscode")?
                .into_dyn(),
                self::rule::nuget::RuleNuget::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator.clone(),
                    lowercase_remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: nuget")?
                .into_dyn(),
                #[cfg(any(not(feature = "apple-networkextension"), feature = "test-utils", test))]
                self::rule::chrome::RuleChrome::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    chrome_policy_evaluator,
                )
                .await
                .context("create block rule: chrome")?
                .into_dyn(),
                self::rule::npm::RuleNpm::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator.clone(),
                    Some(MinPackageAge::new(
                        notifier.clone(),
                        lowercase_remote_endpoint_config.clone(),
                    )),
                    lowercase_remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: npm")?
                .into_dyn(),
                self::rule::pypi::RulePyPI::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator.clone(),
                    lowercase_remote_endpoint_config.clone(),
                )
                .await
                .context("create block rule: pypi")?
                .into_dyn(),
                self::rule::maven::RuleMaven::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator.clone(),
                )
                .await
                .context("create block rule: maven")?
                .into_dyn(),
                self::rule::open_vsx::RuleOpenVsx::try_new(
                    guard.clone(),
                    layered_client.clone(),
                    data.clone(),
                    lowercase_policy_evaluator,
                )
                .await
                .context("create block rule: open vsx")?
                .into_dyn(),
                self::rule::skills_sh::RuleSkillsSh::try_new(
                    guard,
                    layered_client,
                    data,
                    skill_sh_policy_evaluator,
                )
                .await
                .context("create block rule: skills.sh")?
                .into_dyn(),
                self::rule::hijack::RuleHijack::new().into_dyn(),
            ]),
            notifier,
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

    pub fn match_http_rules(&self, domain: &Domain) -> Option<FirewallHttpRules> {
        let matched_rules: Arc<[DynRule]> = self
            .block_rules
            .iter()
            .filter(|rule| rule.match_domain(domain))
            .cloned()
            .collect();

        if matched_rules.is_empty() {
            None
        } else {
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
}

async fn new_policy_evaluator<F: PackageNameFormatter>(
    agent_identity: Option<AgentIdentity>,
    guard: ShutdownGuard,
    endpoint_config_uri: Uri,
    data: SyncCompactDataStorage,
    layered_client: BoxService<Request, Response, OpaqueError>,
) -> (Option<RemoteEndpointConfig<F>>, Option<PolicyEvaluator<F>>) {
    let remote_endpoint_config = match agent_identity.as_ref() {
        Some(identity) => {
            match RemoteEndpointConfig::try_new(
                guard.clone(),
                endpoint_config_uri.clone(),
                ArcStr::from(identity.token.as_ref()),
                ArcStr::from(identity.device_id.as_ref()),
                data.clone(),
                layered_client.clone(),
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

    let policy_evaluator = remote_endpoint_config.clone().map(PolicyEvaluator::new);

    (remote_endpoint_config, policy_evaluator)
}
