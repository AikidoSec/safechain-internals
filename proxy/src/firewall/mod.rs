use std::{sync::Arc, time::Duration};

use rama::{
    Layer as _, Service as _,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{
        Body, HeaderValue, Request, Response,
        header::CONTENT_TYPE,
        layer::{
            decompression::DecompressionLayer,
            map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
        service::web::response::IntoResponse as _,
    },
    layer::MapErrLayer,
    net::address::{Domain, SocketAddress},
    telemetry::tracing,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

pub mod events;
pub mod layer;
pub mod malware_list;
pub mod notifier;
pub mod rule;

mod pac;

use crate::storage::SyncCompactDataStorage;

use self::rule::{RequestAction, Rule};

#[derive(Debug, Clone)]
pub struct Firewall {
    // NOTE: if we ever want to update these rules on the fly,
    // e.g. removing/adding them, we can ArcSwap these and have
    // a background task update these when needed..
    block_rules: Arc<Vec<self::rule::DynRule>>,
    notifier: Option<self::notifier::EventNotifier>,
}

impl Firewall {
    pub async fn try_new(
        guard: ShutdownGuard,
        data: SyncCompactDataStorage,
        reporting_endpoint: Option<rama::http::Uri>,
    ) -> Result<Self, OpaqueError> {
        let inner_https_client = crate::client::new_web_client()?;

        let shared_remote_malware_client = (
            MapResponseBodyLayer::new(Body::new),
            DecompressionLayer::new(),
            MapErrLayer::new(OpaqueError::from_std),
            TimeoutLayer::new(Duration::from_secs(60)), // NOTE: if you have slow servers this might need to be more
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
            MapRequestBodyLayer::new(Body::new),
        )
            .into_layer(inner_https_client)
            .boxed();

        let notifier = match reporting_endpoint {
            Some(endpoint) => match self::notifier::EventNotifier::try_new(endpoint) {
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

        Ok(Self {
            block_rules: Arc::new(vec![
                self::rule::vscode::RuleVSCode::try_new(
                    guard.clone(),
                    shared_remote_malware_client.clone(),
                    data.clone(),
                )
                .await
                .context("create block rule: vscode")?
                .into_dyn(),
                self::rule::chrome::RuleChrome::try_new(data.clone())
                    .await
                    .context("create block rule: chrome")?
                    .into_dyn(),
                self::rule::npm::RuleNpm::try_new(
                    guard.clone(),
                    shared_remote_malware_client.clone(),
                    data.clone(),
                )
                .await
                .context("create block rule: npm")?
                .into_dyn(),
                self::rule::pypi::RulePyPI::try_new(guard, shared_remote_malware_client, data)
                    .await
                    .context("create block rule: pypi")?
                    .into_dyn(),
            ]),
            notifier,
        })
    }

    #[inline]
    pub fn record_blocked_event(&self, info: self::events::BlockedEventInfo) {
        if let Some(notifier) = self.notifier.as_ref() {
            let event = self::events::BlockedEvent::from_info(info);
            notifier.notify(event);
        }
    }

    pub fn match_domain(&self, domain: &Domain) -> bool {
        self.block_rules
            .iter()
            .any(|rule| rule.match_domain(domain))
    }

    pub fn into_evaluate_request_layer(self) -> self::layer::evaluate_req::EvaluateRequestLayer {
        self::layer::evaluate_req::EvaluateRequestLayer(self)
    }

    pub fn into_evaluate_response_layer(self) -> self::layer::evaluate_resp::EvaluateResponseLayer {
        self::layer::evaluate_resp::EvaluateResponseLayer(self)
    }

    async fn evaluate_request(&self, req: Request) -> Result<RequestAction, OpaqueError> {
        let mut mod_req = req;

        for rule in self.block_rules.iter() {
            match rule.evaluate_request(mod_req).await? {
                RequestAction::Allow(new_mod_req) => mod_req = new_mod_req,
                RequestAction::Block(blocked) => {
                    self.record_blocked_event(blocked.info.clone());
                    return Ok(RequestAction::Block(blocked));
                }
            }
        }

        Ok(RequestAction::Allow(mod_req))
    }

    async fn evaluate_response(&self, resp: Response) -> Result<Response, OpaqueError> {
        let mut mod_resp = resp;

        // Iterate rules in reverse order for symmetry with request evaluation
        for rule in self.block_rules.iter().rev() {
            mod_resp = rule.evaluate_response(mod_resp).await?;
        }

        Ok(mod_resp)
    }

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
