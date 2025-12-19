use std::{sync::Arc, time::Duration};

use rama::{
    Layer as _, Service as _,
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::{
        HeaderValue, Request, Response,
        client::EasyHttpWebClient,
        header::CONTENT_TYPE,
        layer::{
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
        service::web::response::IntoResponse as _,
    },
    layer::MapErrLayer,
    net::address::{Domain, SocketAddress},
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

pub mod malware_list;
pub mod rule;

mod pac;
mod utils;

use crate::storage::SyncCompactDataStorage;

use self::rule::BlockRule;

#[derive(Debug, Clone)]
pub struct Firewall {
    // NOTE: if we ever want to update these rules on the fly,
    // e.g. removing/adding them, we can ArcSwap these and have
    // a background task update these when needed..
    block_rules: Arc<Vec<self::rule::DynBlockRule>>,
}

impl Firewall {
    pub async fn try_new(
        guard: ShutdownGuard,
        data: SyncCompactDataStorage,
    ) -> Result<Self, OpaqueError> {
        let shared_remote_malware_client = (
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
                    .unwrap(),
                ),
            ),
        )
            .into_layer(
                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .without_tls_proxy_support()
                    .without_proxy_support()
                    .with_tls_support_using_boringssl(None)
                    .with_default_http_connector()
                    // connections are shared between remote fetchers
                    .try_with_default_connection_pool()
                    .context("create connection pool for proxy web client")?
                    .build_client(),
            )
            .boxed();

        Ok(Self {
            block_rules: Arc::new(vec![
                self::rule::vscode::BlockRuleVSCode::try_new(
                    guard,
                    shared_remote_malware_client,
                    data.clone(),
                )
                .await
                .context("create block rule: vscode")?
                .into_dyn(),
                self::rule::chrome::BlockRuleChrome::try_new(data)
                    .await
                    .context("create block rule: chrome")?
                    .into_dyn(),
            ]),
        })
    }

    pub fn match_domain(&self, domain: &Domain) -> bool {
        self.block_rules
            .iter()
            .any(|rule| rule.match_domain(domain))
    }

    pub async fn block_request(&self, mut req: Request) -> Result<Option<Request>, OpaqueError> {
        for rule in self.block_rules.iter() {
            match rule.block_request(req).await? {
                Some(r) => req = r,
                None => {
                    return Ok(None);
                }
            }
        }
        Ok(Some(req))
    }

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
