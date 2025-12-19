use std::sync::Arc;

use rama::{
    error::OpaqueError,
    http::{
        HeaderValue, Request, Response, header::CONTENT_TYPE,
        service::web::response::IntoResponse as _,
    },
    net::address::{Domain, SocketAddress},
};

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
    pub fn new(data: SyncCompactDataStorage) -> Self {
        Self {
            block_rules: Arc::new(vec![
                self::rule::vscode::BlockRuleVSCode::new(data.clone()).into_dyn(),
                self::rule::chrome::BlockRuleChrome::new(data).into_dyn(),
            ]),
        }
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
