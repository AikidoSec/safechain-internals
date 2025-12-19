use std::{borrow::Cow, fmt};

use rama::{
    error::OpaqueError,
    http::{Request, service::web::extract::Query},
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
};
use serde::Deserialize;

use crate::{firewall::pac::PacScriptGenerator, storage::SyncCompactDataStorage};

use super::BlockRule;

pub(in crate::firewall) struct BlockRuleChrome {
    target_domains: DomainTrie<()>,
}

impl BlockRuleChrome {
    pub(in crate::firewall) async fn try_new(
        _data: SyncCompactDataStorage, // NOTE data will be used to backup malware list once you use a remote list here
    ) -> Result<Self, OpaqueError> {
        Ok(Self {
            target_domains: ["clients2.google.com"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
        })
    }
}

impl fmt::Debug for BlockRuleChrome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockRuleChrome").finish()
    }
}

// NOTE:
//
// Once there is a chrome malware list you'll
// want to fetch this package info from the (remote) Malware list

const CHROME_BLOCKED_EXT_LIST: &[&str] = &["lajondecmobodlejlcjllhojikagldgd"];

#[derive(Deserialize)]
struct ChromeExtInfo<'a> {
    x: Cow<'a, str>,
}

impl BlockRule for BlockRuleChrome {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "Chrome"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    #[inline(always)]
    fn collect_pac_domains(&self, generator: &mut PacScriptGenerator) {
        for (domain, _) in self.target_domains.iter() {
            generator.write_domain(&domain);
        }
    }

    async fn block_request(&self, req: Request) -> Result<Option<Request>, OpaqueError> {
        if let Some(domain) = crate::firewall::utils::try_get_domain_for_req(&req)
            && self.match_domain(&domain)
            && let Some(query) = req.uri().query()
            && let Ok(Query(ChromeExtInfo { x })) = Query::parse_query_str(query)
            && let Some(product_id) = x.strip_prefix("id=").map(|s| s.trim())
        {
            tracing::trace!("inspect chrome extension product id: {product_id}");
            if CHROME_BLOCKED_EXT_LIST
                .iter()
                .any(|c| c.eq_ignore_ascii_case(product_id))
            {
                tracing::debug!("blocked Chrome extension: {product_id}");
                return Ok(None);
            }
        }

        Ok(Some(req))
    }
}
