use std::fmt;

use rama::{
    error::OpaqueError,
    http::Request,
    net::address::{Domain, DomainTrie},
    telemetry::tracing,
    utils::str::starts_with_ignore_ascii_case,
};

use crate::storage::SyncCompactDataStorage;

use super::BlockRule;

#[expect(dead_code)]
pub(in crate::firewall) struct BlockRuleVSCode {
    data: SyncCompactDataStorage,
    target_domains: DomainTrie<()>,
}

impl BlockRuleVSCode {
    #[must_use]
    pub(in crate::firewall) fn new(data: SyncCompactDataStorage) -> Self {
        Self {
            data,
            target_domains: ["gallery.vsassets.io", "gallerycdn.vsassets.io"]
                .into_iter()
                .map(|domain| (Domain::from_static(domain), ()))
                .collect(),
        }
    }
}

impl fmt::Debug for BlockRuleVSCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockRuleVSCode").finish()
    }
}

// NOTE:
//
// - This list should probably come from a remote list of known malicious plugins
// - Is this a global name or do we also need to consider package owner name?
// - What about the version? Is that of importance?

const VSCODE_BLOCKED_EXT_LIST: &[&str] = &["python"];

impl BlockRule for BlockRuleVSCode {
    #[inline(always)]
    fn product_name(&self) -> &'static str {
        "VSCode"
    }

    #[inline(always)]
    fn match_domain(&self, domain: &Domain) -> bool {
        self.target_domains.is_match_parent(domain)
    }

    async fn block_request(&self, req: Request) -> Result<Option<Request>, OpaqueError> {
        if !crate::firewall::utils::try_get_domain_for_req(&req)
            .map(|domain| self.match_domain(&domain))
            .unwrap_or_default()
        {
            tracing::trace!("VSCode rule did not match incoming request: passthrough");
            return Ok(Some(req));
        }

        let path = req.uri().path().trim_start_matches('/');
        if !starts_with_ignore_ascii_case(path, "extensions/") {
            tracing::debug!("VSCode url: path no match: {path}; passthrough");
            return Ok(Some(req));
        }

        let Some(plugin_name) = path.split('/').nth(2) else {
            tracing::debug!("VSCode url: plugin name not found in uri path: {path}; passthrough");
            return Ok(Some(req));
        };

        let plugin_name = plugin_name.trim();
        if VSCODE_BLOCKED_EXT_LIST
            .iter()
            .any(|c| c.eq_ignore_ascii_case(plugin_name))
        {
            tracing::debug!("blocked VSCode plugin: {plugin_name}");
            return Ok(None);
        }

        tracing::debug!("VSCode url: plugin {plugin_name}: blocked");
        Ok(Some(req))
    }
}
