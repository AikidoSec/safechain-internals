use std::borrow::Cow;

use rama::{
    error::OpaqueError,
    http::{Request, service::web::extract::Query},
    telemetry::tracing,
};
use serde::Deserialize;

use super::BlockRule;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BlockRuleChrome;

impl BlockRuleChrome {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// NOTE:
//
// - This list should probably come from a remote list of known malicious plugins
// - Is this a global name or do we also need to consider package owner name?
// - What about the version? Is that of importance?

// https://chromewebstore.google.com/detail/zoom-for-google-chrome/lajondecmobodlejlcjllhojikagldgd
const CHROME_BLOCKED_EXT_LIST: &[&str] = &["lajondecmobodlejlcjllhojikagldgd"];

#[derive(Deserialize)]
struct ChromeExtInfo<'a> {
    x: Cow<'a, str>,
}

impl BlockRule for BlockRuleChrome {
    async fn block_request(&self, req: Request) -> Result<Option<Request>, OpaqueError> {
        if let Some(query) = req.uri().query()
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
