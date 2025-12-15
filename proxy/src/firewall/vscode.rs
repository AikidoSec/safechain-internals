use rama::{
    error::OpaqueError, http::Request, telemetry::tracing,
    utils::str::starts_with_ignore_ascii_case,
};

use super::BlockRule;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BlockRuleVSCode;

impl BlockRuleVSCode {
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

const VSCODE_BLOCKED_EXT_LIST: &[&str] = &["python"];

impl BlockRule for BlockRuleVSCode {
    async fn block_request(&self, req: Request) -> Result<Option<Request>, OpaqueError> {
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
