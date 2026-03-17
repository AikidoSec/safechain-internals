#![cfg(target_vendor = "apple")]
#![cfg(target_os = "macos")]

use rama::{
    net::apple::networkextension::{
        self as apple_ne,
        tproxy::{
            TransparentProxyConfig, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
            TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
        },
    },
    telemetry::tracing,
};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod config;
mod tcp;
mod utils;

fn init(config: Option<&apple_ne::ffi::tproxy::TransparentProxyInitConfig>) -> bool {
    if let Some(config) = config {
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(path) = unsafe { config.storage_dir() } {
            tracing::debug!(path = %path.display(), "received storage directory: pass to set_storage_dir");
            self::utils::storage::set_storage_dir(Some(path));
        }
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(app_group_dir) = unsafe { config.app_group_dir() } {
            tracing::debug!(path = %app_group_dir.display(), "received app-group directory");
        }
    }

    let init_status = self::utils::init_tracing();
    tracing::info!("aikido L4 proxy initialized: {init_status}");
    init_status
}

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
}

fn should_intercept_flow(meta: &TransparentProxyFlowMeta) -> bool {
    tracing::trace!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        "flow intercept decision: evaluating (rust callback entered)"
    );

    if meta.protocol != TransparentProxyFlowProtocol::Tcp {
        return false;
    }

    if meta.remote_endpoint.is_none() {
        return false;
    };

    true
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    should_intercept_flow = should_intercept_flow,
    tcp_service = self::tcp::try_new_service,
}
