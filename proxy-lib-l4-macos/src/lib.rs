#![cfg(target_os = "macos")]

use std::net::IpAddr;

use rama::{
    net::{
        address::{Host, HostWithPort},
        apple::networkextension::{
            self as apple_ne,
            tproxy::{
                TransparentProxyConfig, TransparentProxyFlowMeta, TransparentProxyFlowProtocol,
                TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
            },
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

    const FD_LIMIT: rama::unix::utils::rlim_t = 262_144;
    if let Err(err) = rama::unix::utils::raise_nofile(FD_LIMIT) {
        tracing::error!("failed to increase FD limit for L4 (t)proxy: {err}");
    } else {
        tracing::info!("increased FD limit for L4 (t)proxy to: {FD_LIMIT}");
    }

    tracing::info!("aikido L4 proxy initialized: {init_status}");
    init_status
}

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
}

fn should_intercept_flow(meta: &TransparentProxyFlowMeta) -> bool {
    // we wish to intercept _only_ TCP traffic
    // that has a remote endpoint (such that we can make a outbound/egress connection to it)
    //
    // (in future once we can support h3 we will also need to intercept (some) UDP traffic)
    let should_intercept = meta.protocol == TransparentProxyFlowProtocol::Tcp
        && should_intercept_remote_endpoint(meta.remote_endpoint.as_ref());

    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        should_intercept,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow intercept decision: evaluating (rust callback entered)"
    );

    should_intercept
}

#[inline(always)]
fn should_intercept_remote_endpoint(remote_endpoint: Option<&HostWithPort>) -> bool {
    let Some(target) = remote_endpoint else {
        return false;
    };

    match &target.host {
        Host::Name(_) => true,
        Host::Address(IpAddr::V4(addr)) => !addr.is_loopback() && !addr.is_private(),
        Host::Address(IpAddr::V6(addr)) => !addr.is_loopback() && !addr.is_unique_local(),
    }
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    should_intercept_flow = should_intercept_flow,
    tcp_service = self::tcp::try_new_service,
}
