#![cfg(target_os = "macos")]

use std::net::IpAddr;

use rama::{
    net::{
        address::Host,
        apple::networkextension::{
            self as apple_ne,
            tproxy::{
                TransparentProxyConfig, TransparentProxyFlowAction, TransparentProxyFlowMeta,
                TransparentProxyFlowProtocol, TransparentProxyNetworkRule,
                TransparentProxyRuleProtocol,
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
    if !self::utils::init_tracing() {
        return false;
    }

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

    const FD_LIMIT: rama::unix::utils::rlim_t = 262_144;
    if let Err(err) = rama::unix::utils::raise_nofile(FD_LIMIT) {
        tracing::warn!("failed to increase FD limit for L4 (t)proxy: {err}");
    } else {
        tracing::info!("increased FD limit for L4 (t)proxy to: {FD_LIMIT}");
    }

    tracing::info!("aikido L4 proxy initialized");
    true
}

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
}

fn flow_action(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow intercept decision: evaluating (rust callback entered)"
    );

    if is_ip_remote_host_passthrough(meta) {
        return TransparentProxyFlowAction::Passthrough;
    }

    match meta.protocol {
        TransparentProxyFlowProtocol::Tcp => flow_action_tcp(meta),
        TransparentProxyFlowProtocol::Udp => flow_action_udp(meta),
    }
}

fn flow_action_tcp(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow action: tcp traffic: intercept all"
    );
    TransparentProxyFlowAction::Intercept
}

fn flow_action_udp(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow action: udp traffic: pass through"
    );
    TransparentProxyFlowAction::Passthrough
}

fn is_ip_remote_host_passthrough(meta: &TransparentProxyFlowMeta) -> bool {
    let Some(target) = meta.remote_endpoint.as_ref() else {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "remote host is missing: passthrough traffic"
        );
        return true;
    };

    match &target.host {
        Host::Name(_) => true,
        Host::Address(IpAddr::V4(addr)) => addr.is_loopback() || addr.is_private(),
        Host::Address(IpAddr::V6(addr)) => addr.is_loopback() || addr.is_unique_local(),
    }
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    flow_action = flow_action,
    tcp_service = self::tcp::try_new_service,
}
