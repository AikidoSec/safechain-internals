#![cfg(target_os = "macos")]

use std::net::{IpAddr, Ipv4Addr};

use rama::{
    net::{
        address::{Host, HostWithPort},
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
    utils::str::any_starts_with_ignore_ascii_case,
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
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Udp),
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

    let Some(remote_host) = is_ip_remote_host_passthrough(meta) else {
        return TransparentProxyFlowAction::Passthrough;
    };

    match meta.protocol {
        TransparentProxyFlowProtocol::Tcp => flow_action_tcp(meta),
        TransparentProxyFlowProtocol::Udp => flow_action_udp(meta, remote_host),
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

fn flow_action_udp(
    meta: &TransparentProxyFlowMeta,
    remote_host: HostWithPort,
) -> TransparentProxyFlowAction {
    if remote_host.port != 443 {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "flow action: udp traffic w/ port != 443: pass through"
        );
        return TransparentProxyFlowAction::Passthrough;
    }

    if meta
        .source_app_bundle_identifier
        .as_deref()
        .map(|identifier| {
            any_starts_with_ignore_ascii_case(
                identifier,
                [
                    // Google Chrome
                    "com.google.chrome",
                    // Chromium and forks that reuse upstream id
                    "org.chromium",
                    // Microsoft Edge
                    "com.microsoft.edgemac",
                    "com.microsoft.msedge",
                    // Brave
                    "com.brave.browser",
                    "com.brave.ios",
                    // Opera
                    "com.operasoftware.opera",
                    // Vivaldi
                    "com.vivaldi",
                    // Arc
                    "company.thebrowser",
                    // Yandex
                    "ru.yandex",
                    // Common alt Chromium builds
                    "com.github.eloston", // ungoogled chromium
                ],
            )
        })
        .unwrap_or_default()
    {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "flow action: udp traffic @ port 443: chromium browser detected via source app bundle id: block"
        );
        return TransparentProxyFlowAction::Blocked;
    }

    // NOTE: if we bundle id turns out to not be reliable,
    // we can also start to check the source app's FS path (location),
    // based on the audit token... this has however a bundle syscall cost...
    // so hopefully we can avoid it

    tracing::debug!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        app_bundle_id = ?meta.source_app_bundle_identifier,
        app_sign_id = ?meta.source_app_signing_identifier,
        "flow action: udp traffic @ port 443: pass through, chrome not detected"
    );
    TransparentProxyFlowAction::Passthrough
}

fn is_ip_remote_host_passthrough(meta: &TransparentProxyFlowMeta) -> Option<HostWithPort> {
    let Some(target) = meta.remote_endpoint.as_ref() else {
        tracing::debug!(
            protocol = ?meta.protocol,
            remote = ?meta.remote_endpoint,
            local = ?meta.local_endpoint,
            app_bundle_id = ?meta.source_app_bundle_identifier,
            app_sign_id = ?meta.source_app_signing_identifier,
            "remote host is missing: passthrough traffic"
        );
        return None;
    };

    match &target.host {
        Host::Name(_) => return None,
        Host::Address(IpAddr::V4(addr)) => {
            if is_passthrough_ipv4(*addr) {
                tracing::debug!(
                    protocol = ?meta.protocol,
                    remote = ?meta.remote_endpoint,
                    local = ?meta.local_endpoint,
                    app_bundle_id = ?meta.source_app_bundle_identifier,
                    app_sign_id = ?meta.source_app_signing_identifier,
                    "remote host is within passthrough IPv4 range: passthrough traffic"
                );
                return None;
            }
        }
        Host::Address(IpAddr::V6(addr)) => {
            if addr.is_loopback() || addr.is_unique_local() {
                tracing::debug!(
                    protocol = ?meta.protocol,
                    remote = ?meta.remote_endpoint,
                    local = ?meta.local_endpoint,
                    app_bundle_id = ?meta.source_app_bundle_identifier,
                    app_sign_id = ?meta.source_app_signing_identifier,
                    "remote host is within passthrough IPv6 range: passthrough traffic"
                );
                return None;
            }
        }
    }

    Some(target.clone())
}

fn is_passthrough_ipv4(addr: Ipv4Addr) -> bool {
    if addr.is_loopback() || addr.is_private() {
        return true;
    }
    // Tailscale peer IPs come from the IETF shared address space (RFC 6598).
    // `is_private()` only covers RFC-1918, so this range needs an explicit check.
    // https://tailscale.com/docs/concepts/tailscale-ip-addresses
    let [a, b, ..] = addr.octets();
    a == 100 && (64..=127).contains(&b)
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    flow_action = flow_action,
    tcp_service = self::tcp::try_new_service,
}

#[cfg(test)]
#[path = "./lib_tests.rs"]
mod tests;
