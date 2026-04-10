use alloc::vec::Vec;
use core::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use spin::RwLock;

use crate::wfp::{TcpRedirectDecision, WfpFlowMeta, build_redirect_context, is_local_destination};

#[derive(Debug, Clone, Copy, Default)]
struct ProxyEndpointState {
    ipv4: Option<SocketAddrV4>,
    ipv6: Option<SocketAddrV6>,
}

/// Mutable driver-controlled state for WFP redirection.
///
/// The state is read often by classify callbacks and updated rarely by startup
/// config loading and IOCTL updates.
pub struct ProxyDriverController {
    state: RwLock<ProxyEndpointState>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProxyDriverStartupConfig {
    pub proxy_ipv4: SocketAddrV4,
    pub proxy_ipv6: Option<SocketAddrV6>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyDriverConfigUpdate {
    SetIpv4(SocketAddrV4),
    SetIpv6(Option<SocketAddrV6>),
}

impl Default for ProxyDriverController {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyDriverController {
    pub const fn new() -> Self {
        Self {
            state: RwLock::new(ProxyEndpointState {
                ipv4: None,
                ipv6: None,
            }),
        }
    }

    pub fn configure_proxy_ipv4(&self, proxy: SocketAddrV4) {
        self.state.write().ipv4 = Some(proxy);
    }

    pub fn configure_proxy_ipv6(&self, proxy: SocketAddrV6) {
        self.state.write().ipv6 = Some(proxy);
    }

    pub fn clear_proxy_endpoint(&self) {
        *self.state.write() = ProxyEndpointState::default();
    }

    pub fn clear_proxy_ipv6_endpoint(&self) {
        self.state.write().ipv6 = None;
    }

    pub fn apply_startup_config(&self, config: ProxyDriverStartupConfig) {
        let mut state = self.state.write();

        state.ipv4 = Some(config.proxy_ipv4);
        state.ipv6 = config.proxy_ipv6;

        crate::log::driver_log_info!(
            "apply startup config: ipv4={:?}; ipv6={:?}",
            state.ipv4,
            state.ipv6,
        );
    }

    pub fn apply_runtime_update(&self, update: ProxyDriverConfigUpdate) -> bool {
        let mut state = self.state.write();
        match update {
            ProxyDriverConfigUpdate::SetIpv4(proxy_v4) => {
                crate::log::driver_log_info!(
                    "apply runtime update: set ipv4 proxy addr: {proxy_v4}",
                );
                state.ipv4 = Some(proxy_v4);
                true
            }
            ProxyDriverConfigUpdate::SetIpv6(Some(proxy_v6)) => {
                crate::log::driver_log_info!(
                    "apply runtime update: set ipv6 proxy addr: {proxy_v6}",
                );
                state.ipv6 = Some(proxy_v6);
                true
            }
            ProxyDriverConfigUpdate::SetIpv6(None) => {
                crate::log::driver_log_info!("apply runtime update: unset ipv6 proxy addr",);
                state.ipv6 = None;
                true
            }
        }
    }

    pub fn proxy_endpoint_for(&self, remote: SocketAddr) -> Option<SocketAddr> {
        let state = *self.state.read();
        match remote {
            SocketAddr::V4(_) => state.ipv4.map(SocketAddr::V4),
            SocketAddr::V6(_) => state.ipv6.map(SocketAddr::V6),
        }
    }

    pub fn has_ipv6_proxy(&self) -> bool {
        self.state.read().ipv6.is_some()
    }

    pub fn classify_outbound_tcp_connect(&self, flow: WfpFlowMeta) -> TcpRedirectDecision {
        if is_local_destination(flow.remote) {
            crate::log::driver_log_info!(
                "tcp: passthrough: local/private destination: {} (source pid = {:?})",
                flow.remote,
                flow.source_pid,
            );
            return TcpRedirectDecision::Passthrough;
        }

        let Some(proxy_target) = self.proxy_endpoint_for(flow.remote) else {
            crate::log::driver_log_info!(
                "tcp: passthrough: no proxy configured for traffic: {} (source pid = {:?})",
                flow.remote,
                flow.source_pid,
            );
            return TcpRedirectDecision::Passthrough;
        };

        if flow.remote == proxy_target {
            crate::log::driver_log_info!(
                "tcp: passthrough: cycle: {} (source pid = {:?})",
                flow.remote,
                flow.source_pid,
            );
            return TcpRedirectDecision::Passthrough;
        }
        let redirect_context: Vec<u8> = match build_redirect_context(&flow) {
            Ok(bytes) => bytes,
            Err(err) => {
                crate::log::driver_log_error!(
                    "tcp: passthrough: failed to build redirect context (err = {err}): {} (source pid = {:?})",
                    flow.remote,
                    flow.source_pid,
                );
                return TcpRedirectDecision::Passthrough;
            }
        };

        crate::log::driver_log_info!(
            "tcp: redirect to L4 proxy @ {proxy_target}: {} (source pid = {:?})",
            flow.remote,
            flow.source_pid,
        );

        TcpRedirectDecision::Redirect {
            proxy_target,
            redirect_context,
        }
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
