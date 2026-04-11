use alloc::vec::Vec;
use core::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use spin::RwLock;

use crate::wfp::{TcpRedirectDecision, WfpFlowMeta, build_redirect_context, is_local_destination};

#[derive(Debug, Clone, Copy)]
struct ProxyEndpoint {
    socket_addr: SocketAddr,
    process_id: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProxyEndpointState {
    ipv4: Option<ProxyEndpoint>,
    ipv6: Option<ProxyEndpoint>,
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
    pub proxy_ipv4_pid: u32,
    pub proxy_ipv6: Option<SocketAddrV6>,
    pub proxy_ipv6_pid: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyDriverConfigUpdate {
    SetIpv4 {
        proxy: SocketAddrV4,
        pid: u32,
    },
    SetIpv6 {
        proxy: Option<SocketAddrV6>,
        pid: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectTarget {
    pub socket_addr: SocketAddr,
    pub process_id: u32,
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

    pub fn configure_proxy_ipv4(&self, proxy: SocketAddrV4, pid: u32) {
        self.state.write().ipv4 = Some(ProxyEndpoint {
            socket_addr: SocketAddr::V4(proxy),
            process_id: pid,
        });
    }

    pub fn configure_proxy_ipv6(&self, proxy: SocketAddrV6, pid: u32) {
        self.state.write().ipv6 = Some(ProxyEndpoint {
            socket_addr: SocketAddr::V6(proxy),
            process_id: pid,
        });
    }

    pub fn clear_proxy_endpoint(&self) {
        *self.state.write() = ProxyEndpointState::default();
    }

    pub fn clear_proxy_ipv6_endpoint(&self) {
        self.state.write().ipv6 = None;
    }

    pub fn apply_startup_config(&self, config: ProxyDriverStartupConfig) {
        let mut state = self.state.write();

        state.ipv4 = Some(ProxyEndpoint {
            socket_addr: SocketAddr::V4(config.proxy_ipv4),
            process_id: config.proxy_ipv4_pid,
        });
        state.ipv6 = config
            .proxy_ipv6
            .zip(config.proxy_ipv6_pid)
            .map(|(proxy, pid)| ProxyEndpoint {
                socket_addr: SocketAddr::V6(proxy),
                process_id: pid,
            });

        crate::log::driver_log_info!(
            "apply startup config: ipv4={:?}; ipv6={:?}",
            state.ipv4,
            state.ipv6,
        );
    }

    pub fn apply_runtime_update(&self, update: ProxyDriverConfigUpdate) -> bool {
        let mut state = self.state.write();
        match update {
            ProxyDriverConfigUpdate::SetIpv4 {
                proxy: proxy_v4,
                pid,
            } => {
                crate::log::driver_log_info!(
                    "apply runtime update: set ipv4 proxy addr: {proxy_v4} (pid = {pid})",
                );
                state.ipv4 = Some(ProxyEndpoint {
                    socket_addr: SocketAddr::V4(proxy_v4),
                    process_id: pid,
                });
                true
            }
            ProxyDriverConfigUpdate::SetIpv6 {
                proxy: Some(proxy_v6),
                pid: Some(pid),
            } => {
                crate::log::driver_log_info!(
                    "apply runtime update: set ipv6 proxy addr: {proxy_v6} (pid = {pid})",
                );
                state.ipv6 = Some(ProxyEndpoint {
                    socket_addr: SocketAddr::V6(proxy_v6),
                    process_id: pid,
                });
                true
            }
            ProxyDriverConfigUpdate::SetIpv6 {
                proxy: None,
                pid: None,
            } => {
                crate::log::driver_log_info!("apply runtime update: unset ipv6 proxy addr");
                state.ipv6 = None;
                true
            }
            ProxyDriverConfigUpdate::SetIpv6 { .. } => false,
        }
    }

    pub fn proxy_endpoint_for(&self, remote: SocketAddr) -> Option<RedirectTarget> {
        let state = *self.state.read();
        match remote {
            SocketAddr::V4(_) => state.ipv4.map(|proxy| RedirectTarget {
                socket_addr: proxy.socket_addr,
                process_id: proxy.process_id,
            }),
            SocketAddr::V6(_) => state.ipv6.map(|proxy| RedirectTarget {
                socket_addr: proxy.socket_addr,
                process_id: proxy.process_id,
            }),
        }
    }

    pub fn has_ipv6_proxy(&self) -> bool {
        self.state.read().ipv6.is_some()
    }

    pub fn classify_outbound_tcp_connect(&self, flow: WfpFlowMeta) -> TcpRedirectDecision {
        if is_local_destination(flow.remote) {
            crate::log::driver_log_info!(
                "tcp: passthrough: local/private destination: {} (source pid = {:?}, source process = {:?})",
                flow.remote,
                flow.source_pid,
                flow.source_process_path,
            );
            return TcpRedirectDecision::Passthrough;
        }

        if flow.remote.port() == 53 {
            crate::log::driver_log_info!(
                "tcp: passthrough: DNS (port 53): {} (source pid = {:?}, source process = {:?})",
                flow.remote,
                flow.source_pid,
                flow.source_process_path,
            );
            return TcpRedirectDecision::Passthrough;
        }

        let Some(proxy_target) = self.proxy_endpoint_for(flow.remote) else {
            crate::log::driver_log_info!(
                "tcp: passthrough: no proxy configured for traffic: {} (source pid = {:?}, source process = {:?})",
                flow.remote,
                flow.source_pid,
                flow.source_process_path,
            );
            return TcpRedirectDecision::Passthrough;
        };

        if flow.source_pid == Some(proxy_target.process_id) {
            crate::log::driver_log_info!(
                "tcp: passthrough: cycle: {} (source pid = {:?}, source process = {:?})",
                flow.remote,
                flow.source_pid,
                flow.source_process_path,
            );
            return TcpRedirectDecision::Passthrough;
        }
        let redirect_context: Vec<u8> = match build_redirect_context(&flow) {
            Ok(bytes) => bytes,
            Err(err) => {
                crate::log::driver_log_error!(
                    "tcp: passthrough: failed to build redirect context (err = {err}): {} (source pid = {:?}, source process = {:?})",
                    flow.remote,
                    flow.source_pid,
                    flow.source_process_path,
                );
                return TcpRedirectDecision::Passthrough;
            }
        };

        crate::log::driver_log_info!(
            "tcp: redirect to L4 proxy @ {} (pid = {}): {} (source pid = {:?}, source process = {:?})",
            proxy_target.socket_addr,
            proxy_target.process_id,
            flow.remote,
            flow.source_pid,
            flow.source_process_path,
        );

        TcpRedirectDecision::Redirect {
            proxy_target: proxy_target.socket_addr,
            proxy_target_pid: proxy_target.process_id,
            redirect_context,
        }
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
