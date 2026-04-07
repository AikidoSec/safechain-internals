use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
    pub proxy_ipv4: SocketAddr,
    pub proxy_ipv6: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProxyDriverConfigUpdate {
    SetIpv4(SocketAddr),
    SetIpv6(Option<SocketAddr>),
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

    pub fn apply_startup_config(&self, config: ProxyDriverStartupConfig) -> bool {
        let SocketAddr::V4(proxy_v4) = config.proxy_ipv4 else {
            return false;
        };

        let mut state = self.state.write();
        state.ipv4 = Some(proxy_v4);
        state.ipv6 = match config.proxy_ipv6 {
            Some(SocketAddr::V6(proxy_v6)) => Some(proxy_v6),
            Some(SocketAddr::V4(_)) => return false,
            None => None,
        };
        true
    }

    pub fn apply_runtime_update(&self, update: ProxyDriverConfigUpdate) -> bool {
        let mut state = self.state.write();
        match update {
            ProxyDriverConfigUpdate::SetIpv4(SocketAddr::V4(proxy_v4)) => {
                state.ipv4 = Some(proxy_v4);
                true
            }
            ProxyDriverConfigUpdate::SetIpv4(SocketAddr::V6(_)) => false,
            ProxyDriverConfigUpdate::SetIpv6(Some(SocketAddr::V6(proxy_v6))) => {
                state.ipv6 = Some(proxy_v6);
                true
            }
            ProxyDriverConfigUpdate::SetIpv6(Some(SocketAddr::V4(_))) => false,
            ProxyDriverConfigUpdate::SetIpv6(None) => {
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
            return TcpRedirectDecision::Passthrough;
        }

        let Some(proxy_target) = self.proxy_endpoint_for(flow.remote) else {
            return TcpRedirectDecision::Passthrough;
        };

        if flow.remote == proxy_target {
            return TcpRedirectDecision::Passthrough;
        }

        let redirect_context: Vec<u8> = match build_redirect_context(&flow) {
            Ok(bytes) => bytes,
            Err(_) => return TcpRedirectDecision::Passthrough,
        };

        TcpRedirectDecision::Redirect {
            proxy_target,
            redirect_context,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::{ProxyDriverConfigUpdate, ProxyDriverController, ProxyDriverStartupConfig};
    use crate::wfp::{TcpRedirectDecision, WfpFlowMeta};

    #[test]
    fn passthrough_for_private_destinations() {
        let controller = ProxyDriverController::new();
        controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000));

        let flow = WfpFlowMeta {
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            source_pid: Some(42),
            source_process_path: None,
            source_original_process_path: None,
        };

        assert!(matches!(
            controller.classify_outbound_tcp_connect(flow),
            TcpRedirectDecision::Passthrough
        ));
    }

    #[test]
    fn redirects_public_destinations() {
        let controller = ProxyDriverController::new();
        controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000));

        let flow = WfpFlowMeta {
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            source_pid: Some(7),
            source_process_path: None,
            source_original_process_path: None,
        };

        let decision = controller.classify_outbound_tcp_connect(flow);
        assert!(matches!(decision, TcpRedirectDecision::Redirect { .. }));
    }

    #[test]
    fn redirects_public_ipv6_destinations_when_ipv6_proxy_is_configured() {
        let controller = ProxyDriverController::new();
        controller.configure_proxy_ipv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15000, 0, 0));

        let flow = WfpFlowMeta {
            remote: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                443,
            ),
            source_pid: Some(77),
            source_process_path: None,
            source_original_process_path: None,
        };

        let decision = controller.classify_outbound_tcp_connect(flow);
        assert!(matches!(decision, TcpRedirectDecision::Redirect { .. }));
    }

    #[test]
    fn startup_config_requires_ipv4_address_family() {
        let controller = ProxyDriverController::new();
        assert!(!controller.apply_startup_config(ProxyDriverStartupConfig {
            proxy_ipv4: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 15000),
            proxy_ipv6: None,
        }));
    }

    #[test]
    fn runtime_update_can_clear_ipv6_without_touching_ipv4() {
        let controller = ProxyDriverController::new();
        controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000));
        controller.configure_proxy_ipv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15000, 0, 0));

        assert!(controller.apply_runtime_update(ProxyDriverConfigUpdate::SetIpv6(None)));
        assert!(
            controller
                .proxy_endpoint_for(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443))
                .is_some()
        );
        assert!(
            controller
                .proxy_endpoint_for(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                    443,
                ))
                .is_none()
        );
    }
}
