use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::{ProxyDriverConfigUpdate, ProxyDriverController};
use crate::wfp::{TcpRedirectDecision, WfpFlowMeta};

#[test]
fn passthrough_for_private_destinations() {
    let controller = ProxyDriverController::new();
    controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000), 1234);

    let flow = WfpFlowMeta {
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
        source_pid: Some(42),
        source_process_path: None,
    };

    assert!(matches!(
        controller.classify_outbound_tcp_connect(flow),
        TcpRedirectDecision::Passthrough
    ));
}

#[test]
fn redirects_public_destinations() {
    let controller = ProxyDriverController::new();
    controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000), 1234);

    let flow = WfpFlowMeta {
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        source_pid: Some(7),
        source_process_path: None,
    };

    let decision = controller.classify_outbound_tcp_connect(flow);
    assert!(matches!(decision, TcpRedirectDecision::Redirect { .. }));
}

#[test]
fn redirects_public_ipv6_destinations_when_ipv6_proxy_is_configured() {
    let controller = ProxyDriverController::new();
    controller.configure_proxy_ipv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15000, 0, 0), 5678);

    let flow = WfpFlowMeta {
        remote: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            443,
        ),
        source_pid: Some(77),
        source_process_path: None,
    };

    let decision = controller.classify_outbound_tcp_connect(flow);
    assert!(matches!(decision, TcpRedirectDecision::Redirect { .. }));
}

#[test]
fn runtime_update_can_clear_ipv6_without_touching_ipv4() {
    let controller = ProxyDriverController::new();
    controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000), 1234);
    controller.configure_proxy_ipv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15000, 0, 0), 5678);

    assert!(
        controller.apply_runtime_update(ProxyDriverConfigUpdate::SetIpv6 {
            proxy: None,
            pid: None,
        })
    );
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
