use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use alloc::string::String;

use super::{ProxyDriverConfigUpdate, ProxyDriverController};
use crate::wfp::{TcpRedirectDecision, UdpAuthConnectDecision, WfpFlowMeta};

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

#[test]
fn process_exit_clears_matching_proxy_runtime_config() {
    let controller = ProxyDriverController::new();
    controller.configure_proxy_ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000), 1234);
    controller.configure_proxy_ipv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15000, 0, 0), 5678);

    controller.handle_process_exit(1234);
    assert!(
        controller
            .proxy_endpoint_for(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443))
            .is_none()
    );
    assert!(
        controller
            .proxy_endpoint_for(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                443,
            ))
            .is_some()
    );

    controller.handle_process_exit(5678);
    assert!(
        controller
            .proxy_endpoint_for(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
                443,
            ))
            .is_none()
    );
}

#[test]
fn blocks_udp_443_for_chromium_family_browsers() {
    let controller = ProxyDriverController::new();
    let flow = WfpFlowMeta {
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        source_pid: Some(42),
        source_process_path: Some(String::from(
            "\\Device\\HarddiskVolume4\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        )),
    };

    assert!(matches!(
        controller.classify_outbound_udp_connect(flow),
        UdpAuthConnectDecision::Block
    ));
}

#[test]
fn passes_udp_443_for_non_chromium_processes() {
    let controller = ProxyDriverController::new();
    let flow = WfpFlowMeta {
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        source_pid: Some(42),
        source_process_path: Some(String::from(
            "\\Device\\HarddiskVolume4\\Windows\\System32\\curl.exe",
        )),
    };

    assert!(matches!(
        controller.classify_outbound_udp_connect(flow),
        UdpAuthConnectDecision::Passthrough
    ));
}
