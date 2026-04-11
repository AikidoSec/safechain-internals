use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::*;
use crate::driver::ProxyDriverController;

#[test]
fn parse_and_apply_ipv4_update() {
    let controller = ProxyDriverController::new();
    let payload = Ipv4ProxyConfigPayload::new(
        core::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15_000),
        4242,
    );
    let input = payload.to_bytes().expect("encode");

    let (status, _) = handle_device_control_ioctl(&controller, IOCTL_SET_IPV4_PROXY, &input);
    assert_eq!(status, STATUS_SUCCESS);
    assert!(
        controller
            .proxy_endpoint_for(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443))
            .is_some()
    );
}
