use alloc::string::String;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use safechain_proxy_lib_windows_core::redirect_ctx::ProxyRedirectContext;

use super::{WfpFlowMeta, build_redirect_context, is_local_destination};

#[test]
fn local_destination_detection_covers_common_ranges() {
    assert!(is_local_destination(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        80
    )));
    assert!(is_local_destination(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        80
    )));
    assert!(is_local_destination(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        443
    )));
}

#[test]
fn redirect_context_contains_destination_and_pid() {
    let flow = WfpFlowMeta {
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        source_pid: Some(123),
        source_process_path: Some(String::from("C:\\Windows\\System32\\curl.exe")),
    };
    let encoded = build_redirect_context(&flow).expect("encoding failed");
    let decoded: ProxyRedirectContext =
        postcard::from_bytes(&encoded).expect("context decode failed");
    assert_eq!(decoded.destination(), flow.remote);
    assert_eq!(decoded.source_pid(), Some(123));
    assert_eq!(
        decoded.source_process_path(),
        Some("C:\\Windows\\System32\\curl.exe")
    );
}
