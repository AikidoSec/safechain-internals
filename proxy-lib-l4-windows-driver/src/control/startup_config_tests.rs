use core::net::Ipv4Addr;

use super::*;

#[test]
fn parses_blob_with_optional_ipv6_absent() {
    let blob = StartupConfig::new(
        core::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000),
        4242,
        None,
    );
    let encoded = blob.to_bytes().expect("encode");
    let parsed = parse_startup_blob(&encoded).expect("blob should parse");
    assert_eq!(parsed.proxy_ipv4_pid, 4242);
    assert!(parsed.proxy_ipv6.is_none());
    assert!(parsed.proxy_ipv6_pid.is_none());
}
