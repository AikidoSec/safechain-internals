use core::net::Ipv4Addr;

use super::*;

#[test]
fn parses_blob_with_optional_ipv6_absent() {
    let blob = StartupConfig::new(
        core::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 15000),
        None,
    );
    let encoded = blob.to_bytes().expect("encode");
    let parsed = parse_startup_blob(&encoded).expect("blob should parse");
    assert!(matches!(parsed.proxy_ipv4, SocketAddr::V4(_)));
    assert!(parsed.proxy_ipv6.is_none());
}
