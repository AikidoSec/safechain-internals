use super::is_passthrough_ipv4;
use std::net::Ipv4Addr;

#[test]
fn passthrough_includes_loopback_private_and_tailscale_cgnat() {
    let cases = [
        // loopback
        (Ipv4Addr::new(127, 0, 0, 1), true),
        // RFC-1918 private
        (Ipv4Addr::new(10, 0, 0, 1), true),
        (Ipv4Addr::new(172, 16, 0, 1), true),
        (Ipv4Addr::new(192, 168, 1, 1), true),
        // Tailscale CGNAT range (100.64.0.0/10)
        (Ipv4Addr::new(100, 64, 0, 1), true),
        (Ipv4Addr::new(100, 100, 12, 34), true),
        (Ipv4Addr::new(100, 127, 255, 254), true),
        // just outside CGNAT range
        (Ipv4Addr::new(100, 63, 255, 255), false),
        (Ipv4Addr::new(100, 128, 0, 1), false),
        // public internet
        (Ipv4Addr::new(8, 8, 8, 8), false),
        (Ipv4Addr::new(1, 1, 1, 1), false),
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ipv4(addr), expected, "addr: {addr}");
    }
}
