use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{is_passthrough_ip, is_passthrough_ipv4, is_passthrough_ipv6};

#[test]
fn passthrough_ipv4_includes_non_public_ranges() {
    let cases = [
        // loopback
        (Ipv4Addr::new(127, 0, 0, 1), true),
        // RFC-1918 private
        (Ipv4Addr::new(10, 0, 0, 1), true),
        (Ipv4Addr::new(172, 16, 0, 1), true),
        (Ipv4Addr::new(192, 168, 1, 1), true),
        // RFC 791 this-network space
        (Ipv4Addr::new(0, 1, 2, 3), true),
        // RFC 6598 shared address space
        (Ipv4Addr::new(100, 64, 0, 1), true),
        (Ipv4Addr::new(100, 100, 12, 34), true),
        (Ipv4Addr::new(100, 127, 255, 254), true),
        // special protocol assignment sub-ranges that are not globally reachable
        (Ipv4Addr::new(192, 0, 0, 3), true),
        (Ipv4Addr::new(192, 0, 0, 8), true),
        (Ipv4Addr::new(192, 0, 0, 170), true),
        (Ipv4Addr::new(192, 0, 0, 171), true),
        // benchmarking
        (Ipv4Addr::new(198, 18, 0, 1), true),
        (Ipv4Addr::new(198, 19, 255, 254), true),
        // multicast
        (Ipv4Addr::new(224, 0, 0, 1), true),
        // reserved/future use
        (Ipv4Addr::new(250, 10, 20, 30), true),
        // just outside non-public ranges
        (Ipv4Addr::new(100, 63, 255, 255), false),
        (Ipv4Addr::new(100, 128, 0, 1), false),
        (Ipv4Addr::new(192, 0, 0, 9), false),
        (Ipv4Addr::new(192, 0, 0, 10), false),
        (Ipv4Addr::new(198, 17, 255, 255), false),
        (Ipv4Addr::new(198, 20, 0, 0), false),
        // public internet
        (Ipv4Addr::new(8, 8, 8, 8), false),
        (Ipv4Addr::new(1, 1, 1, 1), false),
        // explicit anycast/global
        (Ipv4Addr::new(192, 88, 99, 1), false), // 6to4 Relay Anycast (RFC 3068)
        (Ipv4Addr::new(192, 31, 196, 1), false), // AS112-v4 Anycast (RFC 7535)
        (Ipv4Addr::new(198, 51, 100, 1), true), // TEST-NET-2 (Globally unreachable, but documentation)
        (Ipv4Addr::new(192, 52, 193, 1), false), // AMT Anycast (RFC 7450)
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ipv4(addr), expected, "addr: {addr}");
    }
}

#[test]
fn passthrough_ipv4_boundary_cases_are_correct() {
    let cases = [
        (Ipv4Addr::new(0, 0, 0, 0), true),
        (Ipv4Addr::new(0, 255, 255, 255), true),
        (Ipv4Addr::new(100, 64, 0, 0), true),
        (Ipv4Addr::new(100, 127, 255, 255), true),
        (Ipv4Addr::new(100, 63, 255, 255), false),
        (Ipv4Addr::new(100, 128, 0, 0), false),
        (Ipv4Addr::new(192, 0, 0, 0), true),
        (Ipv4Addr::new(192, 0, 0, 8), true),
        (Ipv4Addr::new(192, 0, 0, 9), false),
        (Ipv4Addr::new(192, 0, 0, 10), false),
        (Ipv4Addr::new(192, 0, 0, 11), false),
        (Ipv4Addr::new(192, 0, 0, 170), true),
        (Ipv4Addr::new(192, 0, 0, 171), true),
        (Ipv4Addr::new(192, 0, 0, 172), false),
        (Ipv4Addr::new(198, 18, 0, 0), true),
        (Ipv4Addr::new(198, 19, 255, 255), true),
        (Ipv4Addr::new(198, 17, 255, 255), false),
        (Ipv4Addr::new(198, 20, 0, 0), false),
        (Ipv4Addr::new(223, 255, 255, 255), false),
        (Ipv4Addr::new(224, 0, 0, 0), true),
        (Ipv4Addr::new(239, 255, 255, 255), true),
        (Ipv4Addr::new(240, 0, 0, 0), true),
        (Ipv4Addr::new(255, 255, 255, 254), true),
        (Ipv4Addr::new(255, 255, 255, 255), true),
        (Ipv4Addr::new(172, 15, 255, 255), false),
        (Ipv4Addr::new(172, 16, 0, 0), true),
        (Ipv4Addr::new(172, 31, 255, 255), true),
        (Ipv4Addr::new(172, 32, 0, 0), false),
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ipv4(addr), expected, "addr: {addr}");
    }
}

#[test]
fn passthrough_ipv6_includes_non_public_ranges() {
    let cases = [
        (Ipv6Addr::LOCALHOST, true),
        (Ipv6Addr::UNSPECIFIED, true),
        ("fc00::1".parse().unwrap(), true),
        ("fe80::1".parse().unwrap(), true),
        ("ff02::1".parse().unwrap(), true),
        ("fec0::1".parse().unwrap(), true),
        ("2001:db8::1".parse().unwrap(), true),
        ("3fff::1".parse().unwrap(), true),
        ("2001:2::1".parse().unwrap(), true),
        ("100::1".parse().unwrap(), true),
        ("100:0:0:1::1".parse().unwrap(), true),
        ("64:ff9b:1::1".parse().unwrap(), true),
        ("64:ff9b::1".parse().unwrap(), false), // Generic NAT64 (Global)
        ("64:ff9b::808:808".parse().unwrap(), false),
        ("2001:4860:4860::8888".parse().unwrap(), false),
        ("2606:4700:4700::1111".parse().unwrap(), false),
        ("2001:0::1".parse().unwrap(), false),  // Teredo
        ("2001:20::1".parse().unwrap(), false), // ORCHIDv2
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ipv6(addr), expected, "addr: {addr}");
    }
}

#[test]
fn passthrough_ipv6_boundary_cases_are_correct() {
    let cases = [
        ("febf:ffff:ffff:ffff::1".parse().unwrap(), true),
        ("fec0::".parse().unwrap(), true),
        ("feff:ffff:ffff:ffff::1".parse().unwrap(), true),
        ("2001:db7:ffff::1".parse().unwrap(), false),
        ("2001:db8::".parse().unwrap(), true),
        ("2001:db8:ffff:ffff::1".parse().unwrap(), true),
        ("2001:db9::1".parse().unwrap(), false),
        ("3ffe:ffff::1".parse().unwrap(), false),
        ("3fff::".parse().unwrap(), true),
        ("3fff:0fff:ffff:ffff::1".parse().unwrap(), true),
        ("3fff:1000::1".parse().unwrap(), false),
        ("4000::1".parse().unwrap(), false),
        ("2001:2::".parse().unwrap(), true),
        ("2001:2:0:1::1".parse().unwrap(), true),
        ("2001:2:1::1".parse().unwrap(), false),
        ("100::".parse().unwrap(), true),
        ("100::ffff".parse().unwrap(), true),
        ("100:0:0:1::".parse().unwrap(), true),
        ("100:0:0:2::1".parse().unwrap(), false),
        ("64:ff9b:1::".parse().unwrap(), true),
        ("64:ff9b:1:ffff::1".parse().unwrap(), true),
        ("64:ff9b:2::1".parse().unwrap(), false),
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ipv6(addr), expected, "addr: {addr}");
    }
}

#[test]
fn passthrough_ip_dispatches_to_both_versions() {
    let cases = [
        (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), false),
        (IpAddr::V6("fc00::1".parse().unwrap()), true),
        (IpAddr::V6("2001:4860:4860::8888".parse().unwrap()), false),
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ip(addr), expected, "addr: {addr}");
    }
}

#[test]
fn defensive_anycast_and_transition_checks() {
    let cases = [
        // IPv4 Anycast that should NOT be passthrough
        (IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1)), false), // 6to4 Anycast
        (IpAddr::V4(Ipv4Addr::new(192, 31, 196, 1)), false), // AS112 Anycast
        (IpAddr::V4(Ipv4Addr::new(192, 52, 193, 1)), false), // AMT Anycast
        // IPv6 Transition/Anycast that should NOT be passthrough
        (IpAddr::V6("2001:0::1".parse().unwrap()), false), // Teredo
        (IpAddr::V6("2001:1::1".parse().unwrap()), false), // Port Control Protocol
        (IpAddr::V6("2620:4f:8000::1".parse().unwrap()), false), // AS112-v6
        (IpAddr::V6("64:ff9b::1".parse().unwrap()), false), // Well-Known NAT64
    ];

    for (addr, expected) in cases {
        assert_eq!(is_passthrough_ip(addr), expected, "addr: {addr}");
    }
}

#[test]
fn test_trait_dispatch_consistency() {
    // Verify that passing raw arrays works as expected via Into<IpAddr>
    assert!(is_passthrough_ip([127, 0, 0, 1]));
    assert!(!is_passthrough_ip([8, 8, 8, 8]));
}

#[test]
fn passthrough_tailscale_infra_ranges() {
    // Tailscale DERP relay: 192.200.0.0/24
    // Tailscale log infra: 199.165.136.0/24
    // Ref: https://tailscale.com/kb/1082/firewall-ports
    let ipv4_cases = [
        // 192.200.0.0/24 — DERP relay servers
        (Ipv4Addr::new(192, 200, 0, 0), true),
        (Ipv4Addr::new(192, 200, 0, 1), true),
        (Ipv4Addr::new(192, 200, 0, 255), true),
        // just outside
        (Ipv4Addr::new(192, 199, 255, 255), false),
        (Ipv4Addr::new(192, 201, 0, 0), false),
        // 199.165.136.0/24 — log.tailscale.com
        (Ipv4Addr::new(199, 165, 136, 0), true),
        (Ipv4Addr::new(199, 165, 136, 100), true),
        (Ipv4Addr::new(199, 165, 136, 255), true),
        // just outside
        (Ipv4Addr::new(199, 165, 135, 255), false),
        (Ipv4Addr::new(199, 165, 137, 0), false),
    ];

    for (addr, expected) in ipv4_cases {
        assert_eq!(is_passthrough_ipv4(addr), expected, "addr: {addr}");
    }

    // Tailscale DERP relay: 2606:B740:49::/48
    // Tailscale log infra: 2606:B740:1::/48
    let ipv6_cases: &[(&str, bool)] = &[
        // 2606:B740:49::/48 — DERP relay servers
        ("2606:b740:49::", true),
        ("2606:b740:49::1", true),
        ("2606:b740:49:ffff:ffff:ffff:ffff:ffff", true),
        // just outside
        ("2606:b740:48:ffff::1", false),
        ("2606:b740:4a::1", false),
        // 2606:B740:1::/48 — log.tailscale.com
        ("2606:b740:1::", true),
        ("2606:b740:1::1", true),
        ("2606:b740:1:ffff:ffff:ffff:ffff:ffff", true),
        // just outside
        ("2606:b740:0:ffff::1", false),
        ("2606:b740:2::1", false),
    ];

    for (addr_str, expected) in ipv6_cases {
        let addr: Ipv6Addr = addr_str.parse().unwrap();
        assert_eq!(is_passthrough_ipv6(addr), *expected, "addr: {addr_str}");
    }
}
