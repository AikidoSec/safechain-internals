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
        ("64:ff9b::808:808".parse().unwrap(), false),
        ("2001:4860:4860::8888".parse().unwrap(), false),
        ("2606:4700:4700::1111".parse().unwrap(), false),
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
