//! Helpers for IP ranges that should bypass public-Internet interception.
//!
//! The goal here is intentionally narrower than "all IANA special-purpose
//! addresses". Some IANA special-purpose blocks contain globally reachable
//! anycast or transition addresses, so treating the entire registry as
//! passthrough would be too broad for proxying.
//!
//! Instead, these helpers focus on ranges that are clearly not intended for
//! ordinary public-Internet destinations, such as loopback, private-use,
//! link-local, benchmarking, documentation, and other non-global blocks.
//!
//! References:
//! - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
//! - <https://www.iana.org/assignments/iana-ipv6-special-registry/>

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` when the address belongs to a range that should be treated as
/// passthrough instead of a normal public-Internet destination.
#[inline(always)]
#[must_use]
pub fn is_passthrough_ip(addr: impl Into<IpAddr>) -> bool {
    match addr.into() {
        IpAddr::V4(addr) => is_passthrough_ipv4(addr),
        IpAddr::V6(addr) => is_passthrough_ipv6(addr),
    }
}

/// Returns `true` for IPv6 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
///
/// This includes loopback, multicast, link-local, unique-local, unspecified,
/// documentation, benchmarking, and a few additional non-global special-use
/// ranges from the IANA IPv6 Special-Purpose Address Space registry.
#[must_use]
pub fn is_passthrough_ipv6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || addr.is_unspecified()
        || is_ipv6_site_local(addr)
        || is_ipv6_documentation(addr)
        || is_ipv6_benchmarking(addr)
        || is_ipv6_discard_only(addr)
        || is_ipv6_dummy_prefix(addr)
        || is_ipv6_local_use_translation(addr)
}

/// Returns `true` for IPv4 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
///
/// This includes the standard loopback/private/link-local/documentation ranges,
/// plus additional special-use blocks such as RFC 6598 shared space, RFC 2544
/// benchmarking space, IPv4 multicast, reserved `240.0.0.0/4`, `0.0.0.0/8`,
/// and the non-global sub-ranges under `192.0.0.0/24`.
#[must_use]
pub fn is_passthrough_ipv4(addr: Ipv4Addr) -> bool {
    if addr.is_loopback()
        || addr.is_private()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified()
        || addr.is_link_local()
        || addr.is_multicast()
        || is_ipv4_this_network(addr)
        || is_ipv4_shared(addr)
        || is_ipv4_protocol_assignments(addr)
        || is_ipv4_benchmarking(addr)
        || is_ipv4_reserved(addr)
    {
        return true;
    }

    false
}

#[inline(always)]
fn is_ipv4_this_network(addr: Ipv4Addr) -> bool {
    // RFC 791 / IANA "This network": 0.0.0.0/8.
    addr.octets()[0] == 0
}

#[inline(always)]
fn is_ipv4_shared(addr: Ipv4Addr) -> bool {
    // RFC 6598 shared address space: 100.64.0.0/10.
    let [a, b, ..] = addr.octets();
    a == 100 && (64..=127).contains(&b)
}

#[inline(always)]
fn is_ipv4_protocol_assignments(addr: Ipv4Addr) -> bool {
    // Conservatively cover only the clearly non-global allocations under
    // 192.0.0.0/24, leaving out the globally reachable anycast addresses
    // 192.0.0.9/32 and 192.0.0.10/32.
    let [a, b, c, d] = addr.octets();
    a == 192 && b == 0 && c == 0 && ((0..=8).contains(&d) || d == 170 || d == 171)
}

#[inline(always)]
fn is_ipv4_benchmarking(addr: Ipv4Addr) -> bool {
    // RFC 2544 benchmarking: 198.18.0.0/15.
    let [a, b, ..] = addr.octets();
    a == 198 && (b == 18 || b == 19)
}

#[inline(always)]
fn is_ipv4_reserved(addr: Ipv4Addr) -> bool {
    // IANA reserved/future-use block: 240.0.0.0/4.
    addr.octets()[0] >= 240
}

#[inline(always)]
fn is_ipv6_site_local(addr: Ipv6Addr) -> bool {
    // Deprecated site-local unicast: fec0::/10.
    (addr.segments()[0] & 0xffc0) == 0xfec0
}

#[inline(always)]
fn is_ipv6_documentation(addr: Ipv6Addr) -> bool {
    // RFC 3849 and RFC 9637 documentation blocks.
    let [a, b, c, d, ..] = addr.octets();
    (a == 0x20 && b == 0x01 && c == 0x0d && d == 0xb8)
        || (a == 0x3f && b == 0xff && (c & 0xf0) == 0x00)
}

#[inline(always)]
fn is_ipv6_benchmarking(addr: Ipv6Addr) -> bool {
    // RFC 5180 benchmarking: 2001:2::/48.
    let [a, b, c, d, e, f, ..] = addr.octets();
    a == 0x20 && b == 0x01 && c == 0x00 && d == 0x02 && e == 0x00 && f == 0x00
}

#[inline(always)]
fn is_ipv6_discard_only(addr: Ipv6Addr) -> bool {
    // RFC 6666 discard-only prefix: 100::/64.
    let segments = addr.segments();
    segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
}

#[inline(always)]
fn is_ipv6_dummy_prefix(addr: Ipv6Addr) -> bool {
    // RFC 9780 dummy prefix: 100:0:0:1::/64.
    let segments = addr.segments();
    segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 1
}

#[inline(always)]
fn is_ipv6_local_use_translation(addr: Ipv6Addr) -> bool {
    // RFC 8215 local-use translation prefix: 64:ff9b:1::/48.
    let segments = addr.segments();
    segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001
}

#[cfg(test)]
#[path = "ip_tests.rs"]
mod tests;
