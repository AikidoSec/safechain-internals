//! Helpers for IP ranges that should bypass public-Internet interception.
//!
//! The goal here is intentionally narrower than "all IANA special-purpose
//! addresses". Some IANA special-purpose blocks contain globally reachable
//! anycast or transition addresses, so treating the entire registry as
//! passthrough would be too broad for proxying.
//!
//! References:
//! - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
//! - <https://www.iana.org/assignments/iana-ipv6-special-registry/>
//! - <https://tailscale.com/kb/1082/firewall-ports> (Tailscale DERP + log infra ranges)

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` when the address belongs to a range that should be treated as
/// passthrough instead of a normal public-Internet destination.
#[inline]
#[must_use]
pub fn is_passthrough_ip(addr: impl Into<IpAddr>) -> bool {
    match addr.into() {
        IpAddr::V4(addr) => is_passthrough_ipv4(addr),
        IpAddr::V6(addr) => is_passthrough_ipv6(addr),
    }
}

/// Returns `true` for IPv4 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
#[inline]
#[must_use]
pub fn is_passthrough_ipv4(addr: Ipv4Addr) -> bool {
    let val = u32::from(addr);

    addr.is_loopback()      // 127.0.0.0/8
        || addr.is_private()   // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || addr.is_link_local() // 169.254.0.0/16
        || addr.is_multicast()  // 224.0.0.0/4
        || addr.is_broadcast()  // 255.255.255.255
        || addr.is_documentation()
        || is_ipv4_this_network(val)
        || is_ipv4_shared(val)
        || is_ipv4_protocol_assignments(val)
        || is_ipv4_benchmarking(val)
        || is_ipv4_reserved(val)
        || is_ipv4_tailscale_infra(val)
}

/// Returns `true` for IPv6 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
#[inline]
#[must_use]
pub fn is_passthrough_ipv6(addr: Ipv6Addr) -> bool {
    let val = u128::from(addr);

    addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || addr.is_unspecified()
        || is_ipv6_site_local(val)
        || is_ipv6_documentation(val)
        || is_ipv6_benchmarking(val)
        || is_ipv6_discard_only(val)
        || is_ipv6_dummy_prefix(val)
        || is_ipv6_local_use_translation(val)
        || is_ipv6_tailscale_infra(val)
}

// --- IPv4 Helpers ---

#[inline(always)]
fn is_ipv4_this_network(val: u32) -> bool {
    // RFC 791 / IANA "This network": 0.0.0.0/8.
    val & 0xFF00_0000 == 0x0000_0000
}

#[inline(always)]
fn is_ipv4_shared(val: u32) -> bool {
    // RFC 6598 shared address space: 100.64.0.0/10.
    val & 0xFFC0_0000 == 0x6440_0000
}

#[inline(always)]
fn is_ipv4_protocol_assignments(val: u32) -> bool {
    // Conservatively cover only the clearly non-global allocations under
    // 192.0.0.0/24, leaving out the globally reachable anycast addresses
    // 192.0.0.9/32 and 192.0.0.10/32.
    if val & 0xFFFF_FF00 == 0xC000_0000 {
        let d = (val & 0xFF) as u8;
        // Exclude globally reachable .9 (PCP Anycast) and .10 (TURN Anycast)
        return (0..=8).contains(&d) || d == 170 || d == 171;
    }
    false
}

#[inline(always)]
fn is_ipv4_benchmarking(val: u32) -> bool {
    // RFC 2544 benchmarking: 198.18.0.0/15.
    val & 0xFFFE_0000 == 0xC612_0000
}

#[inline(always)]
fn is_ipv4_reserved(val: u32) -> bool {
    // IANA reserved/future-use block: 240.0.0.0/4.
    val & 0xF000_0000 == 0xF000_0000
}

#[inline(always)]
fn is_ipv4_tailscale_infra(val: u32) -> bool {
    // Tailscale DERP relay servers: 192.200.0.0/24
    // Tailscale log infrastructure (log.tailscale.com): 199.165.136.0/24
    // Both ranges are statically registered to Tailscale and used as DERP relay
    // and control-plane endpoints. Intercepting them delays WireGuard tunnel
    // recovery without any security benefit.
    // Ref: <https://tailscale.com/kb/1082/firewall-ports>
    (val & 0xFFFF_FF00 == 0xC0C8_0000)  // 192.200.0.0/24
        || (val & 0xFFFF_FF00 == 0xC7A5_8800) // 199.165.136.0/24
}

// --- IPv6 Helpers ---

#[inline(always)]
fn is_ipv6_site_local(val: u128) -> bool {
    // fec0::/10 (Deprecated, but non-global)
    (val >> 118) == 0x03fb
}

#[inline(always)]
fn is_ipv6_documentation(val: u128) -> bool {
    // 2001:db8::/32 (RFC 3849) or 3fff::/20 (RFC 9637)
    (val >> 96 == 0x2001_0db8) || (val >> 108 == 0x3fff0)
}

#[inline(always)]
fn is_ipv6_benchmarking(val: u128) -> bool {
    // RFC 5180 benchmarking: 2001:2::/48.
    (val >> 80) == 0x2001_0002_0000
}

#[inline(always)]
fn is_ipv6_discard_only(val: u128) -> bool {
    // RFC 6666 discard-only prefix: 100::/64.
    (val >> 64) == 0x0100_0000_0000_0000
}

#[inline(always)]
fn is_ipv6_dummy_prefix(val: u128) -> bool {
    // RFC 9780 dummy prefix: 100:0:0:1::/64.
    (val >> 64) == 0x0100_0000_0000_0001
}

#[inline(always)]
fn is_ipv6_local_use_translation(val: u128) -> bool {
    // RFC 8215 local-use translation prefix: 64:ff9b:1::/48.
    (val >> 80) == 0x0064_ff9b_0001
}

#[inline(always)]
fn is_ipv6_tailscale_infra(val: u128) -> bool {
    // Tailscale DERP relay servers: 2606:B740:49::/48
    // Tailscale log infrastructure (log.tailscale.com): 2606:B740:1::/48
    // IPv6 counterparts to the Tailscale-registered IPv4 DERP and log ranges.
    // Ref: <https://tailscale.com/kb/1082/firewall-ports>
    (val >> 80) == 0x2606_B740_0049  // 2606:B740:49::/48
        || (val >> 80) == 0x2606_B740_0001 // 2606:B740:1::/48
}

#[cfg(test)]
#[path = "ip_tests.rs"]
mod tests;
