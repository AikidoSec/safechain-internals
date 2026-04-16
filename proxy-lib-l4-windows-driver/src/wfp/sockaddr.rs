use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::ffi::{AF_INET, AF_INET6, SockAddrStorage};

pub(crate) unsafe fn sockaddr_storage_to_socket_addr(
    storage: &SockAddrStorage,
) -> Option<SocketAddr> {
    let bytes = storage_bytes(storage);
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        AF_INET => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = Ipv4Addr::from([bytes[4], bytes[5], bytes[6], bytes[7]]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let scope_id = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            let addr = Ipv6Addr::from([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
                bytes[22], bytes[23],
            ]);
            Some(SocketAddr::new(IpAddr::V6(addr), port).set_ip_scope_id(scope_id))
        }
        _ => None,
    }
}

pub(crate) fn write_socket_addr_to_storage(storage: &mut SockAddrStorage, socket_addr: SocketAddr) {
    let bytes = storage_bytes_mut(storage);
    bytes.fill(0);
    match socket_addr {
        SocketAddr::V4(addr) => {
            bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            bytes[2..4].copy_from_slice(&addr.port().to_be_bytes());
            bytes[8..24].copy_from_slice(&addr.ip().octets());
            bytes[24..28].copy_from_slice(&addr.scope_id().to_ne_bytes());
        }
    }
}

pub(crate) fn sockaddr_storage_family(storage: &SockAddrStorage) -> u16 {
    let bytes = storage_bytes(storage);
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn storage_bytes(storage: &SockAddrStorage) -> &[u8; 128] {
    unsafe {
        // SAFETY: `sockaddr_storage` is a 128-byte plain old data buffer on Windows.
        &*(storage as *const SockAddrStorage).cast::<[u8; 128]>()
    }
}

fn storage_bytes_mut(storage: &mut SockAddrStorage) -> &mut [u8; 128] {
    unsafe {
        // SAFETY: `sockaddr_storage` is a 128-byte plain old data buffer on Windows.
        &mut *(storage as *mut SockAddrStorage).cast::<[u8; 128]>()
    }
}

trait SocketAddrExt {
    fn set_ip_scope_id(self, scope_id: u32) -> SocketAddr;
}

impl SocketAddrExt for SocketAddr {
    fn set_ip_scope_id(self, scope_id: u32) -> SocketAddr {
        match self {
            SocketAddr::V4(addr) => SocketAddr::V4(addr),
            SocketAddr::V6(addr) => SocketAddr::V6(addr.set_scope_id(scope_id)),
        }
    }
}

trait SocketAddrV6Ext {
    fn set_scope_id(self, scope_id: u32) -> core::net::SocketAddrV6;
}

impl SocketAddrV6Ext for core::net::SocketAddrV6 {
    fn set_scope_id(self, scope_id: u32) -> core::net::SocketAddrV6 {
        core::net::SocketAddrV6::new(*self.ip(), self.port(), self.flowinfo(), scope_id)
    }
}
