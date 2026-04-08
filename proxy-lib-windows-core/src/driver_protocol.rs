use alloc::vec::Vec;
use core::net::{SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Serialize};

pub const STARTUP_VALUE_NAME: &str = "ProxyStartupConfigV1";

const FILE_DEVICE_SAFECHAIN_PROXY: u32 = 0x8000;
const FILE_ANY_ACCESS: u32 = 0;
const METHOD_BUFFERED: u32 = 0;

pub const IOCTL_SET_IPV4_PROXY: u32 = ctl_code(
    FILE_DEVICE_SAFECHAIN_PROXY,
    0x801,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_SET_IPV6_PROXY: u32 = ctl_code(
    FILE_DEVICE_SAFECHAIN_PROXY,
    0x802,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_CLEAR_IPV6_PROXY: u32 = ctl_code(
    FILE_DEVICE_SAFECHAIN_PROXY,
    0x803,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_SET_PROXY_PROCESS_ID: u32 = ctl_code(
    FILE_DEVICE_SAFECHAIN_PROXY,
    0x804,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);
pub const IOCTL_CLEAR_PROXY_PROCESS_ID: u32 = ctl_code(
    FILE_DEVICE_SAFECHAIN_PROXY,
    0x805,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StartupConfig {
    V1 {
        proxy_ipv4: SocketAddrV4,
        proxy_ipv6: Option<SocketAddrV6>,
    },
}

impl StartupConfig {
    pub fn new(proxy_ipv4: SocketAddrV4, proxy_ipv6: Option<SocketAddrV6>) -> Self {
        Self::V1 {
            proxy_ipv4,
            proxy_ipv6,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn proxy_ipv4(&self) -> SocketAddrV4 {
        match self {
            Self::V1 { proxy_ipv4, .. } => *proxy_ipv4,
        }
    }

    pub fn proxy_ipv6(&self) -> Option<SocketAddrV6> {
        match self {
            Self::V1 { proxy_ipv6, .. } => *proxy_ipv6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv4ProxyConfigPayload {
    V1 { proxy: SocketAddrV4 },
}

impl Ipv4ProxyConfigPayload {
    pub fn new(proxy: SocketAddrV4) -> Self {
        Self::V1 { proxy }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn socket_addr(&self) -> SocketAddrV4 {
        match self {
            Self::V1 { proxy } => *proxy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv6ProxyConfigPayload {
    V1 { proxy: SocketAddrV6 },
}

impl Ipv6ProxyConfigPayload {
    pub fn new(proxy: SocketAddrV6) -> Self {
        Self::V1 { proxy }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn socket_addr(&self) -> SocketAddrV6 {
        match self {
            Self::V1 { proxy } => *proxy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyProcessIdPayload {
    V1 { pid: u32 },
}

impl ProxyProcessIdPayload {
    pub fn new(pid: u32) -> Self {
        Self::V1 { pid }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn pid(&self) -> u32 {
        match self {
            Self::V1 { pid } => *pid,
        }
    }
}

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn startup_config_roundtrips() {
        let config = StartupConfig::new(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 15000),
            Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15001, 0, 0)),
        );

        let decoded =
            StartupConfig::from_bytes(&config.to_bytes().expect("encode")).expect("decode");
        assert_eq!(
            decoded.proxy_ipv4(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 15000)
        );
        assert_eq!(
            decoded.proxy_ipv6(),
            Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15001, 0, 0))
        );
    }
}
