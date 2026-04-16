use alloc::vec::Vec;
use core::net::{SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl WindowsGuid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

pub const WFP_PROVIDER_SAFECHAIN_L4_PROXY: WindowsGuid = WindowsGuid::new(
    0x6a625bb6,
    0xf310,
    0x443e,
    [0x98, 0x50, 0x28, 0x0f, 0xac, 0xdc, 0x1a, 0x21],
);
pub const WFP_SUBLAYER_SAFECHAIN_L4_PROXY: WindowsGuid = WindowsGuid::new(
    0xd95a6eaf,
    0x3882,
    0x495f,
    [0x85, 0x8c, 0x65, 0xc2, 0xce, 0x3f, 0x6a, 0x07],
);
pub const WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V4: WindowsGuid = WindowsGuid::new(
    0x5c6262c4,
    0x8ef6,
    0x43d8,
    [0xa8, 0xf9, 0x48, 0x63, 0x6b, 0x17, 0x2b, 0xb8],
);
pub const WFP_CALLOUT_SAFECHAIN_TCP_CONNECT_REDIRECT_V6: WindowsGuid = WindowsGuid::new(
    0x4f05f1f8,
    0x9093,
    0x44f1,
    [0xa8, 0xe7, 0x2d, 0x84, 0x1a, 0x3e, 0x2e, 0x5a],
);
pub const WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V4: WindowsGuid = WindowsGuid::new(
    0xdb5b9241,
    0x4532,
    0x4517,
    [0xb0, 0xe0, 0x6f, 0x85, 0xe4, 0xe6, 0x31, 0xf8],
);
pub const WFP_FILTER_SAFECHAIN_TCP_CONNECT_REDIRECT_V6: WindowsGuid = WindowsGuid::new(
    0x4b60d58c,
    0x85fd,
    0x4fb1,
    [0x82, 0x56, 0x8c, 0x4e, 0x60, 0x53, 0xe4, 0x3a],
);
pub const WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4: WindowsGuid = WindowsGuid::new(
    0x87053c13,
    0x7c73,
    0x4e52,
    [0x8d, 0xdd, 0xf8, 0x2b, 0x38, 0x56, 0xef, 0x41],
);
pub const WFP_CALLOUT_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6: WindowsGuid = WindowsGuid::new(
    0x27b8a5fa,
    0x66b5,
    0x451c,
    [0xa5, 0x66, 0xb7, 0x94, 0x78, 0xb5, 0x2a, 0x81],
);
pub const WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V4: WindowsGuid = WindowsGuid::new(
    0xe4b805fc,
    0xb3ab,
    0x45e8,
    [0x8f, 0x04, 0x20, 0x0d, 0xcb, 0xc0, 0x09, 0x55],
);
pub const WFP_FILTER_SAFECHAIN_UDP_AUTH_CONNECT_BLOCK_V6: WindowsGuid = WindowsGuid::new(
    0xfcbab31f,
    0x7dfb,
    0x4128,
    [0x81, 0x96, 0x55, 0x9f, 0xe0, 0xe0, 0xe8, 0xb4],
);

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv4ProxyConfigPayload {
    V1 { proxy: SocketAddrV4, pid: u32 },
}

impl Ipv4ProxyConfigPayload {
    pub fn new(proxy: SocketAddrV4, pid: u32) -> Self {
        Self::V1 { proxy, pid }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn socket_addr(&self) -> SocketAddrV4 {
        match self {
            Self::V1 { proxy, .. } => *proxy,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            Self::V1 { pid, .. } => *pid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv6ProxyConfigPayload {
    V1 { proxy: SocketAddrV6, pid: u32 },
}

impl Ipv6ProxyConfigPayload {
    pub fn new(proxy: SocketAddrV6, pid: u32) -> Self {
        Self::V1 { proxy, pid }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn socket_addr(&self) -> SocketAddrV6 {
        match self {
            Self::V1 { proxy, .. } => *proxy,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            Self::V1 { pid, .. } => *pid,
        }
    }
}

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}
