use core::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
/// Custom context provided by Windows driver,
/// for traffic redirected to the (Windows) L4 proxy.
pub struct ProxyRedirectContext(ProxyRedirectContextData);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProxyRedirectContextData {
    V1 { destination: SocketAddr, pid: u32 },
}

impl ProxyRedirectContext {
    /// Create a new [`ProxyRedirectContext`]]
    pub fn new(destination: SocketAddr, pid: u32) -> Self {
        Self(ProxyRedirectContextData::V1 { destination, pid })
    }

    /// Return the [`SocketAddr`] of the target (egress).
    pub fn destination(&self) -> SocketAddr {
        match &self.0 {
            ProxyRedirectContextData::V1 { destination, .. } => *destination,
        }
    }

    /// Return the Processer ID (PID) of the source (ingress).
    pub fn source_pid(&self) -> u32 {
        match &self.0 {
            ProxyRedirectContextData::V1 { pid, .. } => *pid,
        }
    }
}
