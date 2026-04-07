use alloc::string::String;
use core::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
/// Custom context provided by Windows driver,
/// for traffic redirected to the (Windows) L4 proxy.
pub struct ProxyRedirectContext(ProxyRedirectContextData);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProxyRedirectContextData {
    V1 {
        destination: SocketAddr,
        source_pid: Option<u32>,
        source_process_path: Option<String>,
    },
}

impl ProxyRedirectContext {
    /// Create a new [`ProxyRedirectContext`] with only required destination.
    pub fn new(destination: SocketAddr) -> Self {
        Self(ProxyRedirectContextData::V1 {
            destination,
            source_pid: None,
            source_process_path: None,
        })
    }

    /// Return the original remote destination endpoint.
    ///
    /// Example values:
    /// - `93.184.216.34:443` for public HTTPS traffic
    /// - `[2606:2800:220:1:248:1893:25c8:1946]:443` for public IPv6 HTTPS
    pub fn destination(&self) -> SocketAddr {
        match &self.0 {
            ProxyRedirectContextData::V1 { destination, .. } => *destination,
        }
    }

    /// Return the source process id when present.
    ///
    /// Example values:
    /// - `1234` for a browser process
    /// - `None` when PID metadata was unavailable at the classify layer
    pub fn source_pid(&self) -> Option<u32> {
        match &self.0 {
            ProxyRedirectContextData::V1 { source_pid, .. } => *source_pid,
        }
    }

    /// Return the source process path when present.
    ///
    /// Example values:
    /// - `C:\Program Files\Google\Chrome\Application\chrome.exe`
    /// - `C:\Windows\System32\curl.exe`
    /// - `None` when app identity metadata was unavailable
    pub fn source_process_path(&self) -> Option<&str> {
        match &self.0 {
            ProxyRedirectContextData::V1 {
                source_process_path,
                ..
            } => source_process_path.as_deref(),
        }
    }

    pub fn with_source_pid(mut self, source_pid: Option<u32>) -> Self {
        match &mut self.0 {
            ProxyRedirectContextData::V1 {
                source_pid: current,
                ..
            } => *current = source_pid,
        }
        self
    }

    pub fn set_source_pid(&mut self, source_pid: Option<u32>) -> &mut Self {
        match &mut self.0 {
            ProxyRedirectContextData::V1 {
                source_pid: current,
                ..
            } => *current = source_pid,
        }
        self
    }

    pub fn with_source_process_path(mut self, source_process_path: Option<String>) -> Self {
        match &mut self.0 {
            ProxyRedirectContextData::V1 {
                source_process_path: current,
                ..
            } => *current = source_process_path,
        }
        self
    }

    pub fn set_source_process_path(&mut self, source_process_path: Option<String>) -> &mut Self {
        match &mut self.0 {
            ProxyRedirectContextData::V1 {
                source_process_path: current,
                ..
            } => *current = source_process_path,
        }
        self
    }
}
