use std::borrow::Cow;

use rama::{
    error::{BoxError, ErrorContext as _},
    http::Uri,
};
use safechain_proxy_lib::utils::token::AgentIdentity;
use serde::{Deserialize, Deserializer};

/// Configuration for the MacOS transparent proxy runtime.
///
/// This configuration controls how the proxy behaves, including
/// connection inspection timing, reporting of blocked events,
/// and integration with Aikido services.
///
/// All fields have sensible defaults and may be omitted.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyConfig {
    /// Duration in seconds to peek into a connection before deciding how to handle it.
    ///
    /// This is typically used during protocol detection or early inspection
    /// of incoming traffic.
    ///
    /// Defaults to `0.5`.
    pub peek_duration_s: f64,

    /// Optional identity of the running agent.
    ///
    /// When provided, this may be used to associate requests and reports
    /// with a specific agent instance.
    pub agent_identity: Option<AgentIdentity>,

    /// Optional endpoint URL to POST blocked-event notifications to.
    ///
    /// Must be a valid absolute URI.
    #[serde(deserialize_with = "deserialize_optional_uri")]
    pub reporting_endpoint: Option<Uri>,

    /// Aikido app base URL used to fetch endpoint protection configuration.
    ///
    /// This endpoint is used by the proxy to retrieve dynamic configuration
    /// such as protection rules and policies.
    ///
    /// Must be a valid absolute URI.
    ///
    /// Defaults to `https://app.aikido.dev`.
    #[serde(deserialize_with = "deserialize_uri")]
    pub aikido_url: Uri,

    /// PEM-encoded root CA certificate supplied by the host.
    pub ca_cert_pem: Option<String>,

    /// PEM-encoded root CA private key supplied by the host.
    pub ca_key_pem: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            peek_duration_s: 0.5,
            agent_identity: None,
            reporting_endpoint: None,
            aikido_url: Uri::from_static("https://app.aikido.dev"),
            ca_cert_pem: None,
            ca_key_pem: None,
        }
    }
}

impl ProxyConfig {
    pub fn from_opaque_config(opaque_config: Option<&[u8]>) -> Result<Self, BoxError> {
        match opaque_config {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice(bytes).context("decode transparent proxy engine config JSON")
            }
            _ => Ok(Self::default()),
        }
    }
}

// NOTE: rama's near term roadmap will have first class
// support for a better and richer Uri type in rama::net....
// once that is there it will also support serde out of the box,
// no longer requiring the code below

fn deserialize_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Cow::<'de, str>::deserialize(deserializer)?;
    s.parse::<Uri>().map_err(serde::de::Error::custom)
}

fn deserialize_optional_uri<'de, D>(deserializer: D) -> Result<Option<Uri>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<Cow<'de, str>>::deserialize(deserializer)?;
    opt.map(|s| s.parse::<Uri>().map_err(serde::de::Error::custom))
        .transpose()
}

#[cfg(test)]
#[path = "./config_tests.rs"]
mod tests;
