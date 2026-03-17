use rama::{
    error::{BoxError, ErrorContext as _},
    http::Uri,
};
use safechain_proxy_lib::utils::token::AgentIdentity;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub peek_duration_s: f64,
    pub agent_identity: Option<AgentIdentity>,
    #[serde(deserialize_with = "deserialize_optional_uri")]
    pub reporting_endpoint: Option<Uri>,
    #[serde(deserialize_with = "deserialize_uri")]
    pub aikido_url: Uri,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            peek_duration_s: 8.,
            agent_identity: None,
            reporting_endpoint: None,
            aikido_url: Uri::from_static("https://app.aikido.dev"),
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

fn deserialize_uri<'de, D>(deserializer: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<Uri>().map_err(serde::de::Error::custom)
}

fn deserialize_optional_uri<'de, D>(deserializer: D) -> Result<Option<Uri>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    opt.map(|s| s.parse::<Uri>().map_err(serde::de::Error::custom))
        .transpose()
}
