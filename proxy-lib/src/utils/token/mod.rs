use std::{io::Read, path::Path};

use rama::{telemetry::tracing, utils::str::arcstr::ArcStr};
use serde::Deserialize;

use crate::storage::app_path;

/// Agent identity loaded from the shared `config.json` file written by the daemon.
pub struct AgentIdentity {
    pub token: Option<ArcStr>,
    pub device_id: Option<ArcStr>,
}

impl AgentIdentity {
    pub fn load() -> Self {
        let system_path = app_path::path_for("config.json");
        let config = Self::try_load_from_path(&system_path);

        match config {
            Some(config) => {
                if config.token.is_some() {
                    tracing::info!("Aikido authentication token loaded");
                } else {
                    tracing::info!(
                        "No token found in config; some endpoint protection features will be disabled"
                    );
                }
                config
            }
            None => {
                tracing::info!(
                    "No Aikido config file found; some endpoint protection features will be disabled"
                );
                Self {
                    token: None,
                    device_id: None,
                }
            }
        }
    }

    fn try_load_from_path(path: &Path) -> Option<Self> {
        let raw = Self::read_config_with_limit(path)?;

        let raw_identity = Self::parse_raw_identity(path, &raw)?;

        let token = raw_identity
            .token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(ArcStr::from);

        let device_id = raw_identity
            .device_id
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(ArcStr::from);

        Some(Self { token, device_id })
    }

    fn read_config_with_limit(path: &Path) -> Option<String> {
        const MAX_CONFIG_SIZE: usize = 4096; // 4KB max
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "failed to read config file");
                return None;
            }
        };

        // Read at most max_size + 1 bytes to detect files that are too large.
        let mut limited = file.by_ref().take(MAX_CONFIG_SIZE as u64 + 1);
        let mut raw = String::new();
        limited
            .read_to_string(&mut raw)
            .map_err(|err| tracing::warn!(path = %path.display(), error = %err, "failed to read config file contents"))
            .ok()?;

        if raw.len() > MAX_CONFIG_SIZE {
            tracing::warn!(
                path = %path.display(),
                size = raw.len(),
                max = MAX_CONFIG_SIZE,
                "config file exceeds maximum size; ignoring",
            );
            return None;
        }

        Some(raw)
    }

    fn parse_raw_identity(path: &Path, raw: &str) -> Option<RawAgentIdentity> {
        serde_json::from_str(raw)
            .map_err(|err| tracing::warn!(path = %path.display(), error = %err, "failed to parse config.json; ignoring"))
            .ok()
    }
}

#[derive(Deserialize)]
struct RawAgentIdentity {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
}

#[cfg(test)]
mod tests;
