use std::{io::Read, path::Path};

use rama::{telemetry::tracing, utils::str::NonEmptyStr};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct AgentIdentity {
    pub token: NonEmptyStr,
    pub device_id: NonEmptyStr,
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("token", &"[REDACTED]")
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl AgentIdentity {
    pub fn load(data_dir: &Path) -> Option<Self> {
        let identity = Self::try_load_from_path(&data_dir.join("config.json"));

        match &identity {
            Some(_) => tracing::info!("Aikido agent identity loaded"),
            None => tracing::info!(
                "No valid agent identity found; some endpoint protection features will be disabled"
            ),
        }

        identity
    }

    fn try_load_from_path(path: &Path) -> Option<Self> {
        let raw = Self::read_config_with_limit(path)?;
        serde_json::from_str(&raw)
            .map_err(|err| tracing::warn!(path = %path.display(), error = %err, "failed to parse config.json; ignoring"))
            .ok()
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
}

#[cfg(test)]
mod tests;
