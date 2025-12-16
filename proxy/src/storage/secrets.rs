use std::{path::PathBuf, str::FromStr};

use rama::{
    error::{ErrorContext, ErrorExt as _, OpaqueError},
    telemetry::tracing,
};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
/// Synchronous Secrets Storage.
///
/// Meant to be created as a [`clap`] optional arg,
/// via its [`FromStr`] implementation.
///
/// ## Usage
///
/// Use this storage at the start of the app,
/// or else from a tokio blocking thread!
pub struct SyncSecrets(Backend);

#[derive(Debug, Clone)]
enum Backend {
    Fs { dir: PathBuf },
    KeyRing,
}

const AIKIDO_SECRET_SVC: &str = crate::utils::env::project_name();

#[cfg(test)]
impl SyncSecrets {
    pub fn new_keyring() -> Self {
        Self(Backend::KeyRing)
    }

    pub fn new_fs(dir: PathBuf) -> Self {
        Self(Backend::Fs { dir })
    }
}

impl FromStr for SyncSecrets {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("keyring") {
            return Ok(Self(Backend::KeyRing));
        }

        let dir = PathBuf::from(s);
        if dir.as_os_str().is_empty() {
            return Err(OpaqueError::from_display(
                "empty secrets value is not allowed",
            ));
        }

        let meta = std::fs::metadata(&dir)
            .with_context(|| format!("fetch metadata for dir @ '{}'", dir.display()))?;

        if !meta.is_dir() {
            return Err(OpaqueError::from_display(format!(
                "secrets path is not a directory: {}",
                dir.display()
            )));
        }

        Ok(SyncSecrets(Backend::Fs { dir }))
    }
}

impl SyncSecrets {
    pub fn store_secret_json<T: Serialize>(&self, key: &str, value: &T) -> Result<(), OpaqueError> {
        let raw = serde_json::to_vec(value)
            .with_context(|| format!("json-encode secret for key '{key}'"))?;

        match self.0 {
            Backend::Fs { ref dir } => {
                tracing::warn!(
                    "secrets storage (store) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret.json"));
                std::fs::write(&path, &raw)
                    .with_context(|| format!("set secret for FS path '{}'", path.display()))
            }
            Backend::KeyRing => {
                let entry = new_key_ring_entry(key)?;
                entry
                    .set_secret(&raw)
                    .with_context(|| format!("set secret for key '{key}'"))
            }
        }
    }

    pub fn load_secret_json<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, OpaqueError> {
        let raw = match self.0 {
            Backend::Fs { ref dir } => {
                tracing::warn!(
                    "secrets storage (load) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret.json"));
                match std::fs::read(&path) {
                    Ok(v) => v,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(err) => {
                        return Err(err.with_context(|| {
                            format!("get secret for FS path '{}'", path.display())
                        }));
                    }
                }
            }
            Backend::KeyRing => {
                let entry = new_key_ring_entry(key)?;
                match entry.get_secret() {
                    Ok(v) => v,
                    Err(keyring::Error::NoEntry) => return Ok(None),
                    Err(err) => {
                        return Err(err.with_context(|| format!("get secret for key '{key}'")));
                    }
                }
            }
        };
        serde_json::from_slice(&raw)
            .with_context(|| format!("json-decode RAW read secret for key '{key}'"))
    }
}

fn new_key_ring_entry(key: &str) -> Result<keyring::Entry, OpaqueError> {
    keyring::Entry::new(key, AIKIDO_SECRET_SVC).context("create Root CA entry")
}
