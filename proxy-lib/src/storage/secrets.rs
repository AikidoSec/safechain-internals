use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};

use keyring_core::api::CredentialStoreApi;
use secrecy::{ExposeSecret, SecretBox};

#[cfg(target_os = "macos")]
use apple_native_keyring_store::keychain::Store;
#[cfg(target_os = "linux")]
use linux_keyutils_keyring_store::Store;
#[cfg(target_os = "windows")]
use windows_native_keyring_store::Store;

use rama::{
    error::{BoxError, ErrorContext, ErrorExt as _},
    telemetry::tracing,
};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
/// Synchronous Secrets Storage.
///
/// ## Usage
///
/// Use this storage at the start of the app,
/// or from a tokio blocking thread!
pub struct SyncSecrets {
    backend: Backend,
    account: &'static str,
}

#[derive(Debug, Clone)]
enum Backend {
    Fs {
        dir: PathBuf,
    },
    KeyRing {
        store: Arc<Store>,
    },
    InMemory {
        secrets: Arc<RwLock<HashMap<String, SecretBox<Vec<u8>>>>>,
    },
}

impl SyncSecrets {
    #[inline(always)]
    pub fn try_new(account: &'static str, storage: StorageKind) -> Result<Self, BoxError> {
        match storage {
            StorageKind::Keyring => Self::try_new_keyring(account),
            StorageKind::Memory => Ok(Self::new_in_memory(account)),
            StorageKind::Fs(dir) => Self::try_new_fs(account, dir),
        }
    }

    #[inline(always)]
    pub(crate) fn try_new_keyring(account: &'static str) -> Result<Self, BoxError> {
        Ok(Self {
            backend: Backend::KeyRing {
                store: try_new_keychain_store()?,
            },
            account,
        })
    }

    #[inline(always)]
    pub(crate) fn new_in_memory(account: &'static str) -> Self {
        Self {
            backend: Backend::InMemory {
                secrets: Arc::new(RwLock::new(HashMap::new())),
            },
            account,
        }
    }

    #[inline(always)]
    pub(crate) fn try_new_fs(account: &'static str, base_dir: PathBuf) -> Result<Self, BoxError> {
        let dir = base_dir.join("secrets").join(account);
        std::fs::create_dir_all(&dir).context("create new fs dir")?;
        Ok(Self {
            backend: Backend::Fs { dir },
            account,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageKind {
    Keyring,
    Memory,
    Fs(PathBuf),
}

impl FromStr for StorageKind {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("keyring") {
            return Ok(Self::Keyring);
        }

        if s.eq_ignore_ascii_case("memory") {
            return Ok(Self::Memory);
        }

        let dir = PathBuf::from(s);
        if dir.as_os_str().is_empty() {
            return Err(BoxError::from("empty secrets value is not allowed"));
        }

        let meta = std::fs::metadata(&dir)
            .context("fetch metadata for dir")
            .with_context_debug_field("path", || dir.clone())?;

        if !meta.is_dir() {
            return Err(
                BoxError::from("secrets path is not a directory").context_debug_field("path", dir)
            );
        }

        Ok(Self::Fs(dir))
    }
}

impl SyncSecrets {
    pub fn store_secret<T: Serialize>(&self, key: &str, value: &T) -> Result<(), BoxError> {
        let raw = postcard::to_allocvec(value)
            .context("(postcard) encode secret")
            .context_str_field("key", key)?
            .to_vec();

        match &self.backend {
            Backend::Fs { dir } => {
                tracing::warn!(
                    "secrets storage (store) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret"));
                tracing::debug!("secrets FS store (store): {}", path.display());
                std::fs::write(&path, &raw)
                    .context("write secret to FS")
                    .context_debug_field("path", path)
            }
            Backend::KeyRing { store } => {
                let entry = new_key_ring_entry(store, key, self.account)?;
                entry
                    .set_secret(&raw)
                    .context("set secret")
                    .context_str_field("key", key)
            }
            Backend::InMemory { secrets } => {
                tracing::warn!(
                    "using in-memory secrets storage; CA keypairs and other secrets will be regenerated on each restart"
                );

                secrets
                    .write()
                    .insert(key.to_string(), SecretBox::new(Box::new(raw)));
                Ok(())
            }
        }
    }

    pub fn load_secret<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, BoxError> {
        match &self.backend {
            Backend::Fs { dir } => {
                tracing::warn!(
                    "secrets storage (load) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret"));
                tracing::debug!("secrets FS storage (load): {}", path.display());
                match std::fs::read(&path) {
                    Ok(raw) => deserialize_secret(&raw, key),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(err) => Err(err
                        .context("read secret from FS")
                        .context_debug_field("path", path)),
                }
            }
            Backend::KeyRing { store } => {
                let entry = new_key_ring_entry(store, key, self.account)?;
                match entry.get_secret() {
                    Ok(raw) => deserialize_secret(&raw, key),
                    Err(keyring_core::Error::NoEntry) => Ok(None),
                    Err(err) => Err(err.context("get secret").context_str_field("key", key)),
                }
            }
            Backend::InMemory { secrets } => {
                if let Some(secret) = secrets.read().get(key) {
                    deserialize_secret(secret.expose_secret(), key)
                } else {
                    Ok(None)
                }
            }
        }
    }
}

fn deserialize_secret<T: DeserializeOwned>(raw: &[u8], key: &str) -> Result<Option<T>, BoxError> {
    let value: T = postcard::from_bytes(raw)
        .context("(postcard) decode RAW read secret")
        .context_str_field("key", key)?;
    Ok(Some(value))
}

#[cfg(target_os = "macos")]
fn try_new_keychain_store() -> Result<Arc<Store>, BoxError> {
    // NOTE: for production version you might prefer the 'protected' API Instead,
    // but this does require a proper bundle ID as app-group,
    // so certainly not possible for a test like this
    tracing::warn!(
        "Consider using the modern Protected MacOS/iOS capabilities for secret storage on thesse platforms!!! Keyring is considered legacy for these purposes..."
    );

    Store::new_with_configuration(&HashMap::from([(
        "keychain",
        if sudo::check() == sudo::RunningAs::Root {
            "system"
        } else {
            "user"
        },
    )]))
    .context("create Apple Keyring Secret store")
}

#[cfg(target_os = "linux")]
fn try_new_keychain_store() -> Result<Arc<Store>, BoxError> {
    linux_keyutils_keyring_store::Store::new().context("create Linux KeyUtils Secret store")
}

#[cfg(target_os = "windows")]
fn try_new_keychain_store() -> Result<Arc<Store>, BoxError> {
    windows_native_keyring_store::Store::new().context("create Windows Native Secret store")
}

fn new_key_ring_entry(
    store: &Store,
    key: &str,
    account: &str,
) -> Result<keyring_core::Entry, BoxError> {
    store
        .build(key, account, None)
        .context("create Root CA entry")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::utils::io::tmp_dir;

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_secret_storage_fs_number_store_can_load() {
        let dir = tmp_dir::try_new("test_secret_storage_fs_number_store_can_load").unwrap();
        let data_storage = SyncSecrets::try_new_fs(crate::utils::env::project_name(), dir).unwrap();

        const NUMBER: usize = 42;

        assert!(
            data_storage
                .load_secret::<usize>("number")
                .unwrap()
                .is_none()
        );

        data_storage.store_secret("number", &NUMBER).unwrap();

        assert!(
            data_storage
                .load_secret::<usize>("string")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            NUMBER,
            data_storage
                .load_secret::<usize>("number")
                .unwrap()
                .unwrap()
        );
    }

    #[traced_test]
    #[test]
    #[ignore]
    fn test_secret_storage_keyring_number_store_can_load() {
        let data_storage = SyncSecrets::try_new_keyring(crate::utils::env::project_name()).unwrap();

        const NUMBER: usize = 42;

        let pid = std::process::id();

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let name = format!("test_{pid}_{nanos}");

        assert!(data_storage.load_secret::<usize>(&name).unwrap().is_none());

        data_storage.store_secret(&name, &NUMBER).unwrap();

        assert!(
            data_storage
                .load_secret::<usize>("string")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            NUMBER,
            data_storage.load_secret::<usize>(&name).unwrap().unwrap()
        );
    }

    #[traced_test]
    #[test]
    fn test_secret_storage_inmemory_number_store_can_load() {
        let data_storage = SyncSecrets::new_in_memory(crate::utils::env::project_name());

        const NUMBER: usize = 42;

        assert!(
            data_storage
                .load_secret::<usize>("number")
                .unwrap()
                .is_none()
        );

        data_storage.store_secret("number", &NUMBER).unwrap();

        assert!(
            data_storage
                .load_secret::<usize>("string")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            NUMBER,
            data_storage
                .load_secret::<usize>("number")
                .unwrap()
                .unwrap()
        );
    }
}
