use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};

use keyring_core::api::CredentialStoreApi;

#[cfg(target_os = "macos")]
use ::{apple_native_keyring_store::keychain::Store, std::collections::HashMap};
#[cfg(target_os = "linux")]
use linux_keyutils_keyring_store::Store;
#[cfg(target_os = "windows")]
use windows_native_keyring_store::Store;

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
    KeyRing { store: Arc<Store> },
}

const AIKIDO_SECRET_SVC: &str = crate::utils::env::project_name();

#[cfg(test)]
impl SyncSecrets {
    /// # Panics
    ///
    /// Panics in case the underlying (platform) keychain store failed to be created.
    pub fn new_keyring() -> Self {
        Self(Backend::KeyRing {
            store: try_new_keychain_store().unwrap(),
        })
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
            let store = try_new_keychain_store()?;
            return Ok(Self(Backend::KeyRing { store }));
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
    pub fn store_secret<T: Serialize>(&self, key: &str, value: &T) -> Result<(), OpaqueError> {
        let raw = postcard::to_allocvec(value)
            .with_context(|| format!("(postcard) encode secret for key '{key}'"))?
            .to_vec();

        match &self.0 {
            Backend::Fs { dir } => {
                tracing::warn!(
                    "secrets storage (store) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret"));
                tracing::debug!("secrets FS store (store): {}", path.display());
                std::fs::write(&path, &raw)
                    .with_context(|| format!("set secret for FS path '{}'", path.display()))
            }
            Backend::KeyRing { store } => {
                let entry = new_key_ring_entry(store, key)?;
                entry
                    .set_secret(&raw)
                    .with_context(|| format!("set secret for key '{key}'"))
            }
        }
    }

    pub fn load_secret<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, OpaqueError> {
        let raw = match &self.0 {
            Backend::Fs { dir } => {
                tracing::warn!(
                    "secrets storage (load) is using FS @ '{}' (key = '{key}'), ensure to use 'keyring' in production!!!",
                    dir.display()
                );

                let path = dir.join(format!("{key}.secret"));
                tracing::debug!("secrets FS storage (load): {}", path.display());
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
            Backend::KeyRing { store } => {
                let entry = new_key_ring_entry(store, key)?;
                match entry.get_secret() {
                    Ok(v) => v,
                    Err(keyring_core::Error::NoEntry) => return Ok(None),
                    Err(err) => {
                        return Err(err.with_context(|| format!("get secret for key '{key}'")));
                    }
                }
            }
        };

        let value: T = postcard::from_bytes(&raw)
            .with_context(|| format!("(postcard) decode RAW read secret for key '{key}'"))?;
        Ok(Some(value))
    }
}

#[cfg(target_os = "macos")]
fn try_new_keychain_store() -> Result<Arc<Store>, OpaqueError> {
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
fn try_new_keychain_store() -> Result<Arc<Store>, OpaqueError> {
    linux_keyutils_keyring_store::Store::new().context("create Linux KeyUtils Secret store")
}

#[cfg(target_os = "windows")]
fn try_new_keychain_store() -> Result<Arc<Store>, OpaqueError> {
    windows_native_keyring_store::Store::new().context("create Windows Native Secret store")
}

fn new_key_ring_entry(store: &Store, key: &str) -> Result<keyring_core::Entry, OpaqueError> {
    store
        .build(key, AIKIDO_SECRET_SVC, None)
        .context("create Root CA entry")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::utils::test::unique_empty_temp_dir;

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_secret_storage_fs_number_store_can_load() {
        let dir = unique_empty_temp_dir("test_secret_storage_fs_number_store_can_load").unwrap();
        let data_storage = SyncSecrets::new_fs(dir);

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
        let data_storage = SyncSecrets::new_keyring();

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
}
