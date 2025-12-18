use std::path::PathBuf;

use rama::error::{ErrorContext, ErrorExt as _, OpaqueError};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
/// Synchronous Compact Data Storage.
///
/// ## Usage
///
/// Use this storage at the start of the app,
/// or else from a tokio blocking thread!
pub struct SyncCompactDataStorage {
    dir: PathBuf,
}

impl SyncCompactDataStorage {
    pub fn try_new(dir: PathBuf) -> Result<Self, OpaqueError> {
        if dir.as_os_str().is_empty() {
            return Err(OpaqueError::from_display(
                "empty data storage dir value is not allowed",
            ));
        }

        let meta = std::fs::metadata(&dir).with_context(|| {
            format!("fetch metadata for data storage dir @ '{}'", dir.display())
        })?;

        if !meta.is_dir() {
            return Err(OpaqueError::from_display(format!(
                "data storage path is not a directory: {}",
                dir.display()
            )));
        }

        Ok(Self { dir })
    }

    pub fn store<T: Serialize>(&self, key: &str, value: &T) -> Result<(), OpaqueError> {
        let raw = postcard::to_allocvec(value)
            .with_context(|| format!("(postcard) encode data for key '{key}'"))?
            .to_vec();

        let path = self.dir.join(format!("{key}.data"));

        std::fs::write(&path, &raw)
            .with_context(|| format!("set data for FS path '{}'", path.display()))
    }

    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, OpaqueError> {
        let path = self.dir.join(format!("{key}.data"));

        match std::fs::read(&path) {
            Ok(raw) => postcard::from_bytes(&raw)
                .with_context(|| format!("(postcard) decode RAW read data for key '{key}'")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => {
                Err(err.with_context(|| format!("get data for FS path '{}'", path.display())))
            }
        }
    }
}
