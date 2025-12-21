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
        let raw_compressed = lz4_flex::compress_prepend_size(&raw);

        let path = self.dir.join(format!("{key}.data"));

        std::fs::write(&path, &raw_compressed)
            .with_context(|| format!("set data for FS path '{}'", path.display()))
    }

    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, OpaqueError> {
        let path = self.dir.join(format!("{key}.data"));

        let raw_compressed = match std::fs::read(&path) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(
                    err.with_context(|| format!("get data for FS path '{}'", path.display()))
                );
            }
        };

        let raw = lz4_flex::decompress_size_prepended(&raw_compressed)
            .with_context(|| format!("(lz4-flex) decompress read data for key '{key}'"))?;

        let value: T = postcard::from_bytes(&raw)
            .with_context(|| format!("(postcard) decode RAW read data for key '{key}'"))?;

        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use crate::test::tmp_dir;

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_data_storage_number_store_can_load() {
        let dir = tmp_dir::try_new("test_data_storage_number").unwrap();
        let data_storage = SyncCompactDataStorage::try_new(dir).unwrap();

        const NUMBER: usize = 42;

        assert!(data_storage.load::<usize>("number").unwrap().is_none());

        data_storage.store("number", &NUMBER).unwrap();

        assert!(data_storage.load::<usize>("string").unwrap().is_none());
        assert_eq!(
            NUMBER,
            data_storage.load::<usize>("number").unwrap().unwrap()
        );
    }
}
