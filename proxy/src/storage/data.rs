use std::path::PathBuf;

use rama::error::{BoxError, ErrorContext, ErrorExt as _};
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
    pub fn try_new(dir: PathBuf) -> Result<Self, BoxError> {
        if dir.as_os_str().is_empty() {
            return Err(BoxError::from(
                "empty data storage dir value is not allowed",
            ));
        }

        match std::fs::metadata(&dir) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(BoxError::from("data storage path is not a directory")
                        .context_debug_field("path", dir));
                }
            }
            Err(err) => {
                return Err(err
                    .context("fetch metadata for data storage dir")
                    .context_debug_field("path", dir));
            }
        }

        Ok(Self { dir })
    }

    pub fn store<T: Serialize>(&self, key: &str, value: &T) -> Result<(), BoxError> {
        let raw = postcard::to_allocvec(value)
            .context("(postcard) encode data")
            .context_str_field("key", key)?
            .to_vec();
        let raw_compressed = lz4_flex::compress_prepend_size(&raw);

        let path = self.dir.join(format!("{key}.data"));

        std::fs::write(&path, &raw_compressed)
            .context("write data to FS")
            .context_debug_field("path", path)
    }

    pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, BoxError> {
        let path = self.dir.join(format!("{key}.data"));

        let raw_compressed = match std::fs::read(&path) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err
                    .context("read data from FS")
                    .context_debug_field("path", path));
            }
        };

        let raw = lz4_flex::decompress_size_prepended(&raw_compressed)
            .context("(lz4-flex) decompress read data")
            .context_str_field("key", key)?;

        let value: T = postcard::from_bytes(&raw)
            .context("(postcard) decode RAW read data")
            .context_str_field("key", key)?;

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
