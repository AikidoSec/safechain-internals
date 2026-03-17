use std::{path::PathBuf, sync::OnceLock};

static STORAGE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_storage_dir(path: Option<PathBuf>) {
    if let Some(path) = path {
        let _ = STORAGE_DIR.set(path);
    }
}

pub fn storage_dir() -> Option<PathBuf> {
    STORAGE_DIR.get().cloned()
}
