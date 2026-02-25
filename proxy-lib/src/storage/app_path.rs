use std::path::{Path, PathBuf};

fn base_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/AikidoSecurity/SafeChainUltimate")
    }

    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\AikidoSecurity\SafeChainUltimate")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".AikidoSecurity/SafeChainUltimate")
    }
}

pub fn path_for(path: impl AsRef<Path>) -> PathBuf {
    base_dir().join(path)
}
