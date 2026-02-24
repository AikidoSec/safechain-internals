use std::path::{Path, PathBuf};

/// Returns the platform-specific application storage directory.
fn base_dir() -> &'static Path {
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Application Support/AikidoSecurity/SafeChainUltimate")
    }

    #[cfg(target_os = "windows")]
    {
        Path::new(r"C:\ProgramData\AikidoSecurity\SafeChainUltimate")
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Path::new(".")
    }
}

/// Resolve a relative filename within the application storage directory.
pub fn resolve(filename: &str) -> PathBuf {
    base_dir().join(filename)
}
