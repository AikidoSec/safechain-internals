#[cfg(target_os = "windows")]
fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_binary_build()
}

#[cfg(not(target_os = "windows"))]
fn main() {}
