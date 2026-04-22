use rama::{
    net::apple::networkextension::ffi::tproxy::TransparentProxyInitConfig, telemetry::tracing,
};

pub(super) fn init(config: Option<&TransparentProxyInitConfig>) -> bool {
    if !crate::utils::init_tracing() {
        return false;
    }

    if let Some(config) = config {
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(path) = unsafe { config.storage_dir() } {
            tracing::debug!(path = %path.display(), "received storage directory: pass to set_storage_dir");
            crate::utils::storage::set_storage_dir(Some(path));
        }
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(app_group_dir) = unsafe { config.app_group_dir() } {
            tracing::debug!(path = %app_group_dir.display(), "received app-group directory");
        }
    }

    const FD_LIMIT: rama::unix::utils::rlim_t = 262_144;
    if let Err(err) = rama::unix::utils::raise_nofile(FD_LIMIT) {
        tracing::warn!("failed to increase FD limit for L4 (t)proxy: {err}");
    } else {
        tracing::info!("increased FD limit for L4 (t)proxy to: {FD_LIMIT}");
    }

    tracing::info!("aikido L4 proxy initialized");
    true
}
