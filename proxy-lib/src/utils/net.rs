use rama::extensions::ExtensionsRef;

#[cfg(not(all(feature = "apple-networkextension", target_os = "macos")))]
pub fn get_app_source_bundle_id_from_ext(_: &impl ExtensionsRef) -> Option<&str> {
    None
}

#[cfg(all(feature = "apple-networkextension", target_os = "macos"))]
pub fn get_app_source_bundle_id_from_ext(input: &impl ExtensionsRef) -> Option<&str> {
    use std::sync::Arc;

    input
        .extensions()
        .get::<Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>>()
        .and_then(|meta| meta.source_app_bundle_identifier.as_deref())
}

#[cfg(not(all(feature = "apple-networkextension", target_os = "macos")))]
pub fn get_app_source_process_path_from_ext(_: &impl ExtensionsRef) -> Option<String> {
    None
}

#[cfg(all(feature = "apple-networkextension", target_os = "macos"))]
pub fn get_app_source_process_path_from_ext(input: &impl ExtensionsRef) -> Option<String> {
    use std::sync::Arc;

    let meta = input
        .extensions()
        .get::<Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>>()?;

    let pid = meta.source_app_pid?;

    // SAFETY: the target process may exit between inspection steps;
    // pid_path handles that gracefully by returning Ok(None).
    unsafe { rama::net::apple::networkextension::process::pid_path(pid) }
        .ok()
        .flatten()
        .map(|p| p.to_string_lossy().into_owned())
}
