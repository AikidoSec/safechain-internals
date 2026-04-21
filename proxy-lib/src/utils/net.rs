use rama::extensions::ExtensionsRef;

#[cfg(not(all(feature = "apple-networkextension", target_os = "macos")))]
pub fn get_app_source_bundle_id_from_ext(_: &impl ExtensionsRef) -> Option<&str> {
    None
}

#[cfg(all(feature = "apple-networkextension", target_os = "macos"))]
pub fn get_app_source_bundle_id_from_ext(input: &impl ExtensionsRef) -> Option<&str> {
    input
        .extensions()
        .get_ref::<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>()
        .and_then(|meta| meta.source_app_bundle_identifier.as_deref())
}

#[cfg(not(any(
    all(target_os = "windows", feature = "windows-driver"),
    all(target_os = "macos", feature = "apple-networkextension"),
)))]
pub fn get_source_process_path_from_ext(_: &impl ExtensionsRef) -> Option<String> {
    None
}

#[cfg(all(target_os = "windows", feature = "windows-driver"))]
pub fn get_source_process_path_from_ext(input: &impl ExtensionsRef) -> Option<String> {
    input
        .extensions()
        .get_ref::<safechain_proxy_lib_nostd::windows::redirect_ctx::ProxyRedirectContext>()
        .and_then(|ctx| ctx.source_process_path())
        .map(|s| s.to_owned())
}

#[cfg(all(target_os = "macos", feature = "apple-networkextension"))]
pub fn get_source_process_path_from_ext(input: &impl ExtensionsRef) -> Option<String> {
    let meta = input
        .extensions()
        .get_ref::<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>()?;

    let pid = meta.source_app_pid?;

    unsafe { rama::net::apple::networkextension::process::pid_path(pid) }
        .ok()
        .flatten()
        .and_then(|p| p.into_os_string().into_string().ok())
}
