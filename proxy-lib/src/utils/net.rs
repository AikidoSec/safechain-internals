use rama::extensions::ExtensionsRef;
use std::sync::Arc;

#[cfg(not(all(feature = "apple-networkextension", target_os = "macos")))]
pub fn get_app_source_bundle_id_from_ext(_: &impl ExtensionsRef) -> Option<&str> {
    None
}

#[cfg(all(feature = "apple-networkextension", target_os = "macos"))]
pub fn get_app_source_bundle_id_from_ext(input: &impl ExtensionsRef) -> Option<&str> {
    input
        .extensions()
        .get::<Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>>()
        .and_then(|meta| meta.source_app_bundle_identifier.as_deref())
}


#[cfg(all(feature = "apple-networkextension", target_os = "macos"))]
pub fn get_transparent_proxy_flow_meta_from_ext(input: &impl ExtensionsRef) -> Option<&Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>> {

    input
        .extensions()
        .get::<Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>>()
}
 