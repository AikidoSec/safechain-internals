use rama::extensions::ExtensionsRef;

#[cfg(not(feature = "apple-networkextension"))]
pub fn get_app_source_bundle_id_from_ext(_: &impl ExtensionsRef) -> Option<&str> {
    None
}

#[cfg(feature = "apple-networkextension")]
pub fn get_app_source_bundle_id_from_ext(input: &impl ExtensionsRef) -> Option<&str> {
    use std::sync::Arc;

    input
        .extensions()
        .get::<Arc<rama::net::apple::networkextension::tproxy::TransparentProxyFlowMeta>>()
        .and_then(|meta| meta.source_app_bundle_identifier.as_deref())
}
