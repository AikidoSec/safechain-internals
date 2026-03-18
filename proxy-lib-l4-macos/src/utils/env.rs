pub const fn project_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub const MANAGED_VPN_SHARED_ACCESS_GROUP: &str = "com.apple.managed.vpn.shared";
pub const L4_PROXY_HOST_BUNDLE_ID: &str = "com.aikido.endpoint.proxy.l4";
