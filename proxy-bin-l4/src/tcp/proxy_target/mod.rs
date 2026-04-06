#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
#[allow(unused)]
pub use self::windows::{
    L4ProxyRedirectContext, L4ProxyRedirectContextDecoder, ProxyTargetFromInput,
    ProxyTargetFromInputLayer, new_proxy_target_from_input_layer,
};

#[cfg(all(not(target_os = "windows"), target_os = "linux"))]
#[allow(unused)]
pub use rama::net::socket::linux::{
    ProxyTargetFromGetSocketname as ProxyTargetFromInput,
    ProxyTargetFromGetSocketnameLayer as ProxyTargetFromInputLayer,
};

#[cfg(all(not(target_os = "windows"), target_os = "linux"))]
#[inline(always)]
pub fn new_proxy_target_from_input_layer() -> ProxyTargetFromInputLayer {
    ProxyTargetFromInputLayer::new()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod deny;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
#[allow(unused)]
pub use self::deny::{
    DenyProxyTargetFromInput as ProxyTargetFromInput,
    DenyProxyTargetFromInputLayer as ProxyTargetFromInputLayer, new_proxy_target_from_input_layer,
};
