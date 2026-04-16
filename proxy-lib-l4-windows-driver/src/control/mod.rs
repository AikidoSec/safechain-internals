use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY, IOCTL_SET_IPV6_PROXY, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload,
};
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

use crate::driver::{ProxyDriverConfigUpdate, ProxyDriverController};

pub fn initialize_runtime_config(
    controller: &ProxyDriverController,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    controller.clear_proxy_endpoint();
    STATUS_SUCCESS
}

pub fn apply_runtime_update(
    controller: &ProxyDriverController,
    update: ProxyDriverConfigUpdate,
) -> NTSTATUS {
    if controller.apply_runtime_update(update) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub mod ioctl;
