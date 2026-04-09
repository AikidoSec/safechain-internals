use core::net::SocketAddr;

use safechain_proxy_lib_nostd::windows::driver_protocol::{
    IOCTL_CLEAR_IPV6_PROXY, IOCTL_CLEAR_PROXY_PROCESS_ID, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, IOCTL_SET_PROXY_PROCESS_ID, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, ProxyProcessIdPayload, STARTUP_VALUE_NAME, StartupConfig,
};
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

use crate::driver::{ProxyDriverConfigUpdate, ProxyDriverController, ProxyDriverStartupConfig};

pub fn initialize_startup_config(
    controller: &ProxyDriverController,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let Some(startup_config) = startup_config::load_startup_config(registry_path) else {
        return STATUS_INVALID_PARAMETER;
    };

    if controller.apply_startup_config(startup_config) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
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
pub mod startup_config;
