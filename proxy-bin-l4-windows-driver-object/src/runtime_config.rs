use std::{
    net::{SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use rama_core::{error::BoxError, telemetry::tracing::info};

use crate::{
    common::{
        DeviceHandle, IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY, IOCTL_SET_IPV6_PROXY,
        Ipv4ProxyConfigPayload, Ipv6ProxyConfigPayload, enable_device,
    },
    wfp::ensure_wfp_objects,
};

#[derive(Debug, Clone)]
pub struct DriverRuntimeConfig<'a> {
    pub device_path: &'a str,
    pub ipv4_proxy: SocketAddrV4,
    pub ipv4_proxy_pid: u32,
    pub ipv6_proxy: Option<SocketAddrV6>,
    pub ipv6_proxy_pid: Option<u32>,
}

pub fn validate_runtime_config(config: &DriverRuntimeConfig<'_>) -> Result<(), BoxError> {
    if config.ipv4_proxy_pid == 0 {
        return Err("`ipv4_proxy_pid` must be a non-zero process id".into());
    }
    if config.ipv6_proxy.is_some() != config.ipv6_proxy_pid.is_some() {
        return Err("`ipv6_proxy` and `ipv6_proxy_pid` must be provided together".into());
    }
    if config.ipv6_proxy_pid == Some(0) {
        return Err("`ipv6_proxy_pid` must be a non-zero process id".into());
    }

    Ok(())
}

pub fn ensure_enabled_and_apply_runtime_config(
    service_name: &str,
    config: &DriverRuntimeConfig<'_>,
) -> Result<(), BoxError> {
    validate_runtime_config(config)?;
    enable_device(service_name)?;
    apply_runtime_config(config)
}

pub fn apply_runtime_config(config: &DriverRuntimeConfig<'_>) -> Result<(), BoxError> {
    validate_runtime_config(config)?;

    info!(
        device_path = %config.device_path,
        ipv4_proxy = %config.ipv4_proxy,
        ipv4_proxy_pid = config.ipv4_proxy_pid,
        ipv6_proxy = ?config.ipv6_proxy,
        ipv6_proxy_pid = ?config.ipv6_proxy_pid,
        "synchronizing SafeChain Windows driver runtime config"
    );

    ensure_wfp_objects()?;

    let device = DeviceHandle::open_with_retry(config.device_path, 10, Duration::from_millis(200))?;
    let ipv4_payload = Ipv4ProxyConfigPayload::new(config.ipv4_proxy, config.ipv4_proxy_pid)
        .to_bytes()
        .map_err(|err| format!("failed to encode IPv4 proxy payload: {err}"))?;
    device.send_ioctl(IOCTL_SET_IPV4_PROXY, &ipv4_payload)?;

    if let Some(ipv6_proxy) = config.ipv6_proxy {
        let Some(ipv6_proxy_pid) = config.ipv6_proxy_pid else {
            return Err("`ipv6_proxy_pid` is required when `ipv6_proxy` is provided".into());
        };
        let ipv6_payload = Ipv6ProxyConfigPayload::new(ipv6_proxy, ipv6_proxy_pid)
            .to_bytes()
            .map_err(|err| format!("failed to encode IPv6 proxy payload: {err}"))?;
        device.send_ioctl(IOCTL_SET_IPV6_PROXY, &ipv6_payload)?;
    } else {
        device.send_ioctl(IOCTL_CLEAR_IPV6_PROXY, &[])?;
    }

    Ok(())
}
