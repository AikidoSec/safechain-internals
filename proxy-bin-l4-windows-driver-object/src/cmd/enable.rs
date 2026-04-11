use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};
use std::{
    net::{SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use crate::common::{
    DeviceHandle, IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY, IOCTL_SET_IPV6_PROXY,
    Ipv4ProxyConfigPayload, Ipv6ProxyConfigPayload, enable_device,
};
use crate::wfp::ensure_wfp_objects;

#[derive(Debug, Args)]
/// Ensure the SafeChain Windows driver device is enabled and synchronized to the provided proxy config.
pub struct EnableArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value = "\\\\.\\SafechainL4Proxy")]
    pub device_path: String,

    #[arg(long)]
    pub ipv4_proxy: SocketAddrV4,

    #[arg(long)]
    pub ipv4_proxy_pid: u32,

    #[arg(long)]
    pub ipv6_proxy: Option<SocketAddrV6>,

    #[arg(long)]
    pub ipv6_proxy_pid: Option<u32>,
}

pub fn run(args: EnableArgs) -> Result<(), BoxError> {
    if args.ipv4_proxy_pid == 0 {
        return Err("`--ipv4-proxy-pid` must be a non-zero process id".into());
    }
    if args.ipv6_proxy.is_some() != args.ipv6_proxy_pid.is_some() {
        return Err("`--ipv6-proxy` and `--ipv6-proxy-pid` must be provided together".into());
    }
    if args.ipv6_proxy_pid == Some(0) {
        return Err("`--ipv6-proxy-pid` must be a non-zero process id".into());
    }

    info!(
        service_name = %args.service_name,
        device_path = %args.device_path,
        ipv4_proxy = %args.ipv4_proxy,
        ipv4_proxy_pid = args.ipv4_proxy_pid,
        ipv6_proxy = ?args.ipv6_proxy,
        ipv6_proxy_pid = ?args.ipv6_proxy_pid,
        "enabling SafeChain Windows driver"
    );
    enable_device(&args.service_name)?;
    ensure_wfp_objects(args.ipv6_proxy.is_some())?;

    let device = DeviceHandle::open_with_retry(&args.device_path, 10, Duration::from_millis(200))?;
    let ipv4_payload = Ipv4ProxyConfigPayload::new(args.ipv4_proxy, args.ipv4_proxy_pid)
        .to_bytes()
        .map_err(|err| format!("failed to encode IPv4 proxy payload: {err}"))?;
    device.send_ioctl(IOCTL_SET_IPV4_PROXY, &ipv4_payload)?;

    if let Some(ipv6_proxy) = args.ipv6_proxy {
        let Some(ipv6_proxy_pid) = args.ipv6_proxy_pid else {
            return Err("`--ipv6-proxy-pid` is required when `--ipv6-proxy` is provided".into());
        };
        let ipv6_payload = Ipv6ProxyConfigPayload::new(ipv6_proxy, ipv6_proxy_pid)
            .to_bytes()
            .map_err(|err| format!("failed to encode IPv6 proxy payload: {err}"))?;
        device.send_ioctl(IOCTL_SET_IPV6_PROXY, &ipv6_payload)?;
    } else {
        device.send_ioctl(IOCTL_CLEAR_IPV6_PROXY, &[])?;
    }

    info!(
        service_name = %args.service_name,
        device_path = %args.device_path,
        ipv4_proxy = %args.ipv4_proxy,
        ipv4_proxy_pid = args.ipv4_proxy_pid,
        ipv6_proxy = ?args.ipv6_proxy,
        ipv6_proxy_pid = ?args.ipv6_proxy_pid,
        "enabled SafeChain Windows driver and applied runtime config"
    );

    Ok(())
}
