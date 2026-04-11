use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};
use std::net::{SocketAddrV4, SocketAddrV6};

use crate::common::{
    DeviceHandle, IOCTL_CLEAR_IPV6_PROXY, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, sync_startup_blob,
};

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value = "\\\\.\\SafechainL4Proxy")]
    pub device_path: String,

    #[arg(long)]
    pub ipv4_proxy: Option<SocketAddrV4>,

    #[arg(long)]
    pub ipv6_proxy: Option<SocketAddrV6>,

    #[arg(long, default_value_t = false)]
    pub clear_ipv6: bool,
}

pub fn run(args: UpdateArgs) -> Result<(), BoxError> {
    info!(
        service_name = %args.service_name,
        device_path = %args.device_path,
        ipv4_proxy = ?args.ipv4_proxy,
        ipv6_proxy = ?args.ipv6_proxy,
        clear_ipv6 = args.clear_ipv6,
        "updating SafeChain Windows driver config"
    );
    let device = DeviceHandle::open(&args.device_path)?;

    if let Some(ipv4_proxy) = args.ipv4_proxy {
        let payload = Ipv4ProxyConfigPayload::new(ipv4_proxy)
            .to_bytes()
            .map_err(|err| format!("failed to encode IPv4 proxy payload: {err}"))?;
        device.send_ioctl(IOCTL_SET_IPV4_PROXY, &payload)?;
    }
    if let Some(ipv6_proxy) = args.ipv6_proxy {
        let payload = Ipv6ProxyConfigPayload::new(ipv6_proxy)
            .to_bytes()
            .map_err(|err| format!("failed to encode IPv6 proxy payload: {err}"))?;
        device.send_ioctl(IOCTL_SET_IPV6_PROXY, &payload)?;
    }
    if args.clear_ipv6 {
        device.send_ioctl(IOCTL_CLEAR_IPV6_PROXY, &[])?;
    }

    if args.ipv4_proxy.is_some() || args.ipv6_proxy.is_some() || args.clear_ipv6 {
        let next_ipv6 = if args.clear_ipv6 {
            Some(None)
        } else {
            args.ipv6_proxy.map(Some)
        };
        sync_startup_blob(&args.service_name, args.ipv4_proxy, next_ipv6)?;
    }

    Ok(())
}
