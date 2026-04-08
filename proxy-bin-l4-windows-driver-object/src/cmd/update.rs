use clap::Args;
use std::net::{SocketAddrV4, SocketAddrV6};

use crate::common::{
    DeviceHandle, IOCTL_CLEAR_IPV6_PROXY, IOCTL_CLEAR_PROXY_PROCESS_ID, IOCTL_SET_IPV4_PROXY,
    IOCTL_SET_IPV6_PROXY, IOCTL_SET_PROXY_PROCESS_ID, Ipv4ProxyConfigPayload,
    Ipv6ProxyConfigPayload, ProxyProcessIdPayload,
};

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long, default_value = "\\\\.\\SafechainL4Proxy")]
    pub device_path: String,

    #[arg(long)]
    pub ipv4_proxy: Option<SocketAddrV4>,

    #[arg(long)]
    pub ipv6_proxy: Option<SocketAddrV6>,

    #[arg(long, default_value_t = false)]
    pub clear_ipv6: bool,

    #[arg(long)]
    pub proxy_pid: Option<u32>,

    #[arg(long, default_value_t = false)]
    pub clear_proxy_pid: bool,
}

pub fn run(args: UpdateArgs) -> Result<(), String> {
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
    if let Some(proxy_pid) = args.proxy_pid {
        let payload = ProxyProcessIdPayload::new(proxy_pid)
            .to_bytes()
            .map_err(|err| format!("failed to encode proxy PID payload: {err}"))?;
        device.send_ioctl(IOCTL_SET_PROXY_PROCESS_ID, &payload)?;
    }
    if args.clear_proxy_pid {
        device.send_ioctl(IOCTL_CLEAR_PROXY_PROCESS_ID, &[])?;
    }

    Ok(())
}
