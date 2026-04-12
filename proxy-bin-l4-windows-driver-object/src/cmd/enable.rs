use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};
use std::net::{SocketAddrV4, SocketAddrV6};

use safechain_l4_proxy_windows_driver_object::runtime_config::{
    DriverRuntimeConfig, ensure_enabled_and_apply_runtime_config,
};

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
    info!(
        service_name = %args.service_name,
        device_path = %args.device_path,
        ipv4_proxy = %args.ipv4_proxy,
        ipv4_proxy_pid = args.ipv4_proxy_pid,
        ipv6_proxy = ?args.ipv6_proxy,
        ipv6_proxy_pid = ?args.ipv6_proxy_pid,
        "enabling SafeChain Windows driver"
    );
    let config = DriverRuntimeConfig {
        device_path: &args.device_path,
        ipv4_proxy: args.ipv4_proxy,
        ipv4_proxy_pid: args.ipv4_proxy_pid,
        ipv6_proxy: args.ipv6_proxy,
        ipv6_proxy_pid: args.ipv6_proxy_pid,
    };
    ensure_enabled_and_apply_runtime_config(&args.service_name, &config)?;

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
