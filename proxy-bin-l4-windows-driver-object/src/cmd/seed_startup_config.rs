use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};
use std::net::{SocketAddrV4, SocketAddrV6};

use crate::common::{StartupConfig, write_startup_blob};

#[derive(Debug, Args)]
/// Persist startup config without changing current device state.
pub struct SeedStartupConfigArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long)]
    pub ipv4_proxy: SocketAddrV4,

    #[arg(long)]
    pub ipv4_proxy_pid: u32,

    #[arg(long)]
    pub ipv6_proxy: Option<SocketAddrV6>,

    #[arg(long)]
    pub ipv6_proxy_pid: Option<u32>,
}

pub fn run(args: SeedStartupConfigArgs) -> Result<(), BoxError> {
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
        ipv4_proxy = %args.ipv4_proxy,
        ipv4_proxy_pid = args.ipv4_proxy_pid,
        ipv6_proxy = ?args.ipv6_proxy,
        ipv6_proxy_pid = ?args.ipv6_proxy_pid,
        "persisting SafeChain Windows driver startup config without changing device state"
    );

    let startup_blob = StartupConfig::new(
        args.ipv4_proxy,
        args.ipv4_proxy_pid,
        args.ipv6_proxy.zip(args.ipv6_proxy_pid),
    );
    write_startup_blob(&args.service_name, &startup_blob)
}
