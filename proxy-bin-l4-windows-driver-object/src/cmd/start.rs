use clap::Args;
use std::net::{SocketAddrV4, SocketAddrV6};

use super::update::{self, UpdateArgs};
use crate::common::{StartupConfig, run_sc, write_startup_blob};

#[derive(Debug, Args)]
pub struct StartArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value = "\\\\.\\SafechainL4Proxy")]
    pub device_path: String,

    #[arg(long)]
    pub ipv4_proxy: SocketAddrV4,

    #[arg(long)]
    pub ipv6_proxy: Option<SocketAddrV6>,

    #[arg(long)]
    pub proxy_pid: Option<u32>,
}

pub fn run(args: StartArgs) -> Result<(), String> {
    let startup_blob = StartupConfig::new(args.ipv4_proxy, args.ipv6_proxy);
    write_startup_blob(&args.service_name, &startup_blob)?;
    run_sc(&["start", &args.service_name], "SERVICE_ALREADY_RUNNING")?;

    update::run(UpdateArgs {
        device_path: args.device_path,
        ipv4_proxy: Some(args.ipv4_proxy),
        ipv6_proxy: args.ipv6_proxy,
        clear_ipv6: args.ipv6_proxy.is_none(),
        proxy_pid: args.proxy_pid,
        clear_proxy_pid: args.proxy_pid.is_none(),
    })
}
