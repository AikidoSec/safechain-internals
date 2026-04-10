use clap::Args;
use rama_core::telemetry::tracing::info;
use std::net::{SocketAddrV4, SocketAddrV6};

use super::update::{self, UpdateArgs};
use crate::common::{StartupConfig, start_service, write_startup_blob};
use crate::wfp::ensure_wfp_objects;

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
}

pub fn run(args: StartArgs) -> Result<(), String> {
    info!(
        service_name = %args.service_name,
        device_path = %args.device_path,
        ipv4_proxy = %args.ipv4_proxy,
        ipv6_proxy = ?args.ipv6_proxy,
        "starting SafeChain Windows driver"
    );
    let startup_blob = StartupConfig::new(args.ipv4_proxy, args.ipv6_proxy);
    write_startup_blob(&args.service_name, &startup_blob)?;
    start_service(&args.service_name)?;
    ensure_wfp_objects(args.ipv6_proxy.is_some())?;

    update::run(UpdateArgs {
        service_name: args.service_name,
        device_path: args.device_path,
        ipv4_proxy: Some(args.ipv4_proxy),
        ipv6_proxy: args.ipv6_proxy,
        clear_ipv6: args.ipv6_proxy.is_none(),
    })
}
