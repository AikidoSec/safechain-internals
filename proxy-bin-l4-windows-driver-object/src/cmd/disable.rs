use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};

use safechain_l4_proxy_windows_driver_object::{common::disable_device, wfp::remove_wfp_objects};

#[derive(Debug, Args)]
/// Disable the SafeChain Windows driver device.
pub struct DisableArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value_t = false)]
    pub force_remove_on_veto: bool,
}

pub fn run(args: DisableArgs) -> Result<(), BoxError> {
    info!(
        service_name = %args.service_name,
        force_remove_on_veto = args.force_remove_on_veto,
        "disabling SafeChain Windows driver"
    );
    remove_wfp_objects()?;
    disable_device(&args.service_name, args.force_remove_on_veto)?;
    Ok(())
}
