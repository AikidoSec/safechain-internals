use clap::Args;
use rama_core::{error::BoxError, telemetry::tracing::info};

use crate::common::{delete_startup_blob, disable_device};
use crate::wfp::remove_wfp_objects;

#[derive(Debug, Args)]
/// Disable the SafeChain Windows driver device.
pub struct DisableArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value_t = false)]
    pub clear_persisted_config: bool,
}

pub fn run(args: DisableArgs) -> Result<(), BoxError> {
    info!(
        service_name = %args.service_name,
        clear_persisted_config = args.clear_persisted_config,
        "disabling SafeChain Windows driver"
    );
    remove_wfp_objects()?;
    disable_device(&args.service_name)?;
    if args.clear_persisted_config {
        delete_startup_blob(&args.service_name)?;
    }
    Ok(())
}
