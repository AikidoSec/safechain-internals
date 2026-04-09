use clap::Args;
use rama::telemetry::tracing::info;

use crate::common::{delete_startup_blob, run_sc};
use crate::wfp::remove_wfp_objects;

#[derive(Debug, Args)]
pub struct StopArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value_t = false)]
    pub clear_persisted_config: bool,
}

pub fn run(args: StopArgs) -> Result<(), String> {
    info!(
        service_name = %args.service_name,
        clear_persisted_config = args.clear_persisted_config,
        "stopping SafeChain Windows driver"
    );
    remove_wfp_objects()?;
    run_sc(&["stop", &args.service_name], "SERVICE_NOT_ACTIVE")?;
    if args.clear_persisted_config {
        delete_startup_blob(&args.service_name)?;
    }
    Ok(())
}
