use clap::Args;

use crate::common::{delete_startup_blob, run_sc};

#[derive(Debug, Args)]
pub struct StopArgs {
    #[arg(long, default_value = "SafeChainL4Proxy")]
    pub service_name: String,

    #[arg(long, default_value_t = false)]
    pub clear_persisted_config: bool,
}

pub fn run(args: StopArgs) -> Result<(), String> {
    run_sc(&["stop", &args.service_name], "SERVICE_NOT_ACTIVE")?;
    if args.clear_persisted_config {
        delete_startup_blob(&args.service_name)?;
    }
    Ok(())
}
