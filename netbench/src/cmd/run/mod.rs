use std::time::Duration;

use clap::Args;
use rama::error::OpaqueError;

#[derive(Debug, Clone, Args)]
/// run benhmarker
pub struct RunCommand {}

pub async fn exec(_args: RunCommand) -> Result<(), OpaqueError> {
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}
