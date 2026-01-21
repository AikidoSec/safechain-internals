use clap::Args;
use rama::error::OpaqueError;

#[derive(Debug, Clone, Args)]
/// run bench mock server
pub struct MockCommand {}

pub async fn exec(_args: MockCommand) -> Result<(), OpaqueError> {
    Ok(())
}
