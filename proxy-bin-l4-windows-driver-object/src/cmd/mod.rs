use clap::Subcommand;
use rama_core::error::BoxError;

pub mod disable;
pub mod enable;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum CommandKind {
    /// Ensure the driver device is enabled and apply the requested runtime proxy config.
    Enable(enable::EnableArgs),
    /// Disable the driver device and remove the userspace-managed WFP objects.
    Disable(disable::DisableArgs),
    /// Update the running driver config.
    Update(update::UpdateArgs),
}

pub fn run(command: CommandKind) -> Result<(), BoxError> {
    match command {
        CommandKind::Enable(args) => enable::run(args),
        CommandKind::Disable(args) => disable::run(args),
        CommandKind::Update(args) => update::run(args),
    }
}
