use clap::Subcommand;
use rama_core::error::BoxError;

pub mod disable;
pub mod enable;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum CommandKind {
    /// Enable the driver device. Fresh installs are already enabled unless you disabled it before.
    Enable(enable::EnableArgs),
    /// Disable the driver device.
    Disable(disable::DisableArgs),
    Update(update::UpdateArgs),
}

pub fn run(command: CommandKind) -> Result<(), BoxError> {
    match command {
        CommandKind::Enable(args) => enable::run(args),
        CommandKind::Disable(args) => disable::run(args),
        CommandKind::Update(args) => update::run(args),
    }
}
