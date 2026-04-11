use clap::Subcommand;
use rama_core::error::BoxError;

pub mod disable;
pub mod enable;
pub mod seed_startup_config;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum CommandKind {
    /// Enable the driver device. Fresh installs are already enabled unless you disabled it before.
    Enable(enable::EnableArgs),
    /// Disable the driver device.
    Disable(disable::DisableArgs),
    /// Persist startup config without touching current device state.
    SeedStartupConfig(seed_startup_config::SeedStartupConfigArgs),
    Update(update::UpdateArgs),
}

pub fn run(command: CommandKind) -> Result<(), BoxError> {
    match command {
        CommandKind::Enable(args) => enable::run(args),
        CommandKind::Disable(args) => disable::run(args),
        CommandKind::SeedStartupConfig(args) => seed_startup_config::run(args),
        CommandKind::Update(args) => update::run(args),
    }
}
