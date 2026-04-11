use clap::Subcommand;
use rama_core::error::BoxError;

pub mod start;
pub mod stop;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum CommandKind {
    Start(start::StartArgs),
    Stop(stop::StopArgs),
    Update(update::UpdateArgs),
}

pub fn run(command: CommandKind) -> Result<(), BoxError> {
    match command {
        CommandKind::Start(args) => start::run(args),
        CommandKind::Stop(args) => stop::run(args),
        CommandKind::Update(args) => update::run(args),
    }
}
