mod cmd;
mod common;
mod telemetry;
mod wfp;

use clap::Parser;
use cmd::CommandKind;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "safechain-l4-proxy-driver-object")]
#[command(bin_name = "safechain-l4-proxy-driver-object")]
#[command(version, about = "Manage the SafeChain Windows L4 proxy driver")]
struct Cli {
    #[arg(long, short = 'v', default_value_t = false)]
    verbose: bool,

    #[arg(long, default_value_t = false)]
    pretty: bool,

    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: CommandKind,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let _tracing_guard = telemetry::init_tracing(&telemetry::TelemetryConfig {
        verbose: cli.verbose,
        pretty: cli.pretty,
        output: cli.output.as_deref(),
    })?;
    cmd::run(cli.command)
}
