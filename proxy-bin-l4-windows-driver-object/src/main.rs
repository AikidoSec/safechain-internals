#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]
#![cfg(target_os = "windows")]

mod cmd;
mod common;

use clap::Parser;
use cmd::CommandKind;

#[derive(Debug, Parser)]
#[command(name = "safechain-l4-proxy-driver-object")]
#[command(bin_name = "safechain-l4-proxy-driver-object")]
#[command(version, about = "Manage the SafeChain Windows L4 proxy driver")]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    cmd::run(cli.command)
}
