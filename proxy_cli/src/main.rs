#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

use rama::{error::BoxError, graceful};

#[cfg(target_family = "unix")]
use rama::error::ErrorContext as _;

use safechain_proxy_lib::{
    cli::{Args, run_with_args},
    utils::telemetry::TelemetryConfig,
};

use clap::Parser;

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    let _tracing_guard =
        safechain_proxy_lib::utils::telemetry::init_tracing(Some(TelemetryConfig {
            verbose: args.verbose,
            pretty: args.pretty,
            output: args.output.as_deref(),
        }))
        .await?;

    #[cfg(target_family = "unix")]
    safechain_proxy_lib::utils::os::raise_nofile(args.ulimit)
        .context("set file descriptor limit")?;

    let base_shutdown_signal = graceful::default_signal();
    if let Err(err) = run_with_args(base_shutdown_signal, args).await {
        eprintln!("🚩 exit with error: {err}");
        std::process::exit(1);
    }

    Ok(())
}
