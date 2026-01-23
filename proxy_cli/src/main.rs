use rama::{error::BoxError, graceful};

use safechain_proxy_lib::{
    cli::{Args, run_with_args},
    utils::{self, telemetry::TelemetryConfig},
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

    self::utils::telemetry::init_tracing(Some(TelemetryConfig {
        verbose: args.verbose,
        pretty: args.pretty,
        output: args.output.as_deref(),
    }))?;

    let base_shutdown_signal = graceful::default_signal();
    if let Err(err) = run_with_args(base_shutdown_signal, args).await {
        eprintln!("🚩 exit with error: {err}");
        std::process::exit(1);
    }

    Ok(())
}
