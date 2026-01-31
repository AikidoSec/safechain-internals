use std::{path::PathBuf, time::Duration};

use rama::{
    error::{BoxError, OpaqueError},
    graceful,
    telemetry::tracing,
};

#[cfg(target_family = "unix")]
use rama::error::ErrorContext as _;

use clap::{Parser, Subcommand};
use safechain_proxy_lib::utils;

pub mod cmd;
pub mod config;
pub mod http;
pub mod mock;

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// CLI arguments for configuring netbench behavior.
#[derive(Debug, Clone, Parser)]
#[command(name = " netbench")]
#[command(bin_name = "netbench")]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    cmds: CliCommands,

    /// debug logging as default instead of Info; use RUST_LOG env for more options
    #[arg(long, short = 'v', default_value_t = false, global = true)]
    pub verbose: bool,

    /// enable pretty logging (format for humans)
    #[arg(long, default_value_t = false, global = true)]
    pub pretty: bool,

    /// write the tracing output to the provided (log) file instead of stderr
    #[arg(long, short = 'o', global = true)]
    pub output: Option<PathBuf>,

    /// directory in which data will be stored on the filesystem
    #[arg(
            long,
            default_value = {
                #[cfg(not(target_os = "windows"))]
                { ".aikido/safechain-netbench" }
                #[cfg(target_os = "windows")]
                { ".aikido\\safechain-netbench" }
            },
            global = true,
        )]
    pub data: PathBuf,

    #[arg(long, value_name = "SECONDS", default_value_t = 0., global = true)]
    /// the graceful shutdown timeout (<= 0.0 = no timeout)
    pub graceful: f64,

    #[cfg(target_family = "unix")]
    /// Set the limit of max open file descriptors for this process and its children.
    #[arg(long, value_name = "N", default_value_t = 262_144, global = true)]
    pub ulimit: safechain_proxy_lib::utils::os::rlim_t,
}

#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum CliCommands {
    Run(self::cmd::run::RunCommand),
    Emulate(self::cmd::emulate::EmulateCommand),
    Mock(self::cmd::mock::MockCommand),
    Proxy(self::cmd::proxy::ProxyCommand),
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    let _tracing_guard = utils::telemetry::init_tracing(Some(utils::telemetry::TelemetryConfig {
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

/// run a netbench cmd with the given args
async fn run_with_args<F>(base_shutdown_signal: F, args: Args) -> Result<(), BoxError>
where
    F: Future<Output: Send + 'static> + Send + 'static,
{
    let graceful_timeout = (args.graceful > 0.).then(|| Duration::from_secs_f64(args.graceful));

    let (error_tx, error_rx) = tokio::sync::oneshot::channel::<OpaqueError>();
    let graceful = graceful::Shutdown::new(new_shutdown_signal(error_rx, base_shutdown_signal));

    graceful.spawn_task_fn(async move |guard| {
        let result = match args.cmds {
            CliCommands::Run(run_args) => self::cmd::run::exec(args.data, guard, run_args).await,
            CliCommands::Emulate(emulate_args) => {
                self::cmd::emulate::exec(args.data, guard, emulate_args).await
            }
            CliCommands::Mock(mock_args) => {
                self::cmd::mock::exec(args.data, guard, mock_args).await
            }
            CliCommands::Proxy(proxy_args) => {
                self::cmd::proxy::exec(args.data, guard, proxy_args).await
            }
        };
        if let Err(err) = result {
            let _ = error_tx.send(err);
        }
    });

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::debug!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}

fn new_shutdown_signal(
    error_rx: tokio::sync::oneshot::Receiver<OpaqueError>,
    base_shutdown_signal: impl Future<Output: Send + 'static> + Send + 'static,
) -> impl Future + Send + 'static {
    async move {
        tokio::select! {
            _ = base_shutdown_signal => {
                tracing::debug!("default signal triggered: init graceful shutdown");
            }
            result = error_rx => {
                match result {
                    Ok(err) => {
                        tracing::error!("fatal err received: {err}; abort");
                    },
                    Err(_) => {
                        tracing::debug!("command is finished without error, return control");
                    },
                }
            }
        }
    }
}
