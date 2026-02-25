#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

use std::{path::PathBuf, time::Duration};

use rama::{
    error::{BoxError, ErrorContext},
    graceful,
    net::tls::ApplicationProtocol,
    telemetry::tracing,
};

use clap::Parser;

use safechain_proxy_lib::{storage, tls, utils as safechain_utils};

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod platform;
pub mod utils;

/// CLI arguments for configuring proxy behavior.
#[derive(Debug, Clone, Parser)]
#[command(name = "safechain-l4-proxy")]
#[command(bin_name = "safechain-l4-proxy")]
#[command(version, about, long_about = None)]
pub struct Args {
    /// secrets storage to use (e.g. for root CA)
    #[arg(
        long,
        value_name = "keyring | memory | <dir>",
        default_value = "keyring"
    )]
    pub secrets: storage::SecretStorageKind,

    /// debug logging as default instead of Info; use RUST_LOG env for more options
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// enable pretty logging (format for humans)
    #[arg(long, default_value_t = false)]
    pub pretty: bool,

    /// directory in which data will be stored on the filesystem
    #[arg(
        long,
        short = 'D',
        default_value = {
            #[cfg(not(target_os = "windows"))]
            { ".aikido/safechain-l4-proxy" }
            #[cfg(target_os = "windows")]
            { ".aikido\\safechain-l4-proxy" }
        },
    )]
    pub data: PathBuf,

    /// write the tracing output to the provided (log) file instead of stderr
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "SECONDS", default_value_t = 1.)]
    /// the graceful shutdown timeout (<= 0.0 = no timeout)
    pub graceful: f64,

    #[cfg(target_family = "unix")]
    /// Set the limit of max open file descriptors for this process and its children.
    #[arg(long, value_name = "N", default_value_t = 262_144)]
    pub ulimit: rama::unix::utils::rlim_t,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    let _tracing_guard = safechain_utils::telemetry::init_tracing(Some(
        safechain_utils::telemetry::TelemetryConfig {
            verbose: args.verbose,
            pretty: args.pretty,
            output: args.output.as_deref(),
        },
    ))
    .await?;

    #[cfg(target_family = "unix")]
    rama::unix::utils::raise_nofile(args.ulimit).context("set file descriptor limit")?;

    if let Err(err) = run_with_args(args).await {
        eprintln!("🚩 exit with error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

/// Runs all the safechain-l4-proxy services and blocks until
/// a critical error occurs or the (graceful) shutdown has been initiated.
async fn run_with_args(args: Args) -> Result<(), BoxError> {
    tokio::fs::create_dir_all(&args.data)
        .await
        .context("create data directory")
        .with_context_debug_field("path", || args.data.clone())?;

    let data_storage = storage::SyncCompactDataStorage::try_new(args.data.clone())
        .context("create compact data storage using dir")
        .with_context_debug_field("path", || args.data.clone())?;
    tracing::info!(path = ?args.data, "data directory ready to be used");

    let graceful_timeout = (args.graceful > 0.).then(|| Duration::from_secs_f64(args.graceful));

    let secret_storage =
        storage::SyncSecrets::try_new(self::utils::env::project_name(), args.secrets.clone())
            .context("create secrets storage")?;

    let (_tls_acceptor, _root_ca) = tls::new_tls_acceptor_layer(
        &secret_storage,
        &data_storage,
        Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
    )
    .context("prepare TLS acceptor")?;

    let graceful = graceful::Shutdown::default();

    #[cfg(feature = "har")]
    let (_har_client, _har_export_layer) =
        { safechain_proxy_lib::diagnostics::har::HarClient::new(&args.data, graceful.guard()) };

    // the actual proxy initialisation is platform-specific
    self::platform::init_platform(args)
        .await
        .context("initialise platform")?;

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}
