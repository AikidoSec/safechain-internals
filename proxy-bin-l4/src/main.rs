#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    time::Duration,
};

use rama::{
    error::{BoxError, ErrorContext},
    graceful,
    http::Uri,
    net::address::SocketAddress,
    rt::Executor,
    telemetry::tracing,
};

use clap::Parser;

use safechain_proxy_lib::{
    storage,
    utils::{self as safechain_utils, token::AgentIdentity},
};

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod tcp;
pub mod utils;

/// CLI arguments for configuring proxy behavior.
#[derive(Debug, Clone, Parser)]
#[command(name = "safechain-l4-proxy")]
#[command(bin_name = "safechain-l4-proxy")]
#[command(version, about, long_about = None)]
pub struct Args {
    /// network interface to bind the transparent proxy to
    #[arg(long, default_values_t = default_bind_addresses())]
    pub bind: Vec<SocketAddr>,

    /// secrets storage to use (e.g. for root CA)
    #[arg(
        long,
        value_name = "keyring | memory | <dir>",
        default_value = "memory"
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

    /// Optional endpoint URL to POST blocked-event notifications to.
    ///
    /// If omitted, blocked events are still recorded locally but not reported.
    #[arg(long = "reporting-endpoint", value_name = "URL")]
    pub reporting_endpoint: Option<Uri>,

    /// Aikido app base URL used to fetch endpoint protection config.
    #[arg(
        long = "aikido-url",
        value_name = "URL",
        default_value = "https://app.aikido.dev"
    )]
    pub aikido_url: Uri,

    /// Peek duration in seconds (fractional).
    #[arg(long, default_value_t = 0.5)]
    pub peek_duration: f64,

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

    let graceful = graceful::Shutdown::default();

    let agent_identity = AgentIdentity::load(&args.data);

    let tcp_server_addr = self::tcp::start_tcp_servers(
        &args.bind,
        Executor::graceful(graceful.guard()),
        Duration::from_secs_f64(args.peek_duration.max(0.05)),
        agent_identity,
        args.reporting_endpoint,
        args.aikido_url,
        data_storage,
        secret_storage,
    )
    .await
    .context("start tcp services")?;

    for addr in &tcp_server_addr {
        tracing::info!(address = %addr, "tcp server up and running");
    }

    write_server_socket_addresses_as_files(&args.data, &tcp_server_addr)
        .await
        .context("write server addrs to fs")
        .context_debug_field("dir", args.data)?;

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}

fn default_bind_addresses() -> Vec<SocketAddr> {
    vec![
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
    ]
}

async fn write_server_socket_addresses_as_files(
    dir: &Path,
    addrs: &[SocketAddress],
) -> Result<(), BoxError> {
    remove_stale_server_socket_address_files(dir).await?;

    let mut v4_index = 0usize;
    let mut v6_index = 0usize;

    for addr in addrs {
        let (kind, index) = if addr.ip_addr.is_ipv4() {
            let index = v4_index;
            v4_index += 1;
            ("v4", index)
        } else {
            let index = v6_index;
            v6_index += 1;
            ("v6", index)
        };

        let file_name = if index == 0 {
            format!("l4_proxy.addr.{kind}.txt")
        } else {
            format!("l4_proxy.addr.{kind}.{index}.txt")
        };
        let path = dir.join(file_name);
        tokio::fs::write(&path, addr.to_string())
            .await
            .context("write server's socket address to file")
            .context_field("address", *addr)
            .with_context_debug_field("path", || path.to_owned())?;
    }

    Ok(())
}

async fn remove_stale_server_socket_address_files(dir: &Path) -> Result<(), BoxError> {
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .context("read data directory while clearing stale socket address files")
        .with_context_debug_field("path", || dir.to_owned())?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .context("iterate data directory while clearing stale socket address files")?
    {
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };

        let is_socket_address_file =
            file_name.starts_with("l4_proxy.addr.v4") || file_name.starts_with("l4_proxy.addr.v6");
        if !is_socket_address_file || !file_name.ends_with(".txt") {
            continue;
        }

        let path = entry.path();
        tokio::fs::remove_file(&path)
            .await
            .context("remove stale socket address file")
            .with_context_debug_field("path", || path.clone())?;
    }

    Ok(())
}
