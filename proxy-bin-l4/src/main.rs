#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
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

#[cfg(target_os = "windows")]
use ::{
    safechain_l4_proxy_windows_driver_object::runtime_config::{
        DriverRuntimeConfig, apply_runtime_config,
    },
    std::net::IpAddr,
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
    /// IPv4 network interface to bind the transparent proxy to
    #[arg(long, default_value_t = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))]
    pub bind_ipv4: SocketAddrV4,

    /// Optional IPv6 network interface to bind the transparent proxy to
    #[arg(long)]
    pub bind_ipv6: Option<SocketAddrV6>,

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
    #[arg(long, default_value_t = 0.2)]
    pub peek_duration: f64,

    #[cfg(target_family = "unix")]
    /// Set the limit of max open file descriptors for this process and its children.
    #[arg(long, value_name = "N", default_value_t = 262_144)]
    pub ulimit: rama::unix::utils::rlim_t,

    /// Use Aikido Core KMS-backed intermediate CA instead of a local self-signed root CA.
    /// Requires a valid agent identity (token + device_id in config.json).
    #[arg(long = "use-aikido-ca", default_value_t = false)]
    pub use_aikido_ca: bool,
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
    let peek_duration = Duration::from_secs_f64(args.peek_duration.max(0.001));

    let maybe_tcp_server_addr_v6 = if let Some(bind_ipv6) = args.bind_ipv6 {
        Some(
            self::tcp::start_tcp_server(
                SocketAddr::V6(bind_ipv6),
                Executor::graceful(graceful.guard()),
                peek_duration,
                args.use_aikido_ca,
                agent_identity.clone(),
                args.reporting_endpoint.clone(),
                args.aikido_url.clone(),
                data_storage.clone(),
                secret_storage.clone(),
            )
            .await
            .context("start tcp services (v6)")?,
        )
    } else {
        None
    };

    let tcp_server_addr_v4 = self::tcp::start_tcp_server(
        SocketAddr::V4(args.bind_ipv4),
        Executor::graceful(graceful.guard()),
        peek_duration,
        args.use_aikido_ca,
        agent_identity,
        args.reporting_endpoint,
        args.aikido_url,
        data_storage,
        secret_storage,
    )
    .await
    .context("start tcp services (v4)")?;

    tracing::info!(address = %tcp_server_addr_v4, "tcp server (v4) up and running");
    if let Some(tcp_server_addr_v6) = maybe_tcp_server_addr_v6 {
        tracing::info!(address = %tcp_server_addr_v6, "tcp server (v6) up and running");
    }

    #[cfg(target_os = "windows")]
    sync_windows_driver_runtime_config(tcp_server_addr_v4, maybe_tcp_server_addr_v6)
        .context("synchronize SafeChain Windows driver runtime config with running L4 proxy")?;

    write_server_socket_addresses_as_files(
        &args.data,
        tcp_server_addr_v4,
        maybe_tcp_server_addr_v6,
    )
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

async fn write_server_socket_addresses_as_files(
    dir: &Path,
    addr_ipv4: SocketAddress,
    maybe_addr_ipv6: Option<SocketAddress>,
) -> Result<(), BoxError> {
    remove_stale_server_socket_address_files(dir).await?;

    for addr in [addr_ipv4].iter().chain(maybe_addr_ipv6.iter()) {
        let file_name = if addr.ip_addr.is_ipv4() {
            "l4_proxy.addr.v4.txt"
        } else {
            "l4_proxy.addr.v6.txt"
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

#[cfg(target_os = "windows")]
fn sync_windows_driver_runtime_config(
    addr_ipv4: SocketAddress,
    maybe_addr_ipv6: Option<SocketAddress>,
) -> Result<(), BoxError> {
    let mut ipv4_proxy = None;
    let mut ipv6_proxy = None;

    for addr in [addr_ipv4].iter().chain(maybe_addr_ipv6.iter()) {
        let socket_addr = socket_address_to_std(addr)?;
        match socket_addr {
            SocketAddr::V4(v4) => {
                if ipv4_proxy.replace(v4).is_some() {
                    return Err("expected exactly one IPv4 listener for Windows driver sync".into());
                }
            }
            SocketAddr::V6(v6) => {
                if ipv6_proxy.replace(v6).is_some() {
                    return Err("expected at most one IPv6 listener for Windows driver sync".into());
                }
            }
        }
    }

    let Some(ipv4_proxy) = ipv4_proxy else {
        return Err("missing IPv4 listener for Windows driver sync".into());
    };
    let pid = std::process::id();
    let config = DriverRuntimeConfig {
        device_path: "\\\\.\\SafechainL4Proxy",
        ipv4_proxy,
        ipv4_proxy_pid: pid,
        ipv6_proxy,
        ipv6_proxy_pid: ipv6_proxy.map(|_| pid),
    };

    apply_runtime_config(&config)
}

#[cfg(target_os = "windows")]
fn socket_address_to_std(addr: &SocketAddress) -> Result<SocketAddr, BoxError> {
    Ok(match addr.ip_addr {
        IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, addr.port)),
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, addr.port, 0, 0)),
    })
}
