use std::{path::PathBuf, time::Duration};

use rama::{
    error::{BoxError, ErrorContext, OpaqueError},
    graceful::{self, ShutdownGuard},
    http::Uri,
    net::{address::SocketAddress, socket::Interface},
    telemetry::tracing::{self, Instrument as _},
    tls::boring::server::TlsAcceptorLayer,
};

use clap::Parser;

pub mod client;
pub mod diagnostics;
pub mod firewall;
pub mod http;
pub mod server;
pub mod storage;
pub mod tls;
pub mod utils;

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
pub mod test;

/// CLI arguments for configuring proxy behavior.
#[derive(Debug, Clone, Parser)]
#[command(name = "safechain-proxy")]
#[command(bin_name = "safechain-proxy")]
#[command(version, about, long_about = None)]
pub struct Args {
    /// network interface to bind the proxy to
    #[arg(
        long,
        short = 'b',
        value_name = "INTERFACE",
        default_value = "127.0.0.1:0"
    )]
    pub bind: Interface,

    /// network interface to bind the meta http(s) service to
    #[arg(long = "meta", value_name = "INTERFACE", default_value = "127.0.0.1:0")]
    pub meta_bind: Interface,

    /// secrets storage to use (e.g. for root CA)
    #[arg(
        long,
        value_name = "keyring | memory | <dir>",
        default_value = "keyring"
    )]
    pub secrets: self::storage::SyncSecrets,

    /// debug logging as default instead of Info; use RUST_LOG env for more options
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// enable pretty logging (format for humans)
    #[arg(long, default_value_t = false)]
    pub pretty: bool,

    /// MITM all traffic, regardless of the firewall host filters
    #[arg(long = "all", short = 'A')]
    pub mitm_all: bool,

    /// directory in which data will be stored on the filesystem
    #[arg(
        long,
        short = 'D',
        default_value = {
            #[cfg(not(target_os = "windows"))]
            { ".aikido/safechain-proxy" }
            #[cfg(target_os = "windows")]
            { ".aikido\\safechain-proxy" }
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

    #[cfg(target_family = "unix")]
    /// Set the limit of max open file descriptors for this process and its children.
    #[arg(long, value_name = "N", default_value_t = 262_144)]
    pub ulimit: self::utils::os::rlim_t,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    self::utils::telemetry::init_tracing(&args)?;

    #[cfg(target_family = "unix")]
    self::utils::os::raise_nofile(args.ulimit).context("set file descriptor limit")?;

    let base_shutdown_signal = graceful::default_signal();
    if let Err(err) = run_with_args(base_shutdown_signal, args).await {
        eprintln!("🚩 exit with error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

/// Runs all the safechain-proxy services and blocks until
/// a critical error occurs or the (graceful) shutdown has been initiated.
///
/// This entry point is used by both the (binary) `main` function as well as
/// for the e2e test suite found in the test module.
async fn run_with_args<F>(base_shutdown_signal: F, args: Args) -> Result<(), BoxError>
where
    F: Future<Output: Send + 'static> + Send + 'static,
{
    tokio::fs::create_dir_all(&args.data)
        .await
        .with_context(|| format!("create data directory at path '{}'", args.data.display()))?;
    let data_storage = self::storage::SyncCompactDataStorage::try_new(args.data.clone())
        .with_context(|| {
            format!(
                "create compact data storage using dir at path '{}'",
                args.data.display()
            )
        })?;
    tracing::info!(path = ?args.data, "data directory ready to be used");

    let graceful_timeout = (args.graceful > 0.).then(|| Duration::from_secs_f64(args.graceful));

    let (tls_acceptor, root_ca) =
        self::tls::new_tls_acceptor_layer(&args, &data_storage).context("prepare TLS acceptor")?;

    let (error_tx, error_rx) = tokio::sync::mpsc::channel::<OpaqueError>(1);
    let graceful = graceful::Shutdown::new(new_shutdown_signal(error_rx, base_shutdown_signal));

    #[cfg(feature = "har")]
    let (har_client, har_export_layer) =
        { self::diagnostics::har::HarClient::new(&args.data, graceful.guard()) };

    // ensure to not wait for firewall creation in case shutdown was initiated,
    // this can happen for example in case remote lists need to be fetched and the
    // something on the network on either side is not working
    let firewall = tokio::select! {
        result = self::firewall::Firewall::try_new(
            graceful.guard(),
            data_storage,
            args.reporting_endpoint.clone(),
        ) => {
            result?
        }

        _ = graceful.guard_weak().into_cancelled() => {
            return Err(OpaqueError::from_display(
                "shutdown initiated prior to firewall created; exit process immediately",
            ).into());
        }
    };

    // used to provide actual bind (socket) address of proxy interface
    // to the meta server for purposes such as PAC (file) generation
    let (proxy_addr_tx, proxy_addr_rx) = tokio::sync::oneshot::channel();

    graceful.spawn_task_fn({
        let args = args.clone();
        let error_tx = error_tx.clone();

        let tls_acceptor = tls_acceptor.clone();
        let root_ca = root_ca.clone();

        let firewall = firewall.clone();

        |guard| {
            run_meta_https_server(
                args,
                guard,
                error_tx,
                tls_acceptor,
                root_ca,
                proxy_addr_rx,
                firewall,
                #[cfg(feature = "har")]
                har_client,
            )
        }
    });

    graceful.spawn_task_fn({
        move |guard| {
            run_proxy_server(
                args,
                guard,
                error_tx,
                tls_acceptor,
                proxy_addr_tx,
                firewall,
                #[cfg(feature = "har")]
                har_export_layer,
            )
        }
    });

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_meta_https_server(
    args: Args,
    guard: ShutdownGuard,
    error_tx: tokio::sync::mpsc::Sender<OpaqueError>,
    tls_acceptor: TlsAcceptorLayer,
    root_ca: self::tls::RootCA,
    proxy_addr_rx: tokio::sync::oneshot::Receiver<SocketAddress>,
    firewall: self::firewall::Firewall,
    #[cfg(feature = "har")] har_client: self::diagnostics::har::HarClient,
) {
    tracing::info!("spawning meta http(s) server...");
    if let Err(err) = self::server::meta::run_meta_https_server(
        args,
        guard,
        tls_acceptor,
        root_ca,
        proxy_addr_rx,
        firewall,
        #[cfg(feature = "har")]
        har_client,
    )
    .instrument(tracing::debug_span!(
        "meta server lifetime",
        server.service.name = format!("{}-meta", self::utils::env::project_name()),
        otel.kind = "server",
        network.protocol.name = "http",
    ))
    .await
    {
        tracing::error!("meta server exited with an error: {err}");
        let _ = error_tx.send(err).await;
    }
}

async fn run_proxy_server(
    args: Args,
    guard: ShutdownGuard,
    error_tx: tokio::sync::mpsc::Sender<OpaqueError>,
    tls_acceptor: TlsAcceptorLayer,
    proxy_addr_tx: tokio::sync::oneshot::Sender<SocketAddress>,
    firewall: self::firewall::Firewall,
    #[cfg(feature = "har")] har_export_layer: self::diagnostics::har::HARExportLayer,
) {
    tracing::info!("spawning proxy server...");
    if let Err(err) = self::server::proxy::run_proxy_server(
        args,
        guard,
        tls_acceptor,
        proxy_addr_tx,
        firewall,
        #[cfg(feature = "har")]
        har_export_layer,
    )
    .instrument(tracing::debug_span!(
        "proxy server lifetime",
        server.service.name = self::utils::env::project_name(),
        otel.kind = "server",
        network.protocol.name = "tcp",
    ))
    .await
    {
        tracing::error!("proxy server exited with an error: {err}");
        let _ = error_tx.send(err).await;
    }
}

fn new_shutdown_signal(
    error_rx: tokio::sync::mpsc::Receiver<OpaqueError>,
    base_shutdown_signal: impl Future<Output: Send + 'static> + Send + 'static,
) -> impl Future + Send + 'static {
    async move {
        let mut mut_error_rx = error_rx;
        let mut signal = Box::pin(base_shutdown_signal);

        tokio::select! {
            _ = signal.as_mut() => {
                tracing::debug!("default signal triggered: init graceful shutdown");
            }
            err = mut_error_rx.recv() => {
                if let Some(err) = err {
                    tracing::error!("fatal err received: {err}; abort");
                } else {
                    tracing::info!("wait for default signal, no error was received");
                    signal.await;
                    tracing::debug!("default signal triggered: init graceful shutdown");
                }
            }
        }
    }
}
