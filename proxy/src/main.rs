use std::{path::PathBuf, time::Duration};

use rama::{
    error::{BoxError, ErrorContext, OpaqueError},
    graceful,
    net::socket::Interface,
    telemetry::tracing::{self, Instrument as _},
};

use clap::Parser;

pub mod diagnostics;
pub mod firewall;
pub mod server;
pub mod storage;
pub mod tls;
pub mod utils;

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
    #[arg(long, value_name = "keyring | <dir>", default_value = "keyring")]
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
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    self::utils::telemetry::init_tracing(&args)?;

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

    let (etx, mut erx) = tokio::sync::mpsc::channel::<OpaqueError>(1);
    let graceful = graceful::Shutdown::new(async move {
        let mut signal = Box::pin(graceful::default_signal());
        tokio::select! {
            _ = signal.as_mut() => {
                tracing::debug!("default signal triggered: init graceful shutdown");
            }
            err = erx.recv() => {
                if let Some(err) = err {
                    tracing::error!("fatal err received: {err}; abort");
                } else {
                    tracing::info!("wait for default signal, no error was received");
                    signal.await;
                    tracing::debug!("default signal triggered: init graceful shutdown");
                }
            }
        }
    });

    #[cfg(feature = "har")]
    let (har_client, har_export_layer) =
        { self::diagnostics::har::HarClient::new(&args.data, graceful.guard()) };

    let firewall = self::firewall::Firewall::new(data_storage);

    // used to provide actual bind (socket) address of proxy interface
    // to the meta server for purposes such as PAC (file) generation
    let (proxy_addr_tx, proxy_addr_rx) = tokio::sync::oneshot::channel();

    graceful.spawn_task_fn({
        let args = args.clone();
        let etx = etx.clone();

        let tls_acceptor = tls_acceptor.clone();
        let root_ca = root_ca.clone();

        let firewall = firewall.clone();

        async move |guard| {
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
                let _ = etx.send(err).await;
            }
        }
    });

    graceful.spawn_task_fn({
        async move |guard| {
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
                let _ = etx.send(err).await;
            }
        }
    });

    let delay = match graceful_timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}
