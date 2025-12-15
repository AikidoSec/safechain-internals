use std::time::Duration;

use rama::{
    error::{BoxError, ErrorContext, OpaqueError},
    graceful,
    net::socket::Interface,
    telemetry::tracing::{self, Instrument as _},
};

use clap::Parser;

pub mod firewall;
pub mod server;
pub mod tls;
pub mod utils;

/// CLI arguments for configuring proxy behavior.
#[derive(Debug, Clone, Parser)]
#[command(name = "aikido-proxy")]
#[command(bin_name = "aikido-proxy")]
#[command(version, about, long_about = None)]
pub struct Args {
    /// network interface to bind the proxy to
    #[arg(
        short = 'b',
        long,
        value_name = "INTERFACE",
        default_value = "127.0.0.1:0"
    )]
    pub bind: Interface,

    /// network interface to bind the meta http(s) service to
    #[arg(long = "meta", value_name = "INTERFACE", default_value = "127.0.0.1:0")]
    pub meta_bind: Interface,

    /// debug logging as default instead of Info; use RUST_LOG env for more options
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    /// enable pretty logging (format for humans)
    #[arg(long, default_value_t = false)]
    pub pretty: bool,

    #[arg(long, value_name = "SECONDS", default_value_t = 1.)]
    /// the graceful shutdown timeout (<= 0.0 = no timeout)
    pub graceful: f64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    self::utils::telemetry::init_tracing(&args);

    let graceful_timeout = (args.graceful > 0.).then(|| Duration::from_secs_f64(args.graceful));

    let (tls_acceptor, root_ca) =
        self::tls::new_tls_acceptor_layer().context("prepare TLS acceptor")?;

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
                    signal.await;
                    tracing::debug!("default signal triggered: init graceful shutdown");
                }
            }
        }
    });

    graceful.spawn_task_fn({
        let args = args.clone();
        let etx = etx.clone();

        let tls_acceptor = tls_acceptor.clone();
        let root_ca = root_ca.clone();

        async move |guard| {
            tracing::info!("spawning meta http(s) server...");
            if let Err(err) =
                self::server::meta::run_meta_https_server(args, guard, tls_acceptor, root_ca)
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
            if let Err(err) = self::server::proxy::run_proxy_server(args, guard)
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
