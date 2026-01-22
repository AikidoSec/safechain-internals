use std::path::PathBuf;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::Uri,
    net::socket::Interface,
    telemetry::tracing,
};

use clap::Args;
use safechain_proxy_lib::{diagnostics, firewall, server, storage, tls};

#[derive(Debug, Clone, Args)]
/// run proxy in function of benchmarker
pub struct ProxyCommand {
    /// network interface to bind to
    #[arg(
        long,
        short = 'b',
        value_name = "INTERFACE",
        default_value = "127.0.0.1:0"
    )]
    pub bind: Interface,

    #[arg(long)]
    /// Record the entire proxy traffic to a HAR file.
    pub record_har: bool,

    /// Optional endpoint URL to POST blocked-event notifications to.
    #[arg(long, value_name = "URL")]
    pub reporting_endpoint: Option<Uri>,
}

pub async fn exec(
    data: PathBuf,
    guard: ShutdownGuard,
    secrets: storage::SyncSecrets,
    args: ProxyCommand,
) -> Result<(), OpaqueError> {
    tokio::fs::create_dir_all(&data)
        .await
        .with_context(|| format!("create data directory at path '{}'", data.display()))?;
    let data_storage =
        storage::SyncCompactDataStorage::try_new(data.clone()).with_context(|| {
            format!(
                "create compact data storage using dir at path '{}'",
                data.display()
            )
        })?;
    tracing::info!(path = ?data, "data directory ready to be used");

    let (tls_acceptor, _root_ca) =
        tls::new_tls_acceptor_layer(&secrets, &data_storage).context("prepare TLS acceptor")?;

    // ensure to not wait for firewall creation in case shutdown was initiated,
    // this can happen for example in case remote lists need to be fetched and the
    // something on the network on either side is not working
    let firewall = tokio::select! {
        result = firewall::Firewall::try_new(
            guard.clone(),
            data_storage,
            args.reporting_endpoint.clone(),
        ) => {
            result?
        }

        _ = guard.cancelled() => {
            return Err(OpaqueError::from_display(
                "shutdown initiated prior to firewall created; exit process immediately",
            ));
        }
    };

    let (har_client, har_layer) = diagnostics::har::HarClient::new(&data, guard.clone());
    if args.record_har
        && har_client
            .toggle()
            .await
            .context("failed to enable HAR recording")?
    {
        return Err(OpaqueError::from_display(
            "HAR recording was unexpectely already enabled",
        ));
    }

    let proxy_server = server::proxy::build_proxy_server(
        args.bind,
        false,
        guard,
        tls_acceptor,
        firewall,
        har_layer,
    )
    .await?;

    let proxy_addr = proxy_server.socket_address();
    server::write_server_socket_address_as_file(&data, "proxy", proxy_addr).await?;

    proxy_server.serve().await
}
