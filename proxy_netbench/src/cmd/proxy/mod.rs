use std::path::PathBuf;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    graceful::ShutdownGuard,
    http::Uri,
    net::{
        address::{ProxyAddress, SocketAddress},
        socket::Interface,
    },
    telemetry::tracing,
};

use clap::Args;
use safechain_proxy_lib::{client, diagnostics, firewall, server, storage, tls};

#[derive(Debug, Clone, Args)]
/// run proxy in function of benchmarker
pub struct ProxyCommand {
    /// socket address of the mock server to be used
    /// by proxy for all egress connections
    #[arg(value_name = "ADDRESS", required = true)]
    pub mock: SocketAddress,

    /// network interface to bind to
    #[arg(
        long,
        short = 'b',
        value_name = "INTERFACE",
        default_value = "127.0.0.1:0"
    )]
    pub bind: Interface,

    /// Set an upstream proxy to be used for all egress proxy traffic.
    #[arg(long, value_name = "<scheme>://[user:[password]@]<host>[:port]")]
    pub proxy: Option<ProxyAddress>,

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
    args: ProxyCommand,
) -> Result<(), OpaqueError> {
    tracing::info!(mock = %args.mock, "try set mock server as egress address overwrite");
    client::transport::try_set_egress_address_overwrite(args.mock)?;

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

    let secrets = storage::SyncSecrets::new_in_memory();

    let (tls_acceptor, root_ca) =
        tls::new_tls_acceptor_layer(&secrets, &data_storage).context("prepare TLS acceptor")?;
    tracing::info!(path = ?data, "write new (tmp) root CA to disk");
    server::write_root_ca_as_file(&data, &root_ca).await?;

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

    const DO_NOT_MITM_ALL: bool = false;
    let proxy_server = server::proxy::build_proxy_server(
        args.bind,
        args.proxy,
        DO_NOT_MITM_ALL,
        guard,
        tls_acceptor,
        firewall,
        har_layer,
    )
    .await?;

    let proxy_addr = proxy_server.socket_address();
    server::write_server_socket_address_as_file(&data, "proxy", proxy_addr).await?;

    let result = proxy_server.serve().await;

    if args.record_har
        && let Err(err) = har_client.toggle().await
    {
        tracing::error!("failed to toggle HAR recording off again: {err}");
    }

    result
}
