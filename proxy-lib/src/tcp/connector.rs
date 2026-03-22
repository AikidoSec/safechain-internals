use std::{sync::Arc, time::Duration};

use rama::{
    error::BoxError,
    extensions::ExtensionsMut,
    io::Io,
    net::{
        client::ConnectorService,
        socket::{SocketOptions, opts::TcpKeepAlive},
        transport::TryRefIntoTransportContext,
    },
    rt::Executor,
    tcp::client::service::TcpConnector,
};

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(2);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(not(target_os = "windows"))]
const TCP_KEEPALIVE_RETRIES: u32 = 5;

#[inline(always)]
/// Create a TCP [`ConnectorService`] for internal usage (for example: API calls).
pub fn new_tcp_connector_service_for_internal<Input>(
    exec: Executor,
) -> impl ConnectorService<Input, Connection: Io + Unpin> + Clone
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    TcpConnector::new(exec)
}

#[inline(always)]
/// Create a TCP [`ConnectorService`] for egress connections in proxies.
pub fn new_tcp_connector_service_for_proxy<Input>(
    exec: Executor,
) -> impl ConnectorService<Input, Connection: Io + Unpin> + Clone
where
    Input:
        ExtensionsMut + TryRefIntoTransportContext<Error: Send + Sync + 'static> + Send + 'static,
    BoxError: From<Input::Error>,
{
    TcpConnector::new(exec).with_connector(Arc::new(SocketOptions {
        keep_alive: Some(true),
        tcp_keep_alive: Some(TcpKeepAlive {
            time: Some(TCP_KEEPALIVE_TIME),
            interval: Some(TCP_KEEPALIVE_INTERVAL),
            #[cfg(not(target_os = "windows"))]
            retries: Some(TCP_KEEPALIVE_RETRIES),
        }),
        ..SocketOptions::default_tcp()
    }))
}
