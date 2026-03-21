use std::{sync::Arc, time::Duration};

use rama::{
    io::Io,
    net::{
        client::ConnectorService,
        socket::{SocketOptions, opts::TcpKeepAlive},
    },
    rt::Executor,
    tcp::client::service::TcpConnector,
};

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(2);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_RETRIES: u32 = 5;

pub fn tcp_connector_service(
    exec: Executor,
) -> impl ConnectorService<rama::tcp::client::Request, Connection: Io + Unpin> + Clone {
    TcpConnector::new(exec).with_connector(Arc::new(SocketOptions {
        keep_alive: Some(true),
        tcp_keep_alive: Some(TcpKeepAlive {
            time: Some(TCP_KEEPALIVE_TIME),
            interval: Some(TCP_KEEPALIVE_INTERVAL),
            retries: Some(TCP_KEEPALIVE_RETRIES),
        }),
        ..SocketOptions::default_tcp()
    }))
}
