use std::path::Path;

use rama::{
    error::{BoxError, ErrorContext as _},
    net::address::SocketAddress,
};

// Real servers
//
// These have their own (ingress) socket(s).
pub mod meta;
pub mod proxy;

// Pseudo servers
//
// These are reachable but do not have a socket,
// but instead operate from within inside the proxy.
pub mod connectivity;

async fn write_server_socket_address_as_file(
    dir: &Path,
    name: &str,
    addr: SocketAddress,
) -> Result<(), BoxError> {
    let path = dir.join(format!("{name}.addr.txt"));
    tokio::fs::write(&path, addr.to_string())
        .await
        .context("write server's socket address to file")
        .context_field("address", addr)
        .with_context_debug_field("path", || path.to_owned())
}
