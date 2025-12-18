use std::path::Path;

use rama::{
    error::{ErrorContext as _, OpaqueError},
    net::address::SocketAddress,
};

pub mod meta;
pub mod proxy;

async fn write_server_socket_address_as_file(
    dir: &Path,
    name: &str,
    addr: SocketAddress,
) -> Result<(), OpaqueError> {
    let path = dir.join(format!("{name}.addr.txt"));
    tokio::fs::write(&path, addr.to_string())
        .await
        .with_context(|| {
            format!(
                "write socket address '{addr}' for server '{name}' to file '{}'",
                path.display()
            )
        })
}
