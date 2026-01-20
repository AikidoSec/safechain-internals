use std::path::Path;

use rama::{
    error::{ErrorContext as _, OpaqueError},
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
) -> Result<(), OpaqueError> {
    let path = dir.join(format!("{name}.addr.txt"));

    // Write via a temp file + rename so readers never observe a truncated/partial file.
    // This matters for the e2e runtime which polls these files while the proxy is starting.
    let tmp_path = dir.join(format!("{name}.addr.txt.tmp"));

    tokio::fs::write(&tmp_path, addr.to_string())
        .await
        .with_context(|| {
            format!(
                "write socket address '{addr}' for server '{name}' to temp file '{}'",
                tmp_path.display()
            )
        })?;

    // On Windows, renaming over an existing file can fail; remove best-effort.
    #[cfg(target_os = "windows")]
    {
        let _ = tokio::fs::remove_file(&path).await;
    }

    tokio::fs::rename(&tmp_path, &path).await.with_context(|| {
        format!(
            "rename temp socket address file '{}' to '{}'",
            tmp_path.display(),
            path.display()
        )
    })
}
