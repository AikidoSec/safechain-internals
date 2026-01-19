use std::sync::Arc;

use rama::{net::address::Authority, telemetry::tracing};
use serde::Serialize;
use tokio::sync::mpsc;

/// Information about a blocked request, attached to the response via extensions.
/// Rules should add this to their blocked responses so the firewall can send notifications.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// The name of the blocked package
    pub package_name: String,
    /// The version of the blocked package (if known)
    pub package_version: Option<String>,
}

/// Information about a blocked request to be sent to the daemon.
#[derive(Debug, Clone, Serialize)]
pub struct BlockEvent {
    /// The product/rule that triggered the block (e.g., "npm", "vscode", "chrome", "pypi")
    pub product: &'static str,
    /// The name of the blocked package
    pub package_name: String,
    /// The version of the blocked package (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    /// The original request URL that was blocked
    pub url: String,
    /// Additional context about why the block occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A handle to send block notifications to the daemon.
///
/// This is cheaply cloneable and can be shared across rules.
#[derive(Clone)]
pub struct BlockNotifier {
    inner: Option<Arc<BlockNotifierInner>>,
}

struct BlockNotifierInner {
    tx: mpsc::UnboundedSender<BlockEvent>,
}

impl std::fmt::Debug for BlockNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockNotifier")
            .field("enabled", &self.inner.is_some())
            .finish()
    }
}

impl BlockNotifier {
    /// Creates a new block notifier that sends events to the given callback URL.
    ///
    /// Returns a no-op notifier if no callback URL is provided.
    pub fn new(callback_url: Option<Authority>) -> Self {
        let Some(callback_url) = callback_url else {
            return Self::noop();
        };

        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn background task to send notifications
        tokio::spawn(notification_worker(callback_url, rx));

        Self {
            inner: Some(Arc::new(BlockNotifierInner { tx })),
        }
    }

    /// Creates a no-op notifier that discards all events.
    pub fn noop() -> Self {
        Self { inner: None }
    }

    /// Returns true if notifications are enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Sends a block event notification.
    ///
    /// This is non-blocking and will not fail if the receiver is full or closed.
    pub fn notify(&self, event: BlockEvent) {
        if let Some(inner) = &self.inner {
            if let Err(e) = inner.tx.send(event) {
                tracing::debug!("failed to send block notification (receiver dropped): {}", e);
            }
        }
    }
}

async fn notification_worker(callback_authority: Authority, mut rx: mpsc::UnboundedReceiver<BlockEvent>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    let url = format!("http://{}/block", callback_authority);
    let host = callback_authority.to_string();

    tracing::info!("block notifier worker started, sending events to {}", url);

    while let Some(event) = rx.recv().await {
        tracing::debug!(
            "sending block notification: product={} package={}",
            event.product,
            event.package_name
        );

        let body = match serde_json::to_vec(&event) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("failed to serialize block event: {}", e);
                continue;
            }
        };

        // Simple HTTP/1.1 POST request (no need for full client stack for localhost)
        let request = format!(
            "POST /block HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            host,
            body.len()
        );

        // Spawn blocking IO in separate task
        let host_clone = host.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut stream = TcpStream::connect(&host_clone)?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.write_all(request.as_bytes())?;
            stream.write_all(&body)?;
            stream.flush()?;

            // Read response status
            let mut response = [0u8; 128];
            let n = stream.read(&mut response)?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&response[..n]).to_string())
        })
        .await;

        match result {
            Ok(Ok(resp)) if resp.contains("200") => {
                tracing::debug!("block notification sent successfully");
            }
            Ok(Ok(resp)) => {
                tracing::warn!("block notification returned non-success: {}", resp.lines().next().unwrap_or("unknown"));
            }
            Ok(Err(e)) => {
                tracing::warn!("failed to send block notification: {}", e);
            }
            Err(e) => {
                tracing::warn!("block notification task panicked: {}", e);
            }
        }
    }

    tracing::debug!("block notifier worker shutting down");
}
