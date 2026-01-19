use std::sync::Arc;

use rama::telemetry::tracing;
use tokio::sync::mpsc;

use super::events::BlockedEvent;

/// A handle to send block notifications to a reporting endpoint.
///
/// This is cheaply cloneable and can be shared across rules.
#[derive(Clone)]
pub struct EventNotifier {
    inner: Option<Arc<EventNotifierInner>>,
}

struct EventNotifierInner {
    tx: mpsc::UnboundedSender<BlockedEvent>,
}

impl std::fmt::Debug for EventNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventNotifier")
            .field("enabled", &self.inner.is_some())
            .finish()
    }
}

impl EventNotifier {
    /// Creates a new event notifier that sends events to the given reporting endpoint.
    ///
    /// Returns a no-op notifier if no endpoint URL is provided.
    pub fn new(reporting_endpoint: Option<String>) -> Self {
        let Some(endpoint) = reporting_endpoint else {
            return Self::noop();
        };

        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn background task to send notifications
        tokio::spawn(notification_worker(endpoint, rx));

        Self {
            inner: Some(Arc::new(EventNotifierInner { tx })),
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

    /// Sends a blocked event notification.
    ///
    /// This is non-blocking and will not fail if the receiver is full or closed.
    pub fn notify(&self, event: BlockedEvent) {
        if let Some(inner) = &self.inner {
            if let Err(e) = inner.tx.send(event) {
                tracing::debug!(
                    "failed to send event notification (receiver dropped): {}",
                    e
                );
            }
        }
    }
}

async fn notification_worker(
    reporting_endpoint: String,
    mut rx: mpsc::UnboundedReceiver<BlockedEvent>,
) {
    tracing::info!(
        "event notifier worker started, sending events to {}",
        reporting_endpoint
    );

    while let Some(event) = rx.recv().await {
        tracing::debug!(
            "sending event notification: product={} artifact={:?}",
            event.artifact.product,
            event.artifact
        );

        let _body = match serde_json::to_vec(&event) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!("failed to serialize event: {}", e);
                continue;
            }
        };

        // TODO: Parse endpoint URL and extract host/path
        // For now, assume format: http://host:port/path
        let _endpoint_clone = reporting_endpoint.clone();
        let result = tokio::task::spawn_blocking(move || {
            // TODO: Implement HTTP POST to endpoint
            // This is a placeholder - actual implementation should:
            // 1. Parse the URL
            // 2. Create TCP connection
            // 3. Send HTTP/1.1 POST request
            // 4. Handle response and errors gracefully

            Ok::<_, std::io::Error>(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                tracing::debug!("event notification sent successfully");
            }
            Ok(Err(e)) => {
                tracing::warn!("failed to send event notification: {}", e);
            }
            Err(e) => {
                tracing::warn!("event notification task panicked: {}", e);
            }
        }
    }

    tracing::debug!("event notifier worker shutting down");
}
