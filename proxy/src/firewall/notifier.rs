use super::events::BlockedEvent;
use rama::telemetry::tracing;
use std::sync::Arc;
use tokio::sync::mpsc;

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
    pub fn new(reporting_endpoint: Option<String>) -> Self {
        let Some(endpoint) = reporting_endpoint else {
            return Self::noop();
        };

        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(notification_worker(endpoint, rx));

        Self {
            inner: Some(Arc::new(EventNotifierInner { tx })),
        }
    }

    pub fn noop() -> Self {
        Self { inner: None }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub fn notify(&self, event: BlockedEvent) {
        if let Some(inner) = &self.inner
            && let Err(e) = inner.tx.send(event)
        {
            tracing::debug!(
                "failed to send event notification (receiver dropped): {}",
                e
            );
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

        let _endpoint_clone = reporting_endpoint.clone();
        let result = tokio::task::spawn_blocking(move || {
            // TODO: Implement HTTP POST to endpoint
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
