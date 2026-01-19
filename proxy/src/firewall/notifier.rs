use super::events::BlockedEvent;
use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{Request, Response, Uri, service::client::HttpClientExt as _},
    telemetry::tracing,
};
use std::{str::FromStr as _, sync::Arc};
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

        let endpoint_uri = match Uri::from_str(&endpoint) {
            Ok(uri) => uri,
            Err(err) => {
                tracing::warn!(
                    "invalid reporting endpoint URL for blocked events: '{endpoint}': {err}"
                );
                return Self::noop();
            }
        };

        let client = match crate::client::new_web_client() {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to create web client for blocked-event reporting; notifier disabled"
                );
                return Self::noop();
            }
        };

        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(notification_worker(endpoint_uri, client, rx));

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

async fn notification_worker<C>(
    reporting_endpoint: Uri,
    client: C,
    mut rx: mpsc::UnboundedReceiver<BlockedEvent>,
) where
    C: Service<Request, Output = Response, Error = OpaqueError> + 'static,
{
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

        let resp = client
            .post(reporting_endpoint.clone())
            .json(&event)
            .send()
            .await
            .with_context(|| {
                format!(
                    "send blocked-event notification to reporting endpoint '{}'",
                    reporting_endpoint
                )
            });

        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("event notification sent successfully");
            }
            Ok(resp) => {
                let status = resp.status();
                tracing::warn!(
                    status = %status,
                    endpoint = %reporting_endpoint,
                    "blocked-event notification endpoint returned non-success status"
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    endpoint = %reporting_endpoint,
                    "failed to send blocked-event notification"
                );
            }
        }
    }

    tracing::debug!("event notifier worker shutting down");
}
