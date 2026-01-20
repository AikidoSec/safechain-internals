use super::events::BlockedEvent;
use rama::{
    Service,
    error::OpaqueError,
    http::{Request, Response, Uri, service::client::HttpClientExt as _},
    telemetry::tracing,
};
use tokio::sync::mpsc;

const NOTIFIER_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct EventNotifier {
    tx: mpsc::Sender<BlockedEvent>,
}

impl std::fmt::Debug for EventNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventNotifier").finish()
    }
}

impl EventNotifier {
    pub fn try_new(reporting_endpoint: Uri) -> Result<Self, OpaqueError> {
        let client = crate::client::new_web_client()?;

        let (tx, rx) = mpsc::channel(NOTIFIER_CHANNEL_CAPACITY);

        tokio::spawn(notification_worker(reporting_endpoint, client, rx));

        Ok(Self { tx })
    }

    pub fn notify(&self, event: BlockedEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!(
                    "dropping blocked-event notification: notifier queue is full (capacity = {})",
                    NOTIFIER_CHANNEL_CAPACITY
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(
                    "failed to send event notification (receiver dropped): channel closed"
                );
            }
        }
    }
}

async fn notification_worker<C>(
    reporting_endpoint: Uri,
    client: C,
    mut rx: mpsc::Receiver<BlockedEvent>,
) where
    C: Service<Request, Output = Response, Error = OpaqueError>,
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
            .await;

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
