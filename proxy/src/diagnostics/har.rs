use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use rama::error::{BoxError, ErrorContext};
use rama::graceful::ShutdownGuard;
use rama::http::layer::har;
use rama::http::layer::har::recorder::FileRecorder;
use tokio::sync::mpsc;

pub type HARExportLayer = har::layer::HARExportLayer<FileRecorder, Arc<AtomicBool>>;

#[derive(Debug, Clone)]
pub struct HarClient {
    toggle_tx: mpsc::Sender<()>,
    toggle_state: Arc<AtomicBool>,
}

impl HarClient {
    /// Toggles the har recording status and returns previous state of toggle.
    pub async fn toggle(&self) -> Result<bool, BoxError> {
        let previous = self.toggle_state.load(std::sync::atomic::Ordering::Relaxed);
        self.toggle_tx
            .send(())
            .await
            .context("failed to switch the HAR client toggle")?;
        Ok(previous)
    }
}

impl HarClient {
    pub fn new(data: &Path, guard: ShutdownGuard) -> (Self, HARExportLayer) {
        let recorder =
            har::recorder::FileRecorder::new(data.join("diagnostics"), "proxy".to_owned());

        let (toggle_state, toggle_tx) =
            har::toggle::mpsc_toggle(2, guard.downgrade().into_cancelled());

        let layer = har::layer::HARExportLayer::new(recorder, toggle_state.clone());
        let this = HarClient {
            toggle_tx,
            toggle_state,
        };

        (this, layer)
    }
}
