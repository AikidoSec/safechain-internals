use std::{path::PathBuf, sync::OnceLock};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::subscriber::{
        self, filter, layer::SubscriberExt as _, util::SubscriberInitExt as _,
    },
};
use tracing_oslog::OsLogger;

pub mod env;

pub fn init_tracing() -> bool {
    static CTX: OnceLock<Option<TraceContext>> = OnceLock::new();
    CTX.get_or_init(|| match setup_tracing() {
        Ok(ctx) => Some(ctx),
        Err(err) => {
            eprintln!("failed to setup tracing: {err}");
            None
        }
    })
    .is_some()
}

static STORAGE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn set_storage_dir(path: Option<PathBuf>) {
    if let Some(path) = path {
        let _ = STORAGE_DIR.set(path);
    }
}

pub fn storage_dir() -> Option<PathBuf> {
    STORAGE_DIR.get().cloned()
}

#[derive(Debug)]
struct TraceContext;

fn setup_tracing() -> Result<TraceContext, BoxError> {
    let stderr_layer = subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stderr);

    let oslog_layer = OsLogger::new("com.aikido.endpoint.proxy.l4", "proxy");

    subscriber::registry()
        .with(filter::LevelFilter::DEBUG)
        .with(stderr_layer)
        .with(oslog_layer)
        .try_init()
        .context("init tracing subsriber")?;

    Ok(TraceContext)
}
