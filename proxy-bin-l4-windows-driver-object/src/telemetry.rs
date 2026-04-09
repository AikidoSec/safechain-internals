use std::{fs, io::IsTerminal as _, path::Path};

use rama::telemetry::tracing;
use rama::telemetry::tracing::appender::{self, non_blocking::WorkerGuard};
use rama::telemetry::tracing::metadata::LevelFilter;
use rama::telemetry::tracing::subscriber::{
    self, EnvFilter, Layer as _, fmt::writer::BoxMakeWriter, layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

#[derive(Debug)]
pub struct TracingGuard {
    _guard: Option<WorkerGuard>,
}

#[derive(Debug, Default)]
pub struct TelemetryConfig<'a> {
    pub verbose: bool,
    pub pretty: bool,
    pub output: Option<&'a Path>,
}

pub fn init_tracing(cfg: &TelemetryConfig<'_>) -> Result<TracingGuard, String> {
    let directive = if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let (make_writer, guard) = match cfg.output {
        Some(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|err| {
                    format!("failed to create log directory {}: {err}", parent.display())
                })?;
            }

            let file_appender = appender::rolling::never(
                path.parent().unwrap_or_else(|| Path::new(".")),
                path.file_name().ok_or_else(|| {
                    format!("output path {} must include a file name", path.display())
                })?,
            );
            let (non_blocking, guard) = appender::non_blocking(file_appender);
            (BoxMakeWriter::new(non_blocking), Some(guard))
        }
        None => (BoxMakeWriter::new(std::io::stderr), None),
    };

    let fmt_layer = subscriber::fmt::layer()
        .with_ansi(cfg.output.is_none() && std::io::stderr().is_terminal())
        .with_writer(make_writer);
    let fmt_layer = if cfg.pretty {
        fmt_layer.pretty().boxed()
    } else {
        fmt_layer.boxed()
    };

    subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(directive.into())
                .from_env_lossy(),
        )
        .with(fmt_layer)
        .try_init()
        .map_err(|err| format!("failed to initialize tracing: {err}"))?;

    tracing::info!(
        verbose = cfg.verbose,
        pretty = cfg.pretty,
        output = ?cfg.output,
        "tracing initialized"
    );

    Ok(TracingGuard { _guard: guard })
}
