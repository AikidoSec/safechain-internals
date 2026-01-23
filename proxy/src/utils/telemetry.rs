use std::{io::IsTerminal as _, path::Path};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::{
        self,
        metadata::LevelFilter,
        subscriber::{EnvFilter, fmt::writer::BoxMakeWriter},
    },
};

#[derive(Debug, Default)]
pub struct TelemetryConfig<'a> {
    /// Log verbose (for more control use `RUST_LOG` env var)
    pub verbose: bool,
    /// Enable pretty logging (human-friendly, not for computer integestion)
    pub pretty: bool,
    /// Log to a file instead of stderr.
    pub output: Option<&'a Path>,
}

/// Configures structured logging with runtime control via `RUST_LOG` environment variable.
///
/// Defaults to INFO level to balance visibility with performance.
/// Use `RUST_LOG=debug` or `RUST_LOG=trace` for troubleshooting.
pub fn init_tracing(cfg: Option<TelemetryConfig<'_>>) -> Result<(), BoxError> {
    let cfg = cfg.unwrap_or_default();

    let directive = if cfg.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    }
    .into();

    let make_writer = match cfg.output {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .context("open log file")?;

            BoxMakeWriter::new(file)
        }
        None => BoxMakeWriter::new(std::io::stderr),
    };

    let subscriber = tracing::subscriber::fmt()
        .with_ansi(cfg.output.is_none() && std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(directive)
                .from_env_lossy(),
        )
        .with_writer(make_writer);

    if cfg.pretty {
        subscriber.pretty().try_init()?;
    } else {
        subscriber.try_init()?;
    }

    tracing::info!("Tracing is set up");
    Ok(())
}

// NOTES for development team:
//
// Rama also supports OpenTelemetry:
//   - For tracing (with spans)
//   - As well as metrics
//
// Reach out to Glen (rama) if you need help with setting this up.
//
// Relevant docs:
//
// - setup: <https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html>
// - http metrics layer: <https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html>
// - transport (e.g. tcp) metrics layer: <https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html>
//
