use std::{borrow::Cow, env::current_dir, io::IsTerminal as _};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::{
        self,
        appender::{
            self,
            rolling::{Rotation, RollingFileAppender},
        },
        metadata::LevelFilter,
        subscriber::{EnvFilter, fmt::writer::BoxMakeWriter},
    },
};
use tokio::fs::create_dir_all;

use crate::Args;

#[derive(Debug)]
pub struct TracingGuard {
    _appender_guard: Option<appender::non_blocking::WorkerGuard>,
}

/// Configures structured logging with runtime control via `RUST_LOG` environment variable.
///
/// Defaults to INFO level to balance visibility with performance.
/// Use `RUST_LOG=debug` or `RUST_LOG=trace` for troubleshooting.
pub async fn init_tracing(args: &Args) -> Result<TracingGuard, BoxError> {
    let directive = if args.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    }
    .into();

    let (make_writer, _appender_guard) = match args.output.as_deref() {
        Some(path) => {
            let log_dir =
                if let Some(parent) = path.parent()
                    && !parent.exists()
                {
                    create_dir_all(parent).await.context("create log dir")?;
                    Cow::Borrowed(parent)
                } else {
                    Cow::Owned(current_dir().context(
                        "failed to fetch current directory as fallback log directory",
                    )?)
                };

            let prefix = path
                .file_stem()
                .context("file name expected if parent exists")?
                .to_string_lossy();
            let file_appender = RollingFileAppender::builder()
                .rotation(Rotation::HOURLY)
                .filename_prefix(prefix.as_ref())
                .filename_suffix("log")
                .build(&*log_dir)
                .context("init rolling file appender")?;
            let (non_blocking, guard) = appender::non_blocking(file_appender);

            (BoxMakeWriter::new(non_blocking), Some(guard))
        }
        None => (BoxMakeWriter::new(std::io::stderr), None),
    };

    let subscriber = tracing::subscriber::fmt()
        .with_ansi(args.output.is_none() && std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(directive)
                .from_env_lossy(),
        )
        .with_writer(make_writer);

    if args.pretty {
        subscriber.pretty().try_init()?;
    } else {
        subscriber.try_init()?;
    }

    tracing::info!("Tracing is set up");
    Ok(TracingGuard { _appender_guard })
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
